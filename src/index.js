import { DurableObject } from "cloudflare:workers";

export class LoginRateLimiter extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS login_state (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          failed_attempts INTEGER NOT NULL DEFAULT 0,
          locked_until INTEGER NOT NULL DEFAULT 0
        )
      `);
    });
  }

  async check(passwordIsValid) {
    const now = Date.now();
    const rows = this.ctx.storage.sql.exec(
      "SELECT failed_attempts, locked_until FROM login_state WHERE id = 1"
    ).toArray();
    const state = rows[0] || { failed_attempts: 0, locked_until: 0 };

    if (state.locked_until > now) {
      return {
        allowed: false,
        locked: true,
        retryAfter: Math.max(1, Math.ceil((state.locked_until - now) / 1000))
      };
    }

    if (passwordIsValid) {
      this.ctx.storage.sql.exec("DELETE FROM login_state WHERE id = 1");
      return { allowed: true, locked: false, retryAfter: 0 };
    }

    const failedAttempts = state.locked_until > 0 ? 1 : state.failed_attempts + 1;
    const lockedUntil = failedAttempts >= 3 ? now + 60_000 : 0;
    const savedFailures = lockedUntil > 0 ? 0 : failedAttempts;

    this.ctx.storage.sql.exec(
      `INSERT INTO login_state (id, failed_attempts, locked_until)
       VALUES (1, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         failed_attempts = excluded.failed_attempts,
         locked_until = excluded.locked_until`,
      savedFailures,
      lockedUntil
    );

    return {
      allowed: false,
      locked: lockedUntil > now,
      retryAfter: lockedUntil > now ? 60 : 0
    };
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Dashboard
    if (url.pathname === "/") {
      return env.ASSETS.fetch(request);
    }

    // QR Redirect
    if (url.pathname.startsWith("/r/")) {
      const code = url.pathname.slice(3);

      if (!code || !/^[a-zA-Z0-9_-]+$/.test(code)) {
        return new Response("Invalid QR code", { status: 400 });
      }

      try {
        if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) {
          return new Response("Service unavailable", { status: 503 });
        }

        const supabaseUrl = env.SUPABASE_URL.replace(/\/+$/, "");

        const response = await fetch(
          `${supabaseUrl}/rest/v1/qr_codes?code=eq.${encodeURIComponent(code)}&select=destination_url,is_active&limit=1`,
          {
            headers: {
              apikey: env.SUPABASE_SERVICE_ROLE_KEY,
              Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
              Accept: "application/json"
            }
          }
        );

        if (!response.ok) {
          return new Response("Service unavailable", { status: 503 });
        }

        const data = await response.json();
        const item = data[0];

        if (!item || !item.is_active) {
          return new Response("QR code not found", { status: 404 });
        }

        const destination = new URL(item.destination_url);

        if (!["https:", "http:"].includes(destination.protocol)) {
          return new Response("Invalid destination", { status: 400 });
        }

        // Record QR scan in the background
        ctx.waitUntil(
          fetch(
            `${supabaseUrl}/rest/v1/qr_scans`,
            {
              method: "POST",
              headers: {
                apikey: env.SUPABASE_SERVICE_ROLE_KEY,
                Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
                "Content-Type": "application/json",
                Prefer: "return=minimal"
              },
              body: JSON.stringify({ code })
            }
          ).then(response => {
            if (!response.ok) {
              console.error("QR scan logging failed:", response.status);
            }
          }).catch(error => {
            console.error("QR scan logging error:", error);
          })
        );

        return Response.redirect(destination.toString(), 302);
      } catch {
        return new Response("Service unavailable", { status: 503 });
      }
    }

    // API response helper
    const json = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json" }
      });

    // Encode / decode token helpers
    const encode = (value) => {
      const bytes = new TextEncoder().encode(value);
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    };

    const decode = (value) => {
      const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
      const binary = atob(base64);
      const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
      return new TextDecoder().decode(bytes);
    };

    const getKey = async () => {
      if (!env.ADMIN_PASSWORD) {
        throw new Error("Admin password is not configured");
      }

      return crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(env.ADMIN_PASSWORD),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"]
      );
    };

    // Create signed admin token
    const createToken = async () => {
      const payload = encode(JSON.stringify({
        exp: Date.now() + 12 * 60 * 60 * 1000
      }));

      const key = await getKey();

      const signature = await crypto.subtle.sign(
        "HMAC",
        key,
        new TextEncoder().encode(payload)
      );

      const bytes = new Uint8Array(signature);
      let binary = "";

      for (const byte of bytes) binary += String.fromCharCode(byte);

      const signed = btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");

      return `${payload}.${signed}`;
    };

    // Check admin token
    const isAuthorized = async () => {
      try {
        const auth = request.headers.get("Authorization") || "";

        if (!auth.startsWith("Bearer ")) return false;

        const token = auth.slice(7).split(".");

        if (token.length !== 2) return false;

        const key = await getKey();

        const signatureBase64 = token[1]
          .replace(/-/g, "+")
          .replace(/_/g, "/");

        const signatureBinary = atob(signatureBase64);

        const signature = Uint8Array.from(
          signatureBinary,
          c => c.charCodeAt(0)
        );

        const valid = await crypto.subtle.verify(
          "HMAC",
          key,
          signature,
          new TextEncoder().encode(token[0])
        );

        if (!valid) return false;

        const payload = JSON.parse(decode(token[0]));

        return payload.exp > Date.now();
      } catch {
        return false;
      }
    };

    // Admin login with failed-attempt rate limiting
    if (url.pathname === "/api/login" && request.method === "POST") {
      try {
        const body = await request.json();

        if (!env.ADMIN_PASSWORD) {
          return json({ error: "Admin password is not configured" }, 500);
        }

        const ip = request.headers.get("CF-Connecting-IP") || "unknown";
        const loginGuard = env.LOGIN_GUARD.getByName(ip);
        const decision = await loginGuard.check(body.password === env.ADMIN_PASSWORD);

        if (decision.locked) {
          return json({
            error: `Too many failed attempts. Please wait ${decision.retryAfter} seconds and try again.`
          }, 429);
        }

        if (!decision.allowed) {
          return json({ error: "Wrong password" }, 401);
        }

        return json({ token: await createToken() });
      } catch (error) {
        console.error("Login failed:", error);
        return json({ error: "Login failed" }, 400);
      }
    }

    // Admin API
    if (url.pathname.startsWith("/api/")) {
      if (!(await isAuthorized())) {
        return json({ error: "Unauthorized" }, 401);
      }

      if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) {
        return json({ error: "Supabase settings are missing" }, 500);
      }

      const supabaseUrl = env.SUPABASE_URL.replace(/\/+$/, "");

      const headers = {
        apikey: env.SUPABASE_SERVICE_ROLE_KEY,
        Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
        "Content-Type": "application/json",
        Accept: "application/json"
      };

      // List QR codes with scan statistics
      if (url.pathname === "/api/qr" && request.method === "GET") {
        try {
          const response = await fetch(
            `${supabaseUrl}/rest/v1/qr_codes?select=code,destination_url,is_active&order=code.asc`,
            { headers }
          );

          if (!response.ok) {
            const errorText = await response.text();
            console.error("Supabase list error:", response.status, errorText);

            return json({
              error: `Could not load QR codes (${response.status})`
            }, 502);
          }

          const items = await response.json();

          try {
            const statsResponse = await fetch(
              `${supabaseUrl}/rest/v1/qr_scan_stats?select=code,scan_count,last_scanned_at`,
              { headers }
            );

            if (statsResponse.ok) {
              const stats = await statsResponse.json();
              const statsByCode = new Map(
                stats.map(item => [item.code, item])
              );

              return json(items.map(item => {
                const stat = statsByCode.get(item.code);
                return {
                  ...item,
                  scan_count: stat ? Number(stat.scan_count) : 0,
                  last_scanned_at: stat ? stat.last_scanned_at : null
                };
              }));
            }

            console.error(
              "Supabase scan stats unavailable:",
              statsResponse.status,
              await statsResponse.text()
            );
          } catch (statsError) {
            console.error("Scan stats request failed:", statsError);
          }

          return json(items.map(item => ({
            ...item,
            scan_count: null,
            last_scanned_at: null
          })));
        } catch (error) {
          console.error("List request failed:", error);
          return json({ error: "Could not connect to Supabase" }, 502);
        }
      }

      // Add QR code
      if (url.pathname === "/api/qr" && request.method === "POST") {
        try {
          const body = await request.json();

          const code = String(body.code || "").trim();

          if (!/^[a-zA-Z0-9_-]+$/.test(code)) {
            return json({ error: "Invalid QR code name" }, 400);
          }

          let destination;

          try {
            destination = new URL(body.destination_url);
          } catch {
            return json({ error: "Invalid destination URL" }, 400);
          }

          if (!["http:", "https:"].includes(destination.protocol)) {
            return json({ error: "Invalid destination URL" }, 400);
          }

          const response = await fetch(
            `${supabaseUrl}/rest/v1/qr_codes`,
            {
              method: "POST",
              headers: {
                ...headers,
                Prefer: "return=representation"
              },
              body: JSON.stringify({
                title: code,
                code,
                destination_url: destination.toString(),
                is_active: true
              })
            }
          );

          if (!response.ok) {
            const errorText = await response.text();

            console.error(
              "Supabase insert failed:",
              response.status,
              errorText
            );

            let detail = errorText;

            try {
              const parsed = JSON.parse(errorText);

              detail = [
                parsed.message,
                parsed.details,
                parsed.hint,
                parsed.code
              ].filter(Boolean).join(" | ") || errorText;
            } catch {
              // Keep original error text
            }

            return json({
              error: `Supabase insert failed (${response.status}): ${detail}`
            }, 502);
          }

          return json(await response.json(), 201);

        } catch (error) {
          console.error("Add QR request failed:", error);

          return json({
            error: "Invalid data or request failed"
          }, 400);
        }
      }

      // Update QR code
      if (url.pathname.startsWith("/api/qr/") && request.method === "PATCH") {
        try {
          const code = decodeURIComponent(
            url.pathname.slice("/api/qr/".length)
          );

          if (!/^[a-zA-Z0-9_-]+$/.test(code)) {
            return json({ error: "Invalid QR code" }, 400);
          }

          const body = await request.json();
          const update = {};

          if (body.destination_url !== undefined) {
            let destination;

            try {
              destination = new URL(body.destination_url);
            } catch {
              return json({ error: "Invalid destination URL" }, 400);
            }

            if (!["https:", "http:"].includes(destination.protocol)) {
              return json({ error: "Invalid destination URL" }, 400);
            }

            update.destination_url = destination.toString();
          }

          if (body.is_active !== undefined) {
            update.is_active = Boolean(body.is_active);
          }

          if (Object.keys(update).length === 0) {
            return json({ error: "Nothing to update" }, 400);
          }

          const response = await fetch(
            `${supabaseUrl}/rest/v1/qr_codes?code=eq.${encodeURIComponent(code)}`,
            {
              method: "PATCH",
              headers: {
                ...headers,
                Prefer: "return=representation"
              },
              body: JSON.stringify(update)
            }
          );

          if (!response.ok) {
            const errorText = await response.text();

            console.error("Supabase update failed:", response.status, errorText);

            return json({
              error: `Could not update QR code (${response.status}): ${errorText}`
            }, 502);
          }

          return json(await response.json());

        } catch (error) {
          console.error("Update request failed:", error);
          return json({ error: "Invalid data" }, 400);
        }
      }

      // Delete QR code
      if (url.pathname.startsWith("/api/qr/") && request.method === "DELETE") {
        try {
          const code = decodeURIComponent(
            url.pathname.slice("/api/qr/".length)
          );

          if (!/^[a-zA-Z0-9_-]+$/.test(code)) {
            return json({ error: "Invalid QR code" }, 400);
          }

          const response = await fetch(
            `${supabaseUrl}/rest/v1/qr_codes?code=eq.${encodeURIComponent(code)}`,
            {
              method: "DELETE",
              headers: {
                ...headers,
                Prefer: "return=minimal"
              }
            }
          );

          if (!response.ok) {
            const errorText = await response.text();

            console.error("Supabase delete failed:", response.status, errorText);

            return json({
              error: `Could not delete QR code (${response.status}): ${errorText}`
            }, 502);
          }

          return json({ success: true });

        } catch (error) {
          console.error("Delete request failed:", error);
          return json({ error: "Delete request failed" }, 400);
        }
      }

      return json({ error: "API route not found" }, 404);
    }

    return new Response("Not Found", { status: 404 });
  }
};
