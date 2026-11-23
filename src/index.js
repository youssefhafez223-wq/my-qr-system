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

      
      // Shop management
      if (url.pathname === "/api/stores" && request.method === "GET") {
        try {
          const response = await fetch(`${supabaseUrl}/rest/v1/stores?select=id,name,slug,address,phone,destination_url,is_active,is_locked,created_at&order=name.asc`, { headers });
          if (!response.ok) return json({ error: "Could not load shops" }, 502);
          return json(await response.json());
        } catch (error) {
          console.error("List shops failed:", error);
          return json({ error: "Could not load shops" }, 502);
        }
      }

      if (url.pathname === "/api/stores" && request.method === "POST") {
        try {
          const body = await request.json();
          const name = String(body.name || "").trim();
          if (!name || name.length > 100) return json({ error: "Enter a shop name (up to 100 characters)" }, 400);
          let destination;
          try { destination = new URL(String(body.destination_url || "")); } catch { return json({ error: "Enter a valid Shop URL" }, 400); }
          if (!["http:", "https:"].includes(destination.protocol)) return json({ error: "Shop URL must start with http:// or https://" }, 400);
          const slug = "shop-" + crypto.randomUUID().slice(0, 8);
          const response = await fetch(`${supabaseUrl}/rest/v1/stores`, {
            method: "POST",
            headers: { ...headers, Prefer: "return=representation" },
            body: JSON.stringify({ name, slug, address: String(body.address || "").trim() || null, phone: String(body.phone || "").trim() || null, destination_url: destination.toString(), is_active: true })
          });
          if (!response.ok) {
            const detail = await response.text();
            console.error("Create shop failed:", response.status, detail);
            return json({ error: "Could not create shop" }, 502);
          }
          return json(await response.json(), 201);
        } catch (error) {
          console.error("Create shop failed:", error);
          return json({ error: "Invalid shop data" }, 400);
        }
      }

      if (url.pathname.startsWith("/api/stores/") && url.pathname.endsWith("/lock") && request.method === "POST") {
        try {
          const id = decodeURIComponent(url.pathname.slice("/api/stores/".length, -"/lock".length));
          if (!/^[0-9a-f-]{36}$/i.test(id)) return json({ error: "Invalid shop ID" }, 400);
          const body = await request.json();
          if (typeof body.is_locked !== "boolean") return json({ error: "Invalid lock state" }, 400);
          const response = await fetch(`${supabaseUrl}/rest/v1/stores?id=eq.${encodeURIComponent(id)}`, {
            method: "PATCH", headers: { ...headers, Prefer: "return=representation" },
            body: JSON.stringify({ is_locked: body.is_locked })
          });
          if (!response.ok) return json({ error: "Could not update shop lock" }, 502);
          return json(await response.json());
        } catch (error) {
          console.error("Shop lock update failed:", error);
          return json({ error: "Could not update shop lock" }, 400);
        }
      }

      if (url.pathname.startsWith("/api/stores/") && request.method === "PATCH") {
        try {
          const id = decodeURIComponent(url.pathname.slice("/api/stores/".length));
          if (!/^[0-9a-f-]{36}$/i.test(id)) return json({ error: "Invalid shop ID" }, 400);
          const currentResponse = await fetch(`${supabaseUrl}/rest/v1/stores?id=eq.${encodeURIComponent(id)}&select=id,is_locked,slug&limit=1`, { headers });
          if (!currentResponse.ok) return json({ error: "Could not verify shop lock" }, 502);
          const currentRows = await currentResponse.json();
          const currentShop = currentRows[0];
          if (!currentShop) return json({ error: "Shop not found" }, 404);
          if (currentShop.is_locked) return json({ error: "This shop is locked. Unlock it before editing." }, 423);
          const body = await request.json();
          if (body.name !== undefined || body.destination_url !== undefined || body.is_active !== undefined) {
            const linkedQrResponse = await fetch(`${supabaseUrl}/rest/v1/qr_codes?code=eq.${encodeURIComponent(currentShop.slug)}&store_id=eq.${encodeURIComponent(id)}&select=code,is_locked&limit=1`, { headers });
            if (!linkedQrResponse.ok) return json({ error: "Could not verify the shop QR lock" }, 502);
            const linkedQrs = await linkedQrResponse.json();
            if (linkedQrs[0]?.is_locked) return json({ error: "The shop's QR code is locked. Unlock that QR code before changing the shop name, URL, or active state." }, 423);
          }
          const update = {};
          if (body.name !== undefined) {
            const name = String(body.name).trim();
            if (!name || name.length > 100) return json({ error: "Invalid shop name" }, 400);
            update.name = name;
          }
          if (body.address !== undefined) update.address = String(body.address || "").trim() || null;
          if (body.phone !== undefined) update.phone = String(body.phone || "").trim() || null;
          if (body.destination_url !== undefined) {
            let destination;
            try { destination = new URL(String(body.destination_url || "")); } catch { return json({ error: "Invalid Shop URL" }, 400); }
            if (!["http:", "https:"].includes(destination.protocol)) return json({ error: "Shop URL must start with http:// or https://" }, 400);
            update.destination_url = destination.toString();
          }
          if (body.is_active !== undefined) update.is_active = Boolean(body.is_active);
          if (Object.keys(update).length === 0) return json({ error: "Nothing to update" }, 400);
          const response = await fetch(`${supabaseUrl}/rest/v1/stores?id=eq.${encodeURIComponent(id)}`, {
            method: "PATCH",
            headers: { ...headers, Prefer: "return=representation" },
            body: JSON.stringify(update)
          });
          if (!response.ok) return json({ error: "Could not update shop" }, 502);
          const updatedShop = await response.json();
          const qrUpdate = {};
          if (update.name !== undefined) qrUpdate.title = update.name;
          if (update.destination_url !== undefined) qrUpdate.destination_url = update.destination_url;
          if (update.is_active !== undefined) qrUpdate.is_active = update.is_active;
          const savedShop = Array.isArray(updatedShop) ? updatedShop[0] : null;
          if (Object.keys(qrUpdate).length && savedShop?.slug) {
            // Sync only the shop's dedicated QR (code = shop slug).
            // Legacy QR codes linked to this shop keep their own destinations.
            const sync = await fetch(`${supabaseUrl}/rest/v1/qr_codes?code=eq.${encodeURIComponent(savedShop.slug)}&store_id=eq.${encodeURIComponent(id)}`, {
              method: "PATCH", headers: { ...headers, Prefer: "return=minimal" }, body: JSON.stringify(qrUpdate)
            });
            if (!sync.ok) return json({ error: "Shop was updated, but its dedicated QR code could not be synchronized. Please retry Edit." }, 502);
          }
          return json(updatedShop);
        } catch (error) {
          console.error("Update shop failed:", error);
          return json({ error: "Invalid shop data" }, 400);
        }
      }

      if (url.pathname.startsWith("/api/stores/") && url.pathname.endsWith("/generate") && request.method === "POST") {
        try {
          const id = decodeURIComponent(url.pathname.slice("/api/stores/".length, -"/generate".length));
          if (!/^[0-9a-f-]{36}$/i.test(id)) return json({ error: "Invalid shop ID" }, 400);
          const storeResponse = await fetch(`${supabaseUrl}/rest/v1/stores?id=eq.${encodeURIComponent(id)}&select=id,name,slug,destination_url,is_active,is_locked&limit=1`, { headers });
          if (!storeResponse.ok) return json({ error: "Could not load shop" }, 502);
          const shops = await storeResponse.json();
          const shop = shops[0];
          if (!shop) return json({ error: "Shop not found" }, 404);
          if (!shop.destination_url) return json({ error: "Add a Shop URL in Edit before generating its QR code." }, 400);
          // Reuse only the dedicated shop QR whose permanent code equals the shop slug.
          // Do not hijack older QR codes that happen to be linked to the same shop.
          const existingResponse = await fetch(`${supabaseUrl}/rest/v1/qr_codes?code=eq.${encodeURIComponent(shop.slug)}&store_id=eq.${encodeURIComponent(id)}&select=code&limit=1`, { headers });
          if (!existingResponse.ok) return json({ error: "Could not check existing shop QR code" }, 502);
          const existing = await existingResponse.json();
          if (existing.length) {
            const code = existing[0].code;
            const existingQrCheck = await fetch(`${supabaseUrl}/rest/v1/qr_codes?code=eq.${encodeURIComponent(code)}&select=is_locked&limit=1`, { headers });
            if (!existingQrCheck.ok) return json({ error: "Could not verify the existing QR code" }, 502);
            const existingQrRows = await existingQrCheck.json();
            if (!existingQrRows[0]?.is_locked) {
              const sync = await fetch(`${supabaseUrl}/rest/v1/qr_codes?code=eq.${encodeURIComponent(code)}`, {
                method: "PATCH", headers: { ...headers, Prefer: "return=minimal" },
                body: JSON.stringify({ title: shop.name, destination_url: shop.destination_url, is_active: shop.is_active })
              });
              if (!sync.ok) return json({ error: "Could not refresh the shop QR code" }, 502);
            }
            return json({ code, existing: true });
          }
          const code = shop.slug;
          const created = await fetch(`${supabaseUrl}/rest/v1/qr_codes`, {
            method: "POST", headers: { ...headers, Prefer: "return=representation" },
            body: JSON.stringify({ title: shop.name, code, destination_url: shop.destination_url, is_active: shop.is_active, store_id: id })
          });
          if (!created.ok) {
            const detail = await created.text();
            console.error("Generate shop QR failed:", created.status, detail);
            return json({ error: "Could not generate the shop QR code" }, 502);
          }
          return json({ code, existing: false }, 201);
        } catch (error) {
          console.error("Generate shop QR failed:", error);
          return json({ error: "Could not generate the shop QR code" }, 502);
        }
      }

      if (url.pathname.startsWith("/api/stores/") && request.method === "DELETE") {
        try {
          const id = decodeURIComponent(url.pathname.slice("/api/stores/".length));
          if (!/^[0-9a-f-]{36}$/i.test(id)) return json({ error: "Invalid shop ID" }, 400);
          const shopCheck = await fetch(`${supabaseUrl}/rest/v1/stores?id=eq.${encodeURIComponent(id)}&select=is_locked&limit=1`, { headers });
          if (!shopCheck.ok) return json({ error: "Could not verify shop lock" }, 502);
          const shopRows = await shopCheck.json();
          if (!shopRows[0]) return json({ error: "Shop not found" }, 404);
          if (shopRows[0].is_locked) return json({ error: "This shop is locked. Unlock it before removing it." }, 423);
          const linkedCheck = await fetch(`${supabaseUrl}/rest/v1/qr_codes?store_id=eq.${encodeURIComponent(id)}&select=code,is_locked`, { headers });
          if (!linkedCheck.ok) return json({ error: "Could not verify linked QR codes" }, 502);
          const linkedCodes = await linkedCheck.json();
          if (linkedCodes.some(item => item.is_locked)) return json({ error: "At least one linked QR code is locked. Unlock it before removing this shop." }, 423);
          // Unlink QR codes first; never delete QR codes or scan history with a shop. never delete QR codes or scan history with a shop.
          const unlink = await fetch(`${supabaseUrl}/rest/v1/qr_codes?store_id=eq.${encodeURIComponent(id)}`, {
            method: "PATCH",
            headers: { ...headers, Prefer: "return=minimal" },
            body: JSON.stringify({ store_id: null })
          });
          if (!unlink.ok) return json({ error: "Could not unlink QR codes from this shop" }, 502);
          const response = await fetch(`${supabaseUrl}/rest/v1/stores?id=eq.${encodeURIComponent(id)}`, {
            method: "DELETE",
            headers: { ...headers, Prefer: "return=minimal" }
          });
          if (!response.ok) return json({ error: "Could not remove shop" }, 502);
          return json({ success: true });
        } catch (error) {
          console.error("Delete shop failed:", error);
          return json({ error: "Could not remove shop" }, 502);
        }
      }

      // List QR codes with scan statistics
      if (url.pathname === "/api/qr" && request.method === "GET") {
        try {
          const response = await fetch(
            `${supabaseUrl}/rest/v1/qr_codes?select=title,code,destination_url,is_active,store_id,is_locked&order=code.asc`,
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

          const code = body.code
            ? String(body.code).trim()
            : "q-" + crypto.randomUUID().replace(/-/g, "").slice(0, 16);

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
                title: String(body.title || "").trim() || code,
                code,
                destination_url: destination.toString(),
                is_active: true,
                store_id: body.store_id || null
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
      if (url.pathname.startsWith("/api/qr/") && url.pathname.endsWith("/lock") && request.method === "POST") {
        try {
          const code = decodeURIComponent(url.pathname.slice("/api/qr/".length, -"/lock".length));
          if (!/^[a-zA-Z0-9_-]+$/.test(code)) return json({ error: "Invalid QR code" }, 400);
          const body = await request.json();
          if (typeof body.is_locked !== "boolean") return json({ error: "Invalid lock state" }, 400);
          const response = await fetch(`${supabaseUrl}/rest/v1/qr_codes?code=eq.${encodeURIComponent(code)}`, {
            method: "PATCH", headers: { ...headers, Prefer: "return=representation" },
            body: JSON.stringify({ is_locked: body.is_locked })
          });
          if (!response.ok) return json({ error: "Could not update QR lock" }, 502);
          return json(await response.json());
        } catch (error) {
          console.error("QR lock update failed:", error);
          return json({ error: "Could not update QR lock" }, 400);
        }
      }

      if (url.pathname.startsWith("/api/qr/") && request.method === "PATCH") {
        try {
          const code = decodeURIComponent(
            url.pathname.slice("/api/qr/".length)
          );

          if (!/^[a-zA-Z0-9_-]+$/.test(code)) {
            return json({ error: "Invalid QR code" }, 400);
          }

          const lockCheck = await fetch(`${supabaseUrl}/rest/v1/qr_codes?code=eq.${encodeURIComponent(code)}&select=is_locked&limit=1`, { headers });
          if (!lockCheck.ok) return json({ error: "Could not verify QR lock" }, 502);
          const lockRows = await lockCheck.json();
          if (!lockRows[0]) return json({ error: "QR code not found" }, 404);
          if (lockRows[0].is_locked) return json({ error: "This QR code is locked. Unlock it before editing." }, 423);
          const body = await request.json();
          const update = {};

          if (body.title !== undefined) {
            const title = String(body.title || "").trim();
            if (!title || title.length > 120) return json({ error: "QR name is required (up to 120 characters)" }, 400);
            update.title = title;
          }

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
          if (body.store_id !== undefined) {
            if (body.store_id !== null && !/^[0-9a-f-]{36}$/i.test(String(body.store_id))) {
              return json({ error: "Invalid shop selection" }, 400);
            }
            update.store_id = body.store_id;
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

      // Private admin notes linked to a shop, a QR code, or both.
      if (url.pathname === "/api/notes" && request.method === "GET") {
        try {
          const response = await fetch(`${supabaseUrl}/rest/v1/qroma_notes?select=id,store_id,code,note,status,created_at,updated_at&order=created_at.desc`, { headers });
          if (!response.ok) return json({ error: "Could not load notes" }, 502);
          return json(await response.json());
        } catch (error) {
          console.error("Load notes failed:", error);
          return json({ error: "Could not load notes" }, 502);
        }
      }

      if (url.pathname === "/api/notes" && request.method === "POST") {
        try {
          const body = await request.json();
          const note = String(body.note || "").trim();
          const status = String(body.status || "pending");
          if (!note || note.length > 4000) return json({ error: "Write a note (up to 4000 characters)." }, 400);
          if (!["done", "pending", "rejected"].includes(status)) return json({ error: "Invalid note status" }, 400);
          if (!body.store_id && !body.code) return json({ error: "Choose a shop or QR code for this note." }, 400);
          if (body.store_id && !/^[0-9a-f-]{36}$/i.test(String(body.store_id))) return json({ error: "Invalid shop selection" }, 400);
          if (body.code && !/^[a-zA-Z0-9_-]+$/.test(String(body.code))) return json({ error: "Invalid QR selection" }, 400);
          const response = await fetch(`${supabaseUrl}/rest/v1/qroma_notes`, {
            method: "POST", headers: { ...headers, Prefer: "return=representation" },
            body: JSON.stringify({ store_id: body.store_id || null, code: body.code || null, note, status })
          });
          if (!response.ok) {
            const detail = await response.text();
            console.error("Create note failed:", response.status, detail);
            return json({ error: "Could not save note" }, 502);
          }
          return json(await response.json(), 201);
        } catch (error) {
          console.error("Create note failed:", error);
          return json({ error: "Could not save note" }, 400);
        }
      }

      if (url.pathname.startsWith("/api/notes/") && request.method === "PATCH") {
        try {
          const id = decodeURIComponent(url.pathname.slice("/api/notes/".length));
          if (!/^[0-9a-f-]{36}$/i.test(id)) return json({ error: "Invalid note ID" }, 400);
          const body = await request.json();
          const update = {};
          if (body.note !== undefined) {
            const note = String(body.note || "").trim();
            if (!note || note.length > 4000) return json({ error: "Write a note (up to 4000 characters)." }, 400);
            update.note = note;
          }
          if (body.status !== undefined) {
            if (!["done", "pending", "rejected"].includes(String(body.status))) return json({ error: "Invalid note status" }, 400);
            update.status = String(body.status);
          }
          if (!Object.keys(update).length) return json({ error: "Nothing to update" }, 400);
          update.updated_at = new Date().toISOString();
          const response = await fetch(`${supabaseUrl}/rest/v1/qroma_notes?id=eq.${encodeURIComponent(id)}`, {
            method: "PATCH", headers: { ...headers, Prefer: "return=representation" },
            body: JSON.stringify(update)
          });
          if (!response.ok) return json({ error: "Could not update note" }, 502);
          return json(await response.json());
        } catch (error) {
          console.error("Update note failed:", error);
          return json({ error: "Could not update note" }, 400);
        }
      }

      if (url.pathname.startsWith("/api/notes/") && request.method === "DELETE") {
        try {
          const id = decodeURIComponent(url.pathname.slice("/api/notes/".length));
          if (!/^[0-9a-f-]{36}$/i.test(id)) return json({ error: "Invalid note ID" }, 400);
          const response = await fetch(`${supabaseUrl}/rest/v1/qroma_notes?id=eq.${encodeURIComponent(id)}`, {
            method: "DELETE", headers: { ...headers, Prefer: "return=minimal" }
          });
          if (!response.ok) return json({ error: "Could not delete note" }, 502);
          return json({ success: true });
        } catch (error) {
          console.error("Delete note failed:", error);
          return json({ error: "Could not delete note" }, 400);
        }
      }

      // Scan counter and history management. Omit codes to apply an action to all QR codes.
      if (url.pathname === "/api/scans/manage" && request.method === "POST") {
        try {
          const body = await request.json();
          const action = String(body.action || "");
          const allowed = ["reset_counters", "delete_history", "delete_all_history"];
          if (!allowed.includes(action)) return json({ error: "Invalid scan management action" }, 400);
          let codes = null;
          if (body.codes !== undefined && body.codes !== null) {
            if (!Array.isArray(body.codes) || body.codes.length > 200 || body.codes.some(code => !/^[a-zA-Z0-9_-]+$/.test(String(code)))) {
              return json({ error: "Invalid QR code selection" }, 400);
            }
            codes = [...new Set(body.codes.map(String))];
            if (!codes.length) return json({ error: "Select at least one QR code." }, 400);
          }
          if (action === "delete_history" && !codes) return json({ error: "Select QR codes before deleting selected history." }, 400);
          const response = await fetch(`${supabaseUrl}/rest/v1/rpc/qroma_manage_scans`, {
            method: "POST", headers,
            body: JSON.stringify({ action, codes })
          });
          if (!response.ok) {
            const detail = await response.text();
            console.error("Scan management failed:", response.status, detail);
            return json({ error: "Could not update scan records" }, 502);
          }
          return json(await response.json());
        } catch (error) {
          console.error("Scan management failed:", error);
          return json({ error: "Could not update scan records" }, 502);
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

          const lockCheck = await fetch(`${supabaseUrl}/rest/v1/qr_codes?code=eq.${encodeURIComponent(code)}&select=is_locked&limit=1`, { headers });
          if (!lockCheck.ok) return json({ error: "Could not verify QR lock. Please retry." }, 502);
          const lockRows = await lockCheck.json();
          if (!lockRows[0]) return json({ error: "QR code not found" }, 404);
          if (lockRows[0].is_locked) return json({ error: "This QR code is locked. Unlock it before deleting." }, 423);

          const baselineDelete = await fetch(`${supabaseUrl}/rest/v1/rpc/qroma_delete_scan_baseline`, {
            method: "POST", headers, body: JSON.stringify({ target_code: code })
          });
          if (!baselineDelete.ok) {
            const detail = await baselineDelete.text();
            console.error("Delete QR baseline failed:", detail);
            return json({ error: "Could not prepare QR deletion" }, 502);
          }

          // qr_scans.code uses ON DELETE CASCADE, so deleting the QR removes its scan history too.
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
