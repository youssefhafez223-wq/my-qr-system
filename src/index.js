export default {
  async fetch(request, env) {
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
        const response = await fetch(
          `${env.SUPABASE_URL.replace(/\/+$/, "")}/rest/v1/qr_codes?code=eq.${encodeURIComponent(code)}&select=destination_url,is_active&limit=1`,
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
      if (!env.ADMIN_PASSWORD) throw new Error("Admin password is not configured");
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
        const signatureBase64 = token[1].replace(/-/g, "+").replace(/_/g, "/");
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

    // Admin login
    if (url.pathname === "/api/login" && request.method === "POST") {
      try {
        const body = await request.json();

        if (!env.ADMIN_PASSWORD) {
          return json({ error: "Admin password is not configured" }, 500);
        }

        if (body.password !== env.ADMIN_PASSWORD) {
          return json({ error: "Wrong password" }, 401);
        }

        return json({ token: await createToken() });
      } catch {
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

      // List QR codes
      if (url.pathname === "/api/qr" && request.method === "GET") {
        const response = await fetch(
          `${supabaseUrl}/rest/v1/qr_codes?select=code,destination_url,is_active&order=code.asc`,
          { headers }
        );

        if (!response.ok) {
          return json({ error: "Could not load QR codes" }, 502);
        }

        return json(await response.json());
      }

      // Add QR code
      if (url.pathname === "/api/qr" && request.method === "POST") {
        try {
          const body = await request.json();
          const code = String(body.code || "").trim();
          const destination = new URL(body.destination_url);

          if (!/^[a-zA-Z0-9_-]+$/.test(code)) {
            return json({ error: "Invalid QR code name" }, 400);
          }

          if (!["http:", "https:"].includes(destination.protocol)) {
            return json({ error: "Invalid destination URL" }, 400);
          }

          const response = await fetch(`${supabaseUrl}/rest/v1/qr_codes`, {
            method: "POST",
            headers: { ...headers, Prefer: "return=representation" },
            body: JSON.stringify({
              code,
              destination_url: destination.toString(),
              is_active: true
            })
          });

          if (!response.ok) {
            return json({ error: "Could not add QR code. Check that the code is unique." }, 400);
          }

          return json(await response.json(), 201);
        } catch {
          return json({ error: "Invalid data" }, 400);
        }
      }

      // Update QR code
      if (url.pathname.startsWith("/api/qr/") && request.method === "PATCH") {
        try {
          const code = decodeURIComponent(url.pathname.slice("/api/qr/".length));

          if (!/^[a-zA-Z0-9_-]+$/.test(code)) {
            return json({ error: "Invalid QR code" }, 400);
          }

          const body = await request.json();
          const update = {};

          if (body.destination_url !== undefined) {
            const destination = new URL(body.destination_url);

            if (!["http:", "https:"].includes(destination.protocol)) {
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
              headers: { ...headers, Prefer: "return=representation" },
              body: JSON.stringify(update)
            }
          );

          if (!response.ok) {
            return json({ error: "Could not update QR code" }, 400);
          }

          return json(await response.json());
        } catch {
          return json({ error: "Invalid data" }, 400);
        }
      }

      // Delete QR code
      if (url.pathname.startsWith("/api/qr/") && request.method === "DELETE") {
        const code = decodeURIComponent(url.pathname.slice("/api/qr/".length));

        if (!/^[a-zA-Z0-9_-]+$/.test(code)) {
          return json({ error: "Invalid QR code" }, 400);
        }

        const response = await fetch(
          `${supabaseUrl}/rest/v1/qr_codes?code=eq.${encodeURIComponent(code)}`,
          {
            method: "DELETE",
            headers: { ...headers, Prefer: "return=minimal" }
          }
        );

        if (!response.ok) {
          return json({ error: "Could not delete QR code" }, 400);
        }

        return json({ success: true });
      }

      return json({ error: "API route not found" }, 404);
    }

    return new Response("Not Found", { status: 404 });
  }
};
