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
        const supabaseUrl = env.SUPABASE_URL.replace(/\/+$/, "");

        const response = await fetch(
          `${supabaseUrl}/rest/v1/qr_codes?code=eq.${encodeURIComponent(code)}&select=destination_url,is_active&limit=1`,
          {
            headers: {
              apikey: env.SUPABASE_SERVICE_ROLE_KEY,
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

        let destination;

        try {
          destination = new URL(item.destination_url);
        } catch {
          return new Response("Invalid destination", { status: 500 });
        }

        if (!["https:", "http:"].includes(destination.protocol)) {
          return new Response("Invalid destination", { status: 400 });
        }

        return Response.redirect(destination.toString(), 302);

      } catch {
        return new Response("Service unavailable", { status: 503 });
      }
    }

    return new Response("Not Found", { status: 404 });
  }
};
