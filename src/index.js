
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/") {
      return new Response("My QR System is running!", {
        headers: { "content-type": "text/plain" }
      });
    }

    if (url.pathname.startsWith("/r/")) {
      const code = url.pathname.slice(3);

      if (!code || !/^[a-zA-Z0-9_-]+$/.test(code)) {
        return new Response("Invalid QR code", { status: 400 });
      }

      const response = await fetch(
        `${env.SUPABASE_URL}/rest/v1/qr_codes?code=eq.${encodeURIComponent(code)}&select=destination_url,is_active&limit=1`,
        {
          headers: {
            apikey: env.SUPABASE_SERVICE_ROLE_KEY,
            Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`
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
    }

    return new Response("Not Found", { status: 404 });
  }
};
