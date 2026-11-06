export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      return Response.json({
        status: "online",
        project: "EarnZone",
        backend: "connected"
      });
    }

    if (url.pathname === "/api/db-test") {
      try {
        const result = await env.DB.prepare(
          "SELECT name FROM sqlite_master WHERE type='table'"
        ).all();

        return Response.json({
          status: "success",
          database: "connected",
          tables: result.results
        });
      } catch (error) {
        return Response.json({
          status: "error",
          message: error.message
        }, { status: 500 });
      }
    }

    return env.ASSETS.fetch(request);
  }
};
