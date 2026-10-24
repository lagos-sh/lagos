// Minimal origin for gateway load runs: a fixed small JSON body, with a
// cacheable variant under /cached. Run with `bun origin.js <port>`.
const port = Number(process.argv[2] ?? 19101);
const body = JSON.stringify({ id: 42, name: "item", tags: ["a", "b"] });

Bun.serve({
  port,
  hostname: "127.0.0.1",
  fetch(req) {
    const cacheable = new URL(req.url).pathname.startsWith("/cached");
    return new Response(body, {
      headers: {
        "content-type": "application/json",
        "cache-control": cacheable ? "public, max-age=300" : "no-store",
      },
    });
  },
});
