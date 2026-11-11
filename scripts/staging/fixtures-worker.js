// A second Worker that the owner deploys for staging verification. It serves
// hostile-but-harmless responses that the main Worker's /api/fetch must handle:
// redirects to private addresses, loops, long chains, a slow body, a body that
// exceeds the cap with a lying Content-Length, and a Set-Cookie response.
const html = (body, headers = {}) => new Response(`<!doctype html><title>fixture</title><p>${body}</p>`, { headers: { 'content-type': 'text/html; charset=utf-8', ...headers } });
const redirect = (to, status = 302) => new Response(null, { status, headers: { location: to } });

function stream(totalBytes, chunkBytes, delayMs) {
  let sent = 0;
  return new ReadableStream({
    async pull(controller) {
      if (sent >= totalBytes) { controller.close(); return; }
      if (delayMs) await new Promise((r) => setTimeout(r, delayMs));
      const n = Math.min(chunkBytes, totalBytes - sent);
      sent += n;
      controller.enqueue(new Uint8Array(n).fill(97));
    },
  });
}

export const ROUTES = [
  '/redirect-private', '/redirect-metadata', '/loop-a', '/loop-b', '/chain/6', '/slow-drip', '/big-lying', '/set-cookie', '/final',
];

export default {
  /** @param {Request} request */
  fetch(request) {
    const url = new URL(request.url);
    const origin = url.origin;
    const { pathname } = url;
    if (pathname === '/redirect-private') return redirect('https://10.0.0.1/');
    if (pathname === '/redirect-metadata') return redirect('https://169.254.169.254/latest/meta-data/');
    if (pathname === '/loop-a') return redirect(`${origin}/loop-b`);
    if (pathname === '/loop-b') return redirect(`${origin}/loop-a`);
    const chain = /^\/chain\/(\d+)$/.exec(pathname);
    if (chain) {
      const n = Number(chain[1]);
      return n <= 0 ? html('end of chain') : redirect(`${origin}/chain/${n - 1}`);
    }
    if (pathname === '/slow-drip') {
      return new Response(stream(1024, 1, 500), { headers: { 'content-type': 'text/html' } });
    }
    if (pathname === '/big-lying') {
      return new Response(stream(2 * 1048576, 65536, 0), { headers: { 'content-type': 'text/html', 'content-length': '10' } });
    }
    if (pathname === '/set-cookie') return html('cookie fixture', { 'set-cookie': 'sid=STAGING-SECRET; HttpOnly; Secure' });
    if (pathname === '/final') return html('final');
    return new Response('not found', { status: 404 });
  },
};
