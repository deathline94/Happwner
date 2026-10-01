/**
 * Happwner Web — subscription relay for Cloudflare Workers.
 *
 * Why: some Happ providers require TLS 1.3 AND the Happ User-Agent. Windows 10
 * clients (v2rayN/v2rayNG updaters use .NET/schannel) have no TLS 1.3, so their
 * subscription update fails with `net_http_ssl_connection_failed` /
 * `net_auth_tls_alert, ProtocolVersion`. A Worker fetches the subscription from
 * Cloudflare's edge (full TLS 1.3) and re-serves it to any client over a
 * connection your client *can* negotiate.
 *
 * Deploy (dashboard, no tools needed):
 *   1. workers.cloudflare.com → Create Worker → paste this file → Deploy.
 *   2. Settings → Variables → add a plain-text variable `TOKEN` with a random
 *      secret (e.g. `openssl rand -hex 16`). Requests without the right token
 *      are refused, so strangers can't abuse your worker as an open relay.
 *   3. Use it in v2rayN as the subscription URL:
 *      https://<your-worker>.<your-subdomain>.workers.dev/?token=<TOKEN>&url=<URL-encoded subscription URL>
 *      Optional: &hwid=<id>  (sent as x-hwid)   &ua=<custom user-agent>
 */

const DEFAULT_UA = 'Happ/1.16.2 (Android 15; Android SDK built for x86_64)';

// Response headers worth passing through to the client (traffic/expire display)
const PASSTHROUGH_HEADERS = [
  'content-type',
  'subscription-userinfo',
  'profile-update-interval',
  'profile-title',
  'content-disposition',
];

function jsonError(status, message) {
  return new Response(message + '\n', {
    status,
    headers: { 'content-type': 'text/plain; charset=utf-8', 'access-control-allow-origin': '*' },
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/' && !url.search) {
      return new Response('Happwner subscription relay is running.\n', {
        status: 200,
        headers: { 'content-type': 'text/plain; charset=utf-8' },
      });
    }

    // token check (set the TOKEN variable in worker settings)
    const token = url.searchParams.get('token') || request.headers.get('x-relay-token') || '';
    if (typeof TOKEN === 'string' && TOKEN !== '' && token !== TOKEN) {
      return jsonError(403, 'relay: bad or missing token');
    }

    const target = url.searchParams.get('url');
    if (!target || !/^https?:\/\//i.test(target)) {
      return jsonError(400, 'relay: ?url=<http(s) subscription url> is required');
    }

    const headers = {
      'User-Agent': url.searchParams.get('ua') || DEFAULT_UA,
      'Accept': '*/*',
    };
    const hwid = url.searchParams.get('hwid');
    if (hwid) headers['x-hwid'] = hwid;

    let upstream;
    try {
      upstream = await fetch(target, { headers, redirect: 'follow' });
    } catch (e) {
      return jsonError(502, 'relay: upstream fetch failed: ' + (e && e.message ? e.message : 'error'));
    }

    const out = new Headers();
    for (const name of PASSTHROUGH_HEADERS) {
      const value = upstream.headers.get(name);
      if (value) out.set(name, value);
    }
    out.set('access-control-allow-origin', '*');
    out.set('cache-control', 'no-store');

    return new Response(upstream.body, { status: upstream.status, headers: out });
  },
};
