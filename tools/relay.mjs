// Local subscription relay — a stopgap for Windows 10 clients whose system TLS
// (schannel) has no TLS 1.3, while the provider's front-end requires it.
// Node's OpenSSL handles TLS 1.3, so this fetches the subscription and re-serves
// it over plain HTTP on localhost, which v2rayN can always fetch.
//
// Usage:
//   node tools/relay.mjs                 # listens on 127.0.0.1:8787
//   PORT=9000 node tools/relay.mjs       # custom port
//
// Then use in v2rayN (URL-encode the target!):
//   http://127.0.0.1:8787/sub?url=<urlencoded subscription url>[&hwid=<id>][&ua=<custom>]
//
// The relay must keep running for v2rayN's auto-update; use the Cloudflare
// Worker in worker/ for a permanent, always-on setup.

import http from 'http';
import https from 'https';
import { URL } from 'url';

const PORT = parseInt(process.env.PORT || '8787', 10);
const DEFAULT_UA = 'Happ/1.16.2 (Android 15; Android SDK built for x86_64)';
const PASSTHROUGH = ['content-type', 'subscription-userinfo', 'profile-update-interval', 'profile-title', 'content-disposition'];

const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://127.0.0.1');
  if (u.pathname !== '/sub') {
    res.writeHead(404, { 'content-type': 'text/plain' });
    return res.end('use /sub?url=<urlencoded subscription url>');
  }
  const target = u.searchParams.get('url');
  if (!target || !/^https?:\/\//i.test(target)) {
    res.writeHead(400, { 'content-type': 'text/plain' });
    return res.end('missing or invalid ?url=');
  }

  const headers = { 'User-Agent': u.searchParams.get('ua') || DEFAULT_UA, Accept: '*/*' };
  const hwid = u.searchParams.get('hwid');
  if (hwid) headers['x-hwid'] = hwid;

  console.log(new Date().toISOString(), '->', target);

  const upstream = https.request(target, { headers, timeout: 20000 }, (up) => {
    const out = {};
    for (const name of PASSTHROUGH) {
      const v = up.headers[name];
      if (v) out[name] = v;
    }
    out['access-control-allow-origin'] = '*';
    out['cache-control'] = 'no-store';
    res.writeHead(up.statusCode || 502, out);
    up.pipe(res);
    up.on('end', () => console.log(new Date().toISOString(), '<-', up.statusCode));
  });
  upstream.on('error', (e) => {
    console.error('upstream error:', e.message);
    res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('relay: upstream fetch failed: ' + e.message);
  });
  upstream.on('timeout', () => upstream.destroy(new Error('timeout')));
  req.resume();
  upstream.end();
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('Happwner local relay on http://127.0.0.1:' + PORT + '/sub?url=<urlencoded target>');
});
