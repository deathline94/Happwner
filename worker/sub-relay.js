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

// The ten AES-128 keys built into Happ ("keyNN:..." ASCII, 16 bytes each),
// from Happwner's HappCrypto.kt. Used when the provider sends an encrypted
// body (key= in URL + Encrypt-Tag response header).
const SUB_AES_KEYS = {
  key01: 'key01:3jk#R2d&Dd',
  key02: 'key02:+]%4ij#P"/',
  key03: 'key03:?&YNg/"L3}',
  key04: 'key04:+-4b"-?S${',
  key05: 'key05:N5<a/(~jJ\'',
  key06: 'key06:s5\\["=`uC/',
  key07: 'key07:(H+b\'\')_@5',
  key08: 'key08:W\'=)[/~i9w',
  key09: 'key09:\'2%`C~>)_d',
  key10: 'key10:)\\\'h]*#7MP',
};
const SUB_IV = new Uint8Array(12).fill(0x6b); // "kkkkkkkkkkkk"

// Happ-encrypted body -> plaintext. ct is base64, tag is base64 (16 bytes);
// JCE appends the tag to the ciphertext, exactly what WebCrypto expects.
async function decryptSubBody(keyName, bodyB64, tagB64) {
  const keyBytes = new TextEncoder().encode(SUB_AES_KEYS[keyName]);
  const ct = atob(bodyB64.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, ''));
  const tag = atob(tagB64.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, ''));
  if (tag.length !== 16) throw new Error('Encrypt-Tag must be 16 bytes');
  const joined = new Uint8Array(ct.length + 16);
  for (let i = 0; i < ct.length; i++) joined[i] = ct.charCodeAt(i);
  for (let i = 0; i < 16; i++) joined[ct.length + i] = tag.charCodeAt(i);

  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: SUB_IV }, key, joined);
  return new TextDecoder().decode(plain);
}

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
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/' && !url.search) {
      return new Response('Happwner subscription relay is running.\n', {
        status: 200,
        headers: { 'content-type': 'text/plain; charset=utf-8' },
      });
    }

    // token check (set the TOKEN secret in worker settings)
    const token = url.searchParams.get('token') || request.headers.get('x-relay-token') || '';
    const expected = env && typeof env.TOKEN === 'string' ? env.TOKEN : '';
    if (expected !== '' && token !== expected) {
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

    // Happ-encrypted subscription? (key= in the target URL + Encrypt-Tag header)
    // Decrypt here so plain clients get ordinary content. &decrypt=0 disables.
    const wantDecrypt = url.searchParams.get('decrypt') !== '0';
    const keyName = (() => {
      try { return new URL(target).searchParams.get('key'); } catch (e) { return null; }
    })();
    const tagB64 = upstream.headers.get('encrypt-tag');
    if (wantDecrypt && keyName && SUB_AES_KEYS[keyName] && tagB64 && upstream.status === 200) {
      try {
        const plain = await decryptSubBody(keyName, await upstream.text(), tagB64);
        out.delete('content-disposition');
        out.set('content-type', 'text/plain; charset=utf-8');
        return new Response(plain, { status: 200, headers: out });
      } catch (e) {
        // fall through: serve the original (encrypted) body
      }
    }

    return new Response(upstream.body, { status: upstream.status, headers: out });
  },
};
