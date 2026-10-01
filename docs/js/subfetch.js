// Subscription fetching from the browser. Direct requests usually hit CORS, so a
// chain of public CORS proxies is offered as fallback. The Encrypt-Tag response
// header is only reachable on a direct CORS-enabled response; otherwise the user
// can paste the tag manually.
"use strict";
(function (global) {

  // Public CORS proxies (body only; response headers are not exposed)
  const PROXIES = [
    { id: 'direct', label: 'Direct (no proxy)' },
    { id: 'corsproxy', label: 'corsproxy.io', wrap: (u) => 'https://corsproxy.io/?url=' + encodeURIComponent(u) },
    { id: 'allorigins', label: 'api.allorigins.win', wrap: (u) => 'https://api.allorigins.win/raw?url=' + encodeURIComponent(u) },
    { id: 'codetabs', label: 'api.codetabs.com', wrap: (u) => 'https://api.codetabs.com/v1/proxy?quest=' + encodeURIComponent(u) },
  ];

  function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

  // Fetch with x-hwid (and best-effort User-Agent). mode: 'auto' | 'direct' | proxy id.
  // Returns { ok, body, encryptTag, via, status, error }
  async function fetchSubscription(url, opts) {
    const o = opts || {};
    const hwid = o.hwid || '';
    const ua = o.ua || '';
    const mode = o.mode || 'auto';
    const timeoutMs = o.timeoutMs || 20000;

    const attempts = [];
    if (mode === 'auto') {
      attempts.push('direct', 'corsproxy', 'allorigins', 'codetabs');
    } else {
      attempts.push(mode);
    }

    let lastError = null;
    for (const attemptId of attempts) {
      const proxy = PROXIES.find((p) => p.id === attemptId);
      if (!proxy) { lastError = 'unknown transport: ' + attemptId; continue; }

      const headers = {};
      if (proxy.id === 'direct') {
        // custom headers trigger CORS preflight; only worth trying directly
        if (hwid) headers['x-hwid'] = hwid;
        if (ua) { try { headers['User-Agent'] = ua; } catch (e) { /* forbidden header; ignored */ } }
      }

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const target = proxy.wrap ? proxy.wrap(url) : url;
        const resp = await fetch(target, { headers, signal: controller.signal, redirect: 'follow' });
        clearTimeout(timer);
        if (!resp.ok) {
          lastError = 'HTTP ' + resp.status + ' via ' + proxy.label;
          continue;
        }
        const body = await resp.text();
        let encryptTag = null;
        try { encryptTag = resp.headers.get('Encrypt-Tag') || resp.headers.get('encrypt-tag'); } catch (e) { /* opaque */ }
        return { ok: true, body, encryptTag, via: proxy.label, status: resp.status, error: null };
      } catch (e) {
        clearTimeout(timer);
        lastError = (e && e.name === 'AbortError' ? 'timeout' : (e && e.message) || 'network error') + ' via ' + proxy.label;
        await sleep(150);
      }
    }
    return { ok: false, body: null, encryptTag: null, via: null, status: 0, error: lastError || 'all transports failed' };
  }

  // Random HWID in the shape Happ uses (16 lowercase alphanumeric chars)
  function generateHwid() {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const bytes = new Uint8Array(16);
    (global.crypto || {}).getRandomValues ? crypto.getRandomValues(bytes) : bytes.forEach((_, i) => bytes[i] = Math.floor(Math.random() * 256));
    let out = '';
    for (let i = 0; i < 16; i++) out += alphabet[bytes[i] % alphabet.length];
    return out;
  }

  // User-Agent presets for subscription requests (browsers cannot override the real UA header;
  // these are informational for the manual/tooling path)
  const UA_PRESETS = {
    happ_android: 'Happ/1.16.2 (Android 15; Android SDK built for x86_64)',
    happ_ios: 'Happ/1.10.0 (iOS 18.0; iPhone15,3)',
    v2rayng: 'v2rayNG/1.9.16',
    nekobox: 'NekoBox/1.3.8 (Android)',
    curl: 'curl/8.6.0',
  };

  global.HWSubFetch = { fetchSubscription, generateHwid, UA_PRESETS, PROXIES };
})(typeof window !== 'undefined' ? window : globalThis);
