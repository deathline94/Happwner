// v2RayTun + INCY deep-link handling, ported from V2RayTunCrypto.kt / IncyLinks.kt.
"use strict";
(function (global) {
  const U = global.HWUtil;
  const R = global.HWRsa;
  const Keys = global.HWKeys;

  const VT_CRYPT_PREFIX = 'v2raytun://crypt/';
  const VT_IMPORT_PREFIX = 'v2raytun://import/';
  const VT_SCHEME = 'v2raytun://';
  const EXTRACT_MAX_DEPTH = 2;

  const INCY_ADD_PREFIX = 'incy://add/';
  const INCY_IMPORT_PREFIX = 'incy://import/';
  const INCY_SCHEME = 'incy://';
  const INCY_SCHEMES = [
    'http://', 'https://', 'vless://', 'vmess://', 'trojan://',
    'ss://', 'hy2://', 'hysteria2://', 'socks://', 'socks5://',
    'wireguard://', 'wg://',
  ];

  // ---- v2raytun://crypt/ : RSA-4096 PKCS#1 v1.5, tries each bundled key ----

  function isV2RayTunCryptLink(link) {
    if (!link) return false;
    return link.trim().toLowerCase().startsWith(VT_CRYPT_PREFIX);
  }

  function decryptV2RayTunCryptLink(link) {
    if (!link) return { status: 'nothapp' };
    const trimmed = link.trim();
    if (!trimmed.toLowerCase().startsWith(VT_CRYPT_PREFIX)) return { status: 'nothapp' };

    const payload = trimmed.substring(VT_CRYPT_PREFIX.length).trim();
    if (payload === '') return { status: 'error', reason: 'empty payload' };

    let cipherBytes;
    try {
      cipherBytes = U.b64DecodeFlexible(payload);
    } catch (e) {
      return { status: 'error', reason: 'payload is not valid base64' };
    }
    if (cipherBytes.length === 0) return { status: 'error', reason: 'ciphertext is empty after base64 decode' };

    let lastReason = 'no bundled key could decrypt the link';
    for (let ordinal = 0; ordinal < Keys.V2RAYTUN_PKCS8_KEYS_B64.length; ordinal++) {
      let key;
      try {
        key = R.getBundledPkcs8(Keys.V2RAYTUN_PKCS8_KEYS_B64[ordinal]);
      } catch (e) {
        lastReason = 'bundled key #' + ordinal + ' is malformed';
        continue;
      }
      const ks = R.keySizeBytes(key);
      if (cipherBytes.length % ks !== 0) {
        lastReason = 'ciphertext length ' + cipherBytes.length + ' not a multiple of RSA block ' + ks;
        continue;
      }
      let plain;
      try {
        plain = R.decryptBlocks(key, cipherBytes);
      } catch (e) {
        continue; // wrong key: padding check throws
      }
      const text = U.utf8DecodeStrict(plain);
      if (!text) continue;
      const candidate = text.trim();
      if (U.looksLikeSchemeLink(candidate)) {
        return { status: 'ok', mode: 'v2raytun', plaintext: candidate };
      }
    }
    return { status: 'error', reason: lastReason };
  }

  // ---- v2raytun://import/ and incy:// wrappers ----

  function isV2RayTunImportLink(link) {
    return !!link && link.trim().toLowerCase().startsWith(VT_IMPORT_PREFIX);
  }

  function stripV2RayTunImportPrefix(link) {
    return stripWrappedPrefix(link, VT_IMPORT_PREFIX);
  }

  function isIncyLink(link) {
    if (!link) return false;
    const t = link.trim().toLowerCase();
    return t.startsWith(INCY_ADD_PREFIX) || t.startsWith(INCY_IMPORT_PREFIX);
  }

  function stripIncyPrefix(link) {
    if (!link) return null;
    const trimmed = link.trim();
    const tl = trimmed.toLowerCase();
    let tail;
    if (tl.startsWith(INCY_ADD_PREFIX)) tail = trimmed.substring(INCY_ADD_PREFIX.length);
    else if (tl.startsWith(INCY_IMPORT_PREFIX)) tail = trimmed.substring(INCY_IMPORT_PREFIX.length);
    else return null;
    tail = tail.trim();
    if (tail === '') return null;

    const decoded = U.uriDecode(tail);
    const body = decoded && decoded.length ? decoded : tail;
    if (looksLikeIncySchemeLink(body)) return body;

    const normalized = body.replace(/-/g, '+').replace(/_/g, '/');
    return decodeBase64OrNull(normalized) || decodeBase64OrNull(body) || null;
  }

  function looksLikeIncySchemeLink(s) {
    const t = (s || '').toLowerCase();
    for (const p of INCY_SCHEMES) if (t.startsWith(p)) return true;
    return false;
  }

  function stripWrappedPrefix(link, prefix) {
    if (!link) return null;
    const trimmed = link.trim();
    if (!trimmed.toLowerCase().startsWith(prefix)) return null;
    let rest = trimmed.substring(prefix.length).trim();
    if (rest === '') return null;
    if (rest.indexOf('%') >= 0) {
      const decoded = U.uriDecode(rest);
      if (decoded) rest = decoded.trim();
    }
    if (U.looksLikeSchemeLink(rest)) return rest;
    const fromB64 = global.HWHappCrypto.decodeBase64Link(rest);
    if (fromB64) return fromB64;
    return rest === '' ? null : rest;
  }

  function decodeBase64OrNull(s) {
    let t = s;
    while (t.length % 4 !== 0) t += '=';
    try {
      const data = U.b64DecodeFlexible(t);
      if (data.length === 0) return null;
      for (const b of data) {
        const v = b & 0xff;
        if (!((v >= 0x20 && v <= 0x7e) || v === 0x09 || v === 0x0a || v === 0x0d)) return null;
      }
      const str = U.utf8Decode(data);
      return str === '' ? null : str;
    } catch (e) {
      return null;
    }
  }

  // ---- embedded link extraction from http(s) carriers (generic over a scheme word) ----

  function extractEmbedded(schemeWord, raw, depth) {
    if (raw == null) return null;
    depth = depth || 0;
    const trimmed = raw.trim();
    const scheme = schemeWord + '://';
    if (trimmed === '') return null;
    if (trimmed.toLowerCase().startsWith(scheme)) return null;
    if (!trimmed.toLowerCase().startsWith('http://') && !trimmed.toLowerCase().startsWith('https://')) return null;

    const start = indexOfScheme(trimmed, schemeWord);
    if (start < 0) {
      if (depth < EXTRACT_MAX_DEPTH && trimmed.toLowerCase().indexOf(schemeWord + '%') >= 0) {
        const once = U.uriDecode(trimmed);
        if (once && once !== trimmed) return extractEmbedded(schemeWord, once, depth + 1);
      }
      return null;
    }

    const candidate = carveCandidate(trimmed, start);
    const rawDecoded = U.uriDecode(candidate) || candidate;
    let decoded = (rawDecoded || candidate).trim();

    let guard = 0;
    while (guard < EXTRACT_MAX_DEPTH && decoded.toLowerCase().startsWith(schemeWord + '%')) {
      const next = U.uriDecode(decoded);
      if (!next) break;
      const nextTrimmed = next.trim();
      if (nextTrimmed === decoded) break;
      decoded = nextTrimmed;
      guard++;
    }

    if (!decoded.toLowerCase().startsWith(scheme)) return null;
    if (decoded.length <= scheme.length) return null;
    if (decoded === trimmed) return null;
    return decoded;
  }

  function indexOfScheme(s, schemeWord) {
    const n = s.length;
    let i = 0;
    while (i < n) {
      if (i + schemeWord.length <= n &&
        s.substring(i, i + schemeWord.length).toLowerCase() === schemeWord) {
        const rest = i + schemeWord.length;
        if (rest + 3 <= n && s[rest] === ':' && s[rest + 1] === '/' && s[rest + 2] === '/') return i;
        if (rest + 3 <= n && s[rest] === '%' && s[rest + 1] === '3' && (s[rest + 2] === 'a' || s[rest + 2] === 'A')) return i;
      }
      i++;
    }
    return -1;
  }

  function carveCandidate(s, start) {
    let end = start;
    while (end < s.length && !isDelimiter(s[end])) end++;
    return s.substring(start, end);
  }

  function isDelimiter(c) {
    const o = c.charCodeAt(0);
    if (o < 0x20 || o > 0x7e) return true;
    return ' &#"\'`<>\\|^{}[]'.indexOf(c) >= 0;
  }

  function extractEmbeddedV2RayLink(raw) { return extractEmbedded('v2raytun', raw, 0); }
  function extractEmbeddedIncyLink(raw) { return extractEmbedded('incy', raw, 0); }

  global.HWV2RayTun = {
    isV2RayTunCryptLink, decryptV2RayTunCryptLink,
    isV2RayTunImportLink, stripV2RayTunImportPrefix,
    isIncyLink, stripIncyPrefix,
    extractEmbeddedV2RayLink, extractEmbeddedIncyLink,
  };
})(typeof window !== 'undefined' ? window : globalThis);
