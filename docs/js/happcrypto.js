// Happ link + subscription crypto, ported from Happwner's HappCrypto.kt.
"use strict";
(function (global) {
  const U = global.HWUtil;
  const R = global.HWRsa;
  const CC = global.HWChaCha;
  const GCM = global.HWAesGcm;
  const Keys = global.HWKeys;

  const HAPP_PREFIXES = [
    ['happ://crypt5/', 4],
    ['happ://crypt4/', 3],
    ['happ://crypt3/', 2],
    ['happ://crypt2/', 1],
    ['happ://crypt/', 0],
  ];
  const MODE_NAMES = ['crypt', 'crypt2', 'crypt3', 'crypt4', 'crypt5'];
  const HAPP_SCHEME = 'happ://';
  const ADD_PREFIX = 'happ://add/';
  const EXTRACT_MAX_DEPTH = 2;
  // Fixed IV "kkkkkkkkkkkk" (12 bytes of 0x6b)
  const SUB_IV = new Uint8Array(12).fill(0x6b);

  // ---- decryption results: { status: 'ok'|'error'|'nothapp', mode?, plaintext?, reason? } ----

  function parseInput(link) {
    for (const [prefix, ordinal] of HAPP_PREFIXES) {
      if (link.toLowerCase().startsWith(prefix)) {
        return { ordinal, modeName: MODE_NAMES[ordinal], payload: link.substring(prefix.length) };
      }
    }
    return null;
  }

  // crypt..crypt4: RSA/ECB/PKCS1, block by block by key size
  function decryptCrypt1to4(ordinal, payload) {
    const key = R.getBundledPkcs1(ordinal);
    const cipherBytes = U.b64DecodeFlexible(payload);
    return U.utf8Decode(R.decryptBlocks(key, cipherBytes));
  }

  // crypt5: block-swap, marker-keyed RSA yields a ChaCha key, ChaCha20-Poly1305, final base64
  function decryptCrypt5(payload) {
    const shuffled = U.blockPairSwap(payload);
    if (shuffled.length < 8) throw new Error('crypt5 payload too short');

    const marker = shuffled.substring(0, 4) + shuffled.substring(shuffled.length - 4);
    const body = shuffled.substring(4, shuffled.length - 4);
    if (body.length < 13) throw new Error('crypt5 body too short');

    const b64 = Keys.CRYPT5_PKCS8_KEYS_B64[marker];
    if (!b64) throw new Error('unknown crypt5 marker: ' + marker);
    const privateKey = R.getBundledPkcs8(b64);

    // legacy: nonce(12) + length-prefixed url-b64 + RSA blob; salted: 2-char tag + 8-char salt after nonce
    const preferSalted = body.length > 12 && !(body[12] >= '0' && body[12] <= '9');
    const layouts = preferSalted ? [true, false] : [false, true];

    let lastError = null;
    for (const salted of layouts) {
      try {
        return decryptCrypt5Body(body, privateKey, salted);
      } catch (e) {
        lastError = e;
      }
    }
    throw lastError || new Error('crypt5 decryption failed');
  }

  function decryptCrypt5Body(body, privateKey, salted) {
    const nonceStr = body.substring(0, 12);
    let salt = null;
    let lenStart;
    if (salted) {
      if (body.length < 22) throw new Error('crypt5 header too short for salted layout');
      salt = U.bytesFromString(body.substring(14, 22));
      lenStart = 22;
    } else {
      lenStart = 12;
    }

    const rest = body.substring(lenStart);
    let digitCount = 0;
    while (digitCount < rest.length && rest[digitCount] >= '0' && rest[digitCount] <= '9') digitCount++;
    if (digitCount === 0) throw new Error('crypt5 segment length missing');
    const segmentLen = parseInt(rest.substring(0, digitCount), 10);
    if (Number.isNaN(segmentLen)) throw new Error('crypt5 segment length not parseable');
    const packed = rest.substring(digitCount);
    if (!(segmentLen >= 0 && segmentLen <= packed.length - 1)) throw new Error('crypt5 segment truncated');

    const urlB64 = packed.substring(1, 1 + segmentLen);
    const rsaCipher = packed.substring(1 + segmentLen);

    const rsaPlainBytes = R.decryptBlock(privateKey, U.b64DecodeFlexible(rsaCipher));
    const rsaPlainStr = U.latin1Decode(rsaPlainBytes);
    const rsaValue = U.b64DecodeFlexible(U.swapPairs(rsaPlainStr));
    if (rsaValue.length !== 32) throw new Error('chacha key has invalid length: ' + rsaValue.length);

    let chachaKey;
    if (salted) {
      if (salt.length !== 8) throw new Error('crypt5 salt must be 8 bytes');
      chachaKey = new Uint8Array(32);
      for (let i = 0; i < 32; i++) chachaKey[i] = rsaValue[i] ^ salt[i % 8];
    } else {
      chachaKey = rsaValue;
    }

    if (nonceStr.length !== 12) throw new Error('nonce must be 12 bytes');
    const nonce = U.bytesFromString(nonceStr);

    const ciphertext = U.b64DecodeFlexible(urlB64);
    const intermediate = CC.decrypt(chachaKey, nonce, new Uint8Array(0), ciphertext);

    const intermediateStr = U.latin1Decode(intermediate);
    const finalB64 = U.swapPairs(intermediateStr);
    const finalBytes = U.b64DecodeFlexible(finalB64);
    return U.utf8Decode(finalBytes);
  }

  function decryptHappLink(link) {
    if (!link) return { status: 'nothapp' };
    const input = parseInput(link.trim());
    if (!input) return { status: 'nothapp' };
    try {
      const plaintext = input.ordinal === 4
        ? decryptCrypt5(input.payload)
        : decryptCrypt1to4(input.ordinal, input.payload);
      return { status: 'ok', mode: input.modeName, plaintext };
    } catch (e) {
      return { status: 'error', mode: input.modeName, reason: e.message || String(e) };
    }
  }

  // ---- embedded happ:// link extraction from http(s) carriers ----

  function indexOfHappScheme(s) {
    const n = s.length;
    let i = 0;
    while (i < n) {
      if (i + 4 <= n &&
        (s[i] === 'h' || s[i] === 'H') &&
        (s[i + 1] === 'a' || s[i + 1] === 'A') &&
        (s[i + 2] === 'p' || s[i + 2] === 'P') &&
        (s[i + 3] === 'p' || s[i + 3] === 'P')) {
        const rest = i + 4;
        if (rest + 3 <= n && s[rest] === ':' && s[rest + 1] === '/' && s[rest + 2] === '/') return i;
        if (rest + 3 <= n && s[rest] === '%' && s[rest + 1] === '3' && (s[rest + 2] === 'a' || s[rest + 2] === 'A')) return i;
      }
      i++;
    }
    return -1;
  }

  function isHappDelimiter(c) {
    const o = c.charCodeAt(0);
    if (o < 0x20 || o > 0x7e) return true;
    // space and the characters that terminate a happ:// link
    return ' &#"\'`<>\\|^{}[]'.indexOf(c) >= 0;
  }

  function carveHappCandidate(s, start) {
    let end = start;
    while (end < s.length && !isHappDelimiter(s[end])) end++;
    return s.substring(start, end);
  }

  function extractEmbeddedHappLink(raw, depth) {
    if (raw == null) return null;
    depth = depth || 0;
    const trimmed = raw.trim();
    if (trimmed === '') return null;
    if (trimmed.toLowerCase().startsWith(HAPP_SCHEME)) return null;
    if (!trimmed.toLowerCase().startsWith('http://') && !trimmed.toLowerCase().startsWith('https://')) return null;

    const start = indexOfHappScheme(trimmed);
    if (start < 0) {
      if (depth < EXTRACT_MAX_DEPTH && trimmed.toLowerCase().indexOf('happ%') >= 0) {
        const once = U.uriDecode(trimmed);
        if (once && once !== trimmed) return extractEmbeddedHappLink(once, depth + 1);
      }
      return null;
    }

    const candidate = carveHappCandidate(trimmed, start);
    const rawDecoded = U.uriDecode(candidate) || candidate;
    let decoded = (rawDecoded || candidate).trim();

    let guard = 0;
    while (guard < EXTRACT_MAX_DEPTH && decoded.toLowerCase().startsWith('happ%')) {
      const next = U.uriDecode(decoded);
      if (!next) break;
      const nextTrimmed = next.trim();
      if (nextTrimmed === decoded) break;
      decoded = nextTrimmed;
      guard++;
    }

    if (!decoded.toLowerCase().startsWith(HAPP_SCHEME)) return null;
    if (decoded.length <= HAPP_SCHEME.length) return null;
    if (!decoded.startsWith(HAPP_SCHEME)) {
      decoded = HAPP_SCHEME + decoded.substring(HAPP_SCHEME.length);
    }
    if (decoded === trimmed) return null;
    return decoded;
  }

  function isOpenableHappLink(link) {
    if (!link) return false;
    const t = link.trim().toLowerCase();
    if (t.startsWith(ADD_PREFIX)) return true;
    for (const [prefix] of HAPP_PREFIXES) if (t.startsWith(prefix)) return true;
    return false;
  }

  // Strip happ://add/ and unwrap (url-decode or base64) to the inner link
  function stripAddPrefix(link) {
    if (!link) return null;
    const trimmed = link.trim();
    if (!trimmed.toLowerCase().startsWith(ADD_PREFIX)) return null;
    let rest = trimmed.substring(ADD_PREFIX.length).trim();
    if (rest === '') return null;
    if (rest.indexOf('%') >= 0) {
      const decoded = U.uriDecode(rest);
      if (decoded) rest = decoded.trim();
    }
    if (U.looksLikeSchemeLink(rest)) return rest;
    const fromB64 = decodeBase64Link(rest);
    if (fromB64) return fromB64;
    return rest === '' ? null : rest;
  }

  function decodeBase64Link(s) {
    const cleaned = s.trim();
    if (cleaned.length < 8) return null;
    let hasStd = false, hasUrl = false;
    for (const c of cleaned) {
      if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c === '=') continue;
      if (c === '+' || c === '/') hasStd = true;
      else if (c === '-' || c === '_') hasUrl = true;
      else return null;
    }
    if (hasStd && hasUrl) return null;
    let padded = cleaned;
    if (cleaned.length % 4 === 2) padded += '==';
    else if (cleaned.length % 4 === 3) padded += '=';
    else if (cleaned.length % 4 !== 0) return null;
    let data;
    try {
      data = U.b64DecodeFlexible(padded);
    } catch (e) { return null; }
    if (data.length === 0) return null;
    for (const b of data) {
      const v = b & 0xff;
      if (!((v >= 0x20 && v <= 0x7e) || v === 0x09 || v === 0x0a || v === 0x0d)) return null;
    }
    const decoded = U.utf8Decode(data).trim();
    return U.looksLikeSchemeLink(decoded) ? decoded : null;
  }

  // ---- encrypted subscription body: AES-128-GCM with key= param + Encrypt-Tag header ----
  // Result: { status: 'ok'|'failed'|'notencrypted', keyName?, plaintext?, reason?, originalBody? }

  function extractKeyName(url) {
    try {
      const qIndex = url.indexOf('?');
      if (qIndex < 0) return null;
      const params = new URLSearchParams(url.substring(qIndex + 1));
      return params.get('key');
    } catch (e) { return null; }
  }

  function processSubscriptionBody(url, body, encryptTag) {
    const safeBody = body || '';
    const keyName = url ? extractKeyName(url) : null;
    if (!keyName || !Keys.SUB_AES_KEYS[keyName]) {
      return { status: 'notencrypted' };
    }
    if (!encryptTag) {
      return { status: 'notencrypted' };
    }
    if (safeBody === '') {
      return { status: 'failed', keyName, reason: 'empty body', originalBody: safeBody };
    }
    try {
      const key = U.utf8Encode(Keys.SUB_AES_KEYS[keyName]);
      const tag = U.b64DecodeFlexible(encryptTag);
      if (tag.length !== 16) throw new Error('Encrypt-Tag must be 16 bytes, got ' + tag.length);
      const cipherText = U.b64DecodeFlexible(safeBody);
      if (cipherText.length === 0) throw new Error('ciphertext is empty after base64 decode');
      const plaintext = GCM.decrypt(key, SUB_IV, new Uint8Array(0), cipherText, tag);
      return { status: 'ok', keyName, plaintext: U.utf8Decode(plaintext) };
    } catch (e) {
      return { status: 'failed', keyName, reason: e.message || String(e), originalBody: safeBody };
    }
  }

  global.HWHappCrypto = {
    decryptHappLink, extractEmbeddedHappLink, isOpenableHappLink, stripAddPrefix,
    processSubscriptionBody, extractKeyName, decodeBase64Link,
    HAPP_PREFIXES, MODE_NAMES, ADD_PREFIX, SUB_IV,
  };
})(typeof window !== 'undefined' ? window : globalThis);
