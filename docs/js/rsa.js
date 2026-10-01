// RSA PKCS#1 v1.5 decryption with BigInt (CRT-accelerated).
// WebCrypto cannot do RSAES-PKCS1-v1_5 decryption, hence a pure-JS implementation.
"use strict";
(function (global) {
  const U = global.HWUtil;

  // Parse PKCS#1 RSAPrivateKey DER: version, n, e, d, p, q, dp, dq, qinv
  function parsePkcs1(der) {
    const reader = new U.Asn1Reader(der);
    const seq = reader.readTlv(0x30);
    if (reader.pos !== der.length) throw new Error('trailing bytes after PKCS#1 SEQUENCE');
    const inner = new U.Asn1Reader(seq);
    const version = inner.readInteger();
    if (version !== 0n) throw new Error('PKCS#1 version unsupported: ' + version);
    const n = inner.readInteger();
    const e = inner.readInteger();
    const d = inner.readInteger();
    const p = inner.readInteger();
    const q = inner.readInteger();
    const dp = inner.readInteger();
    const dq = inner.readInteger();
    const qinv = inner.readInteger();
    return { n, e, d, p, q, dp, dq, qinv };
  }

  // Unwrap PKCS#8: SEQUENCE { INTEGER 0, AlgorithmIdentifier, OCTET STRING pkcs1 }
  function parsePkcs8(der) {
    const reader = new U.Asn1Reader(der);
    const seq = reader.readTlv(0x30);
    if (reader.pos !== der.length) throw new Error('trailing bytes after PKCS#8 SEQUENCE');
    const inner = new U.Asn1Reader(seq);
    const version = inner.readInteger();
    if (version !== 0n) throw new Error('PKCS#8 version unsupported: ' + version);
    inner.readTlv(0x30); // AlgorithmIdentifier
    const octets = inner.readTlv(0x04);
    return parsePkcs1(octets);
  }

  function modPow(base, exp, mod) {
    let result = 1n;
    let b = base % mod;
    let e = exp;
    while (e > 0n) {
      if (e & 1n) result = (result * b) % mod;
      b = (b * b) % mod;
      e >>= 1n;
    }
    return result;
  }

  function bigToBytes(v, len) {
    const out = new Uint8Array(len);
    let x = v;
    for (let i = len - 1; i >= 0; i--) {
      out[i] = Number(x & 0xffn);
      x >>= 8n;
    }
    return out;
  }

  function bytesToBig(bytes) {
    let hex = '';
    for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
    return BigInt('0x' + (hex || '0'));
  }

  function modBits(n) { return n.toString(2).length; }

  function keySizeBytes(key) { return (modBits(key.n) + 7) >> 3; }

  // One PKCS#1 v1.5 block decrypt (type-2 padding), CRT
  function decryptBlock(key, cipherBytes) {
    const c = bytesToBig(cipherBytes);
    if (c >= key.n) throw new Error('RSA: ciphertext larger than modulus');
    const m1 = modPow(c % key.p, key.dp, key.p);
    const m2 = modPow(c % key.q, key.dq, key.q);
    let h = (key.qinv * (m1 - m2)) % key.p;
    if (h < 0n) h += key.p;
    const m = m2 + h * key.q;

    const ks = keySizeBytes(key);
    const em = bigToBytes(m, ks);
    // EM = 0x00 || 0x02 || PS (non-zero) || 0x00 || M
    if (em[0] !== 0x00 || em[1] !== 0x02) throw new Error('RSA: bad PKCS#1 padding');
    let sep = -1;
    for (let i = 2; i < em.length; i++) {
      if (em[i] === 0x00) { sep = i; break; }
      if (em[i] === 0) { /* unreachable */ }
    }
    if (sep < 0 || sep < 10) throw new Error('RSA: no padding separator');
    return em.subarray(sep + 1);
  }

  function decryptBlocks(key, cipherBytes) {
    const ks = keySizeBytes(key);
    if (cipherBytes.length === 0) throw new Error('ciphertext is empty');
    if (cipherBytes.length % ks !== 0) {
      throw new Error('ciphertext length ' + cipherBytes.length + ' not multiple of RSA block ' + ks);
    }
    const parts = [];
    let total = 0;
    for (let off = 0; off < cipherBytes.length; off += ks) {
      const part = decryptBlock(key, cipherBytes.subarray(off, off + ks));
      parts.push(part);
      total += part.length;
    }
    const out = new Uint8Array(total);
    let w = 0;
    for (const p of parts) { out.set(p, w); w += p.length; }
    return out;
  }

  // ---- key caches built from HWKeys ----
  const pkcs1Cache = [];
  function getBundledPkcs1(ordinal) {
    if (pkcs1Cache[ordinal]) return pkcs1Cache[ordinal];
    const der = U.b64DecodeFlexible(global.HWKeys.CRYPT_PKCS1_KEYS_B64[ordinal]);
    const key = parsePkcs1(der);
    pkcs1Cache[ordinal] = key;
    return key;
  }

  const pkcs8Cache = new Map();
  function getBundledPkcs8(b64) {
    if (pkcs8Cache.has(b64)) return pkcs8Cache.get(b64);
    const der = U.b64DecodeFlexible(b64);
    const key = parsePkcs8(der);
    pkcs8Cache.set(b64, key);
    return key;
  }

  global.HWRsa = {
    parsePkcs1, parsePkcs8, decryptBlocks, decryptBlock,
    keySizeBytes, getBundledPkcs1, getBundledPkcs8, modPow, bytesToBig, bigToBytes,
  };
})(typeof window !== 'undefined' ? window : globalThis);
