// ChaCha20-Poly1305 AEAD (RFC 8439), ported from the Happwner Kotlin implementation.
"use strict";
(function (global) {
  const U = global.HWUtil;

  const C0 = 0x61707865, C1 = 0x3320646e, C2 = 0x79622d32, C3 = 0x6b206574;

  function rotl(x, n) { return ((x << n) | (x >>> (32 - n))) >>> 0; }

  function u8ToU32Le(b, off) {
    return ((b[off]) | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
  }

  function u32ToU8Le(out, off, w) {
    w = w >>> 0;
    out[off] = w & 0xff;
    out[off + 1] = (w >>> 8) & 0xff;
    out[off + 2] = (w >>> 16) & 0xff;
    out[off + 3] = (w >>> 24) & 0xff;
  }

  // One 64-byte ChaCha20 keystream block for this counter
  function chacha20Block(key, counter, nonce, out) {
    const s0 = C0, s1 = C1, s2 = C2, s3 = C3;
    const s4 = u8ToU32Le(key, 0), s5 = u8ToU32Le(key, 4), s6 = u8ToU32Le(key, 8), s7 = u8ToU32Le(key, 12);
    const s8 = u8ToU32Le(key, 16), s9 = u8ToU32Le(key, 20), s10 = u8ToU32Le(key, 24), s11 = u8ToU32Le(key, 28);
    const s12 = counter >>> 0;
    const s13 = u8ToU32Le(nonce, 0), s14 = u8ToU32Le(nonce, 4), s15 = u8ToU32Le(nonce, 8);

    let x0 = s0, x1 = s1, x2 = s2, x3 = s3;
    let x4 = s4, x5 = s5, x6 = s6, x7 = s7;
    let x8 = s8, x9 = s9, x10 = s10, x11 = s11;
    let x12 = s12, x13 = s13, x14 = s14, x15 = s15;

    for (let i = 0; i < 10; i++) {
      x0 = (x0 + x4) >>> 0; x12 = rotl(x12 ^ x0, 16);
      x8 = (x8 + x12) >>> 0; x4 = rotl(x4 ^ x8, 12);
      x0 = (x0 + x4) >>> 0; x12 = rotl(x12 ^ x0, 8);
      x8 = (x8 + x12) >>> 0; x4 = rotl(x4 ^ x8, 7);

      x1 = (x1 + x5) >>> 0; x13 = rotl(x13 ^ x1, 16);
      x9 = (x9 + x13) >>> 0; x5 = rotl(x5 ^ x9, 12);
      x1 = (x1 + x5) >>> 0; x13 = rotl(x13 ^ x1, 8);
      x9 = (x9 + x13) >>> 0; x5 = rotl(x5 ^ x9, 7);

      x2 = (x2 + x6) >>> 0; x14 = rotl(x14 ^ x2, 16);
      x10 = (x10 + x14) >>> 0; x6 = rotl(x6 ^ x10, 12);
      x2 = (x2 + x6) >>> 0; x14 = rotl(x14 ^ x2, 8);
      x10 = (x10 + x14) >>> 0; x6 = rotl(x6 ^ x10, 7);

      x3 = (x3 + x7) >>> 0; x15 = rotl(x15 ^ x3, 16);
      x11 = (x11 + x15) >>> 0; x7 = rotl(x7 ^ x11, 12);
      x3 = (x3 + x7) >>> 0; x15 = rotl(x15 ^ x3, 8);
      x11 = (x11 + x15) >>> 0; x7 = rotl(x7 ^ x11, 7);

      x0 = (x0 + x5) >>> 0; x15 = rotl(x15 ^ x0, 16);
      x10 = (x10 + x15) >>> 0; x5 = rotl(x5 ^ x10, 12);
      x0 = (x0 + x5) >>> 0; x15 = rotl(x15 ^ x0, 8);
      x10 = (x10 + x15) >>> 0; x5 = rotl(x5 ^ x10, 7);

      x1 = (x1 + x6) >>> 0; x12 = rotl(x12 ^ x1, 16);
      x11 = (x11 + x12) >>> 0; x6 = rotl(x6 ^ x11, 12);
      x1 = (x1 + x6) >>> 0; x12 = rotl(x12 ^ x1, 8);
      x11 = (x11 + x12) >>> 0; x6 = rotl(x6 ^ x11, 7);

      x2 = (x2 + x7) >>> 0; x13 = rotl(x13 ^ x2, 16);
      x8 = (x8 + x13) >>> 0; x7 = rotl(x7 ^ x8, 12);
      x2 = (x2 + x7) >>> 0; x13 = rotl(x13 ^ x2, 8);
      x8 = (x8 + x13) >>> 0; x7 = rotl(x7 ^ x8, 7);

      x3 = (x3 + x4) >>> 0; x14 = rotl(x14 ^ x3, 16);
      x9 = (x9 + x14) >>> 0; x4 = rotl(x4 ^ x9, 12);
      x3 = (x3 + x4) >>> 0; x14 = rotl(x14 ^ x3, 8);
      x9 = (x9 + x14) >>> 0; x4 = rotl(x4 ^ x9, 7);
    }

    u32ToU8Le(out, 0, (x0 + s0) >>> 0); u32ToU8Le(out, 4, (x1 + s1) >>> 0);
    u32ToU8Le(out, 8, (x2 + s2) >>> 0); u32ToU8Le(out, 12, (x3 + s3) >>> 0);
    u32ToU8Le(out, 16, (x4 + s4) >>> 0); u32ToU8Le(out, 20, (x5 + s5) >>> 0);
    u32ToU8Le(out, 24, (x6 + s6) >>> 0); u32ToU8Le(out, 28, (x7 + s7) >>> 0);
    u32ToU8Le(out, 32, (x8 + s8) >>> 0); u32ToU8Le(out, 36, (x9 + s9) >>> 0);
    u32ToU8Le(out, 40, (x10 + s10) >>> 0); u32ToU8Le(out, 44, (x11 + s11) >>> 0);
    u32ToU8Le(out, 48, (x12 + s12) >>> 0); u32ToU8Le(out, 52, (x13 + s13) >>> 0);
    u32ToU8Le(out, 56, (x14 + s14) >>> 0); u32ToU8Le(out, 60, (x15 + s15) >>> 0);
  }

  // ---- Poly1305 (BigInt arithmetic mod 2^130 - 5), mirroring the Kotlin port ----
  const P1305 = (1n << 130n) - 5n;
  const MASK128 = (1n << 128n) - 1n;
  const R_CLAMP = BigInt('0x0ffffffc0ffffffc0ffffffc0fffffff');

  function leBytesToBig(b, off, len) {
    if (len <= 0) return 0n;
    let v = 0n;
    for (let i = len - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[off + i]);
    return v;
  }

  function bigToLeBytes(v, len) {
    const out = new Uint8Array(len);
    let x = v;
    for (let i = 0; i < len; i++) {
      out[i] = Number(x & 0xffn);
      x >>= 8n;
    }
    return out;
  }

  function poly1305Mac(key32, msg) {
    if (key32.length !== 32) throw new Error('poly1305 key must be 32 bytes');
    const r = leBytesToBig(key32, 0, 16) & R_CLAMP;
    const s = leBytesToBig(key32, 16, 16);

    let acc = 0n;
    let off = 0;
    while (off < msg.length) {
      const take = Math.min(msg.length - off, 16);
      let n = leBytesToBig(msg, off, take) | (1n << BigInt(8 * take));
      acc = ((acc + n) % P1305);
      acc = (acc * r) % P1305;
      off += take;
    }
    const tag = (acc + s) & MASK128;
    return bigToLeBytes(tag, 16);
  }

  function padTo16(n) {
    const r = n & 15;
    return r === 0 ? n : n + (16 - r);
  }

  function writeU64Le(out, off, v) {
    let x = BigInt(v);
    for (let i = 0; i < 8; i++) {
      out[off + i] = Number(x & 0xffn);
      x >>= 8n;
    }
  }

  // AEAD open: derive the Poly1305 key, verify the tag, then decrypt
  function decrypt(key, nonce, aad, ciphertextWithTag) {
    if (key.length !== 32) throw new Error('ChaCha20-Poly1305 key must be 32 bytes');
    if (nonce.length !== 12) throw new Error('ChaCha20-Poly1305 nonce must be 12 bytes');
    if (ciphertextWithTag.length < 16) throw new Error('ciphertext too short to contain tag');

    const ctLen = ciphertextWithTag.length - 16;

    const block0 = new Uint8Array(64);
    chacha20Block(key, 0, nonce, block0);
    const polyKey = block0.subarray(0, 32);

    const macLen = padTo16(aad.length) + padTo16(ctLen) + 16;
    const macData = new Uint8Array(macLen);
    let off = 0;
    macData.set(aad, off); off += padTo16(aad.length);
    macData.set(ciphertextWithTag.subarray(0, ctLen), off); off += padTo16(ctLen);
    writeU64Le(macData, off, aad.length); off += 8;
    writeU64Le(macData, off, ctLen);

    const expectedTag = poly1305Mac(polyKey, macData);
    const providedTag = ciphertextWithTag.subarray(ctLen);
    if (!U.constantTimeEquals(expectedTag, providedTag)) {
      throw new Error('ChaCha20-Poly1305 authentication failed');
    }

    const plaintext = new Uint8Array(ctLen);
    const blockBuf = new Uint8Array(64);
    let blockIndex = -1;
    for (let i = 0; i < ctLen; i++) {
      const bi = i >>> 6;
      if (bi !== blockIndex) {
        chacha20Block(key, 1 + bi, nonce, blockBuf);
        blockIndex = bi;
      }
      plaintext[i] = ciphertextWithTag[i] ^ blockBuf[i & 63];
    }
    return plaintext;
  }

  // AEAD seal (symmetric; used to build test vectors and crypt5-style payloads)
  function encrypt(key, nonce, aad, plaintext) {
    if (key.length !== 32) throw new Error('ChaCha20-Poly1305 key must be 32 bytes');
    if (nonce.length !== 12) throw new Error('ChaCha20-Poly1305 nonce must be 12 bytes');
    const ptLen = plaintext.length;

    const ciphertext = new Uint8Array(ptLen + 16);
    const blockBuf = new Uint8Array(64);
    let blockIndex = -1;
    for (let i = 0; i < ptLen; i++) {
      const bi = i >>> 6;
      if (bi !== blockIndex) {
        chacha20Block(key, 1 + bi, nonce, blockBuf);
        blockIndex = bi;
      }
      ciphertext[i] = plaintext[i] ^ blockBuf[i & 63];
    }

    const block0 = new Uint8Array(64);
    chacha20Block(key, 0, nonce, block0);
    const polyKey = block0.subarray(0, 32);

    const macLen = padTo16(aad.length) + padTo16(ptLen) + 16;
    const macData = new Uint8Array(macLen);
    let off = 0;
    macData.set(aad, off); off += padTo16(aad.length);
    macData.set(ciphertext.subarray(0, ptLen), off); off += padTo16(ptLen);
    writeU64Le(macData, off, aad.length); off += 8;
    writeU64Le(macData, off, ptLen);

    ciphertext.set(poly1305Mac(polyKey, macData), ptLen);
    return ciphertext;
  }

  global.HWChaCha = { decrypt, encrypt, poly1305Mac, chacha20Block };
})(typeof window !== 'undefined' ? window : globalThis);
