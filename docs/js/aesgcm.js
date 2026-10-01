// Pure-JS AES-128-GCM (encrypt + decrypt). Only the forward cipher is needed for both
// directions (GCM uses CTR mode), so no inverse cipher is implemented.
"use strict";
(function (global) {
  const U = global.HWUtil;

  // AES S-box
  const SBOX = new Uint8Array([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
  ]);

  function xtime(a) { return ((a << 1) ^ ((a & 0x80) ? 0x1b : 0)) & 0xff; }
  function gmul2(a) { return xtime(a); }
  function gmul3(a) { return xtime(a) ^ a; }

  // AES-128 key expansion -> 11 round keys as Uint8Array(176)
  function expandKey(key) {
    if (key.length !== 16) throw new Error('AES-128 key must be 16 bytes');
    const w = new Uint8Array(176);
    w.set(key, 0);
    let rcon = 1;
    for (let i = 16; i < 176; i += 4) {
      let t0 = w[i - 4], t1 = w[i - 3], t2 = w[i - 2], t3 = w[i - 1];
      if (i % 16 === 0) {
        const tmp = t0;
        t0 = SBOX[t1] ^ rcon; t1 = SBOX[t2]; t2 = SBOX[t3]; t3 = SBOX[tmp];
        rcon = xtime(rcon);
      }
      w[i] = w[i - 16] ^ t0;
      w[i + 1] = w[i - 15] ^ t1;
      w[i + 2] = w[i - 14] ^ t2;
      w[i + 3] = w[i - 13] ^ t3;
    }
    return w;
  }

  // Encrypt one 16-byte block in place into out (16 bytes)
  function encryptBlock(rk, input, out) {
    const s = new Uint8Array(16);
    for (let i = 0; i < 16; i++) s[i] = input[i] ^ rk[i];

    for (let round = 1; round <= 10; round++) {
      const k = round * 16;
      const t = new Uint8Array(16);
      // SubBytes + ShiftRows: state is column-major (s[c*4+r])
      for (let c = 0; c < 4; c++) {
        for (let r = 0; r < 4; r++) {
          t[c * 4 + r] = SBOX[s[((c + r) & 3) * 4 + r]];
        }
      }
      // MixColumns (skipped on the final round)
      if (round < 10) {
        for (let c = 0; c < 4; c++) {
          const a0 = t[c * 4], a1 = t[c * 4 + 1], a2 = t[c * 4 + 2], a3 = t[c * 4 + 3];
          s[c * 4]     = gmul2(a0) ^ gmul3(a1) ^ a2 ^ a3;
          s[c * 4 + 1] = a0 ^ gmul2(a1) ^ gmul3(a2) ^ a3;
          s[c * 4 + 2] = a0 ^ a1 ^ gmul2(a2) ^ gmul3(a3);
          s[c * 4 + 3] = gmul3(a0) ^ a1 ^ a2 ^ gmul2(a3);
        }
      } else {
        s.set(t);
      }
      for (let i = 0; i < 16; i++) s[i] ^= rk[k + i];
    }
    out.set(s);
  }

  // ---- GHASH over GF(2^128) using 32-bit big-endian words ----
  function gfMult(X, Y, out) {
    // Z = 0; V = Y
    let z0 = 0, z1 = 0, z2 = 0, z3 = 0;
    let v0 = Y[0], v1 = Y[1], v2 = Y[2], v3 = Y[3];
    for (let i = 0; i < 128; i++) {
      const bit = (X[i >>> 5] >>> (31 - (i & 31))) & 1;
      if (bit) { z0 ^= v0; z1 ^= v1; z2 ^= v2; z3 ^= v3; }
      const lsb = v3 & 1;
      v3 = (v3 >>> 1) | ((v2 & 1) << 31);
      v2 = (v2 >>> 1) | ((v1 & 1) << 31);
      v1 = (v1 >>> 1) | ((v0 & 1) << 31);
      v0 = v0 >>> 1;
      if (lsb) v0 ^= 0xe1000000;
    }
    out[0] = z0; out[1] = z1; out[2] = z2; out[3] = z3;
  }

  function wordsFromBlock(block, words, off) {
    for (let i = 0; i < 4; i++) {
      words[off + i] = ((block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3]) >>> 0;
    }
  }

  function blockFromWords(words, off, block) {
    for (let i = 0; i < 4; i++) {
      const w = words[off + i];
      block[i * 4] = (w >>> 24) & 0xff;
      block[i * 4 + 1] = (w >>> 16) & 0xff;
      block[i * 4 + 2] = (w >>> 8) & 0xff;
      block[i * 4 + 3] = w & 0xff;
    }
  }

  function ghash(hashTable, aad, ciphertext) {
    // Y = 0; blocks: AAD (padded), CT (padded), len block
    const yWords = new Uint32Array(4);
    const tmpWords = new Uint32Array(4);
    const block = new Uint8Array(16);

    const feed = (bytes) => {
      let i = 0;
      while (i < bytes.length) {
        const take = Math.min(16, bytes.length - i);
        if (take === 16) {
          wordsFromBlock(bytes.subarray(i, i + 16), tmpWords, 0);
          yWords[0] ^= tmpWords[0]; yWords[1] ^= tmpWords[1]; yWords[2] ^= tmpWords[2]; yWords[3] ^= tmpWords[3];
          gfMult(yWords, hashTable, yWords);
        } else {
          block.fill(0);
          block.set(bytes.subarray(i, i + take));
          wordsFromBlock(block, tmpWords, 0);
          yWords[0] ^= tmpWords[0]; yWords[1] ^= tmpWords[1]; yWords[2] ^= tmpWords[2]; yWords[3] ^= tmpWords[3];
          gfMult(yWords, hashTable, yWords);
        }
        i += 16;
      }
    };

    feed(aad);
    feed(ciphertext);

    // lengths in bits, as 64-bit BE values split into two words each
    const lenBlock = new Uint8Array(16);
    const aadBits = aad.length * 8;
    const ctBits = ciphertext.length * 8;
    const aadHi = Math.floor(aadBits / 0x100000000), aadLo = aadBits >>> 0;
    const ctHi = Math.floor(ctBits / 0x100000000), ctLo = ctBits >>> 0;
    lenBlock[0] = (aadHi >>> 24) & 0xff; lenBlock[1] = (aadHi >>> 16) & 0xff; lenBlock[2] = (aadHi >>> 8) & 0xff; lenBlock[3] = aadHi & 0xff;
    lenBlock[4] = (aadLo >>> 24) & 0xff; lenBlock[5] = (aadLo >>> 16) & 0xff; lenBlock[6] = (aadLo >>> 8) & 0xff; lenBlock[7] = aadLo & 0xff;
    lenBlock[8] = (ctHi >>> 24) & 0xff; lenBlock[9] = (ctHi >>> 16) & 0xff; lenBlock[10] = (ctHi >>> 8) & 0xff; lenBlock[11] = ctHi & 0xff;
    lenBlock[12] = (ctLo >>> 24) & 0xff; lenBlock[13] = (ctLo >>> 16) & 0xff; lenBlock[14] = (ctLo >>> 8) & 0xff; lenBlock[15] = ctLo & 0xff;
    wordsFromBlock(lenBlock, tmpWords, 0);
    yWords[0] ^= tmpWords[0]; yWords[1] ^= tmpWords[1]; yWords[2] ^= tmpWords[2]; yWords[3] ^= tmpWords[3];
    gfMult(yWords, hashTable, yWords);
    return yWords;
  }

  function inc32(counterBlock) {
    for (let i = 15; i >= 12; i--) {
      counterBlock[i] = (counterBlock[i] + 1) & 0xff;
      if (counterBlock[i] !== 0) break;
    }
  }

  // GCM decrypt; throws when the tag does not verify. iv must be 12 bytes, tag 16 bytes.
  function decrypt(key, iv, aad, ciphertext, tag) {
    if (iv.length !== 12) throw new Error('GCM IV must be 12 bytes');
    if (tag.length !== 16) throw new Error('GCM tag must be 16 bytes');
    const rk = expandKey(key);

    // H = E(K, 0^128)
    const zero = new Uint8Array(16);
    const hBlock = new Uint8Array(16);
    encryptBlock(rk, zero, hBlock);
    const hashTable = new Uint32Array(4);
    wordsFromBlock(hBlock, hashTable, 0);

    // J0 = IV || 0x00000001
    const j0 = new Uint8Array(16);
    j0.set(iv, 0); j0[15] = 1;

    // ghash pads partial blocks internally, so the raw AAD goes straight in
    const yWords = ghash(hashTable, aad, ciphertext);

    // tag = E(K, J0) XOR S
    const ej0 = new Uint8Array(16);
    encryptBlock(rk, j0, ej0);
    const tagBlock = new Uint8Array(16);
    blockFromWords(yWords, 0, tagBlock);
    for (let i = 0; i < 16; i++) tagBlock[i] ^= ej0[i];
    if (!U.constantTimeEquals(tagBlock, tag)) {
      throw new Error('AES-GCM authentication failed');
    }

    // CTR decrypt from inc32(J0)
    const ctr = new Uint8Array(j0);
    inc32(ctr);
    const ks = new Uint8Array(16);
    const out = new Uint8Array(ciphertext.length);
    for (let i = 0; i < ciphertext.length; i += 16) {
      encryptBlock(rk, ctr, ks);
      const take = Math.min(16, ciphertext.length - i);
      for (let j = 0; j < take; j++) out[i + j] = ciphertext[i + j] ^ ks[j];
      inc32(ctr);
    }
    return out;
  }

  // GCM encrypt (for building test vectors)
  function encrypt(key, iv, aad, plaintext) {
    if (iv.length !== 12) throw new Error('GCM IV must be 12 bytes');
    const rk = expandKey(key);

    const zero = new Uint8Array(16);
    const hBlock = new Uint8Array(16);
    encryptBlock(rk, zero, hBlock);
    const hashTable = new Uint32Array(4);
    wordsFromBlock(hBlock, hashTable, 0);

    const j0 = new Uint8Array(16);
    j0.set(iv, 0); j0[15] = 1;

    const out = new Uint8Array(plaintext.length + 16);
    const ciphertext = out.subarray(0, plaintext.length);

    const ctr = new Uint8Array(j0);
    inc32(ctr);
    const ks = new Uint8Array(16);
    for (let i = 0; i < plaintext.length; i += 16) {
      encryptBlock(rk, ctr, ks);
      const take = Math.min(16, plaintext.length - i);
      for (let j = 0; j < take; j++) ciphertext[i + j] = plaintext[i + j] ^ ks[j];
      inc32(ctr);
    }

    const yWords = ghash(hashTable, aad, ciphertext);
    const ej0 = new Uint8Array(16);
    encryptBlock(rk, j0, ej0);
    const tagBlock = new Uint8Array(16);
    blockFromWords(yWords, 0, tagBlock);
    for (let i = 0; i < 16; i++) out[plaintext.length + i] = tagBlock[i] ^ ej0[i];
    return out;
  }

  global.HWAesGcm = { decrypt, encrypt, expandKey, encryptBlock };
})(typeof window !== 'undefined' ? window : globalThis);
