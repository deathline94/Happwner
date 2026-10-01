// Shared helpers: flexible base64, strict UTF-8, DER (ASN.1) reader, string transforms.
"use strict";
(function (global) {

  const enc = new TextEncoder();
  const decStrict = new TextDecoder('utf-8', { fatal: true });
  const decLazy = new TextDecoder('utf-8');

  function utf8Encode(str) { return enc.encode(str); }

  // null when not well-formed UTF-8
  function utf8DecodeStrict(bytes) {
    try { return decStrict.decode(bytes); } catch (e) { return null; }
  }
  function utf8Decode(bytes) { return decLazy.decode(bytes); }

  // bytes -> string, 1:1 char per byte (latin-1)
  function latin1Decode(bytes) {
    let out = '';
    const CH = 0x8000;
    for (let i = 0; i < bytes.length; i += CH) {
      out += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
    }
    return out;
  }

  function bytesFromString(s) {
    // ascii/latin1 string -> bytes 1:1 (for latin1Decode round-trips)
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
    return out;
  }

  const B64_STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const B64_URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

  // Base64 that accepts std/url-safe alphabets, whitespace and missing padding
  function b64DecodeFlexible(s) {
    let clean = '';
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === ' ' || c === '\n' || c === '\r' || c === '\t') continue;
      if (c === '-') { clean += '+'; continue; }
      if (c === '_') { clean += '/'; continue; }
      clean += c;
    }
    const rem = clean.length % 4;
    if (rem === 1) throw new Error('invalid base64 length');
    if (rem !== 0) clean += '='.repeat(4 - rem);
    return universal(clean);
  }

  // atob works in browsers and Node >= 16 (global). Fallback to manual decode.
  function universal(clean) {
    if (typeof atob === 'function') {
      const bin = atob(clean);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    const table = new Uint8Array(128).fill(255);
    for (let i = 0; i < 64; i++) { table[B64_STD.charCodeAt(i)] = i; table[B64_URL.charCodeAt(i)] = i; }
    table['='.charCodeAt(0)] = 0;
    let outLen = 0;
    let acc = 0, accBits = 0;
    const chunks = [];
    let buf = new Uint8Array(Math.ceil(clean.length / 4) * 3);
    let n = 0;
    for (let i = 0; i < clean.length; i++) {
      const v = table[clean.charCodeAt(i) & 0x7f];
      if (v === 255) throw new Error('invalid base64 character');
      if (clean[i] === '=') break;
      acc = (acc << 6) | v; accBits += 6;
      if (accBits >= 8) { accBits -= 8; buf[n++] = (acc >> accBits) & 0xff; }
    }
    return buf.subarray(0, n);
  }

  function b64Encode(bytes, opts) {
    const o = opts || {};
    const alphabet = o.urlsafe ? B64_URL : B64_STD;
    let out = '';
    const CH = 0x8000;
    for (let i = 0; i < bytes.length; i += CH) {
      const chunk = bytes.subarray(i, i + CH);
      let s = '';
      for (let j = 0; j < chunk.length; j++) s += String.fromCharCode(chunk[j]);
      if (typeof btoa === 'function') {
        out += btoa(s);
      } else {
        out += Buffer.from(chunk).toString('base64');
      }
    }
    if (o.urlsafe) out = out.replace(/\+/g, '-').replace(/\//g, '_');
    if (!o.pad) out = out.replace(/=+$/, '');
    return out;
  }

  // ---- minimal ASN.1 DER reader (enough for RSA keys) ----
  class Asn1Reader {
    constructor(buf) { this.buf = buf; this.pos = 0; }
    readByte() {
      if (this.pos >= this.buf.length) throw new Error('asn1: truncated at pos ' + this.pos);
      return this.buf[this.pos++];
    }
    readLen() {
      const first = this.readByte();
      if (first < 0x80) return first;
      const nBytes = first & 0x7f;
      if (nBytes === 0 || nBytes > 4) throw new Error('asn1: invalid length form (' + nBytes + ')');
      if (this.pos + nBytes > this.buf.length) throw new Error('asn1: truncated length');
      let result = 0;
      for (let i = 0; i < nBytes; i++) result = (result * 256) + this.buf[this.pos + i];
      this.pos += nBytes;
      if (!Number.isSafeInteger(result)) throw new Error('asn1: length overflow');
      return result;
    }
    readTlv(expectedTag) {
      const tag = this.readByte();
      if (tag !== expectedTag) {
        throw new Error('asn1: expected tag 0x' + expectedTag.toString(16) + ', got 0x' + tag.toString(16));
      }
      const length = this.readLen();
      if (this.pos + length > this.buf.length) throw new Error('asn1: truncated value (need ' + length + ' at ' + this.pos + ')');
      const data = this.buf.subarray(this.pos, this.pos + length);
      this.pos += length;
      return data;
    }
    readInteger() {
      const data = this.readTlv(0x02);
      if (data.length === 0) return 0n;
      // positive bigint (keys are unsigned; DER integers here are positive)
      let hex = '';
      for (let i = 0; i < data.length; i++) hex += data[i].toString(16).padStart(2, '0');
      return BigInt('0x' + hex);
    }
  }

  // ---- string transforms from the Kotlin sources ----
  // Swap adjacent characters in pairs
  function swapPairs(s) {
    if (s.length < 2) return s;
    const arr = s.split('');
    let i = 0;
    while (i + 1 < s.length) {
      arr[i] = s[i + 1];
      arr[i + 1] = s[i];
      i += 2;
    }
    return arr.join('');
  }

  // Swap the two halves of each 4-character block
  function blockPairSwap(s) {
    if (s.length < 4) return s;
    const fullLen = s.length - (s.length % 4);
    const arr = s.split('');
    let i = 0;
    while (i < fullLen) {
      arr[i] = s[i + 2];
      arr[i + 1] = s[i + 3];
      arr[i + 2] = s[i];
      arr[i + 3] = s[i + 1];
      i += 4;
    }
    return arr.join('');
  }

  const SCHEME_LINK_RE = /^[A-Za-z][A-Za-z0-9+.\-]*:\/\//;
  function looksLikeSchemeLink(s) { return SCHEME_LINK_RE.test((s || '').trimStart()); }

  // Uri.decode-like: best-effort percent decoding
  function uriDecode(s) {
    try { return decodeURIComponent(s); } catch (e) { return s; }
  }

  function constantTimeEquals(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  function bytesToHex(b) {
    let s = '';
    for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
  }

  function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
  }

  global.HWUtil = {
    utf8Encode, utf8Decode, utf8DecodeStrict, latin1Decode, bytesFromString,
    b64DecodeFlexible, b64Encode,
    Asn1Reader, swapPairs, blockPairSwap, looksLikeSchemeLink, uriDecode,
    constantTimeEquals, bytesToHex, bytesEqual,
  };
})(typeof window !== 'undefined' ? window : globalThis);
