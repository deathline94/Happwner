// Generates docs/js/keys.js from the Kotlin sources so no key is transcribed by hand.
import fs from 'fs';
import crypto from 'crypto';

const kda = fs.readFileSync('app/src/main/java/com/happwner/HappCrypto.kt', 'utf8');
const vda = fs.readFileSync('app/src/main/java/com/happwner/V2RayTunCrypto.kt', 'utf8');

// Unescape a Kotlin string literal body
function unescapeKotlin(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '\\') {
      const n = s[++i];
      const map = { n: '\n', r: '\r', t: '\t', b: '\b', '"': '"', "'": "'", '$': '$', '\\': '\\' };
      if (n === 'u') { const hex = s.slice(i + 1, i + 5); out += String.fromCharCode(parseInt(hex, 16)); i += 4; }
      else if (n in map) out += map[n];
      else out += n;
    } else out += c;
  }
  return out;
}

// Grab the text of `private val NAME ... = <expr>` (arrayOf/mapOf block) up to the matching close paren
function grabBlock(src, name) {
  const idx = src.indexOf('val ' + name);
  if (idx < 0) throw new Error('not found: val ' + name);
  const start = src.indexOf('=', idx) + 1;
  let depth = 0, i = start, inStr = false;
  for (; i < src.length; i++) {
    const c = src[i];
    if (inStr) { if (c === '\\') i++; else if (c === '"') inStr = false; continue; }
    if (c === '"') inStr = true;
    else if (c === '(') depth++;
    else if (c === ')') { depth--; if (depth === 0) { i++; break; } }
  }
  return src.slice(start, i);
}

const b64re = /"([A-Za-z0-9+/=]{100,})"/g;

// 1) crypt1-4 PKCS#1 keys
const p1block = grabBlock(kda, 'CRYPT_PKCS1_KEYS_B64');
const pkcs1 = [];
let m;
while ((m = b64re.exec(p1block))) pkcs1.push(m[1]);
b64re.lastIndex = 0;
if (pkcs1.length !== 4) throw new Error('expected 4 PKCS1 keys, got ' + pkcs1.length);

// 2) crypt5 PKCS#8 map
const c5block = grabBlock(kda, 'CRYPT5_PKCS8_KEYS_B64');
const crypt5 = {};
const c5re = /"([a-z]{8})"\s+to\s+"([A-Za-z0-9+/=]{100,})"/g;
while ((m = c5re.exec(c5block))) crypt5[m[1]] = m[2];
if (Object.keys(crypt5).length < 4) throw new Error('crypt5 keys found: ' + Object.keys(crypt5).length);

// 3) key01..key10 AES keys (unescape Kotlin literals)
const keysBlock = grabBlock(kda, 'KEYS: Map');
const keyRe = /"(key\d\d)"\s+to\s+"((?:[^"\\]|\\.)*)"/g;
const aesKeys = {};
while ((m = keyRe.exec(keysBlock))) {
  const lit = unescapeKotlin(m[2]);
  const bytes = Buffer.from(lit, 'utf8');
  if (bytes.length !== 16) throw new Error(m[1] + ' length ' + bytes.length + ' :: ' + JSON.stringify(lit));
  aesKeys[m[1]] = lit;
}
if (Object.keys(aesKeys).length !== 10) throw new Error('aes keys: ' + Object.keys(aesKeys).length);

// 4) v2raytun RSA keys
const vtBlock = grabBlock(vda, 'KEYS_B64');
const vtKeys = [];
while ((m = b64re.exec(vtBlock))) vtKeys.push(m[1]);
if (vtKeys.length !== 3) throw new Error('v2raytun keys: ' + vtKeys.length);

// sanity: report modulus sizes via node crypto
function bits(der, isPkcs8) {
  const key = crypto.createPrivateKey({
    key: Buffer.from(der, 'base64'), format: 'der', type: isPkcs8 ? 'pkcs8' : 'pkcs1',
  });
  const jwk = crypto.createPublicKey(key).export({ format: 'jwk' });
  return { bits: (jwk.n.length * 3) / 4 };
}
console.log('pkcs1 key sizes:', pkcs1.map(k => bits(k, false).bits).join(', '));
console.log('crypt5 markers:', Object.keys(crypt5).join(','));
console.log('v2raytun key sizes:', vtKeys.map(k => bits(k, true).bits).join(', '));

const out = `// Auto-generated from Happwner Android sources (HappCrypto.kt / V2RayTunCrypto.kt)
// by tools/extract_keys.mjs — do not edit by hand.
"use strict";
(function (global) {
  // PKCS#1 private keys for happ://crypt .. crypt4 (index 0..3)
  const CRYPT_PKCS1_KEYS_B64 = ${JSON.stringify(pkcs1, null, 4).replace(/\n/g, '\n  ')};

  // PKCS#8 private keys for crypt5, keyed by the 8-char marker
  const CRYPT5_PKCS8_KEYS_B64 = ${JSON.stringify(crypt5, null, 4).replace(/\n/g, '\n  ')};

  // 16-byte AES-128 keys for encrypted subscription bodies ("keyNN:..." ASCII)
  const SUB_AES_KEYS = ${JSON.stringify(aesKeys, null, 4).replace(/\n/g, '\n  ')};

  // RSA-4096 PKCS#8 keys bundled in v2RayTun ([0]=crypt3 docs key, [1]=crypt4, [2]=key3)
  const V2RAYTUN_PKCS8_KEYS_B64 = ${JSON.stringify(vtKeys, null, 4).replace(/\n/g, '\n  ')};

  global.HWKeys = { CRYPT_PKCS1_KEYS_B64, CRYPT5_PKCS8_KEYS_B64, SUB_AES_KEYS, V2RAYTUN_PKCS8_KEYS_B64 };
})(typeof window !== 'undefined' ? window : globalThis);
`;
fs.writeFileSync('docs/js/keys.js', out);
console.log('wrote docs/js/keys.js');
