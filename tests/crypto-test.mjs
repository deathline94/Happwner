// Round-trip tests for the web crypto layer, using node:crypto to build valid vectors.
// Run: node tests/crypto-test.mjs
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, '..');
const load = (f) => fs.readFileSync(path.join(root, 'docs/js', f), 'utf8');

// Evaluate the browser scripts in this context (they attach to globalThis)
const ctx = globalThis;
for (const f of ['util.js', 'keys.js', 'rsa.js', 'chacha.js', 'aesgcm.js', 'happcrypto.js', 'v2raytun.js']) {
  new Function(load(f)).call(ctx);
}

const U = ctx.HWUtil, R = ctx.HWRsa, CC = ctx.HWChaCha, G = ctx.HWAesGcm;
const H = ctx.HWHappCrypto, V = ctx.HWV2RayTun, K = ctx.HWKeys;

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok  ' + name); }
  else { fail++; console.log('FAIL  ' + name + (extra ? ' :: ' + extra : '')); }
}

// ---------- util ----------
{
  const b = U.b64DecodeFlexible('aGVsbG8=');
  check('b64 std', new TextDecoder().decode(b) === 'hello');
  const b2 = U.b64DecodeFlexible('aGVsbG8');
  check('b64 nopad', new TextDecoder().decode(b2) === 'hello');
  const b3 = U.b64DecodeFlexible('aGVsbG8-');
  check('b64 urlsafe', Buffer.compare(Buffer.from(b3), Buffer.from('aGVsbG8+', 'base64')) === 0); // '-' == '+'
  const b4 = U.b64DecodeFlexible('aG Vs\nbG8=');
  check('b64 whitespace', new TextDecoder().decode(b4) === 'hello');
  check('swapPairs', U.swapPairs('abcd') === 'badc' && U.swapPairs('abc') === 'bac');
  check('blockPairSwap', U.blockPairSwap('abcd1234') === 'cdab3412' && U.blockPairSwap('abcde') === 'cdabe');
}

// ---------- RSA PKCS1v1.5 ----------
for (let i = 0; i < K.CRYPT_PKCS1_KEYS_B64.length; i++) {
  const key = R.getBundledPkcs1(i);
  const ks = R.keySizeBytes(key);
  const msg = crypto.randomBytes(Math.min(ks - 11, 64));
  const pub = crypto.createPublicKey(crypto.createPrivateKey({
    key: Buffer.from(K.CRYPT_PKCS1_KEYS_B64[i], 'base64'), format: 'der', type: 'pkcs1',
  }));
  const ct = crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_PKCS1_PADDING }, msg);
  const pt = R.decryptBlocks(key, new Uint8Array(ct));
  check('rsa pkcs1 roundtrip key#' + i + ' (' + (ks * 8) + '-bit)', Buffer.compare(Buffer.from(pt), msg) === 0);
}

// ---------- ChaCha20-Poly1305 vs node ----------
{
  const key = crypto.randomBytes(32), nonce = crypto.randomBytes(12), aad = crypto.randomBytes(7), pt = crypto.randomBytes(131);
  const cc = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  cc.setAAD(aad);
  const ct = Buffer.concat([cc.update(pt), cc.final()]);
  const tag = cc.getAuthTag();
  const dec = CC.decrypt(new Uint8Array(key), new Uint8Array(nonce), new Uint8Array(aad), new Uint8Array(Buffer.concat([ct, tag])));
  check('chacha decrypt vs node', Buffer.compare(Buffer.from(dec), pt) === 0);
  const enc = CC.encrypt(new Uint8Array(key), new Uint8Array(nonce), new Uint8Array(aad), new Uint8Array(pt));
  check('chacha encrypt vs node', Buffer.compare(Buffer.from(enc), Buffer.concat([ct, tag])) === 0);
  // tamper
  const bad = Buffer.from(Buffer.concat([ct, tag])); bad[3] ^= 1;
  let threw = false;
  try { CC.decrypt(new Uint8Array(key), new Uint8Array(nonce), new Uint8Array(aad), new Uint8Array(bad)); } catch (e) { threw = true; }
  check('chacha rejects tampered', threw);
}

// ---------- AES-128-GCM vs node ----------
{
  const key = crypto.randomBytes(16), iv = Buffer.alloc(12, 0x6b), aad = new Uint8Array(0), pt = crypto.randomBytes(1023);
  const c = crypto.createCipheriv('aes-128-gcm', key, iv);
  const ct = Buffer.concat([c.update(pt), c.final()]);
  const tag = c.getAuthTag();
  const dec = G.decrypt(new Uint8Array(key), new Uint8Array(iv), new Uint8Array(aad), new Uint8Array(ct), new Uint8Array(tag));
  check('aesgcm decrypt vs node', Buffer.compare(Buffer.from(dec), pt) === 0);
  const enc = G.encrypt(new Uint8Array(key), new Uint8Array(iv), new Uint8Array(aad), new Uint8Array(pt));
  check('aesgcm encrypt vs node', Buffer.compare(Buffer.from(enc), Buffer.concat([ct, tag])) === 0);
  // with AAD
  const aad2 = crypto.randomBytes(20);
  const c2 = crypto.createCipheriv('aes-128-gcm', key, iv);
  c2.setAAD(aad2);
  const ct2 = Buffer.concat([c2.update(pt), c2.final()]);
  const tag2 = c2.getAuthTag();
  const dec2 = G.decrypt(new Uint8Array(key), new Uint8Array(iv), new Uint8Array(aad2), new Uint8Array(ct2), new Uint8Array(tag2));
  check('aesgcm with aad', Buffer.compare(Buffer.from(dec2), pt) === 0);
  const badTag = Buffer.from(tag2); badTag[0] ^= 1;
  let threw = false;
  try { G.decrypt(new Uint8Array(key), new Uint8Array(iv), new Uint8Array(aad2), new Uint8Array(ct2), new Uint8Array(badTag)); } catch (e) { threw = true; }
  check('aesgcm rejects bad tag', threw);
}

// ---------- happ crypt1-4 link roundtrip ----------
{
  const inner = 'vless://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443?sni=a.b.c#Test%d0%a1';
  for (let i = 0; i < 4; i++) {
    const prefix = 'happ://crypt' + (i === 0 ? '' : String(i + 1)) + '/';
    const key = R.getBundledPkcs1(i);
    const ks = R.keySizeBytes(key);
    const pub = crypto.createPublicKey(crypto.createPrivateKey({
      key: Buffer.from(K.CRYPT_PKCS1_KEYS_B64[i], 'base64'), format: 'der', type: 'pkcs1',
    }));
    // multi-block payload: encrypt several chunks
    const chunkSize = ks - 11;
    const text = Buffer.from(inner + ' ' + 'x'.repeat(chunkSize), 'utf8');
    const chunks = [];
    for (let off = 0; off < text.length; off += chunkSize) {
      chunks.push(crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_PKCS1_PADDING }, text.subarray(off, off + chunkSize)));
    }
    const payload = Buffer.concat(chunks).toString('base64');
    const res = H.decryptHappLink(prefix + payload);
    check('happ ' + prefix + ' decrypt', res.status === 'ok' && res.plaintext === text.toString('utf8'), JSON.stringify(res).slice(0, 120));
  }
}

// ---------- crypt5 roundtrip ----------
function makeCrypt5(inner, salted) {
  const marker = 'asajzqxt';
  const keyB64 = K.CRYPT5_PKCS8_KEYS_B64[marker];
  const priv = crypto.createPrivateKey({ key: Buffer.from(keyB64, 'base64'), format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(priv);

  const nonce = '0123456789ab'; // 12 ascii chars
  const salt = Buffer.from('salt1234', 'ascii');
  const chachaKey = crypto.randomBytes(32);

  const swap = (s) => {
    const arr = s.split('');
    for (let i = 0; i + 1 < s.length; i += 2) { arr[i] = s[i + 1]; arr[i + 1] = s[i]; }
    return arr.join('');
  };
  const blockSwap = (s) => {
    const arr = s.split('');
    const full = s.length - (s.length % 4);
    for (let i = 0; i < full; i += 4) {
      arr[i] = s[i + 2]; arr[i + 1] = s[i + 3]; arr[i + 2] = s[i]; arr[i + 3] = s[i + 1];
    }
    return arr.join('');
  };

  // Decrypt path (Kotlin): ciphertext=b64(urlSegment); intermediate=chachaDecrypt(ciphertext);
  // finalB64 = swapPairs(latin1(intermediate)); inner = b64decode(finalB64).
  // So: finalB64 = b64(inner); intermediate = latin1bytes(swapPairs(finalB64));
  //     urlSegment = b64(chachaEncrypt(intermediate)).
  const innerB64 = Buffer.from(inner, 'utf8').toString('base64');
  const intermediate = Buffer.from(swap(innerB64), 'latin1');
  const aead = crypto.createCipheriv('chacha20-poly1305', chachaKey, Buffer.from(nonce, 'ascii'), { authTagLength: 16 });
  const ct = Buffer.concat([aead.update(intermediate), aead.final()]);
  const tag = aead.getAuthTag();
  const urlSegment = Buffer.concat([ct, tag]).toString('base64');

  // rsa value: swapPairs(latin1(rsaPlain)) must b64-decode to the chacha key
  const rsaPlainStr = swap(chachaKey.toString('base64'));
  const rsaCipher = crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(rsaPlainStr, 'latin1'));

  let body;
  if (salted) {
    const saltedKey = Buffer.from(Array.from({ length: 32 }, (_, i2) => chachaKey[i2] ^ salt[i2 % 8]));
    const rsaPlainStr2 = swap(saltedKey.toString('base64'));
    const rsaCipher2 = crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(rsaPlainStr2, 'latin1'));
    body = nonce + 'Tg' + salt.toString('ascii') + String(urlSegment.length) + 'u' + urlSegment + rsaCipher2.toString('base64');
  } else {
    body = nonce + String(urlSegment.length) + 'u' + urlSegment + rsaCipher.toString('base64');
  }
  // shuffled = marker[0..4] + body + marker[4..8] (the 8-char marker is split across the two ends)
  const shuffled = marker.slice(0, 4) + body + marker.slice(4);
  const payload = blockSwap(shuffled); // blockPairSwap is an involution on the full-block part
  return 'happ://crypt5/' + payload;
}

{
  const inner = 'https://sub.example.com/api/v1/client/subscribe?token=abc123';
  const link1 = makeCrypt5(inner, false);
  const r1 = H.decryptHappLink(link1);
  check('happ crypt5 legacy layout', r1.status === 'ok' && r1.plaintext === inner, JSON.stringify(r1).slice(0, 200));
  const link2 = makeCrypt5(inner, true);
  const r2 = H.decryptHappLink(link2);
  check('happ crypt5 salted layout', r2.status === 'ok' && r2.plaintext === inner, JSON.stringify(r2).slice(0, 200));
}

// ---------- v2raytun crypt ----------
{
  const inner = 'vless://uuid@host:443?security=tls#node';
  const idx = 1; // crypt4 key
  const priv = crypto.createPrivateKey({ key: Buffer.from(K.V2RAYTUN_PKCS8_KEYS_B64[idx], 'base64'), format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(priv);
  const ct = crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(inner, 'utf8'));
  const link = 'v2raytun://crypt/' + ct.toString('base64');
  const res = V.decryptV2RayTunCryptLink(link);
  check('v2raytun crypt decrypt', res.status === 'ok' && res.plaintext === inner, JSON.stringify(res).slice(0, 160));
}

// ---------- encrypted subscription body ----------
{
  const keyName = 'key03';
  const key = Buffer.from(K.SUB_AES_KEYS[keyName], 'utf8');
  const iv = Buffer.alloc(12, 0x6b);
  const body = 'vless://a@b:1#x\nvmess://dummy';
  const c = crypto.createCipheriv('aes-128-gcm', key, iv);
  const ct = Buffer.concat([c.update(Buffer.from(body, 'utf8')), c.final()]);
  const tag = c.getAuthTag();
  const url = 'https://provider.example/sub?key=' + keyName;
  const res = H.processSubscriptionBody(url, ct.toString('base64'), tag.toString('base64'));
  check('sub body decrypt key03', res.status === 'ok' && res.plaintext === body, JSON.stringify(res).slice(0, 160));
  const res2 = H.processSubscriptionBody(url, 'plain-body', null);
  check('sub body notencrypted without tag', res2.status === 'notencrypted');
}

// ---------- embedded extraction & add prefix ----------
{
  const inner = 'happ://crypt5/AbCdEf123';
  const carrier = 'https://t.me/proxy?server=x&url=' + encodeURIComponent(inner);
  check('extract embedded happ', H.extractEmbeddedHappLink(carrier) === inner);
  const carrier2 = 'https://example.com/redirect?to=' + encodeURIComponent(encodeURIComponent(inner));
  check('extract embedded double-encoded', H.extractEmbeddedHappLink(carrier2) === inner);
  check('add prefix url', H.stripAddPrefix('happ://add/' + encodeURIComponent('https://sub/x')) === 'https://sub/x');
  check('add prefix b64', H.stripAddPrefix('happ://add/' + Buffer.from('https://sub/x').toString('base64')) === 'https://sub/x');
  check('is openable', H.isOpenableHappLink('happ://crypt/xyz') && !H.isOpenableHappLink('https://x'));
}

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
