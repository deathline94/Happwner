<p align="center">
  <b>English</b> |
  <a href="README_UPSTREAM.md">Android app / upstream docs</a>
</p>

# Happwner Web

<p align="center">
  <img width="100" height="100" alt="Happwner icon" src="https://github.com/user-attachments/assets/93bc69a7-82b3-44b3-a577-52d6b56edc51" />

  <b>🔓 Live app: <a href="https://deathline94.github.io/Happwner-Web/">https://deathline94.github.io/Happwner-Web/</a></b>
</p>

A **fully client-side web port** of [Happwner](https://github.com/Omegaplexx/Happwner) — decrypt `happ://crypt…crypt5` links and Happ-encrypted subscription profiles right in the browser, and export them into any VPN client (v2rayN, v2rayNG, NekoBox, Hiddify, sing-box, …).

**Nothing is uploaded anywhere.** Decryption runs entirely in your browser: links, keys and configs never leave your machine. No backend, no build step, no dependencies — a static site you can host anywhere.

---

## Features

### 🔓 Decrypt tab
* **Link decryption** — `happ://crypt`, `crypt2`, `crypt3`, `crypt4`, `crypt5` (RSA + ChaCha20-Poly1305, legacy & salted layouts). No Happ, no Xposed, no internet connection required.
* **v2rayTun & INCY links** — `v2raytun://crypt/` (RSA-4096), `v2raytun://import/`, `incy://add|import`.
* **Wrapped links** — extracts `happ://`/`v2raytun://`/`incy://` links hidden inside http(s) URLs (incl. double URL-encoding).
* **Batch mode** — one link per line.
* **Base64 blobs** — subscription-style base64 payloads decode inline.
* **Server cards** — every decrypted output is parsed into cards showing protocol, security (TLS/Reality), transport, host and port.

### 📡 Subscription tab
* Fetch a subscription URL and **auto-decrypt Happ-encrypted bodies** (AES-128-GCM with the ten keys built into Happ, `key01`–`key10` + `Encrypt-Tag`).
* **HWID field** — generate a random hardware ID to send as `x-hwid` (device-limit workarounds), optionally a new one per request.
* **User-Agent** — client presets (Happ Android/iOS, v2rayNG, NekoBox, curl) plus **Extract UA**: copies your browser's real User-Agent.
* **Transports** — direct request or public CORS-proxy fallbacks; manual paste mode when a provider needs exact headers.
* **Wrap → `happ://add/`** — turns any subscription URL into a Happ-importable deep link.

### 🔁 Converter tab
* Base64 ↔ links, JSON outbounds → proxy links (vless / vmess / ss / trojan / hysteria2 / tuic).
* **Full Xray → sing-box conversion** (TLS/Reality, ws/grpc/http/httpupgrade transports, routing rules, DNS, rule-sets) with config merging.

---

## Notes for VPN clients

When importing a decrypted subscription into v2rayN / v2rayNG / NekoBox:

* **Many Happ providers reject requests without the Happ User-Agent** (they answer `502`) — keep the `Happ/…` UA string in the client's *User-Agent* field.
* Some providers also check `x-hwid`; v2rayN's *HTTP headers (JSON)* field accepts `{"x-hwid": "your-hwid"}`.
* If the subscription body is Happ-encrypted (`key=` in URL + `Encrypt-Tag` header), plain clients **cannot** decrypt it — use this tool's decrypted/converted output instead. If it's plain (like most), clients update it natively.
* Don't leave the auto-update interval at `0` — that disables auto-updates entirely.

---

## Run it yourself

* Live: **https://deathline94.github.io/Happwner-Web/**
* Or serve the `docs/` folder with any static server, e.g. `python -m http.server 8080 --directory docs` — then open `http://localhost:8080`.
* Or host it anywhere static (GitHub Pages, Netlify, …) — it's just files.

## Development

```
docs/                    the web app (index.html + css/ + js/)
tests/                   node test suites (crypto + converters)
tools/extract_keys.mjs   regenerates docs/js/keys.js from the Kotlin sources
```

* Plain ES5+-style JavaScript, no framework, no bundler.
* The RSA / ChaCha20-Poly1305 / AES-GCM implementations are ports of the Kotlin originals; the key material is extracted automatically from `HappCrypto.kt` / `V2RayTunCrypto.kt` so nothing is transcribed by hand.
* Run the tests: `node tests/crypto-test.mjs && node tests/converter-test.mjs` (60 checks, verify against Node's native crypto).

## Credits & license

Based on **[Happwner](https://github.com/Omegaplexx/Happwner)** by [Omegaplex](https://github.com/Omegaplexx) and [slavrom21](https://github.com/21slavrom) — this repository is a fork of it; the original Android/Xposed app and its full documentation live in [`README_UPSTREAM.md`](README_UPSTREAM.md).

Non-commercial use with attribution, per the [upstream terms](https://github.com/Omegaplexx/Happwner#terms-of-use). Use responsibly: the tool is meant for personal convenience and transparency about what your own subscriptions contain.
