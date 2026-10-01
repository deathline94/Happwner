// Link/format converter, ported from Happwner's LinkConverter.kt.
// Pass order: base64 -> xray-to-sing-box -> JSON-to-URI.
"use strict";
(function (global) {
  const SB = global.HWSingBox;

  const PROXY_SCHEMES = [
    'vless://', 'vmess://', 'trojan://', 'ss://', 'ssr://',
    'hysteria://', 'hysteria2://', 'hy2://', 'tuic://', 'socks://',
    'http://', 'https://', 'happ://',
  ];

  const U = global.HWUtil;

  function isCompactJson(s) {
    const limit = Math.min(s.length, 1024);
    for (let i = 0; i < limit; i++) {
      const c = s[i];
      if (c === '\n' || c === '\r') return false;
    }
    return true;
  }

  function isWholeJsonValue(s) {
    try {
      JSON.parse(s);
      return true;
    } catch (e) { return false; }
  }

  function formatJson(value, compact) {
    try {
      return compact ? JSON.stringify(value) : JSON.stringify(value, null, 2);
    } catch (e) { return String(value); }
  }

  // Try to decode as Base64 (remember shape so we can re-encode the same way)
  function tryDecodeBase64(input) {
    if (input.length < 10) return null;
    const cleaned = input.trim();
    if (cleaned === '') return null;

    let hasStd = false, hasUrl = false, hadNewlines = false, hadPadding = false;
    for (const c of cleaned) {
      if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c === ' ' || c === '\t') continue;
      if (c === '=') { hadPadding = true; continue; }
      if (c === '\r' || c === '\n') { hadNewlines = true; continue; }
      if (c === '+' || c === '/') { hasStd = true; continue; }
      if (c === '-' || c === '_') { hasUrl = true; continue; }
      return null;
    }
    if (hasStd && hasUrl) return null;
    const rstripped = input.replace(/[ \t]+$/, '');
    const hadTrailingCrlf = rstripped.endsWith('\r\n');
    const hadTrailingNewline = hadTrailingCrlf || rstripped.endsWith('\n') || rstripped.endsWith('\r');
    const hadCrlf = (hadNewlines && cleaned.includes('\r\n')) || hadTrailingCrlf;

    let data;
    try {
      data = U.b64DecodeFlexible(cleaned);
    } catch (e) { return null; }
    if (data.length === 0) return null;

    // Reject binary: strict UTF-8 + no control chars except \t \n \r
    const decodedRaw = U.utf8DecodeStrict(data);
    if (decodedRaw === null) return null;
    for (const ch of decodedRaw) {
      const cc = ch.codePointAt(0);
      if (cc === 0x7f || (cc < 0x20 && cc !== 0x09 && cc !== 0x0a && cc !== 0x0d)) return null;
    }
    const decoded = decodedRaw.replace(/^\s+/, '');
    const firstLine = (decoded.split(/\r?\n/).find((l) => l.trim() !== '') || '').trimStart();
    if (firstLine === '') return null;
    const looksLikeJson = firstLine.startsWith('{') || firstLine.startsWith('[');
    const looksLikeProxyList = PROXY_SCHEMES.some((s) => firstLine.toLowerCase().startsWith(s));
    if (!looksLikeJson && !looksLikeProxyList) return null;

    return { decoded, hasUrl, hadNewlines, hadCrlf, hadPadding, hadTrailingNewline, hadTrailingCrlf };
  }

  // Re-pack into base64 in the same shape as the input
  function encodeBase64Like(text, b64) {
    let out = U.b64Encode(U.utf8Encode(text), { urlsafe: b64.hasUrl, pad: b64.hadPadding });
    if (b64.hadNewlines && !b64.hadCrlf) {
      // wrap at 76 columns like android Base64.DEFAULT
      const lines = [];
      for (let i = 0; i < out.length; i += 76) lines.push(out.substring(i, i + 76));
      out = lines.join('\n');
    }
    if (b64.hadTrailingCrlf) out += '\r\n';
    else if (b64.hadTrailingNewline) out += '\n';
    return out;
  }

  // ---- JSON outbound -> proxy link builders ----

  function urlencode(s) {
    return encodeURIComponent(s == null ? '' : String(s));
  }

  function isShadowsocks(obj) {
    if (!obj || typeof obj !== 'object') return false;
    if (obj.server !== undefined && obj.server_port !== undefined && obj.password !== undefined && obj.method !== undefined) return true;
    const settings = obj.settings;
    if (settings) {
      const servers = settings.servers;
      if (Array.isArray(servers) && servers.length > 0) {
        const s = servers[0];
        if (s && s.address !== undefined && s.port !== undefined && s.password !== undefined && s.method !== undefined) return true;
      }
    }
    return false;
  }

  function buildVless(ob, rem) {
    try {
      const s = ob.settings;
      if (!s) return null;
      const vnext = s.vnext;
      if (!Array.isArray(vnext) || vnext.length === 0) return null;
      const vn = vnext[0];
      const users = vn.users;
      if (!Array.isArray(users) || users.length === 0) return null;
      const u = users[0];
      const ss = ob.streamSettings;
      const rs = ss ? ss.realitySettings : null;
      const enc = urlencode(rem);
      const fp = rs ? (rs.fingerprint || 'chrome') : 'chrome';
      const pbk = rs ? (rs.publicKey || '') : '';
      const sid = rs ? (rs.shortId || '') : '';
      const sni = rs ? (rs.serverName || '') : '';
      const security = ss ? (ss.security || 'none') : 'none';
      const type = ss ? (ss.network || 'tcp') : 'tcp';
      return 'vless://' + u.id + '@' + vn.address + ':' + vn.port +
        '?encryption=' + (u.encryption || 'none') +
        '&flow=' + (u.flow || '') +
        '&fp=' + fp + '&pbk=' + pbk + '&security=' + security + '&sid=' + sid + '&sni=' + sni +
        '&type=' + type + '#' + enc;
    } catch (e) { return null; }
  }

  function buildVmess(ob, rem) {
    try {
      const linkJson = { v: '2' };
      const settings = ob.settings;
      const vnext = settings && Array.isArray(settings.vnext) ? settings.vnext[0] : null;

      const addr = ob.server !== undefined ? ob.server : (vnext ? (vnext.address || '') : '');
      const port = ob.server_port !== undefined ? ob.server_port : (vnext ? (vnext.port !== undefined ? vnext.port : 0) : 0);
      const uuid = ob.uuid !== undefined ? ob.uuid
        : (vnext && vnext.users && vnext.users[0] ? (vnext.users[0].id || '') : '');

      linkJson.add = addr;
      linkJson.port = String(port);
      linkJson.id = uuid;
      linkJson.aid = '0';
      linkJson.scy = 'auto';

      const transport = ob.transport;
      const stream = ob.streamSettings;
      const net = transport ? (transport.type || (stream ? stream.network : null)) : (stream ? stream.network : null);
      linkJson.net = net || 'tcp';

      const tlsObj = ob.tls;
      const isTls = tlsObj ? tlsObj.enabled : (stream ? stream.security === 'tls' : false);
      linkJson.tls = isTls ? 'tls' : '';

      if (linkJson.net === 'ws') {
        const ws = transport || (stream ? stream.wsSettings : null);
        if (ws && ws.path !== undefined && ws.path !== null) linkJson.path = ws.path;
        const host = ws && ws.headers ? (typeof ws.headers.Host === 'string' ? ws.headers.Host : (ws.headers.Host ? JSON.stringify(ws.headers.Host) : undefined)) : undefined;
        if (ws && ws.headers) {
          if (ws.headers.Host !== undefined && ws.headers.Host !== null) linkJson.host = typeof ws.headers.Host === 'string' ? ws.headers.Host : String(ws.headers.Host);
        }
      }

      const finalRem = ob.tag !== undefined ? ob.tag : (ob.remarks !== undefined ? ob.remarks : rem);
      linkJson.ps = finalRem;

      const b64 = U.b64Encode(U.utf8Encode(JSON.stringify(linkJson)), { pad: true });
      return 'vmess://' + b64;
    } catch (e) { return null; }
  }

  function buildShadowsocks(ob, rem) {
    try {
      let address, port, method, password;
      if (ob.server !== undefined) {
        address = ob.server;
        port = ob.server_port;
        method = ob.method;
        password = ob.password;
      } else {
        const settings = ob.settings;
        const s = settings && Array.isArray(settings.servers) ? settings.servers[0] : null;
        if (!s) return null;
        address = s.address; port = s.port; method = s.method; password = s.password;
      }
      const credentials = method + ':' + password;
      const ui = U.b64Encode(U.utf8Encode(credentials), { pad: true });
      const finalRem = ob.remarks !== undefined ? ob.remarks : rem;
      return 'ss://' + ui + '@' + address + ':' + port + '#' + urlencode(finalRem);
    } catch (e) { return null; }
  }

  function buildTrojan(ob, rem) {
    try {
      const settings = ob.settings;
      const server = settings && Array.isArray(settings.servers) ? settings.servers[0] : null;
      if (!server) return null;
      const address = server.address !== undefined ? server.address : '';
      const port = server.port !== undefined ? server.port : 0;
      const password = server.password !== undefined ? server.password : '';

      const ss = ob.streamSettings;
      const network = ss ? ss.network : undefined;
      const security = ss ? ss.security : undefined;

      const query = {};
      if (network !== undefined && network !== null && network !== '') query.type = network;
      if (security === 'tls' || security === 'reality') {
        const tls = ss ? (ss.tlsSettings || ss.realitySettings) : null;
        const sni = tls ? tls.serverName : undefined;
        if (sni) { query.sni = sni; query.host = sni; }
      }
      if (network === 'ws') {
        const ws = ss ? ss.wsSettings : null;
        const path = ws ? ws.path : undefined;
        const host = ws && ws.headers ? ws.headers.Host : undefined;
        if (path) query.path = path;
        if (host) query.host = host;
      }
      const queryStr = Object.keys(query).sort().map((k) => k + '=' + urlencode(query[k])).join('&');
      const queryString = queryStr !== '' ? '?' + queryStr : '';
      const finalRem = ob.remarks !== undefined ? ob.remarks : rem;
      return 'trojan://' + urlencode(password) + '@' + address + ':' + port + queryString + '#' + urlencode(finalRem);
    } catch (e) { return null; }
  }

  function buildHysteria2(ob, rem) {
    try {
      const settings = ob.settings;
      const server = settings && Array.isArray(settings.servers) ? settings.servers[0] : null;
      if (!server) return null;
      const address = server.address !== undefined ? server.address : '';
      const port = server.port !== undefined ? server.port : 0;

      const ss = ob.streamSettings;
      const hy2 = ss ? ss.hy2Settings : null;
      const password = hy2 ? (hy2.password || '') : '';
      const obfs = hy2 ? hy2.obfs : null;
      const obfsType = obfs ? obfs.type : undefined;
      const obfsPassword = obfs ? obfs.password : undefined;
      const tls = ss ? ss.tlsSettings : null;
      const sni = tls ? tls.serverName : undefined;

      const query = [];
      if (obfsType) query.push('obfs=' + urlencode(obfsType));
      if (obfsPassword) query.push('obfs-password=' + urlencode(obfsPassword));
      if (sni) query.push('sni=' + urlencode(sni));
      const queryString = query.length > 0 ? '?' + query.join('&') : '';
      return 'hysteria2://' + password + '@' + address + ':' + port + '/' + queryString + '#' + urlencode(rem);
    } catch (e) { return null; }
  }

  function buildTuic(ob, rem) {
    try {
      const address = ob.server !== undefined ? ob.server : '';
      const port = ob.server_port !== undefined ? ob.server_port : 0;
      const uuid = ob.uuid !== undefined ? ob.uuid : '';
      const password = ob.password !== undefined ? ob.password : '';

      const query = {};
      const cc = ob.congestion_control;
      if (cc) query.congestion_control = cc;
      const mode = ob.udp_relay_mode;
      if (mode) query.udp_relay_mode = mode;
      const tls = ob.tls;
      if (tls && tls.enabled) {
        if (tls.server_name) query.sni = tls.server_name;
        if (Array.isArray(tls.alpn) && tls.alpn.length > 0) query.alpn = tls.alpn[0];
        if (tls.insecure) query.allow_insecure = '1';
      }
      const queryStr = Object.keys(query).sort().map((k) => k + '=' + urlencode(query[k])).join('&');
      const queryString = queryStr !== '' ? '?' + queryStr : '';
      const finalRem = ob.tag !== undefined ? ob.tag : (ob.remarks !== undefined ? ob.remarks : rem);
      return 'tuic://' + uuid + ':' + password + '@' + address + ':' + port + queryString + '#' + urlencode(finalRem);
    } catch (e) { return null; }
  }

  // JSON outbound (root) -> link
  function processJson(root) {
    if (isShadowsocks(root)) return buildShadowsocks(root, root.remarks || '');
    const protocol = root.protocol !== undefined ? root.protocol : (root.type !== undefined ? root.type : '');
    if (protocol === 'vmess') return buildVmess(root, root.tag || root.remarks || '');
    if (protocol === 'tuic') return buildTuic(root, root.tag || root.remarks || '');

    const obs = root.outbounds;
    if (Array.isArray(obs)) {
      const rem = root.remarks || '';
      for (const ob of obs) {
        if (!ob || typeof ob !== 'object' || Array.isArray(ob)) continue;
        const p = ob.protocol !== undefined ? ob.protocol : (ob.type !== undefined ? ob.type : '');
        let c = null;
        if (p === 'vless') c = buildVless(ob, rem);
        else if (p === 'vmess') c = buildVmess(ob, rem);
        else if (p === 'shadowsocks') c = buildShadowsocks(ob, rem);
        else if (p === 'trojan') c = buildTrojan(ob, rem);
        else if (p === 'hysteria2') c = buildHysteria2(ob, rem);
        else if (p === 'tuic') c = buildTuic(ob, rem);
        else if (isShadowsocks(ob)) c = buildShadowsocks(ob, rem);
        if (c !== null) return c;
      }
    }
    return null;
  }

  // ---- xray pre-filtering ----

  function preFilterUnsupportedXrayOne(t) {
    if (t === '') return null;
    if (!isWholeJsonValue(t)) return null;
    if (t.startsWith('{')) {
      const r = SB.convertToOutbounds(t, '');
      if (r.status === 'ok') {
        let cfg = null;
        try { cfg = JSON.parse(t); } catch (e) { cfg = null; }
        if (cfg && SB.normalizeConfigFlowsInPlace(cfg)) return { text: JSON.stringify(cfg), skipped: 0 };
        return { text: t, skipped: 0 };
      }
      if (r.status === 'unsupported') return { text: '', skipped: 1 };
      return null; // notxray
    }
    if (t.startsWith('[')) {
      let arr;
      try { arr = JSON.parse(t); } catch (e) { return null; }
      if (!Array.isArray(arr)) return null;
      const out = [];
      let anyXray = false, skipped = 0;
      for (const obj of arr) {
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) { out.push(obj); continue; }
        const r = SB.convertToOutbounds(JSON.stringify(obj), '');
        if (r.status === 'ok') {
          SB.normalizeConfigFlowsInPlace(obj);
          out.push(obj);
          anyXray = true;
        } else if (r.status === 'unsupported') {
          skipped++;
          anyXray = true;
        } else {
          out.push(obj);
        }
      }
      if (!anyXray) return null;
      return { text: formatJson(out, isCompactJson(t)), skipped };
    }
    return null;
  }

  function preFilterUnsupportedXray(input) {
    const trimmed = input.trim();
    if ((trimmed.startsWith('{') || trimmed.startsWith('[')) && isWholeJsonValue(trimmed)) {
      const single = preFilterUnsupportedXrayOne(trimmed);
      if (single !== null) return single;
    }
    const res = [];
    let totalSkipped = 0, anyFiltered = false;
    for (const line of input.split(/\r?\n/)) {
      const tt = line.trim();
      if (tt === '') continue;
      const one = preFilterUnsupportedXrayOne(tt);
      if (one !== null) {
        anyFiltered = true;
        if (one.text !== '') res.push(one.text);
        totalSkipped += one.skipped;
      } else {
        res.push(tt);
      }
    }
    if (!anyFiltered) return { text: input, skipped: 0 };
    return { text: res.join('\n'), skipped: totalSkipped };
  }

  function tryConvertXrayArray(text, compact) {
    let arr;
    try { arr = JSON.parse(text); } catch (e) { return null; }
    if (!Array.isArray(arr) || arr.length === 0) return null;

    let anyXray = false;
    for (const obj of arr) {
      if (!obj || typeof obj !== 'object' || Array.isArray(obj)) continue;
      const outs = obj.outbounds;
      if (!Array.isArray(outs)) continue;
      for (const o of outs) {
        if (o && typeof o === 'object' && (o.protocol !== undefined)) { anyXray = true; break; }
      }
      if (anyXray) break;
    }
    if (!anyXray) return null;

    const outArr = [];
    let skipped = 0;
    for (const obj of arr) {
      if (!obj || typeof obj !== 'object' || Array.isArray(obj)) { outArr.push(obj); continue; }
      const r = SB.convert(JSON.stringify(obj), '');
      if (r.status === 'ok') outArr.push(r.config);
      else if (r.status === 'unsupported') skipped++;
      else outArr.push(obj);
    }
    return { text: formatJson(outArr, compact), skipped };
  }

  // Merge xray configs into one sing-box; pass other lines through unchanged
  function convertXrayToSingbox(input, compact) {
    const configs = [];
    let skipped = 0, hadXray = false;
    const passthroughLines = [];

    const ingestObject = (s) => {
      const r = SB.convert(s, '');
      if (r.status === 'ok') { configs.push(r.config); hadXray = true; return true; }
      if (r.status === 'unsupported') { skipped++; hadXray = true; return true; }
      return false;
    };
    const ingestArray = (s) => {
      let arr;
      try { arr = JSON.parse(s); } catch (e) { return false; }
      if (!Array.isArray(arr)) return false;
      let any = false;
      for (const obj of arr) {
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) continue;
        const r = SB.convert(JSON.stringify(obj), '');
        if (r.status === 'ok') { configs.push(r.config); any = true; }
        else if (r.status === 'unsupported') { skipped++; any = true; }
      }
      if (any) hadXray = true;
      return any;
    };

    const trimmed = input.trim();
    let consumedWhole = false;
    if (trimmed.startsWith('{') && isWholeJsonValue(trimmed)) consumedWhole = ingestObject(trimmed);
    else if (trimmed.startsWith('[') && isWholeJsonValue(trimmed)) consumedWhole = ingestArray(trimmed);

    if (!consumedWhole) {
      for (const line of input.split(/\r?\n/)) {
        const t = line.trim();
        if (t === '') continue;
        let consumed = false;
        if (t.startsWith('{') && isWholeJsonValue(t)) consumed = ingestObject(t);
        else if (t.startsWith('[') && isWholeJsonValue(t)) consumed = ingestArray(t);
        if (!consumed) passthroughLines.push(t);
      }
    }

    if (!hadXray) return null;
    if (configs.length === 0 && passthroughLines.length === 0) return null;

    const builder = [];
    if (configs.length > 0) {
      const merged = SB.mergeUnified(configs);
      if (merged !== null) builder.push(formatJson(merged, compact));
    }
    for (const l of passthroughLines) builder.push(l);
    return { text: builder.join('\n'), skipped };
  }

  // ---- main entry ----
  // Options: { jsonToUri: bool, tryBase64: bool, xrayToSb: bool }
  // Returns { text, xraySkipped }
  function convertWithStats(input, jsonToUri, tryBase64, xrayToSb) {
    if (!jsonToUri && !tryBase64 && !xrayToSb) return { text: input.trim(), xraySkipped: 0 };

    const trimmed = input.trim();
    const compact = isCompactJson(trimmed);

    // Whole body is base64 -> decode and recurse
    if (tryBase64 || xrayToSb) {
      const b64 = tryDecodeBase64(input);
      if (b64 !== null) {
        const inner = convertWithStats(b64.decoded, jsonToUri, tryBase64, xrayToSb);
        if (tryBase64) return inner;
        return { text: encodeBase64Like(inner.text, b64), xraySkipped: inner.xraySkipped };
      }
    }

    // xray-to-sing-box only: merge everything into a single config
    if (xrayToSb && !jsonToUri) {
      const merged = convertXrayToSingbox(input, compact);
      if (merged !== null) return { text: merged.text, xraySkipped: merged.skipped };
    }

    // Both modes: drop unsupported xray outbounds, then JSON-to-URI
    if (xrayToSb && jsonToUri) {
      const filtered = preFilterUnsupportedXray(input);
      const inner = convertWithStats(filtered.text, true, tryBase64, false);
      return { text: inner.text, xraySkipped: inner.xraySkipped + filtered.skipped };
    }

    // Whole body is one xray config -> sing-box
    if (xrayToSb && trimmed.startsWith('{') && isWholeJsonValue(trimmed)) {
      const r = SB.convert(trimmed, '');
      if (r.status === 'ok') return { text: formatJson(r.config, compact), xraySkipped: 0 };
    }

    // Whole body is an xray array -> sing-box
    if (xrayToSb && trimmed.startsWith('[') && isWholeJsonValue(trimmed)) {
      const arr = tryConvertXrayArray(trimmed, compact);
      if (arr !== null) return { text: arr.text, xraySkipped: arr.skipped };
    }

    // Web bonus: whole-body (even pretty-printed) JSON -> link, which the line walker misses
    if (jsonToUri && trimmed.startsWith('{') && isWholeJsonValue(trimmed)) {
      try {
        const obj = JSON.parse(trimmed);
        const converted = processJson(obj);
        if (converted !== null) return { text: converted, xraySkipped: 0 };
      } catch (e) { /* fall through to the line walk */ }
    }

    const res = [];
    let skipped = 0;
    for (const line of input.split(/\r?\n/)) {
      const t = line.trim();
      if (t === '') continue;
      const lineCompact = isCompactJson(t);

      if (tryBase64 || xrayToSb) {
        const b64 = tryDecodeBase64(t);
        if (b64 !== null) {
          const inner = convertWithStats(b64.decoded, jsonToUri, tryBase64, xrayToSb);
          const output = tryBase64 ? inner.text : encodeBase64Like(inner.text, b64);
          res.push(output);
          skipped += inner.xraySkipped;
          continue;
        }
      }

      if (xrayToSb && t.startsWith('{') && isWholeJsonValue(t)) {
        const r = SB.convert(t, '');
        if (r.status === 'ok') { res.push(formatJson(r.config, lineCompact)); continue; }
        if (r.status === 'unsupported') { skipped++; continue; }
        // notxray: fall through
      }

      if (xrayToSb && t.startsWith('[') && isWholeJsonValue(t)) {
        const arr = tryConvertXrayArray(t, lineCompact);
        if (arr !== null) { res.push(arr.text); skipped += arr.skipped; continue; }
      }

      // JSON outbound on this line -> proxy link
      if (jsonToUri && (t.startsWith('{') || t.startsWith('[')) && isWholeJsonValue(t)) {
        try {
          const parsed = JSON.parse(t);
          if (Array.isArray(parsed)) {
            for (const obj of parsed) {
              if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
                const piece = processJson(obj) || JSON.stringify(obj);
                res.push(piece);
              } else if (obj !== null && obj !== undefined) {
                res.push(String(obj).trim());
              }
            }
          } else {
            const converted = processJson(parsed);
            if (converted !== null) res.push(converted);
            else res.push(t);
          }
          continue;
        } catch (e) { /* fall through */ }
      }

      res.push(t);
    }
    return { text: res.join('\n'), xraySkipped: skipped };
  }

  function convert(input, jsonToUri, tryBase64, xrayToSb) {
    return convertWithStats(input, jsonToUri, tryBase64, xrayToSb).text;
  }

  global.HWLinkConverter = { convert, convertWithStats, processJson, tryDecodeBase64 };
})(typeof window !== 'undefined' ? window : globalThis);
