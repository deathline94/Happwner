// Proxy link parser: turns vless/vmess/ss/trojan/hysteria2/tuic/socks/http links
// into structured server info cards (a web-native replacement for the app's server list).
"use strict";
(function (global) {
  const U = global.HWUtil;

  function parseParams(qs) {
    const out = {};
    if (!qs) return out;
    try {
      for (const [k, v] of new URLSearchParams(qs)) out[k.toLowerCase()] = v;
    } catch (e) { /* ignore */ }
    return out;
  }

  function nameFromHash(rest) {
    const h = rest.lastIndexOf('#');
    if (h < 0) return '';
    try { return decodeURIComponent(rest.substring(h + 1).replace(/\+/g, ' ')); } catch (e) { return rest.substring(h + 1); }
  }

  function stripName(rest) {
    const h = rest.lastIndexOf('#');
    return h >= 0 ? rest.substring(0, h) : rest;
  }

  // ss:// has two shapes: base64(method:pass)@host:port#name and base64(method:pass@host:port)#name
  function parseSs(rest) {
    const name = nameFromHash(rest);
    let body = stripName(rest);
    if (body.includes('@')) {
      const at = body.lastIndexOf('@');
      const ui = body.substring(0, at);
      const hostPart = body.substring(at + 1);
      let creds;
      try { creds = U.utf8Decode(U.b64DecodeFlexible(decodeURIComponent(ui))); } catch (e) { creds = null; }
      if (creds === null || creds === undefined || creds.indexOf(':') < 0) {
        try { creds = U.utf8Decode(U.b64DecodeFlexible(ui)); } catch (e) { return null; }
      }
      const ci = creds.indexOf(':');
      const hp = splitHostPortLoose(hostPart.split('?')[0]);
      return { name, proto: 'shadowsocks', method: creds.substring(0, ci), password: creds.substring(ci + 1), host: hp.host, port: hp.port, params: parseParams(hostPart.split('?')[1]) };
    }
    // whole thing base64
    try {
      const decoded = U.utf8Decode(U.b64DecodeFlexible(decodeURIComponent(body)));
      const ci = decoded.indexOf(':');
      const at = decoded.lastIndexOf('@');
      if (ci < 0 || at < 0) return null;
      const hp = splitHostPortLoose(decoded.substring(at + 1).split('?')[0]);
      return { name, proto: 'shadowsocks', method: decoded.substring(0, ci), password: decoded.substring(ci + 1, at), host: hp.host, port: hp.port, params: parseParams(decoded.split('?')[1]) };
    } catch (e) { return null; }
  }

  function splitHostPortLoose(s) {
    const i = s.lastIndexOf(':');
    if (i < 0) return { host: s, port: null };
    const host = s.substring(0, i);
    const port = parseInt(s.substring(i + 1), 10);
    return { host, port: Number.isNaN(port) ? null : port };
  }

  function parseVmess(rest) {
    const name = nameFromHash(rest);
    let body = stripName(rest);
    try {
      const json = JSON.parse(U.utf8Decode(U.b64DecodeFlexible(body.replace(/^\/\//, ''))));
      return {
        name: name || json.ps || '', proto: 'vmess',
        host: json.add, port: parseInt(json.port, 10) || null,
        security: json.tls === 'tls' ? 'tls' : 'none',
        transport: json.net || 'tcp',
        uuid: json.id, extra: { scy: json.scy, path: json.path, host: json.host, sni: (json.sni || '') },
      };
    } catch (e) { return null; }
  }

  function parseUserInfoLink(scheme, rest) {
    const name = nameFromHash(rest);
    let body = stripName(rest);
    const qi = body.indexOf('?');
    const params = parseParams(qi >= 0 ? body.substring(qi + 1) : '');
    if (qi >= 0) body = body.substring(0, qi);
    const at = body.lastIndexOf('@');
    if (at < 0) return null;
    const userinfo = body.substring(0, at);
    const hp = splitHostPortLoose(body.substring(at + 1));
    return {
      name, proto: scheme,
      host: decodeHost(hp.host), port: hp.port, params,
      userinfo: /^[\x20-\x7e]+$/.test(userinfo) ? userinfo : '(encoded)',
      security: params.security || (scheme === 'trojan' ? 'tls' : 'none'),
      transport: params.type || 'tcp',
    };
  }

  function decodeHost(h) {
    try { return decodeURIComponent(h); } catch (e) { return h; }
  }

  // Parse one line into a server info object, or null
  function parseLink(line) {
    const t = (line || '').trim();
    if (t === '') return null;
    let m;
    if ((m = t.match(/^ss:\/{1,2}(.*)$/i))) return parseSs(m[1]);
    if ((m = t.match(/^vmess:\/\/(.*)$/i))) return parseVmess(m[1]);
    if ((m = t.match(/^vless:\/\/(.*)$/i))) { const r = parseUserInfoLink('vless', m[1]); return r && Object.assign(r, { uuid: r.userinfo }); }
    if ((m = t.match(/^trojan:\/\/(.*)$/i))) return parseUserInfoLink('trojan', m[1]);
    if ((m = t.match(/^(?:hysteria2|hy2):\/\/(.*)$/i))) return parseUserInfoLink('hysteria2', m[1]);
    if ((m = t.match(/^hysteria:\/\/(.*)$/i))) return parseUserInfoLink('hysteria', m[1]);
    if ((m = t.match(/^tuic:\/\/(.*)$/i))) return parseUserInfoLink('tuic', m[1]);
    if ((m = t.match(/^socks(?:5)?:\/\/(.*)$/i))) return parseUserInfoLink('socks', m[1]);
    return null;
  }

  // Parse a whole text: returns { servers: [], invalid: 0 }
  function parseLinks(text) {
    const servers = [];
    let invalid = 0;
    for (const line of (text || '').split(/\r?\n/)) {
      const t = line.trim();
      if (t === '') continue;
      if (t.startsWith('{') || t.startsWith('[')) { invalid++; continue; }
      const s = parseLink(t);
      if (s) servers.push(s);
      else invalid++;
    }
    return { servers, invalid };
  }

  // Count sing-box outbounds in a JSON text (for the cards view)
  function parseSingBoxOutbounds(text) {
    const out = [];
    try {
      const cfg = JSON.parse(text);
      const list = [];
      if (Array.isArray(cfg)) list.push(...cfg);
      else if (cfg && typeof cfg === 'object') {
        if (Array.isArray(cfg.outbounds)) list.push(...cfg.outbounds);
        if (Array.isArray(cfg.endpoints)) list.push(...cfg.endpoints);
      }
      const proxyTypes = new Set(['vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria', 'hysteria2', 'tuic', 'wireguard', 'socks', 'http', 'anytls', 'ssh']);
      for (const o of list) {
        if (!o || typeof o !== 'object') continue;
        if (!proxyTypes.has(o.type)) continue;
        out.push({
          name: o.tag || '', proto: o.type, host: o.server || o.address || '',
          port: o.server_port !== undefined ? o.server_port : null,
          security: o.tls ? (o.tls.reality ? 'reality' : 'tls') : 'none',
          transport: o.transport ? o.transport.type : 'tcp',
          sb: true,
        });
      }
    } catch (e) { /* not json */ }
    return out;
  }

  global.HWLinkParse = { parseLink, parseLinks, parseSingBoxOutbounds };
})(typeof window !== 'undefined' ? window : globalThis);
