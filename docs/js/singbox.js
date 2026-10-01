// Xray -> sing-box converter, ported from Happwner's SingBoxConverter.kt.
"use strict";
(function (global) {

  const UTLS_FP = new Set(['chrome', 'firefox', 'edge', 'safari', '360', 'qq', 'ios', 'android', 'random', 'randomized']);
  const XRAY_TRANSPORTS_OK = new Set(['tcp', 'raw', '', 'ws', 'grpc', 'http', 'h2', 'httpupgrade', 'quic']);
  const XRAY_SECURITY_OK = new Set(['', 'none', 'tls', 'reality']);
  const XRAY_PROTOCOLS_PROXY = new Set(['vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'wireguard']);
  const XRAY_PROTOCOLS_AUX = new Set(['freedom', 'blackhole', 'dns', 'loopback']);
  const VLESS_FLOW_OK = new Set(['', 'xtls-rprx-vision']);
  const VLESS_FLOW_MAP = { 'xtls-rprx-vision-udp443': 'xtls-rprx-vision' };
  const VMESS_SECURITY_OK = new Set(['auto', 'none', 'zero', 'aes-128-gcm', 'chacha20-poly1305', 'aes-128-ctr']);
  const SS_METHODS_OK = new Set([
    'none', 'aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm',
    'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305',
    'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
    'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
    'rc4-md5', 'chacha20-ietf', 'xchacha20',
  ]);
  const SS_METHOD_ALIAS = { 'chacha20-poly1305': 'chacha20-ietf-poly1305', 'xchacha20-poly1305': 'xchacha20-ietf-poly1305', 'plain': 'none' };
  const SS_PLUGINS_OK = new Set(['', 'obfs-local', 'v2ray-plugin']);
  const QUERY_STRATEGY_MAP = {
    UseIPv4: 'ipv4_only', UseIPv4v6: 'prefer_ipv4', UseIPv6: 'ipv6_only',
    UseIPv6v4: 'prefer_ipv6', UseIP: 'prefer_ipv4', UseSystem: 'prefer_ipv4',
  };
  const DOMAIN_STRATEGY_MAP = {
    AsIs: '', UseIP: 'prefer_ipv4', UseIPv4: 'ipv4_only', UseIPv4v6: 'prefer_ipv4',
    UseIPv6: 'ipv6_only', UseIPv6v4: 'prefer_ipv6', IPIfNonMatch: 'prefer_ipv4', IPOnDemand: 'prefer_ipv4',
  };
  const REMOTE_DNS_TYPES = new Set(['https', 'http3', 'tls', 'quic', 'tcp', 'udp']);
  const ENCRYPTED_DNS_TYPES = new Set(['https', 'http3', 'tls', 'quic', 'tcp']);
  const LOG_LEVEL_MAP = { debug: 'debug', info: 'info', warning: 'warn', warn: 'warn', error: 'error', none: 'fatal' };
  const SINGBOX_OUTBOUND_TYPES = new Set([
    'vless', 'vmess', 'trojan', 'shadowsocks', 'hysteria', 'hysteria2', 'tuic', 'wireguard',
    'anytls', 'ssh', 'naive', 'shadowtls', 'selector', 'urltest', 'direct', 'block', 'dns', 'socks', 'http',
  ]);
  const GEOSITE_URL_TEMPLATE = 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/{name}.srs';
  const GEOIP_URL_TEMPLATE = 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/{name}.srs';

  // ---- small opt* helpers mirroring org.json semantics ----
  function opt(o, k) { return o == null ? undefined : o[k]; }
  function optString(o, k, def) {
    if (o == null) return def === undefined ? '' : def;
    const v = o[k];
    if (v === undefined || v === null) return def === undefined ? '' : def;
    if (typeof v === 'string') return v;
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
  }
  function optBoolean(o, k, def) {
    const v = o ? o[k] : undefined;
    if (v === undefined || v === null) return def;
    if (typeof v === 'boolean') return v;
    if (typeof v === 'number') return v !== 0;
    if (typeof v === 'string') return v.toLowerCase() === 'true';
    return def;
  }
  function has(o, k) { return o != null && Object.prototype.hasOwnProperty.call(o, k); }
  function isTruthy(v) {
    if (v === undefined || v === null) return false;
    if (typeof v === 'boolean') return v;
    if (typeof v === 'number') return v !== 0;
    if (typeof v === 'string') return v.length > 0;
    if (Array.isArray(v)) return v.length > 0;
    if (typeof v === 'object') return Object.keys(v).length > 0;
    return true;
  }
  function asList(v) {
    if (v === undefined || v === null) return [];
    if (Array.isArray(v)) return v;
    return [v];
  }
  function asStringList(v) {
    return asList(v).filter((x) => x !== null && x !== undefined).map((x) => typeof x === 'string' ? x : JSON.stringify(x));
  }
  function deepCopy(o) { return o == null ? o : JSON.parse(JSON.stringify(o)); }
  function utlsFp(fp) { return typeof fp === 'string' && UTLS_FP.has(fp) ? fp : 'chrome'; }
  function normalizeFlow(flow) {
    if (!flow) return '';
    return VLESS_FLOW_MAP[flow] || flow;
  }

  function isIpLiteral(s) {
    if (typeof s !== 'string' || s === '') return false;
    return parseInet4(s) || parseInet6(s);
  }

  function parseInet4(s) {
    const parts = s.split('.');
    if (parts.length !== 4) return false;
    for (const p of parts) {
      if (p === '' || p.length > 3) return false;
      for (const c of p) if (c < '0' || c > '9') return false;
      const n = parseInt(p, 10);
      if (Number.isNaN(n) || n < 0 || n > 255) return false;
      if (p.length > 1 && p[0] === '0') return false;
    }
    return true;
  }

  // Rough IPv6 parsing (::, embedded IPv4, zone-id)
  function parseInet6(s) {
    if (!s) return false;
    const pct = s.indexOf('%');
    const core = pct >= 0 ? s.substring(0, pct) : s;
    if (core === '') return false;
    if (core === '::') return true;
    const hasDoubleColon = core.includes('::');
    const tail = core.substring(core.lastIndexOf(':') + 1);
    const embedded4 = tail.includes('.');
    let groupsRaw;
    if (hasDoubleColon) {
      const idx = core.indexOf('::');
      const left = core.substring(0, idx);
      const right = core.substring(idx + 2);
      groupsRaw = (left === '' ? [] : left.split(':')).concat(right === '' ? [] : right.split(':'));
    } else {
      groupsRaw = core.split(':');
    }
    const groups = groupsRaw.slice();
    if (embedded4) {
      const last = groups.pop();
      if (!parseInet4(last)) return false;
      groups.push('0', '0');
    }
    const expected = 8;
    if (hasDoubleColon) { if (groups.length > expected) return false; }
    else if (groups.length !== expected) return false;
    for (const g of groups) {
      if (g === '' || g.length > 4) return false;
      for (const c of g) {
        const ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok) return false;
      }
    }
    return true;
  }

  function parsePortList(value) {
    const ports = [], ranges = [];
    if (value === undefined || value === null) return { ports, ranges };
    let items = [];
    if (Array.isArray(value)) {
      for (const v of value) if (v != null) items = items.concat(String(v).split(','));
    } else {
      items = String(value).split(',');
    }
    for (const raw of items) {
      const tok = raw.trim();
      if (tok === '') continue;
      if (tok.includes('-')) ranges.push(tok.replace('-', ':'));
      else if (/^[0-9]+$/.test(tok)) ports.push(parseInt(tok, 10));
    }
    return { ports, ranges };
  }

  function parseListenPort(p) {
    if (p === undefined || p === null) return null;
    if (typeof p === 'boolean') return null;
    if (typeof p === 'number') return Math.trunc(p);
    if (typeof p === 'string') {
      const s = p.trim();
      if (s === '') return null;
      if (/^[0-9]+$/.test(s)) return parseInt(s, 10);
      return null;
    }
    if (Array.isArray(p) && p.length >= 1) return parseListenPort(p[0]);
    return null;
  }

  function toDuration(v) {
    if (v === undefined || v === null) return null;
    if (typeof v === 'boolean') return null;
    if (typeof v === 'number') return Math.trunc(v) + 's';
    if (typeof v === 'string') {
      const s = v.trim();
      if (s === '') return null;
      if (/^[0-9]+$/.test(s)) return s + 's';
      return s;
    }
    return null;
  }

  function splitHostPort(s) {
    if (s == null || s === '') return { host: s || '', port: null };
    if (s.startsWith('[')) {
      const rb = s.indexOf(']');
      if (rb < 0) return { host: s, port: null };
      const host = s.substring(1, rb);
      const rest = s.substring(rb + 1);
      if (rest.startsWith(':') && /^[0-9]+$/.test(rest.substring(1))) {
        return { host, port: parseInt(rest.substring(1), 10) };
      }
      return { host, port: null };
    }
    let colons = 0;
    for (const c of s) if (c === ':') colons++;
    if (colons === 1) {
      const idx = s.indexOf(':');
      const host = s.substring(0, idx);
      const port = s.substring(idx + 1);
      if (port !== '' && /^[0-9]+$/.test(port)) return { host, port: parseInt(port, 10) };
    }
    return { host: s, port: null };
  }

  function parseWsPath(path) {
    if (typeof path !== 'string' || !path.includes('?') || !path.includes('ed=')) {
      return { path: typeof path === 'string' ? path : '', earlyData: null };
    }
    const qIdx = path.indexOf('?');
    const base = path.substring(0, qIdx);
    const query = path.substring(qIdx + 1);
    const kept = [];
    let edValue = null;
    for (const pair of query.split('&')) {
      if (pair === '') continue;
      if (pair.startsWith('ed=')) {
        const n = parseInt(pair.substring(3), 10);
        if (!Number.isNaN(n)) edValue = n; else kept.push(pair);
      } else {
        kept.push(pair);
      }
    }
    const newQuery = kept.join('&');
    return { path: newQuery === '' ? base : base + '?' + newQuery, earlyData: edValue };
  }

  function normalizeHeadersV2ray(headers, singleValue) {
    const out = {};
    if (headers == null) return out;
    for (const k of Object.keys(headers)) {
      const v = headers[k];
      if (v === undefined || v === null) continue;
      if (singleValue) {
        if (Array.isArray(v)) out[k] = v.length > 0 ? String(v[0]) : '';
        else out[k] = String(v);
      } else {
        if (Array.isArray(v)) out[k] = v;
        else out[k] = [String(v)];
      }
    }
    return out;
  }

  function serializePluginOpts(opts) {
    if (opts === undefined || opts === null) return '';
    if (typeof opts === 'string') return opts;
    if (typeof opts === 'object' && !Array.isArray(opts)) {
      const parts = [];
      for (const k of Object.keys(opts)) {
        const v = opts[k];
        if (typeof v === 'boolean') parts.push(v ? k : k + '=0');
        else parts.push(k + '=' + String(v));
      }
      return parts.join(';');
    }
    return '';
  }

  function getTcpHttpRequest(stream) {
    const net = optString(stream, 'network', 'tcp') || 'tcp';
    if (!(net === 'tcp' || net === 'raw' || net === '')) return null;
    const ts = stream.tcpSettings || stream.rawSettings;
    if (!ts) return null;
    const hdr = ts.header;
    if (!hdr) return null;
    const type = optString(hdr, 'type', 'none') || 'none';
    if (type !== 'http') return null;
    return hdr.request || {};
  }

  function isSingbox(d) {
    if (!has(d, 'route') || !has(d, 'outbounds')) return false;
    const outs = d.outbounds;
    if (!Array.isArray(outs) || outs.length === 0) return false;
    const first = outs[0];
    if (!first || typeof first !== 'object' || Array.isArray(first)) return false;
    return SINGBOX_OUTBOUND_TYPES.has(optString(first, 'type', ''));
  }

  function firstUser(o) {
    const settings = o.settings;
    if (!settings) return null;
    const vnext = settings.vnext;
    if (!Array.isArray(vnext) || vnext.length === 0) return null;
    const users = vnext[0] && vnext[0].users;
    if (!Array.isArray(users) || users.length === 0) return null;
    return users[0];
  }

  function firstServer(o) {
    const settings = o.settings;
    if (!settings) return null;
    const servers = settings.servers;
    if (!Array.isArray(servers) || servers.length === 0) return null;
    return servers[0];
  }

  // Whether an outbound is supported (protocol/transport/security/flow/method)
  function isOutboundSupported(o) {
    const proto = optString(o, 'protocol', '');
    if (!XRAY_PROTOCOLS_PROXY.has(proto) && !XRAY_PROTOCOLS_AUX.has(proto)) return false;
    if (XRAY_PROTOCOLS_AUX.has(proto) || proto === 'wireguard') return true;
    const stream = o.streamSettings || {};
    const net = optString(stream, 'network', 'tcp') || 'tcp';
    if (!XRAY_TRANSPORTS_OK.has(net)) return false;
    if (net === 'tcp' || net === 'raw') {
      const ts = stream.tcpSettings || stream.rawSettings;
      const hdrType = ts && ts.header ? (optString(ts.header, 'type', 'none') || 'none') : null;
      if (hdrType !== null && hdrType !== 'none' && hdrType !== 'http') return false;
    }
    if (net === 'quic') {
      const qs = stream.quicSettings || {};
      const qsec = (optString(qs, 'security', 'none') || 'none').toLowerCase();
      if (qsec !== 'none' && qsec !== '') return false;
      const qhdr = ((qs.header ? optString(qs.header, 'type', 'none') : 'none') || 'none').toLowerCase();
      if (qhdr !== 'none' && qhdr !== '') return false;
    }
    const sec = optString(stream, 'security', '');
    if (!XRAY_SECURITY_OK.has(sec)) return false;
    if (proto === 'vless') {
      const user = firstUser(o);
      const flow = normalizeFlow(user ? optString(user, 'flow', '') : '');
      if (!VLESS_FLOW_OK.has(flow)) return false;
      const enc = (user ? optString(user, 'encryption', 'none') : 'none').trim();
      if (enc !== '' && enc !== 'none') return false;
    }
    if (proto === 'vmess') {
      const user = firstUser(o);
      const vsec = ((user ? optString(user, 'security', 'auto') : 'auto') || 'auto');
      if (!VMESS_SECURITY_OK.has(vsec)) return false;
    }
    if (proto === 'shadowsocks') {
      const srv = firstServer(o);
      const rawMethod = srv ? optString(srv, 'method', 'aes-256-gcm') : 'aes-256-gcm';
      const method = SS_METHOD_ALIAS[rawMethod] || rawMethod;
      if (!SS_METHODS_OK.has(method)) return false;
      const plugin = srv ? optString(srv, 'plugin', '') : '';
      if (plugin !== '' && !SS_PLUGINS_OK.has(plugin)) return false;
    }
    return true;
  }

  // streamSettings -> sing-box tls block
  function convTls(stream) {
    const sec = optString(stream, 'security', '');
    if (sec !== 'tls' && sec !== 'reality') return null;
    const tls = { enabled: true };

    if (sec === 'reality') {
      const rs = stream.realitySettings || {};
      const sn = optString(rs, 'serverName', '');
      if (sn !== '') tls.server_name = sn;
      tls.utls = { enabled: true, fingerprint: utlsFp(rs.fingerprint) };
      tls.reality = { enabled: true, public_key: optString(rs, 'publicKey', ''), short_id: optString(rs, 'shortId', '') };
      return tls;
    }

    const ts = stream.tlsSettings || {};
    const sn = optString(ts, 'serverName', '');
    if (sn !== '') tls.server_name = sn;
    if (optBoolean(ts, 'allowInsecure', false)) tls.insecure = true;
    const alpn = ts.alpn;
    if (alpn !== undefined && alpn !== null) {
      if (Array.isArray(alpn)) { if (alpn.length > 0) tls.alpn = alpn; }
      else tls.alpn = [String(alpn)];
    }
    if (has(ts, 'minVersion') && ts.minVersion !== null) {
      const v = optString(ts, 'minVersion', '');
      if (v !== '') tls.min_version = v;
    }
    if (has(ts, 'maxVersion') && ts.maxVersion !== null) {
      const v = optString(ts, 'maxVersion', '');
      if (v !== '') tls.max_version = v;
    }
    const fp = optString(ts, 'fingerprint', '');
    if (fp !== '') tls.utls = { enabled: true, fingerprint: utlsFp(fp) };
    const certs = ts.certificates;
    if (Array.isArray(certs) && certs.length > 0) {
      const cert = certs[0] || {};
      const certFile = optString(cert, 'certificateFile', '');
      if (certFile !== '') tls.certificate_path = certFile;
      else if (has(cert, 'certificate') && cert.certificate !== null) {
        const cval = cert.certificate;
        if (Array.isArray(cval)) tls.certificate = cval.map((x) => (x == null ? '' : String(x))).join('\n');
        else if (typeof cval === 'string') tls.certificate = cval;
      }
    }
    let ech = ts.echConfigList;
    if (ech === undefined || ech === null || (Array.isArray(ech) && ech.length === 0) || (typeof ech === 'string' && ech === '')) {
      ech = ts.ech;
    }
    if (ech !== undefined && ech !== null && !(Array.isArray(ech) && ech.length === 0) && !(typeof ech === 'string' && ech === '')) {
      const echObj = { enabled: true };
      if (Array.isArray(ech)) echObj.config = ech;
      else echObj.config_path = String(ech);
      tls.ech = echObj;
    }
    return tls;
  }

  // streamSettings -> sing-box transport block
  function convTransport(stream) {
    let net = optString(stream, 'network', 'tcp') || 'tcp';
    if (net === 'raw') net = 'tcp';

    if (net === 'tcp') {
      const req = getTcpHttpRequest(stream);
      if (!req) return null;
      const tr = { type: 'http' };
      const pathRaw = req.path;
      if (Array.isArray(pathRaw)) { if (pathRaw.length > 0) tr.path = pathRaw[0]; }
      else if (typeof pathRaw === 'string' && pathRaw !== '') tr.path = pathRaw;
      const method = optString(req, 'method', '');
      if (method !== '') tr.method = method;
      let workingHeaders = null;
      if (req.headers && typeof req.headers === 'object' && !Array.isArray(req.headers)) {
        workingHeaders = Object.assign({}, req.headers);
      }
      let hostVals;
      if (workingHeaders) {
        if (has(workingHeaders, 'Host')) { hostVals = workingHeaders.Host; delete workingHeaders.Host; }
        else if (has(workingHeaders, 'host')) { hostVals = workingHeaders.host; delete workingHeaders.host; }
      }
      if (hostVals !== undefined && hostVals !== null) {
        if (Array.isArray(hostVals)) tr.host = hostVals;
        else tr.host = [String(hostVals)];
      }
      if (workingHeaders && Object.keys(workingHeaders).length > 0) {
        tr.headers = normalizeHeadersV2ray(workingHeaders, false);
      }
      return tr;
    }

    if (net === 'ws') {
      const ws = stream.wsSettings || {};
      const tr = { type: 'ws' };
      const parsed = parseWsPath(optString(ws, 'path', ''));
      if (parsed.path !== '') tr.path = parsed.path;
      const headers = normalizeHeadersV2ray(ws.headers, true);
      if (Object.keys(headers).length > 0) tr.headers = headers;
      let earlyData = parsed.earlyData;
      if (earlyData === null && has(ws, 'maxEarlyData') && ws.maxEarlyData !== null) {
        const v = ws.maxEarlyData;
        earlyData = typeof v === 'number' ? Math.trunc(v) : (typeof v === 'string' && /^[0-9]+$/.test(v) ? parseInt(v, 10) : null);
      }
      if (earlyData !== null && earlyData !== 0) {
        tr.max_early_data = earlyData;
        tr.early_data_header_name = optString(ws, 'earlyDataHeaderName', '') || 'Sec-WebSocket-Protocol';
      } else {
        const edh = optString(ws, 'earlyDataHeaderName', '');
        if (edh !== '') tr.early_data_header_name = edh;
      }
      return tr;
    }

    if (net === 'grpc') {
      const g = stream.grpcSettings || {};
      let sn = optString(g, 'serviceName', '');
      if (sn.startsWith('/')) sn = sn.replace(/^\/+/, '');
      const tr = { type: 'grpc', service_name: sn };
      const idle = toDuration(g.idle_timeout);
      if (idle !== null) tr.idle_timeout = idle;
      const hct = toDuration(g.health_check_timeout);
      if (hct !== null) tr.ping_timeout = hct;
      if (optBoolean(g, 'permit_without_stream', false)) tr.permit_without_stream = true;
      return tr;
    }

    if (net === 'http' || net === 'h2') {
      const h = stream.httpSettings || {};
      const tr = { type: 'http' };
      const path = optString(h, 'path', '');
      if (path !== '') tr.path = path;
      const host = h.host;
      if (host !== undefined && host !== null) {
        if (Array.isArray(host)) { if (host.length > 0) tr.host = host; }
        else if (typeof host === 'string') { if (host !== '') tr.host = [host]; }
        else { const hs = String(host); if (hs !== '') tr.host = [hs]; }
      }
      const method = optString(h, 'method', '');
      if (method !== '') tr.method = method;
      const headers = h.headers;
      if (headers && Object.keys(headers).length > 0) {
        tr.headers = normalizeHeadersV2ray(headers, false);
      }
      const idle = toDuration(h.read_idle_timeout);
      if (idle !== null) tr.idle_timeout = idle;
      const hct = toDuration(h.health_check_timeout);
      if (hct !== null) tr.ping_timeout = hct;
      return tr;
    }

    if (net === 'httpupgrade') {
      const hu = stream.httpupgradeSettings || {};
      const tr = { type: 'httpupgrade' };
      const path = optString(hu, 'path', '');
      if (path !== '') tr.path = path;
      let hostTop = optString(hu, 'host', '');
      const headers = normalizeHeadersV2ray(hu.headers, true);
      let hostFromHeaders = null;
      for (const k of Object.keys(headers)) {
        if (k.toLowerCase() === 'host') {
          hostFromHeaders = String(headers[k]);
          delete headers[k];
        }
      }
      if (hostTop === '' && hostFromHeaders) hostTop = hostFromHeaders;
      if (hostTop !== '') tr.host = hostTop;
      if (Object.keys(headers).length > 0) tr.headers = headers;
      return tr;
    }

    if (net === 'quic') {
      return { type: 'quic' };
    }

    return null;
  }

  function convPacketEncoding(o, proto) {
    const settings = o.settings || {};
    let v = settings.packetEncoding;
    if (v === undefined || v === null) {
      const vnext = settings.vnext;
      const user = vnext && Array.isArray(vnext) && vnext[0] && Array.isArray(vnext[0].users) ? vnext[0].users[0] : null;
      v = user ? user.packetEncoding : undefined;
    }
    if (v === undefined || v === null) return null;
    const s = String(v).toLowerCase();
    if (s === 'packet') return 'packetaddr';
    if (s === 'xudp') return proto === 'vless' ? null : 'xudp';
    if (s === 'none' || s === '') return proto === 'vless' ? '' : null;
    return null;
  }

  function applyProxySettings(sb, o) {
    let chainTag = o.proxySettings ? optString(o.proxySettings, 'tag', '') : '';
    if (chainTag === '') {
      const ss = o.streamSettings || {};
      chainTag = optString(ss, 'dialerProxy', '');
      if (chainTag === '') {
        chainTag = ss.sockopt ? optString(ss.sockopt, 'dialerProxy', '') : '';
      }
    }
    if (chainTag !== '') sb.detour = chainTag;
  }

  const FREEDOM_STRATEGY_MAP = {
    AsIs: '', UseIP: 'prefer_ipv4', UseIPv4: 'ipv4_only', UseIPv4v6: 'prefer_ipv4',
    UseIPv6: 'ipv6_only', UseIPv6v4: 'prefer_ipv6', ForceIP: 'prefer_ipv4',
    ForceIPv4: 'ipv4_only', ForceIPv4v6: 'prefer_ipv4', ForceIPv6: 'ipv6_only', ForceIPv6v4: 'prefer_ipv6',
  };

  function applySockopt(sb, stream) {
    if (!stream) return;
    const sock = stream.sockopt;
    if (!sock) return;
    const ds = optString(sock, 'domainStrategy', '').trim();
    const strat = FREEDOM_STRATEGY_MAP[ds] || '';
    if (strat !== '' && !has(sb, 'domain_strategy')) sb.domain_strategy = strat;
    const tfo = sock.tcpFastOpen;
    if (typeof tfo === 'boolean') sb.tcp_fast_open = tfo;
    const kai = sock.tcpKeepAliveInterval;
    if (typeof kai === 'number') {
      if (Math.trunc(kai) > 0) sb.tcp_keep_alive_interval = Math.trunc(kai) + 's';
    }
  }

  // One Xray outbound -> { sb, kind }
  function convOutbound(o) {
    const proto = optString(o, 'protocol', '');
    const tag = optString(o, 'tag', proto) || proto;

    if (proto === 'freedom') {
      const sb = { type: 'direct', tag };
      const settings = o.settings || {};
      const ds = optString(settings, 'domainStrategy', '').trim();
      const strat = FREEDOM_STRATEGY_MAP[ds] || '';
      if (strat !== '') sb.domain_strategy = strat;
      applyProxySettings(sb, o);
      return { sb, kind: 'aux' };
    }
    if (proto === 'blackhole' || proto === 'dns') return { sb: null, kind: 'aux' };
    if (proto === 'loopback') return { sb: null, kind: 'aux' };

    const stream = o.streamSettings || {};
    const settings = o.settings || {};

    if (proto === 'wireguard') {
      return { sb: convWireguard(o, settings, tag), kind: 'wireguard' };
    }

    if (proto === 'vless' || proto === 'vmess') {
      const vnext = (settings.vnext && settings.vnext[0]) || {};
      const user = (vnext.users && vnext.users[0]) || {};
      const sb = { type: proto, tag };
      sb.server = vnext.address !== undefined ? vnext.address : null;
      sb.server_port = vnext.port !== undefined ? vnext.port : null;
      sb.uuid = user.id !== undefined ? user.id : null;
      if (proto === 'vless') {
        const flow = normalizeFlow(optString(user, 'flow', ''));
        if (flow !== '') sb.flow = flow;
      } else {
        sb.security = optString(user, 'security', 'auto');
        const aid = user.alterId;
        sb.alter_id = aid === undefined || aid === null ? 0 : aid;
        let gp = has(user, 'global_padding') ? user.global_padding : user.globalPadding;
        if (gp === undefined || gp === null) sb.global_padding = true;
        else sb.global_padding = typeof gp === 'boolean' ? gp : String(gp).toLowerCase() === 'true';
        const al = has(user, 'authenticated_length') ? user.authenticated_length : user.authenticatedLength;
        if (typeof al === 'boolean' && !al) sb.authenticated_length = false;
      }
      const pe = convPacketEncoding(o, proto);
      if (pe !== null) sb.packet_encoding = pe;
      const tls = convTls(stream);
      if (tls !== null) sb.tls = tls;
      const tr = convTransport(stream);
      if (tr !== null) sb.transport = tr;
      applyProxySettings(sb, o);
      applySockopt(sb, stream);
      return { sb, kind: 'proxy' };
    }

    if (proto === 'trojan') {
      const srv = (settings.servers && settings.servers[0]) || {};
      const sb = { type: 'trojan', tag };
      sb.server = srv.address !== undefined ? srv.address : null;
      sb.server_port = srv.port !== undefined ? srv.port : null;
      sb.password = srv.password !== undefined ? srv.password : null;
      const tls = convTls(stream);
      if (tls !== null) sb.tls = tls;
      const tr = convTransport(stream);
      if (tr !== null) sb.transport = tr;
      applyProxySettings(sb, o);
      applySockopt(sb, stream);
      return { sb, kind: 'proxy' };
    }

    if (proto === 'shadowsocks') {
      const srv = (settings.servers && settings.servers[0]) || {};
      const rawMethod = optString(srv, 'method', 'aes-256-gcm') || 'aes-256-gcm';
      const method = SS_METHOD_ALIAS[rawMethod] || rawMethod;
      const sb = { type: 'shadowsocks', tag };
      sb.server = srv.address !== undefined ? srv.address : null;
      sb.server_port = srv.port !== undefined ? srv.port : null;
      sb.method = method;
      sb.password = srv.password !== undefined ? srv.password : null;
      const plugin = optString(srv, 'plugin', '');
      if (plugin !== '') sb.plugin = plugin;
      let po = has(srv, 'plugin_opts') ? srv.plugin_opts : srv.pluginOpts;
      if (po !== undefined && po !== null) {
        const ser = serializePluginOpts(po);
        if (ser !== '') sb.plugin_opts = ser;
      }
      if (optBoolean(srv, 'uot', false)) {
        const v = srv.UoTVersion;
        let ver = 1;
        if (typeof v === 'number') ver = Math.trunc(v);
        else if (typeof v === 'string' && /^[0-9]+$/.test(v)) ver = parseInt(v, 10);
        sb.udp_over_tcp = { enabled: true, version: ver };
      }
      applyProxySettings(sb, o);
      applySockopt(sb, stream);
      return { sb, kind: 'proxy' };
    }

    if (proto === 'socks') {
      const srv = (settings.servers && settings.servers[0]) || {};
      const sb = { type: 'socks', tag };
      sb.server = srv.address !== undefined ? srv.address : null;
      sb.server_port = srv.port !== undefined ? srv.port : null;
      const users = srv.users;
      if (Array.isArray(users) && users.length > 0) {
        const u0 = users[0] || {};
        sb.username = optString(u0, 'user', '');
        sb.password = optString(u0, 'pass', '');
      }
      const ver = srv.version;
      if (ver !== undefined && ver !== null) {
        const v = String(ver).replace('socks', '');
        if (v === '4' || v === '4a' || v === '5') sb.version = v;
      }
      if (optBoolean(srv, 'uot', false)) sb.udp_over_tcp = { enabled: true };
      applyProxySettings(sb, o);
      applySockopt(sb, stream);
      return { sb, kind: 'proxy' };
    }

    if (proto === 'http') {
      const srv = (settings.servers && settings.servers[0]) || {};
      const sb = { type: 'http', tag };
      sb.server = srv.address !== undefined ? srv.address : null;
      sb.server_port = srv.port !== undefined ? srv.port : null;
      const users = srv.users;
      if (Array.isArray(users) && users.length > 0) {
        const u0 = users[0] || {};
        sb.username = optString(u0, 'user', '');
        sb.password = optString(u0, 'pass', '');
      }
      const tls = convTls(stream);
      if (tls !== null) sb.tls = tls;
      applyProxySettings(sb, o);
      applySockopt(sb, stream);
      return { sb, kind: 'proxy' };
    }

    return { sb: null, kind: null };
  }

  // WireGuard -> sing-box endpoint
  function convWireguard(o, settings, tag) {
    const addressesAny = settings.address;
    const addresses = [];
    if (Array.isArray(addressesAny)) for (const a of addressesAny) if (a != null) addresses.push(a);
    else if (typeof addressesAny === 'string' && addressesAny !== '') addresses.push(addressesAny);

    const ep = { type: 'wireguard', tag };
    if (addresses.length > 0) ep.address = addresses;
    else ep.address = ['10.0.0.2/32'];
    ep.private_key = optString(settings, 'secretKey', '');
    const mtuVal = settings.mtu;
    if (isTruthy(mtuVal)) {
      const mtu = typeof mtuVal === 'number' ? Math.trunc(mtuVal) : (typeof mtuVal === 'string' && /^[0-9]+$/.test(mtuVal) ? parseInt(mtuVal, 10) : null);
      if (mtu !== null) ep.mtu = mtu;
    }
    const workersVal = settings.workers;
    if (isTruthy(workersVal)) {
      const w = typeof workersVal === 'number' ? Math.trunc(workersVal) : (typeof workersVal === 'string' && /^[0-9]+$/.test(workersVal) ? parseInt(workersVal, 10) : null);
      if (w !== null) ep.workers = w;
    }
    if (isTruthy(settings.reserved)) ep.reserved = settings.reserved;

    const peers = [];
    const peerArr = settings.peers;
    if (Array.isArray(peerArr)) {
      for (const p of peerArr) {
        if (!p || typeof p !== 'object') continue;
        const hp = splitHostPort(optString(p, 'endpoint', ''));
        const peer = { address: hp.host, port: hp.port !== null ? hp.port : 0, public_key: optString(p, 'publicKey', '') };
        const allowed = p.allowedIPs;
        if (Array.isArray(allowed) && allowed.length > 0) peer.allowed_ips = allowed;
        else peer.allowed_ips = ['0.0.0.0/0', '::/0'];
        const psk = optString(p, 'preSharedKey', '');
        if (psk !== '') peer.pre_shared_key = psk;
        const ka = p.keepAlive;
        if (isTruthy(ka)) {
          const v = typeof ka === 'number' ? Math.trunc(ka) : (typeof ka === 'string' && /^[0-9]+$/.test(ka) ? parseInt(ka, 10) : null);
          if (v !== null) peer.persistent_keepalive_interval = v;
        }
        if (isTruthy(p.reserved)) peer.reserved = p.reserved;
        peers.push(peer);
      }
    }
    if (peers.length > 0) ep.peers = peers;
    applyProxySettings(ep, o);
    applySockopt(ep, o.streamSettings);
    return ep;
  }

  // ---- routing rules / dns (used by the full-config converter) ----

  function splitDomains(domains) {
    const full = [], suffix = [], keyword = [], regex = [], geosite = [];
    for (const raw of domains) {
      if (typeof raw !== 'string') continue;
      const d = raw;
      if (d.startsWith('!')) continue;
      if (d.startsWith('geosite:')) geosite.push(d.substring('geosite:'.length));
      else if (d.startsWith('domain:')) suffix.push(d.substring('domain:'.length));
      else if (d.startsWith('full:')) full.push(d.substring('full:'.length));
      else if (d.startsWith('regexp:')) regex.push(d.substring('regexp:'.length));
      else if (d.startsWith('keyword:')) keyword.push(d.substring('keyword:'.length));
      else if (d.startsWith('ext:') || d.startsWith('ext-domain:')) { /* skip */ }
      else suffix.push(d);
    }
    return { domain: full, domainSuffix: suffix, domainKeyword: keyword, domainRegex: regex, geosite };
  }

  function splitIps(ips) {
    const cidr = [], geoip = [];
    let isPrivate = false;
    for (const raw of ips) {
      if (typeof raw !== 'string') continue;
      const i = raw;
      if (i.startsWith('!')) continue;
      if (i === 'geoip:private') isPrivate = true;
      else if (i.startsWith('geoip:')) geoip.push(i.substring('geoip:'.length));
      else if (i.startsWith('ext:') || i.startsWith('ext-ip:')) { /* skip */ }
      else cidr.push(i);
    }
    return { ipCidr: cidr, geoip, ipIsPrivate: isPrivate };
  }

  function addRuleSetTags(rule, tags) {
    if (tags.length === 0) return;
    const existing = Array.isArray(rule.rule_set) ? rule.rule_set.slice() : [];
    for (const t of tags) if (!existing.includes(t)) existing.push(t);
    rule.rule_set = existing;
  }

  function applyDomainSplit(rule, split, ruleSets) {
    if (split.domain.length > 0) rule.domain = split.domain;
    if (split.domainSuffix.length > 0) rule.domain_suffix = split.domainSuffix;
    if (split.domainKeyword.length > 0) rule.domain_keyword = split.domainKeyword;
    if (split.domainRegex.length > 0) rule.domain_regex = split.domainRegex;
    if (split.geosite.length > 0) {
      const tags = split.geosite.map((g) => 'geosite-' + g.toLowerCase());
      for (const t of tags) ruleSets.add(t);
      addRuleSetTags(rule, tags);
    }
  }

  function applyGeoipToRuleSet(rule, geoip, ruleSets) {
    if (geoip.length === 0) return;
    const tags = geoip.map((g) => 'geoip-' + g.toLowerCase());
    for (const t of tags) ruleSets.add(t);
    addRuleSetTags(rule, tags);
  }

  // Xray inbound -> { sb, sniffEnabled, sniffResolves }
  function convInbound(inb) {
    const proto = optString(inb, 'protocol', '');
    const sniff = inb.sniffing || {};
    const sniffEnabled = optBoolean(sniff, 'enabled', false);
    const destOverride = sniff.destOverride;
    const hasDestOverride = Array.isArray(destOverride) && destOverride.length > 0;
    const routeOnly = optBoolean(sniff, 'routeOnly', false);
    const sniffResolves = sniffEnabled && hasDestOverride && !routeOnly;

    const listenPort = parseListenPort(inb.port);

    if (proto === 'dokodemo-door') {
      const ds = inb.settings || {};
      const sb = { type: 'direct' };
      sb.tag = optString(inb, 'tag', 'direct-in') || 'direct-in';
      sb.listen = optString(inb, 'listen', '0.0.0.0') || '0.0.0.0';
      sb.listen_port = listenPort !== null ? listenPort : null;
      const net = optString(ds, 'network', 'tcp');
      if (net === 'tcp' || net === 'udp') sb.network = net;
      const addr = ds.address;
      if (isTruthy(addr)) sb.override_address = addr;
      const port = ds.port;
      if (isTruthy(port)) sb.override_port = port;
      return { sb, sniffEnabled, sniffResolves };
    }

    if (['vmess', 'vless', 'trojan', 'shadowsocks'].includes(proto)) return { sb: null, sniffEnabled: false, sniffResolves: false };
    if (!['socks', 'http', 'mixed'].includes(proto)) return { sb: null, sniffEnabled: false, sniffResolves: false };
    if (listenPort === null) return { sb: null, sniffEnabled: false, sniffResolves: false };

    const sb = { type: proto };
    sb.tag = optString(inb, 'tag', proto) || proto;
    sb.listen = optString(inb, 'listen', '127.0.0.1') || '127.0.0.1';
    sb.listen_port = listenPort;
    const settings = inb.settings;
    const accounts = settings ? settings.accounts : null;
    if (Array.isArray(accounts) && accounts.length > 0) {
      const users = [];
      for (const a of accounts) {
        if (!a || typeof a !== 'object') continue;
        users.push({ username: optString(a, 'user', ''), password: optString(a, 'pass', '') });
      }
      sb.users = users;
    }
    return { sb, sniffEnabled, sniffResolves };
  }

  function convRouteRules(routing, balancerMap, specialRemap, specialTagDrop, ruleSets) {
    const out = [];
    const rules = routing.rules;
    if (!Array.isArray(rules)) return out;
    for (const r of rules) {
      if (!r || typeof r !== 'object' || Array.isArray(r)) continue;
      const typeField = optString(r, 'type', '');
      if (typeField !== '' && typeField !== 'field') continue;
      const sb = {};
      if (has(r, 'balancerTag')) {
        const bt = optString(r, 'balancerTag', '');
        if (specialTagDrop.has(bt)) continue;
        sb.outbound = balancerMap[bt] !== undefined ? balancerMap[bt] : bt;
      } else if (has(r, 'outboundTag')) {
        const tgt = optString(r, 'outboundTag', '');
        if (specialTagDrop.has(tgt)) continue;
        const rem = specialRemap[tgt];
        if (rem !== undefined) {
          sb.action = rem[0];
          if (rem[1]) Object.assign(sb, rem[1]);
        } else {
          sb.outbound = tgt;
        }
      } else continue;

      const inTags = asStringList(r.inboundTag);
      if (inTags.length > 0) sb.inbound = inTags;
      if (has(r, 'protocol')) sb.protocol = asStringList(r.protocol);
      if (has(r, 'network')) {
        const netRaw = r.network;
        const nets = [];
        const src = typeof netRaw === 'string' ? netRaw.split(',') : asStringList(netRaw);
        for (const n of src) {
          const t = n.trim();
          if (t === 'tcp' || t === 'udp') nets.push(t);
        }
        if (nets.length > 0) sb.network = nets;
      }
      if (has(r, 'port')) {
        const pl = parsePortList(r.port);
        if (pl.ports.length > 0) sb.port = pl.ports;
        if (pl.ranges.length > 0) sb.port_range = pl.ranges;
      }
      if (has(r, 'sourcePort')) {
        const sp = parsePortList(r.sourcePort);
        if (sp.ports.length > 0) sb.source_port = sp.ports;
        if (sp.ranges.length > 0) sb.source_port_range = sp.ranges;
      }
      if (has(r, 'source')) {
        const ipSplit = splitIps(asList(r.source));
        if (ipSplit.ipCidr.length > 0) sb.source_ip_cidr = ipSplit.ipCidr;
        if (ipSplit.ipIsPrivate) sb.source_ip_is_private = true;
      }
      if (has(r, 'domain')) applyDomainSplit(sb, splitDomains(asList(r.domain)), ruleSets);
      if (has(r, 'ip')) {
        const ipSplit = splitIps(asList(r.ip));
        if (ipSplit.ipCidr.length > 0) sb.ip_cidr = ipSplit.ipCidr;
        if (ipSplit.ipIsPrivate) sb.ip_is_private = true;
        applyGeoipToRuleSet(sb, ipSplit.geoip, ruleSets);
      }
      if (has(r, 'user')) sb.auth_user = asStringList(r.user);
      if (has(r, 'process')) sb.process_name = asStringList(r.process);
      out.push(sb);
    }
    return out;
  }

  function parseDnsAddress(addrRaw) {
    if (addrRaw == null || addrRaw === '') return { type: null, fields: {} };
    const s = addrRaw.trim();
    if (s === 'fakedns') return { type: 'fakeip', fields: {} };
    if (s === 'localhost') return { type: 'local', fields: {} };
    if (s.startsWith('rcode://')) return { type: null, fields: {} };

    if (s.includes('://')) {
      const schemeRaw = s.substring(0, s.indexOf('://'));
      const rest = s.substring(s.indexOf('://') + 3);
      const scheme = schemeRaw.toLowerCase().replace('+local', '').replace('+udp', '');
      const parseHostPath = () => {
        const slashIdx = rest.indexOf('/');
        const hostPort = slashIdx < 0 ? rest : rest.substring(0, slashIdx);
        const path = slashIdx < 0 ? '' : rest.substring(slashIdx + 1);
        return { hp: splitHostPort(hostPort), path };
      };
      if (scheme === 'https') {
        const { hp, path } = parseHostPath();
        const f = { server: hp.host };
        if (hp.port !== null) f.server_port = hp.port;
        if (path !== '') f.path = '/' + path;
        return { type: 'https', fields: f };
      }
      if (['h3', 'https+h3', 'https3', 'http3'].includes(scheme)) {
        const { hp, path } = parseHostPath();
        const f = { server: hp.host };
        if (hp.port !== null) f.server_port = hp.port;
        if (path !== '') f.path = '/' + path;
        return { type: 'http3', fields: f };
      }
      if (['tls', 'quic', 'tcp', 'udp'].includes(scheme)) {
        const hp = splitHostPort(rest);
        const f = { server: hp.host };
        if (hp.port !== null) f.server_port = hp.port;
        return { type: scheme, fields: f };
      }
      if (scheme === 'dhcp') {
        const f = {};
        if (rest !== '' && rest !== 'auto') f.interface = rest;
        return { type: 'dhcp', fields: f };
      }
      return { type: null, fields: {} };
    }

    const hp = splitHostPort(s);
    const f = { server: hp.host };
    if (hp.port !== null) f.server_port = hp.port;
    return { type: 'udp', fields: f };
  }

  function makeDnsRule(obj, serverTag, ruleSets) {
    const domains = asList(obj.domains);
    if (domains.length === 0) return null;
    const rule = { server: serverTag };
    applyDomainSplit(rule, splitDomains(domains), ruleSets);
    return rule;
  }

  function fakeipRanges(fakednsObj) {
    if (fakednsObj === undefined || fakednsObj === null) return ['198.18.0.0/15', 'fc00::/18'];
    const pools = Array.isArray(fakednsObj) ? fakednsObj.filter((p) => p && typeof p === 'object' && !Array.isArray(p)) : (typeof fakednsObj === 'object' ? [fakednsObj] : []);
    let v4 = '198.18.0.0/15', v6 = 'fc00::/18';
    for (const p of pools) {
      const pool = optString(p, 'ipPool', '');
      if (pool.includes('.') && !pool.includes(':')) v4 = pool;
      else if (pool.includes(':')) v6 = pool;
    }
    return [v4, v6];
  }

  function convDns(xrayDns, fakednsObj, dnsDetour, ruleSets) {
    const out = { servers: [], rules: [] };
    const cs = xrayDns ? optString(xrayDns, 'clientIp', '') : '';
    if (cs !== '') out.client_subnet = cs;

    const seenTags = new Set();
    let hasLocal = false, hasFakeip = false, fakeipTag = null, n = 0;

    const serversArr = xrayDns && Array.isArray(xrayDns.servers) ? xrayDns.servers : [];
    for (const raw of serversArr) {
      let addrRaw, obj;
      if (typeof raw === 'string') { addrRaw = raw; obj = {}; }
      else if (raw && typeof raw === 'object' && !Array.isArray(raw)) { addrRaw = optString(raw, 'address', ''); obj = raw; }
      else continue;

      const parsed = parseDnsAddress(addrRaw);
      const st = parsed.type;
      if (st === null) continue;

      const srv = Object.assign({ type: st });
      let tag = optString(obj, 'tag', '');
      if (st === 'local') tag = 'local';
      if (tag === '') { tag = 'dns-' + n; n++; }
      while (seenTags.has(tag)) { tag = tag + '-' + n; n++; }
      seenTags.add(tag);
      srv.tag = tag;
      Object.assign(srv, parsed.fields);
      if (!has(srv, 'server_port')) {
        const v = obj.port;
        if (isTruthy(v)) {
          const p = typeof v === 'number' ? Math.trunc(v) : (typeof v === 'string' && /^[0-9]+$/.test(v) ? parseInt(v, 10) : null);
          if (p !== null) srv.server_port = p;
        }
      }
      const sqs = optString(obj, 'queryStrategy', '');
      if (sqs !== '' && QUERY_STRATEGY_MAP[sqs] !== undefined) srv.strategy = QUERY_STRATEGY_MAP[sqs];
      const sci = optString(obj, 'clientIP', '');
      if (sci !== '') srv.client_subnet = sci;

      if (ENCRYPTED_DNS_TYPES.has(st)) {
        if (dnsDetour !== null) srv.detour = dnsDetour;
        srv.domain_resolver = 'local';
      } else if (st === 'udp') {
        if (dnsDetour !== null) srv.detour = dnsDetour;
      } else if (st === 'local') {
        hasLocal = true;
      } else if (st === 'fakeip') {
        const ranges = fakeipRanges(fakednsObj);
        srv.inet4_range = ranges[0];
        srv.inet6_range = ranges[1];
        hasFakeip = true;
        fakeipTag = tag;
      }
      out.servers.push(srv);

      const rule = makeDnsRule(obj, tag, ruleSets);
      if (rule !== null) {
        if (st === 'fakeip' && !has(rule, 'query_type')) rule.query_type = ['A', 'AAAA'];
        out.rules.push(rule);
      }
    }

    // static hosts -> hosts server in front
    const hosts = xrayDns ? xrayDns.hosts : null;
    if (hosts && Object.keys(hosts).length > 0) {
      const predefined = {};
      for (const host of Object.keys(hosts)) {
        const v = hosts[host];
        const ipsList = typeof v === 'string' ? [v] : (Array.isArray(v) ? v : []);
        const ipsOnly = ipsList.filter((x) => isIpLiteral(x));
        if (ipsOnly.length > 0) predefined[host] = ipsOnly;
      }
      if (Object.keys(predefined).length > 0) {
        out.servers.unshift({ type: 'hosts', tag: 'hosts', predefined });
        out.rules.unshift({ domain: Object.keys(predefined), server: 'hosts' });
      }
    }

    if (!hasLocal) out.servers.push({ type: 'local', tag: 'local' });

    if (hasFakeip && fakeipTag !== null) {
      const hasFakeipRule = out.rules.some((r) => r.server === fakeipTag);
      if (!hasFakeipRule) out.rules.push({ query_type: ['A', 'AAAA'], server: fakeipTag });
    }

    let finalTag = null;
    for (const s of out.servers) {
      if (!REMOTE_DNS_TYPES.has(s.type || '')) continue;
      if (dnsDetour === null || s.detour === dnsDetour) { finalTag = s.tag || ''; break; }
    }
    if (finalTag === null) {
      for (const s of out.servers) {
        if (REMOTE_DNS_TYPES.has(s.type || '')) { finalTag = s.tag || ''; break; }
      }
    }
    if (finalTag === null && out.servers.length > 0) finalTag = out.servers[0].tag || '';
    if (finalTag !== null && finalTag !== '') out.final = finalTag;
    return out;
  }

  function makeUniqueTag(base, used) {
    if (!used.has(base)) return base;
    let i = 2;
    while (used.has(base + ' (' + i + ')')) i++;
    return base + ' (' + i + ')';
  }

  function dedupeByTag(items, used) {
    const out = [];
    for (const it of items) {
      const t = it.tag || '';
      if (t === '' || used.has(t)) continue;
      used.add(t);
      out.push(it);
    }
    return out;
  }

  function stripForkOnlyFields(cfg) {
    const exp = cfg.experimental;
    if (!exp) return;
    if (exp.cache_file && has(exp.cache_file, 'store_dns')) delete exp.cache_file.store_dns;
  }

  function isPreRule(r) {
    const action = r.action || '';
    if (action === 'sniff' && Object.keys(r).length === 1) return true;
    if (action === 'hijack-dns' && (has(r, 'protocol') || has(r, 'port'))) return true;
    if (action === 'resolve' && has(r, 'inbound')) return true;
    return false;
  }

  function renameStr(o, key, rename) {
    const v = o[key];
    if (typeof v !== 'string' || v === '') return;
    const mapped = rename[v];
    if (mapped !== undefined && mapped !== v) o[key] = mapped;
  }
  function renameArr(o, key, rename) {
    const arr = o[key];
    if (!Array.isArray(arr)) return;
    let changed = false;
    const newArr = arr.map((item) => {
      if (typeof item === 'string' && rename[item] !== undefined && rename[item] !== item) { changed = true; return rename[item]; }
      return item;
    });
    if (changed) o[key] = newArr;
  }
  function rewriteOutbound(o, outRename, dnsRename) {
    renameStr(o, 'tag', outRename);
    renameStr(o, 'detour', outRename);
    renameArr(o, 'outbounds', outRename);
    renameStr(o, 'default', outRename);
    const drRaw = o.domain_resolver;
    if (typeof drRaw === 'string' && drRaw !== '') {
      const mapped = dnsRename[drRaw];
      if (mapped !== undefined && mapped !== drRaw) o.domain_resolver = mapped;
    } else if (drRaw && typeof drRaw === 'object') {
      renameStr(drRaw, 'server', dnsRename);
    }
  }
  function rewriteDnsServer(s, outRename, dnsRename) {
    renameStr(s, 'tag', dnsRename);
    renameStr(s, 'detour', outRename);
    const drRaw = s.domain_resolver;
    if (typeof drRaw === 'string' && drRaw !== '') {
      const mapped = dnsRename[drRaw];
      if (mapped !== undefined && mapped !== drRaw) s.domain_resolver = mapped;
    } else if (drRaw && typeof drRaw === 'object') {
      renameStr(drRaw, 'server', dnsRename);
    }
  }
  function rewriteDnsRule(r, outRename, dnsRename) {
    renameStr(r, 'server', dnsRename);
    renameStr(r, 'outbound', outRename);
  }
  function rewriteRouteRule(r, outRename, dnsRename) {
    renameStr(r, 'outbound', outRename);
    renameStr(r, 'server', dnsRename);
  }

  // Extract only supported proxy outbounds; take names from remarks
  function extractProxyOutbounds(xray, nameFallback) {
    const remarks = (optString(xray, 'remarks', '') || optString(xray, 'name', '') || nameFallback || '').trim();
    const outsRaw = xray.outbounds;
    if (!Array.isArray(outsRaw)) return null;

    const supported = [];
    for (const o of outsRaw) {
      if (!o || typeof o !== 'object' || Array.isArray(o)) continue;
      const proto = optString(o, 'protocol', '');
      if (!XRAY_PROTOCOLS_PROXY.has(proto)) continue;
      if (!isOutboundSupported(o)) continue;
      supported.push(o);
    }
    if (supported.length === 0) return null;

    const results = [];
    const singleProxy = supported.length === 1;
    for (const o of supported) {
      const r = convOutbound(o);
      if (!r.sb) continue;
      if (r.kind === 'aux') continue;
      const sb = r.sb;
      delete sb.detour;
      const originalTag = (optString(o, 'tag', '') || '').trim();
      let newTag;
      if (remarks === '') newTag = originalTag !== '' ? originalTag : 'proxy';
      else if (singleProxy) newTag = remarks;
      else newTag = originalTag === '' ? remarks : remarks + ' #' + originalTag;
      sb.tag = newTag;
      results.push(sb);
    }
    return results.length > 0 ? results : null;
  }

  function looksLikeXray(d) {
    const outs = d.outbounds;
    if (!Array.isArray(outs) || outs.length === 0) return false;
    for (const o of outs) {
      if (o && typeof o === 'object' && !Array.isArray(o) && has(o, 'protocol')) return true;
    }
    return false;
  }

  // ---- main entry points ----

  // Full Xray config -> full sing-box config. Returns {status:'ok',config}|{status:'notxray'}|{status:'unsupported'}
  function convert(input, nameFallback) {
    const trimmed = (input || '').trim();
    if (trimmed === '' || !trimmed.startsWith('{')) return { status: 'notxray' };
    let xray;
    try { xray = JSON.parse(trimmed); } catch (e) { return { status: 'notxray' }; }
    if (!xray || typeof xray !== 'object' || Array.isArray(xray)) return { status: 'notxray' };
    if (isSingbox(xray)) return { status: 'notxray' };
    if (!looksLikeXray(xray)) return { status: 'notxray' };
    try {
      const sb = convertObject(xray, nameFallback || '');
      if (!sb) return { status: 'unsupported' };
      return { status: 'ok', config: sb };
    } catch (e) {
      return { status: 'unsupported' };
    }
  }

  // Xray -> list of sing-box outbounds
  function convertToOutbounds(input, nameFallback) {
    const trimmed = (input || '').trim();
    if (trimmed === '' || !trimmed.startsWith('{')) return { status: 'notxray' };
    let xray;
    try { xray = JSON.parse(trimmed); } catch (e) { return { status: 'notxray' }; }
    if (!xray || typeof xray !== 'object' || Array.isArray(xray)) return { status: 'notxray' };
    if (isSingbox(xray)) return { status: 'notxray' };
    if (!looksLikeXray(xray)) return { status: 'notxray' };
    try {
      const list = extractProxyOutbounds(xray, nameFallback || '');
      if (!list) return { status: 'unsupported' };
      if (list.length === 0) return { status: 'unsupported' };
      return { status: 'ok', outbounds: list };
    } catch (e) {
      return { status: 'unsupported' };
    }
  }

  // Main assembly for full configs
  function convertObject(xray, nameFallback) {
    const inbounds = [];
    const usedInbTags = new Set();
    const resolveInbounds = [];

    const xrayInbounds = Array.isArray(xray.inbounds) ? xray.inbounds : null;
    if (xrayInbounds) {
      for (const inb of xrayInbounds) {
        if (!inb || typeof inb !== 'object' || Array.isArray(inb)) continue;
        const result = convInbound(inb);
        if (!result.sb) continue;
        const sbInb = result.sb;
        const base = sbInb.tag || sbInb.type || 'in';
        const tag = makeUniqueTag(base, usedInbTags);
        sbInb.tag = tag;
        usedInbTags.add(tag);
        inbounds.push(sbInb);
        if (result.sniffResolves) resolveInbounds.push(tag);
      }
    }

    const remarks = (optString(xray, 'remarks', '') || optString(xray, 'name', '') || nameFallback || '').trim();

    const xrayProxies = [];
    const outsRaw = Array.isArray(xray.outbounds) ? xray.outbounds : null;
    if (outsRaw) {
      for (const o of outsRaw) {
        if (!o || typeof o !== 'object' || Array.isArray(o)) continue;
        if (XRAY_PROTOCOLS_PROXY.has(optString(o, 'protocol', '')) && isOutboundSupported(o)) xrayProxies.push(o);
      }
    }

    const rename = {};
    if (remarks !== '') {
      if (xrayProxies.length === 1) {
        rename[(optString(xrayProxies[0], 'tag', '') || '').trim()] = remarks;
      } else if (xrayProxies.length > 1) {
        for (const p of xrayProxies) {
          const origTag = (optString(p, 'tag', '') || '').trim();
          rename[origTag] = origTag === '' ? remarks : remarks + ' #' + origTag;
        }
      }
    }

    const proxyOuts = [], proxyTags = [], auxOuts = [], endpoints = [];
    const specialRemap = {}, specialTagDrop = new Set();

    if (outsRaw) {
      for (const o of outsRaw) {
        if (!o || typeof o !== 'object' || Array.isArray(o)) continue;
        const otag = optString(o, 'tag', '');
        const proto = optString(o, 'protocol', '');
        if (proto === 'blackhole') { specialRemap[otag] = ['reject', null]; continue; }
        if (proto === 'dns') { specialRemap[otag] = ['hijack-dns', null]; continue; }
        if (proto === 'loopback') { specialTagDrop.add(otag); continue; }
        if (XRAY_PROTOCOLS_PROXY.has(proto) && !isOutboundSupported(o)) { specialTagDrop.add(otag); continue; }
        const r = convOutbound(o);
        if (!r.sb) continue;
        if (r.kind === 'wireguard') {
          const cTag = r.sb.tag || '';
          const newTag = rename[cTag] !== undefined ? rename[cTag] : cTag;
          r.sb.tag = newTag;
          endpoints.push(r.sb);
          proxyTags.push(newTag);
        } else if (r.kind === 'aux') {
          auxOuts.push(r.sb);
        } else {
          const cTag = r.sb.tag || '';
          const newTag = rename[cTag] !== undefined ? rename[cTag] : cTag;
          r.sb.tag = newTag;
          proxyOuts.push(r.sb);
          proxyTags.push(newTag);
        }
      }
    }

    if (proxyOuts.length === 0 && endpoints.length === 0) return null;

    const hasDirect = auxOuts.some((o) => o.type === 'direct' && o.tag === 'direct');
    if (!hasDirect) auxOuts.push({ type: 'direct', tag: 'direct' });

    for (const o of proxyOuts.concat(endpoints, auxOuts)) {
      const d = o.detour || '';
      if (d !== '') {
        if (specialTagDrop.has(d) || specialRemap[d] !== undefined) delete o.detour;
        else if (rename[d] !== undefined) o.detour = rename[d];
      }
    }

    const routing = xray.routing || {};
    const obs = xray.burstObservatory || xray.observatory || {};
    const pingCfg = obs.pingConfig || {};
    const testUrl = optString(pingCfg, 'destination', '');
    const testInterval = optString(pingCfg, 'interval', '');

    // balancers -> urltest outbounds
    const balancerOuts = [];
    const balancerMap = {};
    let primaryBalancer = null;
    const balancers = Array.isArray(routing.balancers) ? routing.balancers : null;
    if (balancers) {
      for (const b of balancers) {
        if (!b || typeof b !== 'object') continue;
        const btag = optString(b, 'tag', '');
        if (btag === '') continue;
        const prefixesArr = Array.isArray(b.selector) ? b.selector : [];
        const prefixes = prefixesArr.filter((x) => typeof x === 'string');
        const origMatch = (prefixes.length > 0
          ? xrayProxies.map((p) => p.tag || '').filter((t) => t !== '' && prefixes.some((pf) => t.startsWith(pf)))
          : xrayProxies.map((p) => p.tag || '').filter((t) => t !== ''));
        let members = origMatch.map((t) => rename[t] !== undefined ? rename[t] : t);
        if (members.length === 0) members = proxyTags.slice();
        if (members.length === 0) { specialTagDrop.add(btag); continue; }

        const bb = { type: 'urltest', tag: btag, outbounds: members };
        if (testUrl !== '') bb.url = testUrl;
        if (testInterval !== '') bb.interval = testInterval;
        balancerOuts.push(bb);
        balancerMap[btag] = btag;
        if (primaryBalancer === null) primaryBalancer = btag;
      }
    }

    let selectorTag = remarks !== '' ? remarks : 'select';
    const existingTags = new Set(proxyTags);
    for (const b of balancerOuts) existingTags.add(b.tag || '');
    for (const a of auxOuts) existingTags.add(a.tag || '');
    while (existingTags.has(selectorTag)) selectorTag += ' ⊙';

    let selector = null;
    const needSelector = proxyTags.length > 1 || balancerOuts.length > 0;
    if (proxyTags.length > 0 && needSelector) {
      selector = { type: 'selector', tag: selectorTag };
      const outs = [];
      for (const b of balancerOuts) outs.push(b.tag || '');
      for (const t of proxyTags) outs.push(t);
      selector.outbounds = outs;
      selector.default = balancerOuts.length > 0 ? balancerOuts[0].tag || '' : proxyTags[0];
    }

    let sbOutbounds = [];
    if (selector !== null) sbOutbounds.push(selector);
    sbOutbounds = sbOutbounds.concat(balancerOuts, proxyOuts, auxOuts);
    const usedOutTags = new Set();
    sbOutbounds = dedupeByTag(sbOutbounds, usedOutTags);
    const endpointsDedup = dedupeByTag(endpoints, usedOutTags);

    const finalTag = selector !== null ? selectorTag
      : primaryBalancer !== null ? primaryBalancer
      : (proxyTags.find((t) => t !== '') || 'direct');

    const dnsDetour = proxyTags.find((t) => t !== '') || null;
    const ruleSetDownloadDetour = 'direct';
    const requiredRuleSets = new Set();

    const routeRules = convRouteRules(routing, balancerMap, specialRemap, specialTagDrop, requiredRuleSets);
    for (const r of routeRules) {
      const ob = r.outbound || '';
      if (ob !== '' && rename[ob] !== undefined) r.outbound = rename[ob];
    }

    const preRules = [{ action: 'sniff' }, { protocol: 'dns', action: 'hijack-dns' }, { port: [53], action: 'hijack-dns' }];
    if (resolveInbounds.length > 0) preRules.push({ inbound: resolveInbounds, action: 'resolve' });

    const route = {};
    route.rules = preRules.concat(routeRules);
    route.auto_detect_interface = true;
    route.final = finalTag;
    const ddr = { server: 'local' };
    const ds = optString(routing, 'domainStrategy', '').trim();
    const dsMapped = DOMAIN_STRATEGY_MAP[ds] || '';
    if (dsMapped !== '') ddr.strategy = dsMapped;
    else {
      const xrayDnsObj = xray.dns;
      const qs = xrayDnsObj ? optString(xrayDnsObj, 'queryStrategy', '') : '';
      if (qs !== '' && QUERY_STRATEGY_MAP[qs] !== undefined) ddr.strategy = QUERY_STRATEGY_MAP[qs];
    }
    route.default_domain_resolver = ddr;

    let fakednsObj = xray.fakedns;
    if (fakednsObj === undefined || fakednsObj === null) fakednsObj = xray.dns ? xray.dns.fakedns : undefined;
    const sbDns = convDns(xray.dns, fakednsObj, dnsDetour, requiredRuleSets);

    if (requiredRuleSets.size > 0) {
      const rsArr = [];
      for (const tag of Array.from(requiredRuleSets).sort()) {
        let url;
        if (tag.startsWith('geosite-')) url = GEOSITE_URL_TEMPLATE.replace('{name}', tag);
        else if (tag.startsWith('geoip-')) url = GEOIP_URL_TEMPLATE.replace('{name}', tag);
        else continue;
        rsArr.push({ type: 'remote', tag, format: 'binary', url, download_detour: ruleSetDownloadDetour, update_interval: '1d' });
      }
      if (rsArr.length > 0) route.rule_set = rsArr;
    }

    const xlog = xray.log ? optString(xray.log, 'loglevel', 'warning') : 'warning';
    const sbLogLevel = LOG_LEVEL_MAP[xlog] || 'warn';

    const config = {
      log: { level: sbLogLevel, timestamp: true },
      dns: sbDns,
      inbounds,
      outbounds: sbOutbounds,
      route,
      experimental: { cache_file: { enabled: true } },
    };
    if (endpointsDedup.length > 0) config.endpoints = endpointsDedup;
    return config;
  }

  // Merge several sing-box configs into one (rename tags, shared selector/urltest)
  function mergeUnified(fullConfigs) {
    if (fullConfigs.length === 0) return null;
    if (fullConfigs.length === 1) {
      const single = deepCopy(fullConfigs[0]);
      stripForkOnlyFields(single);
      return single;
    }

    const usedOutTags = new Set(['proxy', 'auto', 'direct', 'mixed-in']);
    const usedDnsTags = new Set(['local']);
    const usedRuleSetTags = new Set();

    const outRenames = [], dnsRenames = [];
    for (const cfg of fullConfigs) {
      const outRename = {}, dnsRename = {};
      const outbounds = Array.isArray(cfg.outbounds) ? cfg.outbounds : null;
      if (outbounds) {
        for (const o of outbounds) {
          if (!o || typeof o !== 'object') continue;
          const origTag = o.tag || '';
          const type = o.type || '';
          if (origTag === '') continue;
          if (type === 'selector' || type === 'urltest') { outRename[origTag] = 'proxy'; continue; }
          if (type === 'direct') { outRename[origTag] = 'direct'; continue; }
          const newTag = makeUniqueTag(origTag, usedOutTags);
          usedOutTags.add(newTag);
          outRename[origTag] = newTag;
        }
      }
      const endpointsA = Array.isArray(cfg.endpoints) ? cfg.endpoints : null;
      if (endpointsA) {
        for (const o of endpointsA) {
          if (!o || typeof o !== 'object') continue;
          const origTag = o.tag || '';
          if (origTag === '') continue;
          const newTag = makeUniqueTag(origTag, usedOutTags);
          usedOutTags.add(newTag);
          outRename[origTag] = newTag;
        }
      }
      const dns = cfg.dns;
      if (dns && Array.isArray(dns.servers)) {
        for (const s of dns.servers) {
          if (!s || typeof s !== 'object') continue;
          const origTag = s.tag || '';
          if (origTag === '') continue;
          if (origTag === 'local' && s.type === 'local') { dnsRename[origTag] = 'local'; continue; }
          const newTag = makeUniqueTag(origTag, usedDnsTags);
          usedDnsTags.add(newTag);
          dnsRename[origTag] = newTag;
        }
      }
      outRenames.push(outRename);
      dnsRenames.push(dnsRename);
    }

    const leafOutbounds = [], leafOutboundTags = [], mergedEndpoints = [], mergedEndpointTags = [];
    const mergedDnsServers = [], mergedDnsRules = [], mergedRouteRules = [], mergedRuleSet = [];
    let hasDirect = false, hasLocal = false;

    fullConfigs.forEach((cfg, idx) => {
      const outR = outRenames[idx], dnsR = dnsRenames[idx];

      const obs = Array.isArray(cfg.outbounds) ? cfg.outbounds : null;
      if (obs) {
        for (const o of obs) {
          if (!o || typeof o !== 'object') continue;
          const type = o.type || '';
          if (type === 'selector' || type === 'urltest') continue;
          const obCopy = deepCopy(o);
          rewriteOutbound(obCopy, outR, dnsR);
          if (obCopy.type === 'direct' && obCopy.tag === 'direct') {
            if (hasDirect) continue;
            hasDirect = true;
            leafOutbounds.push(obCopy);
            continue;
          }
          leafOutboundTags.push(obCopy.tag || '');
          leafOutbounds.push(obCopy);
        }
      }
      const eps = Array.isArray(cfg.endpoints) ? cfg.endpoints : null;
      if (eps) {
        for (const o of eps) {
          if (!o || typeof o !== 'object') continue;
          const obCopy = deepCopy(o);
          rewriteOutbound(obCopy, outR, dnsR);
          mergedEndpoints.push(obCopy);
          mergedEndpointTags.push(obCopy.tag || '');
        }
      }

      const dns = cfg.dns;
      if (dns && Array.isArray(dns.servers)) {
        for (const s of dns.servers) {
          if (!s || typeof s !== 'object') continue;
          const sCopy = deepCopy(s);
          rewriteDnsServer(sCopy, outR, dnsR);
          if (sCopy.type === 'local' && sCopy.tag === 'local') {
            if (hasLocal) continue;
            hasLocal = true;
          }
          mergedDnsServers.push(sCopy);
        }
        const drules = Array.isArray(dns.rules) ? dns.rules : null;
        if (drules) {
          for (const r of drules) {
            if (!r || typeof r !== 'object') continue;
            const rCopy = deepCopy(r);
            rewriteDnsRule(rCopy, outR, dnsR);
            mergedDnsRules.push(rCopy);
          }
        }
      }

      const route = cfg.route;
      if (route && Array.isArray(route.rules)) {
        for (const r of route.rules) {
          if (!r || typeof r !== 'object') continue;
          if (idx > 0 && isPreRule(r)) continue;
          const rCopy = deepCopy(r);
          rewriteRouteRule(rCopy, outR, dnsR);
          mergedRouteRules.push(rCopy);
        }
      }
      if (route && Array.isArray(route.rule_set)) {
        for (const rs of route.rule_set) {
          if (!rs || typeof rs !== 'object') continue;
          const tag = rs.tag || '';
          if (tag === '' || usedRuleSetTags.has(tag)) continue;
          usedRuleSetTags.add(tag);
          mergedRuleSet.push(deepCopy(rs));
        }
      }
    });

    const allLeafTags = leafOutboundTags.concat(mergedEndpointTags);
    if (allLeafTags.length === 0) return null;

    if (!hasLocal) mergedDnsServers.unshift({ type: 'local', tag: 'local' });
    if (!hasDirect) leafOutbounds.push({ type: 'direct', tag: 'direct' });

    const selector = { type: 'selector', tag: 'proxy', outbounds: ['auto'].concat(allLeafTags, ['direct']), default: 'auto' };
    const urltest = { type: 'urltest', tag: 'auto', outbounds: allLeafTags.slice(), url: 'https://www.gstatic.com/generate_204', interval: '5m' };

    const merged = {};
    const firstLog = fullConfigs[0].log;
    if (firstLog) merged.log = deepCopy(firstLog);

    const dnsObj = { servers: mergedDnsServers };
    if (mergedDnsRules.length > 0) dnsObj.rules = mergedDnsRules;
    const firstDns = fullConfigs[0].dns;
    if (firstDns) {
      const cs = optString(firstDns, 'client_subnet', '');
      if (cs !== '') dnsObj.client_subnet = cs;
      const df = optString(firstDns, 'final', '');
      if (df !== '') {
        dnsObj.final = dnsRenames[0][df] !== undefined ? dnsRenames[0][df] : df;
      }
    }
    merged.dns = dnsObj;

    const firstInbounds = fullConfigs[0].inbounds;
    if (Array.isArray(firstInbounds) && firstInbounds.length > 0) {
      merged.inbounds = deepCopy(firstInbounds);
    } else {
      merged.inbounds = [{ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 }];
    }

    const outArr = [selector, urltest].concat(leafOutbounds);
    merged.outbounds = outArr;
    if (mergedEndpoints.length > 0) merged.endpoints = mergedEndpoints;

    const routeObj = {};
    if (mergedRouteRules.length > 0) routeObj.rules = mergedRouteRules;
    if (mergedRuleSet.length > 0) routeObj.rule_set = mergedRuleSet;
    routeObj.auto_detect_interface = true;
    routeObj.final = 'proxy';
    routeObj.default_domain_resolver = { server: 'local' };
    merged.route = routeObj;

    const firstExp = fullConfigs[0].experimental;
    if (firstExp) {
      const expCopy = deepCopy(firstExp);
      stripForkOnlyFields(expCopy);
      merged.experimental = expCopy;
    }

    return merged;
  }

  // Normalize vless flow in-place across a config's outbounds; returns true if changed
  function normalizeConfigFlowsInPlace(cfg) {
    const outs = cfg.outbounds;
    if (!Array.isArray(outs)) return false;
    let changed = false;
    for (const ob of outs) {
      if (!ob || typeof ob !== 'object' || optString(ob, 'protocol', '') !== 'vless') continue;
      const vnext = ob.settings && ob.settings.vnext;
      if (!Array.isArray(vnext)) continue;
      for (const vn of vnext) {
        const users = vn && vn.users;
        if (!Array.isArray(users)) continue;
        for (const u of users) {
          if (!u) continue;
          const flow = u.flow || '';
          if (flow !== '') {
            const norm = normalizeFlow(flow);
            if (norm !== flow) { u.flow = norm; changed = true; }
          }
        }
      }
    }
    return changed;
  }

  global.HWSingBox = {
    convert, convertToOutbounds, mergeUnified, normalizeFlow, normalizeConfigFlowsInPlace,
    isOutboundSupported, looksLikeXray, isSingbox,
    convOutbound, convTls, convTransport,
  };
})(typeof window !== 'undefined' ? window : globalThis);
