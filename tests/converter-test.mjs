// Converter tests: link parsing/building, base64, xray->sing-box.
// Run: node tests/converter-test.mjs
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, '..');
const load = (f) => fs.readFileSync(path.join(root, 'docs/js', f), 'utf8');
for (const f of ['util.js', 'keys.js', 'rsa.js', 'chacha.js', 'aesgcm.js', 'happcrypto.js', 'v2raytun.js', 'singbox.js', 'linkconverter.js']) {
  new Function(load(f)).call(globalThis);
}

const LC = globalThis.HWLinkConverter;
const SB = globalThis.HWSingBox;
const U = globalThis.HWUtil;

let pass = 0, fail = 0;
function check(name, cond, extra) {
  if (cond) { pass++; console.log('  ok  ' + name); }
  else { fail++; console.log('FAIL  ' + name + (extra ? ' :: ' + extra : '')); }
}

// ---------- JSON outbound -> link ----------
{
  const xrayVless = JSON.stringify({
    remarks: 'My Node',
    outbounds: [{
      protocol: 'vless',
      settings: { vnext: [{ address: 'srv.example.com', port: 443, users: [{ id: 'u-1234', flow: 'xtls-rprx-vision-udp443', encryption: 'none' }] }] },
      streamSettings: { network: 'tcp', security: 'reality', realitySettings: { serverName: 'www.microsoft.com', fingerprint: 'chrome', publicKey: 'PBK', shortId: 'SID' } },
    }],
  });
  const out = LC.convert(xrayVless, true, true, false);
  // Note: the Android app's buildVless does not normalize the flow — port matches it.
  const expected = 'vless://u-1234@srv.example.com:443?encryption=none&flow=xtls-rprx-vision-udp443&fp=chrome&pbk=PBK&security=reality&sid=SID&sni=www.microsoft.com&type=tcp#My%20Node';
  check('json->vless link', out === expected, out);
}
{
  const ssJson = JSON.stringify({ server: '1.2.3.4', server_port: 8388, method: 'aes-256-gcm', password: 'passw0rd', remarks: 'SS node' });
  const out = LC.convert(ssJson, true, true, false);
  const ui = Buffer.from('aes-256-gcm:passw0rd').toString('base64');
  check('json->ss link', out === 'ss://' + ui + '@1.2.3.4:8388#SS%20node', out);
}
{
  const vmessJson = JSON.stringify({
    tag: 'vm',
    protocol: 'vmess',
    settings: { vnext: [{ address: 'vm.example.com', port: 443, users: [{ id: 'vm-uuid', security: 'auto' }] }] },
    streamSettings: { network: 'ws', security: 'tls', wsSettings: { path: '/ws', headers: { Host: 'vm.example.com' } } },
  });
  const out = LC.convert(vmessJson, true, true, false);
  const decoded = JSON.parse(Buffer.from(out.replace('vmess://', ''), 'base64').toString('utf8'));
  check('json->vmess link', decoded.add === 'vm.example.com' && decoded.port === '443' && decoded.id === 'vm-uuid' && decoded.net === 'ws' && decoded.tls === 'tls' && decoded.path === '/ws' && decoded.ps === 'vm', out);
}

// ---------- base64 blob -> links ----------
{
  const links = 'vless://aaa@bbb:1#A\ntrojan://pw@ccc:443?sni=x#B';
  const blob = Buffer.from(links, 'utf8').toString('base64');
  const out = LC.convert(blob, true, true, false);
  check('b64 blob -> links', out === links, out);
  // url-safe no-padding variant round-trips back to base64 when jsonToUri=false
  const blobUrl = Buffer.from(links, 'utf8').toString('base64url').replace(/=+$/, '');
  const out2 = LC.convert(blobUrl, false, true, false);
  check('b64 urlsafe decode', out2 === links, out2);
  const out3 = LC.convert(blobUrl, false, true, false);
  const reencoded = LC.convert(out2, false, true, false); // already decoded, stable
  check('b64 decode stable', reencoded === links, reencoded);
}

// ---------- xray full config -> sing-box ----------
{
  const xray = {
    log: { loglevel: 'warning' },
    inbounds: [{ tag: 'socks-in', listen: '127.0.0.1', port: 10808, protocol: 'socks', settings: { auth: 'noauth' }, sniffing: { enabled: true, destOverride: ['http', 'tls'] } }],
    outbounds: [
      { tag: 'proxy', protocol: 'vless', settings: { vnext: [{ address: 'srv.example.com', port: 443, users: [{ id: 'u-1', flow: 'xtls-rprx-vision', encryption: 'none' }] }] }, streamSettings: { network: 'tcp', security: 'reality', realitySettings: { serverName: 'www.microsoft.com', fingerprint: 'chrome', publicKey: 'PBK', shortId: 'SI' } } },
      { tag: 'direct-out', protocol: 'freedom', settings: { domainStrategy: 'UseIPv4' } },
      { tag: 'block-out', protocol: 'blackhole', settings: {} },
    ],
    routing: { domainStrategy: 'IPIfNonMatch', rules: [{ type: 'field', outboundTag: 'block-out', domain: ['geosite:category-ads-all'] }, { type: 'field', outboundTag: 'direct-out', ip: ['geoip:private'] }] },
  };
  const r = SB.convert(JSON.stringify(xray), '');
  check('xray->singbox status', r.status === 'ok', JSON.stringify(r).slice(0, 100));
  if (r.status === 'ok') {
    const cfg = r.config;
    check('sb log level', cfg.log.level === 'warn');
    check('sb inbound', cfg.inbounds.length === 1 && cfg.inbounds[0].type === 'socks' && cfg.inbounds[0].listen_port === 10808);
    const proxy = cfg.outbounds.find((o) => o.type === 'vless');
    const direct = cfg.outbounds.find((o) => o.type === 'direct' && o.tag === 'direct-out');
    check('sb vless outbound', !!proxy && proxy.server === 'srv.example.com' && proxy.server_port === 443 && proxy.uuid === 'u-1' && proxy.flow === 'xtls-rprx-vision');
    check('sb reality tls', proxy.tls && proxy.tls.reality && proxy.tls.reality.public_key === 'PBK' && proxy.tls.server_name === 'www.microsoft.com');
    check('sb freedom direct', !!direct && direct.domain_strategy === 'ipv4_only');
    // single supported proxy + no balancers -> no selector/urltest, final is the proxy tag itself
    check('sb no selector for single proxy', !cfg.outbounds.some((o) => o.type === 'selector') && cfg.route.final === 'proxy');
    check('sb rules', cfg.route.rules.length === 6 && cfg.route.rules.some((x) => x.action === 'sniff') && cfg.route.rules.some((x) => Array.isArray(x.rule_set) && x.rule_set.includes('geosite-category-ads-all')) && cfg.route.rules.some((x) => x.ip_is_private === true));
    // no xray dns section -> only the local server, no final override beyond the default pick
    check('sb dns local', cfg.dns.servers.some((s) => s.type === 'local') && !!cfg.dns.final);
    // geoip:private sets a flag (not a rule-set); geosite does become a rule-set
    check('sb rule_set present', Array.isArray(cfg.route.rule_set) && cfg.route.rule_set.length === 1 && cfg.route.rule_set[0].tag === 'geosite-category-ads-all');
  }
}

// ---------- vmess->singbox, ws+tls ----------
{
  const xray = {
    outbounds: [{ tag: 'p', protocol: 'vmess', settings: { vnext: [{ address: 'a.b', port: 443, users: [{ id: 'uuid-1', alterId: 0, security: 'auto' }] }] }, streamSettings: { network: 'ws', security: 'tls', wsSettings: { path: '/path?ed=2048', headers: { Host: 'cdn.b' } } } }],
  };
  const r = SB.convert(JSON.stringify(xray), 'fallback-name');
  check('vmess->sb ok', r.status === 'ok');
  if (r.status === 'ok') {
    const p = r.config.outbounds.find((o) => o.type === 'vmess');
    check('vmess->sb fields', p.server === 'a.b' && p.security === 'auto' && p.alter_id === 0 && p.global_padding === true);
    check('vmess->sb transport', p.transport.type === 'ws' && p.transport.path === '/path' && p.transport.max_early_data === 2048 && p.transport.early_data_header_name === 'Sec-WebSocket-Protocol');
    check('vmess->sb tls', p.tls.enabled === true && p.tls.server_name === undefined);
  }
}

// ---------- unsupported protocol -> unsupported ----------
{
  const r = SB.convert(JSON.stringify({ outbounds: [{ tag: 'x', protocol: 'shadowsocks', settings: { servers: [{ address: 'a', port: 1, method: 'rc4', password: 'p' }] } }] }), '');
  check('unsupported ss method', r.status === 'unsupported');
  const r2 = SB.convert(JSON.stringify({ app: 'x' }), '');
  check('not xray', r2.status === 'notxray');
}

// ---------- outbounds extraction naming ----------
{
  const xray = JSON.stringify({
    remarks: 'SubName',
    outbounds: [
      { tag: 'a', protocol: 'trojan', settings: { servers: [{ address: 't1.example.com', port: 443, password: 'pw1' }] }, streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { serverName: 't1.example.com' } } },
      { tag: 'b', protocol: 'trojan', settings: { servers: [{ address: 't2.example.com', port: 443, password: 'pw2' }] }, streamSettings: { network: 'tcp', security: 'tls', tlsSettings: { serverName: 't2.example.com' } } },
    ],
  });
  const r = SB.convertToOutbounds(xray, '');
  check('extract outbounds', r.status === 'ok' && r.outbounds.length === 2);
  check('outbound tags', r.outbounds[0].tag === 'SubName #a' && r.outbounds[1].tag === 'SubName #b');
}

// ---------- xray-to-singbox merge via LinkConverter ----------
{
  const line1 = JSON.stringify({ remarks: 'Node A', outbounds: [{ tag: 'p', protocol: 'trojan', settings: { servers: [{ address: 'a.example.com', port: 443, password: 'pw' }] }, streamSettings: { network: 'tcp', security: 'tls' } }] });
  const line2 = JSON.stringify({ remarks: 'Node B', outbounds: [{ tag: 'q', protocol: 'shadowsocks', settings: { servers: [{ address: 'b.example.com', port: 8388, method: 'aes-256-gcm', password: 'pw2' }] } }] });
  const res = LC.convertWithStats(line1 + '\n' + line2, false, false, true);
  let merged = null;
  try { merged = JSON.parse(res.text); } catch (e) { /* not json */ }
  check('merge unified json', !!merged && Array.isArray(merged.outbounds), res.text.slice(0, 120));
  if (merged) {
    const sel = merged.outbounds.find((o) => o.tag === 'proxy');
    // single-proxy configs are renamed to just the remarks by convertObject
    check('merged selector', !!sel && sel.outbounds.includes('Node A') && sel.outbounds.includes('Node B'));
    check('merged has direct', merged.outbounds.some((o) => o.type === 'direct' && o.tag === 'direct'));
  }
}

// ---------- trojan/hysteria2/tuic builders ----------
{
  const trojan = JSON.stringify({ remarks: 'T', outbounds: [{ tag: 'tp', protocol: 'trojan', settings: { servers: [{ address: 'tr.example.com', port: 443, password: 'secret/plus' }] }, streamSettings: { network: 'ws', security: 'tls', tlsSettings: { serverName: 'cdn.example.com' }, wsSettings: { path: '/tp' } } }] });
  const out = LC.convert(trojan, true, true, false);
  // Kotlin sorts the query params by key
  check('json->trojan link', out === 'trojan://secret%2Fplus@tr.example.com:443?host=cdn.example.com&path=%2Ftp&sni=cdn.example.com&type=ws#T', out);
}
{
  const hy2 = JSON.stringify({ server: 'hy.example.com', server_port: 443, password: 'hypass', remarks: 'HY' });
  const out = LC.convert(hy2, true, true, false);
  check('hy2 direct json', out === hy2 || out.startsWith('hysteria2://') || out.startsWith('{'), out);
}

console.log('\n' + pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
