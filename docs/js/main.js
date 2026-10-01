// Happwner Web — UI wiring.
"use strict";
(function () {
  const $ = (id) => document.getElementById(id);
  const U = window.HWUtil;
  const H = window.HWHappCrypto;
  const V = window.HWV2RayTun;
  const LC = window.HWLinkConverter;
  const LP = window.HWLinkParse;
  const SF = window.HWSubFetch;

  // ---------- persistence ----------
  const PREF_KEY = 'happwner-web-prefs';
  const prefs = (() => {
    try { return JSON.parse(localStorage.getItem(PREF_KEY)) || {}; } catch (e) { return {}; }
  })();
  function savePrefs() {
    try { localStorage.setItem(PREF_KEY, JSON.stringify(prefs)); } catch (e) { /* private mode */ }
  }
  function bindPref(id, key, transform) {
    const el = $(id);
    if (!el) return;
    if (prefs[key] !== undefined) {
      if (el.type === 'checkbox') el.checked = !!prefs[key];
      else el.value = prefs[key];
    }
    el.addEventListener('change', () => {
      prefs[key] = el.type === 'checkbox' ? el.checked : el.value;
      savePrefs();
    });
    if (transform) el.addEventListener('input', () => {
      prefs[key] = el.value;
      savePrefs();
    });
  }

  // ---------- helpers ----------
  let toastTimer = null;
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, 1800);
  }

  function setStatus(el, kind, html) {
    el.hidden = false;
    el.className = 'status' + (kind ? ' ' + kind : '');
    el.innerHTML = html;
  }
  function clearStatus(el) { el.hidden = true; el.innerHTML = ''; }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      toast('Copied to clipboard');
    } catch (e) {
      // fallback for non-secure contexts
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); toast('Copied to clipboard'); } catch (e2) { toast('Copy failed'); }
      ta.remove();
    }
  }

  function downloadText(text, filename) {
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    toast('Downloading ' + filename);
  }

  async function pasteInto(ta) {
    try {
      const text = await navigator.clipboard.readText();
      if (text) { ta.value = text; toast('Pasted'); }
      else toast('Clipboard is empty');
    } catch (e) { toast('Clipboard read blocked — paste manually (Ctrl+V)'); }
  }

  // ---------- output processing (shared toggles) ----------
  function outputOpts(prefix) {
    return {
      jsonToUri: $('optJsonToUri').checked,
      tryBase64: $('optTryB64').checked,
      xrayToSb: $('optXrayToSb').checked,
      prefix,
    };
  }

  function applyOutputConversion(text, opts) {
    const o = opts || {};
    if (!o.jsonToUri && !o.tryBase64 && !o.xrayToSb) return { text, skipped: 0 };
    const res = LC.convertWithStats(text, o.jsonToUri, o.tryBase64, o.xrayToSb);
    return { text: res.text, skipped: res.xraySkipped };
  }

  // ---------- server cards ----------
  function renderServers(el, text) {
    const links = LP.parseLinks(text);
    const sb = LP.parseSingBoxOutbounds(text);
    const seen = new Set();
    const servers = [];
    for (const s of links.servers.concat(sb)) {
      const key = (s.proto || '') + '|' + (s.host || '') + '|' + (s.port || '') + '|' + (s.name || '');
      if (seen.has(key)) continue;
      seen.add(key);
      servers.push(s);
    }
    el.innerHTML = '';
    if (servers.length === 0) return;
    const title = document.createElement('div');
    title.style.cssText = 'grid-column: 1/-1; font-size:12.5px; color: var(--text-faint);';
    title.textContent = servers.length + ' server' + (servers.length === 1 ? '' : 's') + ' detected';
    el.appendChild(title);
    for (const s of servers) {
      const card = document.createElement('div');
      card.className = 'srv';
      const sec = (s.security || 'none').toLowerCase();
      const secBadge = sec === 'reality' ? '<span class="badge reality">reality</span>'
        : sec === 'tls' ? '<span class="badge tls">tls</span>'
        : '';
      const meta = [];
      if (s.transport && s.transport !== 'tcp') meta.push('<span class="chip">' + esc(s.transport) + '</span>');
      if (s.method) meta.push('<span class="chip">' + esc(s.method) + '</span>');
      if (s.sb) meta.push('<span class="chip">sing-box</span>');
      card.innerHTML =
        '<div class="top"><span class="badge">' + esc(s.proto || '?') + '</span>' + secBadge +
        '<span class="name">' + esc(s.name || '(unnamed)') + '</span></div>' +
        '<div class="addr">' + esc(s.host || '?') + (s.port ? ':' + s.port : '') + '</div>' +
        (meta.length ? '<div class="meta">' + meta.join('') + '</div>' : '');
      el.appendChild(card);
    }
  }

  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // ---------- tabs ----------
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach((b) => b.classList.toggle('active', b === btn));
      document.querySelectorAll('.tab').forEach((t) => t.classList.toggle('active', t.id === 'tab-' + btn.dataset.tab));
    });
  });

  // =====================================================
  // DECRYPT TAB
  // =====================================================
  function processOneLink(line, depth) {
    depth = depth || 0;
    const t = line.trim();
    if (t === '') return { kind: 'empty' };
    const tl = t.toLowerCase();

    // happ:// family
    if (H.isOpenableHappLink(t)) {
      if (tl.startsWith(H.ADD_PREFIX)) {
        const inner = H.stripAddPrefix(t);
        if (inner) {
          // the inner link may itself be a crypt link
          if (depth < 3 && H.isOpenableHappLink(inner) && !inner.toLowerCase().startsWith(H.ADD_PREFIX)) {
            return processOneLink(inner, depth + 1);
          }
          return { kind: 'add', text: inner };
        }
        return { kind: 'error', reason: 'empty happ://add/ payload' };
      }
      const res = H.decryptHappLink(t);
      if (res.status === 'ok') return { kind: 'decrypted', mode: res.mode, text: res.plaintext };
      return { kind: 'error', mode: res.mode, reason: res.reason };
    }

    // v2raytun
    if (V.isV2RayTunCryptLink(t)) {
      const res = V.decryptV2RayTunCryptLink(t);
      if (res.status === 'ok') return { kind: 'decrypted', mode: res.mode, text: res.plaintext };
      return { kind: 'error', reason: res.reason };
    }
    if (V.isV2RayTunImportLink(t)) {
      const inner = V.stripV2RayTunImportPrefix(t);
      return inner ? { kind: 'unwrapped', text: inner } : { kind: 'error', reason: 'empty v2raytun://import/ payload' };
    }

    // incy
    if (V.isIncyLink(t)) {
      const inner = V.stripIncyPrefix(t);
      return inner ? { kind: 'unwrapped', text: inner } : { kind: 'error', reason: 'could not unwrap incy:// link' };
    }

    // wrapped in http(s)?
    if (tl.startsWith('http://') || tl.startsWith('https://')) {
      const embedded = H.extractEmbeddedHappLink(t) || V.extractEmbeddedV2RayLink(t) || V.extractEmbeddedIncyLink(t);
      if (embedded && depth < 3) return processOneLink(embedded, depth + 1);
      return { kind: 'unknown' };
    }

    // web bonus: raw base64 blob of links/JSON decodes right in the decrypt tab
    if ($('optTryB64').checked) {
      const b64 = LC.tryDecodeBase64(t);
      if (b64) return { kind: 'decoded', text: b64.decoded };
    }

    return { kind: 'unknown' };
  }

  function runDecrypt() {
    const input = $('decInput').value;
    const statusEl = $('decStatus');
    const outEl = $('decOutput');
    const serversEl = $('decServers');
    clearStatus(statusEl);

    if (!input.trim()) {
      setStatus(statusEl, 'warn', 'Nothing to decrypt — paste a link first.');
      return;
    }

    const lines = input.split(/\r?\n/).map((l) => l.trim()).filter((l) => l !== '');
    const results = [];
    let ok = 0, err = 0, unknown = 0;
    for (const line of lines) {
      try {
        const r = processOneLink(line);
        results.push({ line, r });
        if (r.kind === 'decrypted' || r.kind === 'add' || r.kind === 'unwrapped' || r.kind === 'decoded') ok++;
        else if (r.kind === 'error') err++;
        else unknown++;
      } catch (e) {
        results.push({ line, r: { kind: 'error', reason: e.message || String(e) } });
        err++;
      }
    }

    const outParts = [];
    for (const { line, r } of results) {
      if (r.kind === 'decrypted' || r.kind === 'decoded') {
        let text = r.text;
        const conv = applyOutputConversion(text, outputOpts());
        text = conv.text;
        if (conv.skipped > 0) outParts.push('# (' + conv.skipped + ' unsupported outbound(s) skipped)');
        outParts.push(text);
      } else if (r.kind === 'add' || r.kind === 'unwrapped') {
        outParts.push(r.text);
      } else if (r.kind === 'error') {
        outParts.push('# ERROR [' + (r.mode || 'link') + '] ' + r.reason + '  ::  ' + truncate(line, 90));
      }
      // 'unknown' lines are left out of the output; counted in status
    }

    const outText = outParts.join('\n').trim();
    outEl.value = outText;
    renderServers(serversEl, outText);

    const bits = [];
    bits.push('<b>' + ok + '</b> processed');
    if (err) bits.push('<b style="color:var(--err)">' + err + '</b> failed');
    if (unknown) bits.push(unknown + ' not a supported link');
    const modes = [...new Set(results.map((x) => x.r.mode).filter(Boolean))];
    if (modes.length) bits.push('mode: <b>' + esc(modes.join(', ')) + '</b>');
    setStatus(statusEl, err ? (ok ? 'warn' : 'err') : 'ok', bits.join(' · '));
  }

  function truncate(s, n) {
    return s.length > n ? s.slice(0, n) + '…' : s;
  }

  $('btnDecrypt').addEventListener('click', runDecrypt);
  $('btnPasteDec').addEventListener('click', () => pasteInto($('decInput')));
  $('btnClearDec').addEventListener('click', () => { $('decInput').value = ''; $('decOutput').value = ''; clearStatus($('decStatus')); $('decServers').innerHTML = ''; });
  $('btnCopyDec').addEventListener('click', () => $('decOutput').value ? copyText($('decOutput').value) : toast('Nothing to copy'));
  $('btnDlDec').addEventListener('click', () => $('decOutput').value ? downloadText($('decOutput').value, 'happwner-decrypted.txt') : toast('Nothing to download'));
  $('decInput').addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runDecrypt();
  });

  // =====================================================
  // SUBSCRIPTION TAB
  // =====================================================
  const FETCH_OPTS = { jsonToUri: 'optJsonToUri', tryBase64: 'optTryB64', xrayToSb: 'optXrayToSb' }; // shared with decrypt tab

  function showSubError(msg, hint) {
    setStatus($('subStatus'), 'err', '<b>Fetch failed.</b> ' + esc(msg) + (hint ? '<br>' + hint : ''));
  }

  function processFetchedBody(url, body, encryptTag, keyOverride, viaLabel) {
    const statusEl = $('subStatus');
    const outEl = $('subOutput');
    const serversEl = $('subServers');

    let proc = H.processSubscriptionBody(url, body, encryptTag);
    if (keyOverride && keyOverride.trim() && proc.status === 'notencrypted') {
      // retry with an explicit key name
      const fakeUrl = url + (url.includes('?') ? '&' : '?') + 'key=' + encodeURIComponent(keyOverride.trim());
      proc = H.processSubscriptionBody(fakeUrl, body, encryptTag);
    }

    let text;
    if (proc.status === 'ok') {
      text = proc.plaintext;
      setStatus(statusEl, 'ok', '<b>Decrypted</b> with ' + esc(proc.keyName) + (viaLabel ? ' · ' + esc(viaLabel) : '') + ' · ' + body.length + ' B → ' + text.length + ' chars');
    } else if (proc.status === 'failed') {
      text = body;
      setStatus(statusEl, 'warn', '<b>Decryption failed</b> (' + esc(proc.keyName) + ': ' + esc(proc.reason) + ') — showing the original body.' + (viaLabel ? ' · ' + esc(viaLabel) : ''));
    } else {
      text = body;
      setStatus(statusEl, 'ok', '<b>Fetched</b>' + (viaLabel ? ' · ' + esc(viaLabel) : '') + ' · body is not Happ-encrypted (no key= + Encrypt-Tag pair detected)');
    }

    const conv = applyOutputConversion(text, {
      jsonToUri: $(FETCH_OPTS.jsonToUri).checked,
      tryBase64: $(FETCH_OPTS.tryBase64).checked,
      xrayToSb: $(FETCH_OPTS.xrayToSb).checked,
    });
    outEl.value = conv.text + (conv.skipped > 0 ? '\n# (' + conv.skipped + ' unsupported outbound(s) skipped)' : '');
    renderServers(serversEl, conv.text);
  }

  async function runFetch() {
    const url = $('subUrl').value.trim();
    const statusEl = $('subStatus');
    if (!/^https?:\/\//i.test(url)) {
      setStatus(statusEl, 'warn', 'Enter a valid http(s) subscription URL.');
      return;
    }
    const btn = $('btnFetch');
    btn.disabled = true;
    btn.textContent = 'Fetching…';
    clearStatus(statusEl);
    try {
      let hwid = $('subHwid').value.trim();
      if ($('chkHwidRandom').checked || !hwid) hwid = SF.generateHwid();
      if ($('chkHwidRandom').checked) $('subHwid').value = hwid;
      const ua = $('subUa').value.trim();

      const res = await SF.fetchSubscription(url, { hwid, ua, mode: $('subProxy').value });

      if (!res.ok) {
        showSubError(res.error, 'Try another transport, or use the manual paste mode below.');
        return;
      }

      const manualTag = $('manualTag').value.trim();
      const encryptTag = res.encryptTag || (manualTag || null);
      if (!res.encryptTag && manualTag) setStatus(statusEl, 'ok', 'Using manually provided Encrypt-Tag · via ' + esc(res.via));
      processFetchedBody(url, res.body, encryptTag, '', res.via + (hwid ? ' · x-hwid: ' + hwid : ''));
    } finally {
      btn.disabled = false;
      btn.textContent = 'Fetch & process';
    }
  }

  function runManual() {
    const body = $('manualBody').value;
    if (!body.trim()) { setStatus($('subStatus'), 'warn', 'Paste the subscription body first.'); return; }
    const url = $('subUrl').value.trim();
    const tag = $('manualTag').value.trim() || null;
    const key = $('manualKey').value.trim() || null;
    if (!url && !key) {
      setStatus($('subStatus'), 'warn', 'Manual decryption needs the subscription URL (for the key= parameter) or an explicit key name.');
      return;
    }
    processFetchedBody(url, body.trim(), tag, key, 'manual body');
  }

  $('btnFetch').addEventListener('click', runFetch);
  $('btnManual').addEventListener('click', runManual);
  $('btnHwidGen').addEventListener('click', () => {
    $('subHwid').value = SF.generateHwid();
    prefs.subHwid = $('subHwid').value;
    savePrefs();
    toast('Random HWID generated');
  });
  $('uaPreset').addEventListener('change', () => {
    const v = SF.UA_PRESETS[$('uaPreset').value];
    if (v) {
      $('subUa').value = v;
      prefs.subUa = v;
      savePrefs();
    }
  });
  // UA extraction: put the browser's real User-Agent into the field and copy it
  $('uaReal').textContent = navigator.userAgent;
  $('btnUaExtract').addEventListener('click', async () => {
    const ua = navigator.userAgent;
    $('subUa').value = ua;
    prefs.subUa = ua;
    savePrefs();
    await copyText(ua);
    toast('Browser User-Agent extracted & copied');
  });
  $('btnWrapAdd').addEventListener('click', () => {
    const url = $('subUrl').value.trim();
    if (!url) { toast('Enter a URL first'); return; }
    const wrapped = 'happ://add/' + encodeURIComponent(url);
    $('decInput').value = wrapped;
    document.querySelector('.tab-btn[data-tab="decrypt"]').click();
    runDecrypt();
  });
  $('btnCopySub').addEventListener('click', () => $('subOutput').value ? copyText($('subOutput').value) : toast('Nothing to copy'));
  $('btnDlSub').addEventListener('click', () => $('subOutput').value ? downloadText($('subOutput').value, 'subscription.txt') : toast('Nothing to download'));

  // =====================================================
  // CONVERTER TAB
  // =====================================================
  function runConvert() {
    const input = $('convInput').value;
    const statusEl = $('convStatus');
    const outEl = $('convOutput');
    const serversEl = $('convServers');
    clearStatus(statusEl);

    if (!input.trim()) { setStatus(statusEl, 'warn', 'Nothing to convert.'); return; }

    const jsonToUri = $('cJsonToUri').checked;
    const tryB64 = $('cTryB64').checked;
    const xrayToSb = $('cXrayToSb').checked;
    const sbMode = $('cSbMode').value;

    if (!jsonToUri && !tryB64 && !xrayToSb) {
      setStatus(statusEl, 'warn', 'Pick at least one conversion option.');
      return;
    }

    let text, skipped = 0;
    if (xrayToSb && sbMode === 'outbounds') {
      // extract sing-box outbounds from each JSON config found
      const SB = window.HWSingBox;
      const parts = [];
      const t = input.trim();
      let handled = false;
      const tryOne = (s) => {
        const r = SB.convertToOutbounds(s, '');
        if (r.status === 'ok') { parts.push(JSON.stringify(r.outbounds, null, 2)); return true; }
        if (r.status === 'unsupported') { skipped++; return true; }
        return false;
      };
      if ((t.startsWith('{') || t.startsWith('[')) && tryOne(t)) handled = true;
      if (!handled) {
        for (const line of input.split(/\r?\n/)) {
          const tt = line.trim();
          if (!tt) continue;
          if (!tryOne(tt)) parts.push(tt);
        }
      }
      text = parts.join('\n');
    } else {
      const res = LC.convertWithStats(input, jsonToUri, tryB64, xrayToSb);
      text = res.text;
      skipped = res.xraySkipped;
    }

    outEl.value = text;
    renderServers(serversEl, text);
    setStatus(statusEl, skipped > 0 ? 'warn' : 'ok',
      'Converted · ' + (skipped > 0 ? '<b>' + skipped + '</b> unsupported config(s) skipped' : 'no unsupported configs'));
  }

  $('btnConvert').addEventListener('click', runConvert);
  $('btnPasteConv').addEventListener('click', () => pasteInto($('convInput')));
  $('btnClearConv').addEventListener('click', () => { $('convInput').value = ''; $('convOutput').value = ''; clearStatus($('convStatus')); $('convServers').innerHTML = ''; });
  $('btnSwapConv').addEventListener('click', () => {
    if (!$('convOutput').value) { toast('No result yet'); return; }
    $('convInput').value = $('convOutput').value;
    toast('Result moved to input');
  });
  $('btnCopyConv').addEventListener('click', () => $('convOutput').value ? copyText($('convOutput').value) : toast('Nothing to copy'));
  $('btnDlConv').addEventListener('click', () => $('convOutput').value ? downloadText($('convOutput').value, 'converted-config.txt') : toast('Nothing to download'));
  $('convInput').addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') runConvert();
  });

  // ---------- bind prefs ----------
  ['optJsonToUri', 'optTryB64', 'optXrayToSb'].forEach((id) => bindPref(id, id));
  ['cJsonToUri', 'cTryB64', 'cXrayToSb', 'cSbMode'].forEach((id) => bindPref(id, id));
  ['subUrl', 'subHwid', 'subUa'].forEach((id) => bindPref(id, id, true));
  bindPref('chkHwidRandom', 'chkHwidRandom');
  bindPref('subProxy', 'subProxy');
})();
