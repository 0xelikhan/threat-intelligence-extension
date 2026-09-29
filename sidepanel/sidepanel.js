/*
 * Threat Intelligence — side panel
 */
(function () {
  'use strict';

  const state = {
    iocs: [],            // parsed IOCs
    enrichments: {},     // key: `${type}:${value}` -> enrichment
    filters: new Set(['ipv4', 'ipv6', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email', 'cve', 'mitre_technique', 'mitre_tactic', 'registry', 'filepath']),
    pageUrl: '',
    caseNotes: [],
  };

  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  document.addEventListener('DOMContentLoaded', init);

  async function init() {
    bindUi();
    await loadCase();
    renderCase();
    // Listen for text injected via context menu / hover pin
    chrome.runtime.onMessage.addListener((msg) => {
      if (msg?.type === 'SIDEPANEL_ADD_TEXT' && typeof msg.text === 'string') {
        $('#pastebox').value = ($('#pastebox').value + '\n' + msg.text).trim();
        parseInput();
      }
    });
  }

  function bindUi() {
    $('#parse-btn').addEventListener('click', parseInput);
    $('#scan-page-btn').addEventListener('click', scanActiveTab);
    $('#rescan').addEventListener('click', scanActiveTab);
    $('#clear-btn').addEventListener('click', () => {
      $('#pastebox').value = '';
      state.iocs = []; state.enrichments = {};
      render();
    });
    $('#enrich-all').addEventListener('click', enrichAll);
    $('#copy-report').addEventListener('click', copyReport);
    $('#send-copilot').addEventListener('click', sendCopilot);
    $('#save-case').addEventListener('click', addAllToCase);
    $('#settings-btn').addEventListener('click', () => chrome.runtime.openOptionsPage());

    $$('.ti-filters input').forEach(cb => {
      cb.addEventListener('change', () => {
        const f = cb.dataset.filter;
        if (cb.checked) {
          if (f === 'sha256') { state.filters.add('sha256'); state.filters.add('sha1'); state.filters.add('md5'); }
          else if (f === 'mitre') { state.filters.add('mitre_technique'); state.filters.add('mitre_tactic'); }
          else if (f === 'other') { state.filters.add('registry'); state.filters.add('filepath'); }
          else state.filters.add(f);
        } else {
          if (f === 'sha256') { state.filters.delete('sha256'); state.filters.delete('sha1'); state.filters.delete('md5'); }
          else if (f === 'mitre') { state.filters.delete('mitre_technique'); state.filters.delete('mitre_tactic'); }
          else if (f === 'other') { state.filters.delete('registry'); state.filters.delete('filepath'); }
          else state.filters.delete(f);
        }
        render();
      });
    });

    $('#case-close').addEventListener('click', () => { $('#case-drawer').hidden = true; });
    $('#case-clear').addEventListener('click', async () => {
      state.caseNotes = [];
      await chrome.storage.local.set({ caseNotes: [] });
      renderCase();
    });
    $('#case-export').addEventListener('click', async () => {
      if (!state.caseNotes.length) return toast('Case is empty');
      const enrichments = state.caseNotes;
      const md = SOCReport.buildMarkdown(enrichments, { pageUrl: '' });
      await navigator.clipboard.writeText(md);
      toast('Case report copied');
    });

    $('#pastebox').addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') parseInput();
    });
  }

  async function parseInput() {
    const text = $('#pastebox').value.trim();
    if (!text) return;
    const iocs = SOCParser.extract(text, { excludePrivateIPs: true, requireKnownTLD: true });
    state.iocs = dedupeIocs(iocs);
    state.enrichments = {};
    render();
    enrichAll();
  }

  async function scanActiveTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;
    state.pageUrl = tab.url || '';
    let text = '';
    try {
      const [{ result }] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => document.body?.innerText || '',
      });
      text = result || '';
    } catch (e) {
      toast('Cannot read page: ' + (e.message || 'permission'));
      return;
    }
    const iocs = SOCParser.extract(text, { excludePrivateIPs: true, requireKnownTLD: true });
    state.iocs = dedupeIocs(iocs);
    state.enrichments = {};
    render();
    enrichAll();
  }

  function dedupeIocs(list) {
    const seen = new Set();
    const out = [];
    for (const i of list) {
      const k = i.type + ':' + i.value;
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(i);
    }
    return out;
  }

  async function enrichAll() {
    const targets = state.iocs.filter(i => !state.enrichments[key(i)]);
    if (!targets.length) return;
    // Batched to avoid rate limits
    const chunkSize = 5;
    for (let i = 0; i < targets.length; i += chunkSize) {
      const chunk = targets.slice(i, i + chunkSize);
      const resp = await chrome.runtime.sendMessage({ type: 'ENRICH_BATCH', iocs: chunk });
      if (resp?.ok) {
        resp.data.forEach(e => { state.enrichments[key(e.ioc)] = e; });
        render();
      }
    }
  }

  function key(ioc) { return ioc.type + ':' + ioc.value; }

  async function copyReport() {
    if (!state.iocs.length) return toast('Nothing to report');
    const enrichments = state.iocs.map(i => state.enrichments[key(i)]).filter(Boolean);
    if (!enrichments.length) return toast('Nothing enriched yet');
    const md = SOCReport.buildMarkdown(enrichments, { pageUrl: state.pageUrl });
    await navigator.clipboard.writeText(md);
    toast('Report copied');
  }

  async function sendCopilot() {
    if (!state.iocs.length) return toast('Nothing to send');
    const enrichments = state.iocs.map(i => state.enrichments[key(i)]).filter(Boolean);
    if (!enrichments.length) return toast('Enrich first');
    const prompt = SOCReport.buildCopilotPrompt(enrichments, { pageUrl: state.pageUrl });
    await navigator.clipboard.writeText(prompt);
    chrome.runtime.sendMessage({ type: 'OPEN_COPILOT', prompt });
    toast('Prompt copied, opening Copilot');
  }

  async function addAllToCase() {
    const enrichments = state.iocs.map(i => state.enrichments[key(i)]).filter(Boolean);
    if (!enrichments.length) return toast('Nothing to pin');
    const existingKeys = new Set(state.caseNotes.map(e => key(e.ioc)));
    for (const e of enrichments) if (!existingKeys.has(key(e.ioc))) state.caseNotes.push(e);
    await chrome.storage.local.set({ caseNotes: state.caseNotes });
    renderCase();
    $('#case-drawer').hidden = false;
    toast(`Pinned ${enrichments.length}`);
  }

  async function loadCase() {
    const { caseNotes = [] } = await chrome.storage.local.get('caseNotes');
    state.caseNotes = caseNotes;
  }

  function renderCase() {
    $('#case-count').textContent = state.caseNotes.length;
    const list = $('#case-list');
    list.innerHTML = '';
    for (const e of state.caseNotes) {
      const row = document.createElement('div');
      row.className = 'ti-case-row';
      row.innerHTML = `
        <span class="ti-case-type">${e.ioc.type}</span>
        <span class="ti-case-value">${escapeHtml(e.ioc.value)}</span>
        <button class="ti-case-remove" title="Remove">×</button>
      `;
      row.querySelector('.ti-case-remove').addEventListener('click', async () => {
        state.caseNotes = state.caseNotes.filter(x => key(x.ioc) !== key(e.ioc));
        await chrome.storage.local.set({ caseNotes: state.caseNotes });
        renderCase();
      });
      list.appendChild(row);
    }
  }

  function render() {
    const filtered = state.iocs.filter(i => state.filters.has(i.type));
    $('#ioc-count').textContent = filtered.length;
    const container = $('#ioc-list');
    container.innerHTML = '';
    if (!filtered.length) return;

    // Group by type
    const groups = new Map();
    for (const i of filtered) {
      if (!groups.has(i.type)) groups.set(i.type, []);
      groups.get(i.type).push(i);
    }
    const order = ['ipv4', 'ipv6', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email', 'cve', 'mitre_technique', 'mitre_tactic', 'registry', 'filepath'];

    for (const type of order) {
      if (!groups.has(type)) continue;
      const groupEl = document.createElement('div');
      groupEl.className = 'ti-group';
      groupEl.innerHTML = `<div class="ti-group-head">${type} (${groups.get(type).length})</div>`;
      for (const ioc of groups.get(type)) {
        groupEl.appendChild(renderCard(ioc));
      }
      container.appendChild(groupEl);
    }
  }

  function renderCard(ioc) {
    const enriched = state.enrichments[key(ioc)];
    const card = document.createElement('div');
    card.className = 'ti-card';
    card.dataset.type = ioc.type;

    const verdict = enriched ? SOCReport.verdictBadge(enriched) : 'PENDING';
    const cls = verdict.startsWith('MALICIOUS') ? 'bad'
              : verdict.startsWith('SUSPICIOUS') ? 'warn'
              : verdict === 'CLEAN' ? 'good' : 'muted';

    card.innerHTML = `
      <div class="ti-card-head">
        <span class="ti-verdict ti-verdict-${cls}">${verdict}</span>
        <span class="ti-card-value" title="${escapeHtml(ioc.value)}">${escapeHtml(ioc.value)}</span>
        <div class="ti-card-actions">
          <button data-act="copy" title="Copy">⧉</button>
          <button data-act="defang" title="Defang">◈</button>
          <button data-act="pin" title="Pin to case">📌</button>
          <button data-act="expand" title="Expand">▾</button>
        </div>
      </div>
      <div class="ti-card-body"></div>
    `;

    if (enriched) renderCardBody(card.querySelector('.ti-card-body'), enriched);
    else card.querySelector('.ti-card-body').innerHTML = `<div class="ti-loading"><span class="ti-dots"><i></i><i></i><i></i></span></div>`;

    card.querySelector('[data-act="copy"]').addEventListener('click', async () => {
      await navigator.clipboard.writeText(ioc.value);
      toast('Copied');
    });
    card.querySelector('[data-act="defang"]').addEventListener('click', async () => {
      await navigator.clipboard.writeText(SOCParser.defang(ioc.value));
      toast('Defanged');
    });
    card.querySelector('[data-act="pin"]').addEventListener('click', async () => {
      if (!enriched) return toast('Not enriched');
      const existing = new Set(state.caseNotes.map(e => key(e.ioc)));
      if (!existing.has(key(ioc))) {
        state.caseNotes.push(enriched);
        await chrome.storage.local.set({ caseNotes: state.caseNotes });
        renderCase();
        toast('Pinned');
      } else {
        toast('Already pinned');
      }
    });
    card.querySelector('[data-act="expand"]').addEventListener('click', () => {
      card.classList.toggle('expanded');
    });
    return card;
  }

  function renderCardBody(el, enriched) {
    const r = enriched.results || {};
    const rows = [];

    if (r.virustotal && !r.virustotal.error) {
      if (r.virustotal.notFound) rows.push(kv('VirusTotal', 'not indexed', r.virustotal.link));
      else {
        const bar = ratioBar(r.virustotal.malicious || 0, r.virustotal.total || 0);
        rows.push(kv('VirusTotal', `${bar} ${r.virustotal.malicious || 0}/${r.virustotal.total || 0}`, r.virustotal.link));
      }
    }
    if (r.abuseipdb && !r.abuseipdb.error) {
      const conf = r.abuseipdb.confidence || 0;
      const dot = conf >= 75 ? '🔴' : conf >= 25 ? '🟠' : '🟢';
      rows.push(kv('AbuseIPDB', `${dot} ${conf}/100 · ${r.abuseipdb.totalReports} reports`, r.abuseipdb.link));
    }
    if (r.greynoise && !r.greynoise.error && !r.greynoise.notFound) {
      rows.push(kv('GreyNoise', `${r.greynoise.classification || ''}${r.greynoise.name ? ' · ' + r.greynoise.name : ''}`, r.greynoise.link));
    }
    if (r.ipApi && !r.ipApi.error) {
      const flag = countryFlag(r.ipApi.countryCode);
      rows.push(kv('Geo', `${flag} ${r.ipApi.country || ''}, ${r.ipApi.city || ''}`));
      rows.push(kv('ASN', `${r.ipApi.asn || ''} · ${r.ipApi.org || r.ipApi.isp || ''}`));
      if (r.ipApi.reverseDns) rows.push(kv('rDNS', r.ipApi.reverseDns));
      const flags = [];
      if (r.ipApi.isProxy) flags.push('proxy');
      if (r.ipApi.isHosting) flags.push('hosting');
      if (r.ipApi.isMobile) flags.push('mobile');
      if (flags.length) rows.push(kv('Flags', flags.join(', ')));
    }
    if (r.forwardDns && !r.forwardDns.error) {
      const a = (r.forwardDns.a || []).slice(0, 5).map(x => x.data).join(', ');
      const mx = (r.forwardDns.mx || []).slice(0, 3).map(x => x.data).join(', ');
      const ns = (r.forwardDns.ns || []).slice(0, 3).map(x => x.data).join(', ');
      if (a) rows.push(kv('A', a));
      if (mx) rows.push(kv('MX', mx));
      if (ns) rows.push(kv('NS', ns));
    }
    if (r.rdap && !r.rdap.error) {
      if (r.rdap.registrar) rows.push(kv('Registrar', r.rdap.registrar));
      if (r.rdap.created) rows.push(kv('Registered', String(r.rdap.created).slice(0, 10)));
      if (r.rdap.expires) rows.push(kv('Expires', String(r.rdap.expires).slice(0, 10)));
      if (r.rdap.name) rows.push(kv('Network', r.rdap.name));
      if (r.rdap.abuseContacts?.length) rows.push(kv('Abuse', r.rdap.abuseContacts.join(', ')));
    }
    if (r.reverseDns && !r.reverseDns.error && r.reverseDns.ptr?.length) {
      rows.push(kv('PTR', r.reverseDns.ptr.join(', ')));
    }
    if (r.nvd && !r.nvd.error) {
      rows.push(kv('CVSS', `${r.nvd.cvssScore ?? ''} (${r.nvd.severity || ''})`, r.nvd.link));
      if (r.nvd.description) rows.push(`<div class="ti-desc">${escapeHtml(r.nvd.description.slice(0, 400))}</div>`);
    }

    // Errors
    Object.entries(r).forEach(([k, v]) => {
      if (v?.error) rows.push(`<div class="ti-row-err">${escapeHtml(k)}: ${escapeHtml(v.error)}</div>`);
    });

    el.innerHTML = rows.length ? rows.join('') : `<div class="ti-empty-body">No enrichment data</div>`;
  }

  function kv(k, v, link) {
    const linkStr = link ? ` <a class="ti-link" href="${escapeHtml(link)}" target="_blank" rel="noopener">↗</a>` : '';
    return `<div class="ti-row"><span class="ti-k">${escapeHtml(k)}</span><span class="ti-v">${escapeHtml(String(v))}${linkStr}</span></div>`;
  }

  function ratioBar(mal, total) {
    if (!total) return '';
    const pct = Math.min(100, Math.round((mal / total) * 100));
    const filled = Math.round(pct / 10);
    return `<span class="ti-bar">${'█'.repeat(filled)}${'░'.repeat(10 - filled)}</span>`;
  }

  function countryFlag(cc) {
    if (!cc || cc.length !== 2) return '';
    return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0)));
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function toast(msg) {
    const el = $('#toast');
    el.textContent = msg;
    el.hidden = false;
    clearTimeout(toast._t);
    toast._t = setTimeout(() => { el.hidden = true; }, 1600);
  }
})();
