/*
 * Threat Intelligence: side panel
 */
(function () {
  'use strict';

  const state = {
    iocs: [],
    enrichments: {},
    pageUrl: '',
  };

  const $ = (s, r = document) => r.querySelector(s);

  document.addEventListener('DOMContentLoaded', init);

  function init() {
    bindUi();
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
    $('#copy-report').addEventListener('click', copyReport);
    $('#send-copilot').addEventListener('click', openCopilotModal);
    $('#settings-btn').addEventListener('click', () => chrome.runtime.openOptionsPage());

    $('#modal-close').addEventListener('click', closeModal);
    $('.ti-modal-backdrop').addEventListener('click', closeModal);
    $('#modal-copy').addEventListener('click', async () => {
      await navigator.clipboard.writeText($('#modal-prompt').value);
      toast('Copied');
    });
    $('#modal-copy-open').addEventListener('click', async () => {
      await navigator.clipboard.writeText($('#modal-prompt').value);
      chrome.tabs.create({ url: 'https://copilot.microsoft.com/' });
      toast('Copied, paste with Ctrl+V');
      closeModal();
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
      toast('Cannot read page');
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
    if (!enrichments.length) return toast('Enrich first');
    const md = SOCReport.buildMarkdown(enrichments, { pageUrl: state.pageUrl });
    await navigator.clipboard.writeText(md);
    toast('Report copied');
  }

  function openCopilotModal() {
    if (!state.iocs.length) return toast('Nothing to send');
    const enrichments = state.iocs.map(i => state.enrichments[key(i)]).filter(Boolean);
    if (!enrichments.length) return toast('Enrich first');
    const prompt = SOCReport.buildCopilotPrompt(enrichments, { pageUrl: state.pageUrl });
    $('#modal-prompt').value = prompt;
    $('#modal').hidden = false;
    setTimeout(() => $('#modal-prompt').focus(), 50);
  }

  function closeModal() { $('#modal').hidden = true; }

  function render() {
    $('#ioc-count').textContent = state.iocs.length;
    const container = $('#ioc-list');
    container.innerHTML = '';
    if (!state.iocs.length) return;

    const groups = new Map();
    for (const i of state.iocs) {
      if (!groups.has(i.type)) groups.set(i.type, []);
      groups.get(i.type).push(i);
    }
    const order = ['ipv4', 'ipv6', 'domain', 'url', 'sha256', 'sha1', 'md5', 'email', 'cve', 'mitre_technique', 'mitre_tactic', 'registry', 'filepath'];

    for (const type of order) {
      if (!groups.has(type)) continue;
      const groupEl = document.createElement('div');
      groupEl.className = 'ti-group';
      groupEl.innerHTML = `<div class="ti-group-head">${type} (${groups.get(type).length})</div>`;
      for (const ioc of groups.get(type)) groupEl.appendChild(renderCard(ioc));
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
          <button data-act="expand" title="Expand">▾</button>
        </div>
      </div>
      <div class="ti-card-body"></div>
    `;

    if (enriched) renderCardBody(card.querySelector('.ti-card-body'), enriched);
    else card.querySelector('.ti-card-body').innerHTML = `<div class="ti-loading"><span class="ti-dots"><i></i><i></i><i></i></span></div>`;

    card.querySelector('[data-act="copy"]').addEventListener('click', async (ev) => {
      ev.stopPropagation();
      await navigator.clipboard.writeText(ioc.value);
      toast('Copied');
    });
    card.querySelector('[data-act="defang"]').addEventListener('click', async (ev) => {
      ev.stopPropagation();
      await navigator.clipboard.writeText(SOCParser.defang(ioc.value));
      toast('Defanged');
    });
    card.querySelector('[data-act="expand"]').addEventListener('click', (ev) => {
      ev.stopPropagation();
      card.classList.toggle('expanded');
    });
    card.querySelector('.ti-card-head').addEventListener('click', (ev) => {
      if (ev.target.closest('button')) return;
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
