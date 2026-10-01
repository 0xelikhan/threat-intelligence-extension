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
    $('#send-copilot').addEventListener('click', openCopilotWindow);
    $('#settings-btn').addEventListener('click', () => chrome.runtime.openOptionsPage());

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

  async function openCopilotWindow() {
    if (!state.iocs.length) return toast('Nothing to send');
    const enrichments = state.iocs.map(i => state.enrichments[key(i)]).filter(Boolean);
    if (!enrichments.length) return toast('Enrich first');
    const prompt = SOCReport.buildCopilotPrompt(enrichments, { pageUrl: state.pageUrl });
    await chrome.storage.local.set({ pendingCopilotPrompt: prompt });
    chrome.windows.create({
      url: chrome.runtime.getURL('copilot/copilot.html'),
      type: 'popup',
      width: 620,
      height: 720,
    });
  }

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
      const v = r.virustotal;
      if (v.notFound) rows.push(kv('VirusTotal', 'not indexed', v.link));
      else {
        const bar = ratioBar(v.malicious || 0, v.total || 0);
        rows.push(kv('VirusTotal', `${bar} ${v.malicious || 0}/${v.total || 0}`, v.link));

        // GTI verdict
        if (v.gti?.verdict) {
          const sev = v.gti.severity ? ` / ${v.gti.severity}` : '';
          const score = v.gti.threatScore != null ? ` · score ${v.gti.threatScore}` : '';
          rows.push(kv('GTI', `${v.gti.verdict}${sev}${score}`));
          if (v.gti.description) rows.push(`<div class="ti-desc">${escapeHtml(v.gti.description.slice(0, 400))}</div>`);
        }
        if (v.mandiantScore != null) rows.push(kv('Mandiant IC', String(v.mandiantScore)));

        // Threat family / categories
        if (v.threatFamily) rows.push(kv('Threat', v.threatFamily));
        if (v.threatCategories?.length) rows.push(kv('Category', v.threatCategories.join(', ')));
        if (v.threatFamilies?.length && !v.threatFamily) rows.push(kv('Family', v.threatFamilies.join(', ')));

        // Popularity ranks (domains)
        if (v.popularity?.length) {
          const ranks = v.popularity.slice(0, 3).map(p => `${p.source}: ${p.rank}`).join(' · ');
          rows.push(kv('Popularity', ranks));
        }

        // Categories per-vendor (domains/URLs)
        if (v.categories && typeof v.categories === 'object') {
          const cats = Object.entries(v.categories).slice(0, 4).map(([k, val]) => `${k}=${val}`).join(', ');
          if (cats) rows.push(kv('Vendor Tags', cats));
        }

        // Tags
        if (v.tags?.length) rows.push(kv('Tags', v.tags.slice(0, 8).join(', ')));

        // Sigma/IDS/YARA
        if (v.sigmaHits?.length) rows.push(kv('Sigma', v.sigmaHits.slice(0, 3).map(s => `${s.title || s.id} [${s.level || ''}]`).join(' · ')));
        if (v.idsHits?.length) rows.push(kv('IDS', v.idsHits.slice(0, 3).map(s => `${s.alert || s.category}`).join(' · ')));
        if (v.yaraHits?.length) rows.push(kv('YARA', v.yaraHits.slice(0, 3).map(s => s.name || s.ruleset).join(' · ')));

        // Sandbox verdicts
        if (v.sandbox?.length) {
          const parts = v.sandbox.slice(0, 3).map(s => `${s.sandbox}: ${s.category}${s.malwareClasses?.length ? ' (' + s.malwareClasses.slice(0, 2).join(', ') + ')' : ''}`);
          rows.push(kv('Sandbox', parts.join(' · ')));
        }

        // Signature (files)
        if (v.signature) {
          const sig = v.signature;
          const verdict = sig.verified === 'Signed' ? '✓ signed' : (sig.verified || 'unsigned');
          const signer = sig.signers ? String(sig.signers).split(';')[0] : '';
          rows.push(kv('Sig', `${verdict}${signer ? ' · ' + signer : ''}`));
        }

        // JARM / TLS cert
        if (v.jarm) rows.push(kv('JARM', v.jarm));
        if (v.httpsCert) {
          const c = v.httpsCert;
          const issuer = c.issuer?.CN || c.issuer?.O || '';
          const subject = c.subject?.CN || '';
          if (issuer || subject) rows.push(kv('TLS Cert', `${subject}${subject && issuer ? ' / ' : ''}${issuer}`));
        }

        // Passive DNS (domains)
        if (v.lastDns?.length) {
          const dns = v.lastDns.slice(0, 4).map(d => `${d.type}: ${d.value}`).join(' · ');
          rows.push(kv('VT DNS', dns));
        }

        // File extras
        if (v.fileExtras) {
          const fe = v.fileExtras;
          if (fe.typeTag || fe.magic) rows.push(kv('File Type', `${fe.typeTag || ''}${fe.typeTag && fe.magic ? ' · ' : ''}${fe.magic || ''}`));
          if (fe.size) rows.push(kv('Size', `${fe.size.toLocaleString()} bytes`));
          if (fe.imphash) rows.push(kv('imphash', fe.imphash));
          if (fe.ssdeep) rows.push(kv('ssdeep', fe.ssdeep));
          if (fe.timesSubmitted) rows.push(kv('Submissions', `${fe.timesSubmitted} · ${fe.uniqueSources} unique sources`));
          if (fe.creationDate) rows.push(kv('Compiled', new Date(fe.creationDate * 1000).toISOString().slice(0, 10)));
        }

        // IP extras
        if (v.ipExtras) {
          const ie = v.ipExtras;
          if (ie.network) rows.push(kv('VT Network', `${ie.network}${ie.rir ? ' · ' + ie.rir : ''}`));
        }

        // URL extras
        if (v.urlExtras) {
          const ue = v.urlExtras;
          if (ue.finalUrl && ue.finalUrl !== enriched.ioc.value) rows.push(kv('Final URL', ue.finalUrl));
          if (ue.title) rows.push(kv('Title', ue.title));
          if (ue.threatNames?.length) rows.push(kv('Threat Names', ue.threatNames.slice(0, 3).join(', ')));
        }
      }
    }

    // VT Behavior (files)
    if (r.vtBehavior && !r.vtBehavior.error && !r.vtBehavior.notFound) {
      const b = r.vtBehavior;
      if (b.processesCreated?.length) rows.push(kv('Processes', b.processesCreated.slice(0, 3).join(' · ')));
      if (b.commandExecutions?.length) rows.push(kv('Commands', b.commandExecutions.slice(0, 2).map(c => c.length > 100 ? c.slice(0, 100) + '…' : c).join(' | ')));
      if (b.filesDropped?.length) rows.push(kv('Files Dropped', b.filesDropped.slice(0, 3).map(f => f.path).filter(Boolean).join(' · ')));
      if (b.registryKeysSet?.length) rows.push(kv('Registry Set', b.registryKeysSet.slice(0, 3).join(' · ')));
      if (b.mutexesCreated?.length) rows.push(kv('Mutexes', b.mutexesCreated.slice(0, 3).join(', ')));
      if (b.dnsLookups?.length) rows.push(kv('DNS Queries', b.dnsLookups.slice(0, 5).join(', ')));
      if (b.ipTraffic?.length) rows.push(kv('IP Traffic', b.ipTraffic.slice(0, 5).join(', ')));
      if (b.mitre?.length) {
        const t = b.mitre.slice(0, 6).map(m => m.id || m.signature_description).filter(Boolean).join(', ');
        if (t) rows.push(kv('MITRE', t));
      }
    }

    // GTI Collections (attribution)
    if (r.gtiCollections && !r.gtiCollections.error && !r.gtiCollections.notFound && r.gtiCollections.count > 0) {
      const g = r.gtiCollections;
      const linkList = (items) => items.slice(0, 4).map(a =>
        `<a class="ti-link" href="${escapeHtml(a.link)}" target="_blank" rel="noopener">${escapeHtml(a.name)}</a>`
      ).join(' · ');
      const rawRow = (k, html) => `<div class="ti-row"><span class="ti-k">${escapeHtml(k)}</span><span class="ti-v">${html}</span></div>`;
      if (g.grouped.threat_actor.length) rows.push(rawRow('Threat Actor', linkList(g.grouped.threat_actor)));
      if (g.grouped.malware_family.length) rows.push(rawRow('Malware', linkList(g.grouped.malware_family)));
      if (g.grouped.campaign.length) rows.push(rawRow('Campaign', linkList(g.grouped.campaign)));
      if (g.grouped.report.length) rows.push(rawRow('Reports', linkList(g.grouped.report)));
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

    // ─── New sources ────────────────────────────────────────────────────
    if (r.proxycheck && !r.proxycheck.error) {
      const p = r.proxycheck;
      const flags = [];
      if (p.proxy) flags.push('proxy');
      if (p.vpn) flags.push('VPN');
      if (p.type) flags.push(p.type);
      rows.push(kv('ProxyCheck', `risk ${p.riskScore ?? '?'}${flags.length ? ' · ' + flags.join(', ') : ''}${p.provider ? ' · ' + p.provider : ''}`, p.link));
    }
    if (r.ipinfo && !r.ipinfo.error) {
      const i = r.ipinfo;
      rows.push(kv('IPInfo', `${i.city || ''}, ${i.region || ''} ${i.country || ''}${i.org ? ' · ' + i.org : ''}`, i.link));
      if (i.privacy) {
        const flags = Object.entries(i.privacy).filter(([k, v]) => v === true).map(([k]) => k);
        if (flags.length) rows.push(kv('IPInfo flags', flags.join(', ')));
      }
    }
    if (r.shodan && !r.shodan.error) {
      if (r.shodan.notFound) rows.push(kv('Shodan', 'not indexed', r.shodan.link));
      else {
        const s = r.shodan;
        rows.push(kv('Shodan', `${(s.ports || []).join(', ')}${s.os ? ' · ' + s.os : ''}${s.org ? ' · ' + s.org : ''}`, s.link));
        if (s.vulns?.length) rows.push(kv('Shodan vulns', (Array.isArray(s.vulns) ? s.vulns.slice(0, 6) : Object.keys(s.vulns).slice(0, 6)).join(', ')));
      }
    }
    if (r.otx && !r.otx.error) {
      if (r.otx.notFound || r.otx.pulseCount === 0) rows.push(kv('OTX', 'no pulses', r.otx.link));
      else {
        const o = r.otx;
        rows.push(kv('OTX', `${o.pulseCount} pulses`, o.link));
        if (o.pulses?.length) {
          const names = o.pulses.slice(0, 3).map(p => p.name).filter(Boolean);
          if (names.length) rows.push(kv('OTX top', names.join(' · ')));
        }
      }
    }
    if (r.urlscan && !r.urlscan.error) {
      const u = r.urlscan;
      const verdict = u.malicious ? '🔴 malicious' : (u.total > 0 ? '🟢 clean history' : 'no scans');
      rows.push(kv('URLScan', `${u.total || 0} scans · ${verdict}`, u.link));
    }
    if (r.crowdsec && !r.crowdsec.error && !r.crowdsec.notFound) {
      const c = r.crowdsec;
      const beh = (c.behaviors || []).slice(0, 3).join(', ');
      rows.push(kv('CrowdSec', `${c.reputation || '?'}${c.confidence ? ' · ' + c.confidence : ''}${beh ? ' · ' + beh : ''}`, c.link));
    }
    if (r.pulsedive && !r.pulsedive.error && !r.pulsedive.notFound) {
      const p = r.pulsedive;
      const threats = (p.threats || []).slice(0, 3).join(', ');
      rows.push(kv('Pulsedive', `risk: ${p.risk || '?'}${threats ? ' · ' + threats : ''}`, p.link));
    }
    if (r.censys && !r.censys.error && !r.censys.notFound) {
      const c = r.censys;
      const ports = (c.services || []).map(s => s.port).join(', ');
      rows.push(kv('Censys', `${ports || 'no services'}${c.os ? ' · ' + c.os : ''}`, c.link));
    }
    if (r.hybridAnalysis && !r.hybridAnalysis.error && !r.hybridAnalysis.notFound) {
      const h = r.hybridAnalysis;
      const dot = h.threatLevel >= 2 ? '🔴' : h.threatLevel === 1 ? '🟠' : '🟢';
      rows.push(kv('HybridAnalysis', `${dot} ${h.verdict || '?'}${h.threatScore != null ? ' · score ' + h.threatScore : ''}${h.threatLabel ? ' · ' + h.threatLabel : ''}`, h.link));
    }
    if (r.anyrun && !r.anyrun.error && r.anyrun.count > 0) {
      const a = r.anyrun;
      const verdicts = a.tasks.slice(0, 3).map(t => t.verdict || t.malwareFamily || 'unknown').filter(Boolean);
      rows.push(kv('Any.Run', `${a.count} tasks${verdicts.length ? ' · ' + verdicts.join(', ') : ''}`, a.link));
    }
    if (r.fullhunt && !r.fullhunt.error && !r.fullhunt.notFound) {
      const f = r.fullhunt;
      rows.push(kv('FullHunt', `${f.subdomainsCount || 0} subdomains${f.ports?.length ? ' · ports: ' + f.ports.slice(0, 6).join(', ') : ''}`, f.link));
    }
    if (r.polyswarm && !r.polyswarm.error && !r.polyswarm.notFound) {
      const p = r.polyswarm;
      rows.push(kv('Polyswarm', `score: ${p.polyscore ?? '?'}${p.mimetype ? ' · ' + p.mimetype : ''}`, p.link));
    }
    if (r.intelx && !r.intelx.error && !r.intelx.notFound && r.intelx.total > 0) {
      rows.push(kv('IntelX', `${r.intelx.total} hits`, r.intelx.link));
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
