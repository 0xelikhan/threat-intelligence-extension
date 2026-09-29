(function () {
  'use strict';
  const $ = (s) => document.querySelector(s);

  document.addEventListener('DOMContentLoaded', () => {
    $('#open-panel').addEventListener('click', async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.windowId != null) await chrome.sidePanel.open({ windowId: tab.windowId });
      window.close();
    });
    $('#open-options').addEventListener('click', () => chrome.runtime.openOptionsPage());
    $('#go').addEventListener('click', enrich);
    $('#query').addEventListener('keydown', (e) => { if (e.key === 'Enter') enrich(); });
  });

  async function enrich() {
    const raw = $('#query').value.trim();
    if (!raw) return;
    const type = SOCParser.classify(raw);
    if (type === 'unknown') {
      $('#result').innerHTML = `<div class="ti-err">Unrecognized indicator</div>`;
      return;
    }
    const value = SOCParser.refang(raw);
    $('#result').innerHTML = `<div class="ti-loading"><span class="ti-dots"><i></i><i></i><i></i></span></div>`;
    const resp = await chrome.runtime.sendMessage({ type: 'ENRICH_IOC', ioc: { type, value } });
    if (!resp?.ok) {
      $('#result').innerHTML = `<div class="ti-err">${escapeHtml(resp?.error || 'error')}</div>`;
      return;
    }
    renderResult(resp.data);
  }

  function renderResult(enriched) {
    const r = enriched.results || {};
    const verdict = SOCReport.verdictBadge(enriched);
    const cls = verdict.startsWith('MALICIOUS') ? 'bad'
              : verdict.startsWith('SUSPICIOUS') ? 'warn'
              : verdict === 'CLEAN' ? 'good' : 'muted';
    const rows = [];
    rows.push(`<div class="ti-verdict ti-verdict-${cls}">${verdict}</div>`);
    rows.push(`<div class="ti-target">${escapeHtml(enriched.ioc.value)}</div>`);

    if (r.virustotal && !r.virustotal.error) {
      if (r.virustotal.notFound) rows.push(row('VT', 'not indexed'));
      else rows.push(row('VT', `${r.virustotal.malicious}/${r.virustotal.total}`, r.virustotal.link));
    }
    if (r.abuseipdb && !r.abuseipdb.error) rows.push(row('AbuseIPDB', `${r.abuseipdb.confidence}/100`, r.abuseipdb.link));
    if (r.ipApi && !r.ipApi.error) {
      rows.push(row('Geo', `${countryFlag(r.ipApi.countryCode)} ${r.ipApi.country || ''}, ${r.ipApi.city || ''}`));
      rows.push(row('ASN', `${r.ipApi.asn || ''} · ${r.ipApi.org || ''}`));
      if (r.ipApi.reverseDns) rows.push(row('rDNS', r.ipApi.reverseDns));
    }
    if (r.forwardDns && !r.forwardDns.error) {
      const a = (r.forwardDns.a || []).slice(0, 3).map(x => x.data).join(', ');
      if (a) rows.push(row('A', a));
    }
    if (r.rdap && !r.rdap.error) {
      if (r.rdap.registrar) rows.push(row('Registrar', r.rdap.registrar));
      if (r.rdap.created) rows.push(row('Registered', String(r.rdap.created).slice(0, 10)));
    }
    if (r.nvd && !r.nvd.error) {
      rows.push(row('CVSS', `${r.nvd.cvssScore ?? ''} (${r.nvd.severity || ''})`, r.nvd.link));
    }
    $('#result').innerHTML = rows.join('');
  }

  function row(k, v, link) {
    const linkStr = link ? ` <a class="ti-link" href="${escapeHtml(link)}" target="_blank" rel="noopener">↗</a>` : '';
    return `<div class="ti-row"><span class="ti-k">${escapeHtml(k)}</span><span class="ti-v">${escapeHtml(String(v))}${linkStr}</span></div>`;
  }
  function countryFlag(cc) {
    if (!cc || cc.length !== 2) return '';
    return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0)));
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }
})();
