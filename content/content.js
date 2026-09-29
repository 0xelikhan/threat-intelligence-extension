/*
 * Threat Intelligence — content script
 * - Scans page text for IOCs on load (when enabled)
 * - Highlights IOCs and shows a floating enrichment card on hover
 */
(function () {
  'use strict';

  const state = {
    settings: null,
    iocs: [],
    hoverEl: null,
    hoverAnchor: null,
    highlightWrappers: new WeakSet(),
    scanTimer: null,
  };

  // Skip if we're inside a chrome-extension or edge://
  if (location.protocol === 'chrome-extension:' || location.protocol === 'edge:') return;

  async function boot() {
    const resp = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }).catch(() => null);
    if (!resp?.ok) return;
    state.settings = resp.data;

    injectHoverCard();

    if (state.settings.behavior.autoScanOnLoad) {
      scheduleScan();
      const mo = new MutationObserver(() => scheduleScan());
      mo.observe(document.body, { childList: true, subtree: true, characterData: true });
    }
  }

  function scheduleScan() {
    clearTimeout(state.scanTimer);
    state.scanTimer = setTimeout(scanAndHighlight, 400);
  }

  async function scanAndHighlight() {
    if (!state.settings?.behavior?.hoverTooltipsEnabled) return;
    const text = document.body.innerText || '';
    const iocs = SOCParser.extract(text, {
      excludePrivateIPs: state.settings.behavior.excludePrivateIPs,
      requireKnownTLD: state.settings.behavior.requireKnownTLD,
    });
    state.iocs = iocs;
    // Publish count to the badge (optional)
    chrome.runtime.sendMessage({ type: 'PAGE_IOC_COUNT', count: iocs.length }).catch(() => {});
    highlightMatches(iocs);
  }

  function highlightMatches(iocs) {
    if (!iocs.length) return;
    // Build a single alternation regex from unique values, escaped
    const values = [...new Set(iocs.map(i => i.value))]
      .filter(v => v.length >= 4 && v.length <= 200)
      .map(escapeRegex)
      .sort((a, b) => b.length - a.length);
    if (!values.length) return;
    const re = new RegExp('(' + values.join('|') + ')', 'g');
    const valueToType = new Map(iocs.map(i => [i.value, i.type]));

    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        const tag = parent.tagName;
        if (['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEXTAREA', 'INPUT'].includes(tag)) return NodeFilter.FILTER_REJECT;
        if (parent.classList.contains('ti-ioc')) return NodeFilter.FILTER_REJECT;
        if (parent.closest('[data-ti-skip]')) return NodeFilter.FILTER_REJECT;
        if (!node.nodeValue || node.nodeValue.length < 4) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      },
    });

    const targets = [];
    let n; let count = 0;
    while ((n = walker.nextNode()) && count < 3000) {
      re.lastIndex = 0;
      if (re.test(n.nodeValue)) {
        targets.push(n);
        count++;
      }
    }

    for (const node of targets) {
      const text = node.nodeValue;
      re.lastIndex = 0;
      const frag = document.createDocumentFragment();
      let lastIndex = 0;
      let match;
      let hadMatch = false;
      while ((match = re.exec(text)) !== null) {
        hadMatch = true;
        const start = match.index;
        const value = match[0];
        const type = valueToType.get(value) || 'unknown';
        if (start > lastIndex) {
          frag.appendChild(document.createTextNode(text.slice(lastIndex, start)));
        }
        const span = document.createElement('span');
        span.className = `ti-ioc ti-ioc-${type}`;
        span.textContent = value;
        span.dataset.tiType = type;
        span.dataset.tiValue = value;
        span.tabIndex = 0;
        frag.appendChild(span);
        lastIndex = start + value.length;
      }
      if (!hadMatch) continue;
      if (lastIndex < text.length) {
        frag.appendChild(document.createTextNode(text.slice(lastIndex)));
      }
      try { node.parentNode?.replaceChild(frag, node); } catch (_) {}
    }
  }

  function escapeRegex(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  // ─── Hover card ────────────────────────────────────────────────────────────
  function injectHoverCard() {
    const el = document.createElement('div');
    el.id = 'ti-hover-card';
    el.setAttribute('data-ti-skip', '');
    el.innerHTML = `
      <div class="ti-hc-head">
        <span class="ti-hc-type"></span>
        <span class="ti-hc-value"></span>
        <button class="ti-hc-close" aria-label="close">×</button>
      </div>
      <div class="ti-hc-body"></div>
      <div class="ti-hc-actions">
        <button data-act="copy">Copy</button>
        <button data-act="defang">Defang</button>
        <button data-act="pivot-vt">VT</button>
        <button data-act="pivot-aipb">AbuseIPDB</button>
        <button data-act="sidepanel">Add to case</button>
      </div>
    `;
    document.documentElement.appendChild(el);
    state.hoverEl = el;

    el.querySelector('.ti-hc-close').addEventListener('click', hideCard);
    el.addEventListener('mouseleave', () => {
      state.hideTimer = setTimeout(hideCard, 200);
    });
    el.addEventListener('mouseenter', () => clearTimeout(state.hideTimer));

    el.addEventListener('click', async (ev) => {
      const btn = ev.target.closest('button[data-act]');
      if (!btn) return;
      const act = btn.dataset.act;
      const ioc = state.hoverAnchor?.dataset.tiValue;
      const type = state.hoverAnchor?.dataset.tiType;
      if (!ioc) return;
      if (act === 'copy') {
        await navigator.clipboard.writeText(ioc);
        flash(btn, 'copied');
      } else if (act === 'defang') {
        await navigator.clipboard.writeText(SOCParser.defang(ioc));
        flash(btn, 'defanged');
      } else if (act === 'pivot-vt') {
        const link = pivotLink('vt', type, ioc);
        window.open(link, '_blank');
      } else if (act === 'pivot-aipb') {
        if (type === 'ipv4' || type === 'ipv6') {
          window.open(`https://www.abuseipdb.com/check/${encodeURIComponent(ioc)}`, '_blank');
        }
      } else if (act === 'sidepanel') {
        chrome.runtime.sendMessage({ type: 'SIDEPANEL_ADD_TEXT', text: ioc }).catch(() => {});
      }
    });

    document.addEventListener('mouseover', onHoverEnter, true);
    document.addEventListener('mouseout', onHoverLeave, true);
  }

  function onHoverEnter(ev) {
    const target = ev.target;
    if (!target || !target.classList || !target.classList.contains('ti-ioc')) return;
    clearTimeout(state.hideTimer);
    state.hoverAnchor = target;
    positionCard(target);
    populateCard(target);
  }

  function onHoverLeave(ev) {
    const target = ev.target;
    if (!target || !target.classList || !target.classList.contains('ti-ioc')) return;
    const to = ev.relatedTarget;
    if (to && (to === state.hoverEl || state.hoverEl.contains(to))) return;
    state.hideTimer = setTimeout(hideCard, 250);
  }

  function positionCard(anchor) {
    const rect = anchor.getBoundingClientRect();
    const card = state.hoverEl;
    card.style.display = 'block';
    const cardRect = card.getBoundingClientRect();
    const gap = 8;
    let top = rect.bottom + window.scrollY + gap;
    let left = rect.left + window.scrollX;
    if (left + cardRect.width > window.scrollX + window.innerWidth - 12) {
      left = window.scrollX + window.innerWidth - cardRect.width - 12;
    }
    if (rect.bottom + cardRect.height + gap > window.innerHeight) {
      top = rect.top + window.scrollY - cardRect.height - gap;
    }
    card.style.top = Math.max(4, top) + 'px';
    card.style.left = Math.max(4, left) + 'px';
  }

  function hideCard() {
    if (state.hoverEl) state.hoverEl.style.display = 'none';
    state.hoverAnchor = null;
  }

  async function populateCard(anchor) {
    const type = anchor.dataset.tiType;
    const value = anchor.dataset.tiValue;
    const card = state.hoverEl;
    card.querySelector('.ti-hc-type').textContent = type.toUpperCase();
    card.querySelector('.ti-hc-value').textContent = value;
    const body = card.querySelector('.ti-hc-body');
    body.innerHTML = `<div class="ti-hc-loading">Enriching<span class="ti-dots"><i></i><i></i><i></i></span></div>`;

    try {
      const resp = await chrome.runtime.sendMessage({ type: 'ENRICH_IOC', ioc: { type, value } });
      if (!resp?.ok) throw new Error(resp?.error || 'unknown');
      if (state.hoverAnchor !== anchor) return; // user moved away
      body.innerHTML = renderEnrichment(resp.data);
    } catch (e) {
      body.innerHTML = `<div class="ti-hc-err">Error: ${escapeHtml(e.message)}</div>`;
    }
  }

  function renderEnrichment(enriched) {
    const r = enriched.results || {};
    const parts = [];

    // Verdict
    const verdict = SOCReport.verdictBadge(enriched);
    const cls = verdict.startsWith('MALICIOUS') ? 'bad'
              : verdict.startsWith('SUSPICIOUS') ? 'warn'
              : verdict === 'CLEAN' ? 'good' : 'muted';
    parts.push(`<div class="ti-verdict ti-verdict-${cls}">${verdict}</div>`);

    if (r.virustotal && !r.virustotal.error) {
      if (r.virustotal.notFound) {
        parts.push(row('VirusTotal', 'not indexed'));
      } else {
        const bar = ratioBar(r.virustotal.malicious, r.virustotal.total);
        parts.push(row('VirusTotal', `${bar} ${r.virustotal.malicious}/${r.virustotal.total}`));
      }
    }
    if (r.abuseipdb && !r.abuseipdb.error) {
      const conf = r.abuseipdb.confidence || 0;
      const dot = conf >= 75 ? '🔴' : conf >= 25 ? '🟠' : '🟢';
      parts.push(row('AbuseIPDB', `${dot} ${conf}/100 · ${r.abuseipdb.totalReports} reports`));
    }
    if (r.greynoise && !r.greynoise.error && !r.greynoise.notFound) {
      parts.push(row('GreyNoise', `${r.greynoise.classification || ''}${r.greynoise.name ? ' · ' + r.greynoise.name : ''}`));
    }
    if (r.ipApi && !r.ipApi.error) {
      const flag = countryFlag(r.ipApi.countryCode);
      parts.push(row('Geo', `${flag} ${r.ipApi.country || ''} · ${r.ipApi.city || ''}`));
      parts.push(row('ASN', `${r.ipApi.asn || ''} · ${r.ipApi.org || r.ipApi.isp || ''}`));
      if (r.ipApi.reverseDns) parts.push(row('rDNS', r.ipApi.reverseDns));
      const flags = [];
      if (r.ipApi.isProxy) flags.push('proxy');
      if (r.ipApi.isHosting) flags.push('hosting');
      if (r.ipApi.isMobile) flags.push('mobile');
      if (flags.length) parts.push(row('Flags', flags.join(', ')));
    }
    if (r.forwardDns && !r.forwardDns.error) {
      const a = (r.forwardDns.a || []).slice(0, 3).map(x => x.data).join(', ');
      if (a) parts.push(row('A', a));
    }
    if (r.rdap && !r.rdap.error) {
      if (r.rdap.registrar) parts.push(row('Registrar', r.rdap.registrar));
      if (r.rdap.created) parts.push(row('Registered', String(r.rdap.created).slice(0, 10)));
      if (r.rdap.name) parts.push(row('Network', r.rdap.name));
    }
    if (r.nvd && !r.nvd.error) {
      parts.push(row('CVSS', `${r.nvd.cvssScore ?? ''} (${r.nvd.severity || ''})`));
      if (r.nvd.description) parts.push(`<div class="ti-desc">${escapeHtml(r.nvd.description.slice(0, 220))}${r.nvd.description.length > 220 ? '…' : ''}</div>`);
    }

    if (!parts.length) parts.push('<div class="ti-hc-loading">No enrichment sources returned data.</div>');
    return parts.join('');
  }

  function row(label, value) {
    return `<div class="ti-row"><span class="ti-k">${escapeHtml(label)}</span><span class="ti-v">${escapeHtml(String(value))}</span></div>`;
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

  function pivotLink(source, type, value) {
    if (source === 'vt') {
      if (type === 'ipv4' || type === 'ipv6') return `https://www.virustotal.com/gui/ip-address/${value}`;
      if (type === 'domain') return `https://www.virustotal.com/gui/domain/${value}`;
      if (type === 'url') return `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
      return `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
    }
    return '#';
  }

  function flash(btn, text) {
    const orig = btn.textContent;
    btn.textContent = text;
    setTimeout(() => { btn.textContent = orig; }, 900);
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
