(function () {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  const IOC_TYPES = [
    ['ipv4', 'IPv4'], ['ipv6', 'IPv6'], ['domain', 'Domains'], ['url', 'URLs'],
    ['sha256', 'SHA256'], ['sha1', 'SHA1'], ['md5', 'MD5'], ['email', 'Emails'],
    ['cve', 'CVEs'], ['mitre_technique', 'MITRE techniques'], ['mitre_tactic', 'MITRE tactics'],
    ['registry', 'Registry keys'], ['filepath', 'File paths'],
  ];

  // Enrichment sources: id (matches lib/enrichment.js), label, and the key inputs
  // it needs. Sources with no key inputs are free and always listed.
  const SOURCES = [
    ['ipapi', 'ip-api (geo / ASN)', []],
    ['dns', 'Google DNS', []],
    ['rdap', 'RDAP', []],
    ['nvd', 'NVD (CVEs)', []],
    ['proxycheck', 'ProxyCheck', []],
    ['circl_hashlookup', 'CIRCL hashlookup', []],
    ['ripestat', 'RIPE Stat (routing / abuse)', []],
    ['cymru', 'Team Cymru (ASN)', []],
    ['dshield', 'SANS ISC / DShield', []],
    ['dnssec', 'DNSSEC validation', []],
    ['virustotal', 'VirusTotal', ['vt']],
    ['abuseipdb', 'AbuseIPDB', ['aipb']],
    ['greynoise', 'GreyNoise', ['gn']],
    ['ipinfo', 'IPInfo', ['ipinfo']],
    ['shodan', 'Shodan', ['shodan']],
    ['otx', 'AlienVault OTX', ['otx']],
    ['urlscan', 'urlscan.io', ['urlscan']],
    ['crowdsec', 'CrowdSec', ['crowdsec']],
    ['pulsedive', 'Pulsedive', ['pulsedive']],
    ['censys', 'Censys', ['censys_id', 'censys_secret']],
    ['hybrid_analysis', 'Hybrid Analysis', ['hybrid_analysis']],
    ['anyrun', 'ANY.RUN', ['anyrun']],
    ['fullhunt', 'FullHunt', ['fullhunt']],
    ['polyswarm', 'PolySwarm', ['polyswarm']],
    ['intelx', 'Intelligence X', ['intelx']],
    ['urlhaus', 'URLhaus (abuse.ch)', ['abusech']],
    ['threatfox', 'ThreatFox (abuse.ch)', ['abusech']],
    ['malwarebazaar', 'MalwareBazaar (abuse.ch)', ['abusech']],
    ['phishtank', 'PhishTank', ['phishtank']],
  ];

  // Source on/off state, kept across re-renders of the source list
  let sourceState = {};

  document.addEventListener('DOMContentLoaded', init);

  async function init() {
    const resp = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });
    if (!resp?.ok) return;
    const s = resp.data;

    $('#vt').value = s.apiKeys.virustotal || '';
    $('#aipb').value = s.apiKeys.abuseipdb || '';
    $('#gn').value = s.apiKeys.greynoise || '';
    const extraKeys = ['proxycheck','ipinfo','shodan','otx','urlscan','crowdsec','pulsedive','censys_id','censys_secret','hybrid_analysis','anyrun','fullhunt','polyswarm','intelx','abusech','phishtank'];
    for (const k of extraKeys) {
      const el = document.getElementById(k);
      if (el) el.value = s.apiKeys[k] || '';
    }
    $('#autoscan').checked = !!s.behavior.autoScanOnLoad;
    $('#hover').checked = !!s.behavior.hoverTooltipsEnabled;
    $('#private-ips').checked = !!s.behavior.excludePrivateIPs;
    $('#known-tld').checked = !!s.behavior.requireKnownTLD;
    $('#defang-copy').checked = !!s.behavior.defangOnCopy;
    $('#gti-enabled').checked = !!s.behavior.gtiEnabled;
    $('#vt-behavior').checked = s.behavior.vtBehaviorEnabled !== false;
    renderToggleGrid($('#tooltip-types'), IOC_TYPES, s.behavior.tooltipTypes || {});
    renderToggleGrid($('#sidepanel-types'), IOC_TYPES, s.behavior.sidepanelTypes || {});
    $('#sp-use-tooltip').checked = s.behavior.sidepanelUseTooltipTypes !== false;
    $('#sp-types-wrap').hidden = $('#sp-use-tooltip').checked;
    $('#sp-use-tooltip').addEventListener('change', (e) => { $('#sp-types-wrap').hidden = e.target.checked; });

    sourceState = Object.assign({}, s.behavior.enabledSources || {});
    renderSources();
    // Show or hide keyed sources as keys are typed or cleared
    const keyInputs = new Set(SOURCES.flatMap(([, , inputs]) => inputs));
    for (const id of keyInputs) document.getElementById(id)?.addEventListener('input', renderSources);

    for (const btn of $$('[data-bulk]')) {
      btn.addEventListener('click', () => {
        const on = btn.dataset.on === '1';
        for (const el of $$('input[type=checkbox]', document.getElementById(btn.dataset.bulk))) {
          el.checked = on;
          el.dispatchEvent(new Event('change'));
        }
      });
    }

    for (const c of (s.apiKeys.custom || [])) addCustomRow(c);

    $('#add-custom').addEventListener('click', () => addCustomRow({}));
    $('#save').addEventListener('click', save);
    $('#export-cfg').addEventListener('click', exportCfg);
    $('#import-cfg').addEventListener('click', () => $('#import-file').click());
    $('#import-file').addEventListener('change', importCfg);
    $('#clear-case').addEventListener('click', async () => {
      await chrome.storage.local.set({ caseNotes: [] });
      flashSaved('Cleared');
    });
  }

  function renderToggleGrid(container, items, values) {
    container.innerHTML = '';
    for (const [id, label] of items) {
      const row = document.createElement('label');
      row.className = 'ti-switch';
      row.innerHTML = '<input type="checkbox"><span></span>';
      row.querySelector('input').dataset.id = id;
      row.querySelector('input').checked = values[id] !== false;
      row.querySelector('span').textContent = label;
      container.appendChild(row);
    }
  }

  function readToggleGrid(container) {
    return Object.fromEntries($$('input[type=checkbox]', container).map(el => [el.dataset.id, el.checked]));
  }

  function hasKeys(inputs) {
    return inputs.every(id => (document.getElementById(id)?.value || '').trim());
  }

  function renderSources() {
    const container = $('#source-list');
    Object.assign(sourceState, readToggleGrid(container));
    const available = SOURCES.filter(([, , inputs]) => hasKeys(inputs));
    renderToggleGrid(container, available, sourceState);
    for (const el of $$('input[type=checkbox]', container)) {
      el.addEventListener('change', () => { sourceState[el.dataset.id] = el.checked; });
    }
  }

  function addCustomRow(c) {
    const tpl = document.getElementById('custom-tpl');
    const node = tpl.content.firstElementChild.cloneNode(true);
    node.querySelector('.c-name').value = c.name || '';
    node.querySelector('.c-url').value = c.url || '';
    node.querySelector('.c-header').value = c.header || '';
    node.querySelector('.c-key').value = c.key || '';
    node.querySelector('.c-remove').addEventListener('click', () => node.remove());
    $('#custom-list').appendChild(node);
  }

  async function save() {
    const custom = $$('.ti-custom').map(el => ({
      name: el.querySelector('.c-name').value.trim(),
      url: el.querySelector('.c-url').value.trim(),
      header: el.querySelector('.c-header').value.trim(),
      key: el.querySelector('.c-key').value.trim(),
    })).filter(c => c.name && c.url);

    const extraKeys = ['proxycheck','ipinfo','shodan','otx','urlscan','crowdsec','pulsedive','censys_id','censys_secret','hybrid_analysis','anyrun','fullhunt','polyswarm','intelx','abusech','phishtank'];
    const apiKeys = {
      virustotal: $('#vt').value.trim(),
      abuseipdb: $('#aipb').value.trim(),
      greynoise: $('#gn').value.trim(),
      custom,
    };
    for (const k of extraKeys) {
      const el = document.getElementById(k);
      if (el) apiKeys[k] = el.value.trim();
    }
    const settings = {
      apiKeys,
      behavior: {
        autoScanOnLoad: $('#autoscan').checked,
        hoverTooltipsEnabled: $('#hover').checked,
        excludePrivateIPs: $('#private-ips').checked,
        requireKnownTLD: $('#known-tld').checked,
        defangOnCopy: $('#defang-copy').checked,
        gtiEnabled: $('#gti-enabled').checked,
        vtBehaviorEnabled: $('#vt-behavior').checked,
        tooltipTypes: readToggleGrid($('#tooltip-types')),
        sidepanelUseTooltipTypes: $('#sp-use-tooltip').checked,
        sidepanelTypes: readToggleGrid($('#sidepanel-types')),
        enabledSources: Object.assign({}, sourceState, readToggleGrid($('#source-list'))),
      },
    };

    const resp = await chrome.runtime.sendMessage({ type: 'SAVE_SETTINGS', settings });
    if (resp?.ok) flashSaved('Saved');
  }

  async function exportCfg() {
    const resp = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });
    if (!resp?.ok) return;
    const blob = new Blob([JSON.stringify(resp.data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'threat-intelligence-config.json';
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 500);
  }

  async function importCfg(ev) {
    const file = ev.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    try {
      const settings = JSON.parse(text);
      await chrome.runtime.sendMessage({ type: 'SAVE_SETTINGS', settings });
      location.reload();
    } catch (e) {
      alert('Invalid config');
    }
  }

  function flashSaved(msg) {
    const el = $('#saved');
    el.textContent = msg;
    el.hidden = false;
    setTimeout(() => { el.hidden = true; }, 1500);
  }
})();
