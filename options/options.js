(function () {
  'use strict';
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

  document.addEventListener('DOMContentLoaded', init);

  async function init() {
    const resp = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });
    if (!resp?.ok) return;
    const s = resp.data;

    $('#vt').value = s.apiKeys.virustotal || '';
    $('#aipb').value = s.apiKeys.abuseipdb || '';
    $('#gn').value = s.apiKeys.greynoise || '';
    const extraKeys = ['proxycheck','ipinfo','shodan','otx','urlscan','crowdsec','pulsedive','censys_id','censys_secret','hybrid_analysis','anyrun','fullhunt','polyswarm','intelx'];
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

    const extraKeys = ['proxycheck','ipinfo','shodan','otx','urlscan','crowdsec','pulsedive','censys_id','censys_secret','hybrid_analysis','anyrun','fullhunt','polyswarm','intelx'];
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
