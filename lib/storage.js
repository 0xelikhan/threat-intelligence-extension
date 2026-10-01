/*
 * Threat Intelligence: settings/storage wrapper
 */
(function (root) {
  'use strict';

  const DEFAULTS = {
    apiKeys: {
      virustotal: '',
      abuseipdb: '',
      greynoise: '',
      proxycheck: '',
      ipinfo: '',
      shodan: '',
      otx: '',
      urlscan: '',
      crowdsec: '',
      pulsedive: '',
      censys_id: '',
      censys_secret: '',
      hybrid_analysis: '',
      anyrun: '',
      fullhunt: '',
      polyswarm: '',
      intelx: '',
      custom: [],
    },
    behavior: {
      excludePrivateIPs: true,
      requireKnownTLD: true,
      autoScanOnLoad: true,
      hoverTooltipsEnabled: true,
      defangOnCopy: false,
      gtiEnabled: false,
      vtBehaviorEnabled: true,
    },
    ui: {
      accent: 'cyan',
    },
    caseNotes: [],
  };

  function deepMerge(target, src) {
    const out = Array.isArray(target) ? target.slice() : Object.assign({}, target);
    for (const k of Object.keys(src || {})) {
      const s = src[k];
      if (s && typeof s === 'object' && !Array.isArray(s) && out[k] && typeof out[k] === 'object') {
        out[k] = deepMerge(out[k], s);
      } else if (s !== undefined) {
        out[k] = s;
      }
    }
    return out;
  }

  async function getSettings() {
    const stored = await chrome.storage.local.get('settings');
    return deepMerge(DEFAULTS, stored.settings || {});
  }

  async function saveSettings(partial) {
    const current = await getSettings();
    const merged = deepMerge(current, partial);
    await chrome.storage.local.set({ settings: merged });
    return merged;
  }

  async function getApiKey(name) {
    const s = await getSettings();
    return s.apiKeys[name] || '';
  }

  root.SOCStorage = { getSettings, saveSettings, getApiKey, DEFAULTS };
})(typeof self !== 'undefined' ? self : globalThis);
