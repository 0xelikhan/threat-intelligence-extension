/*
 * Threat Intelligence — background service worker (module)
 * Coordinates: side panel opening, context menu, enrichment RPC, tab messaging.
 */
import './lib/parser.js';
import './lib/storage.js';
import './lib/enrichment.js';
import './lib/markdown.js';

// Open side panel when action icon clicked
chrome.sidePanel?.setPanelBehavior?.({ openPanelOnActionClick: true }).catch(() => {});

// ─── Context menu ────────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'ti-enrich-selection',
    title: 'Enrich with Threat Intelligence',
    contexts: ['selection'],
  });
  chrome.contextMenus.create({
    id: 'ti-copilot-selection',
    title: 'Send selection to Copilot',
    contexts: ['selection'],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const text = (info.selectionText || '').trim();
  if (!text) return;

  if (info.menuItemId === 'ti-enrich-selection') {
    // Push selection to side panel and open it
    await chrome.sidePanel.open({ tabId: tab.id }).catch(() => {});
    // Give the panel time to boot then send the payload
    setTimeout(() => {
      chrome.runtime.sendMessage({ type: 'SIDEPANEL_ADD_TEXT', text }).catch(() => {});
    }, 250);
  } else if (info.menuItemId === 'ti-copilot-selection') {
    const iocs = SOCParser.extract(text, { excludePrivateIPs: true, requireKnownTLD: true });
    const settings = await SOCStorage.getSettings();
    const enriched = await Promise.all(iocs.slice(0, 20).map(i => SOCEnrichment.enrichIoc(i, settings)));
    const prompt = SOCReport.buildCopilotPrompt(enriched, { pageUrl: tab?.url });
    await copyToClipboardViaOffscreen(prompt);
    chrome.tabs.create({ url: `https://copilot.microsoft.com/?q=${encodeURIComponent(prompt.slice(0, 1500))}` });
  }
});

// ─── Message router ──────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      if (msg?.type === 'ENRICH_IOC') {
        const settings = await SOCStorage.getSettings();
        const enriched = await SOCEnrichment.enrichIoc(msg.ioc, settings);
        sendResponse({ ok: true, data: enriched });
      } else if (msg?.type === 'ENRICH_BATCH') {
        const settings = await SOCStorage.getSettings();
        const enriched = await Promise.all(
          (msg.iocs || []).map(i => SOCEnrichment.enrichIoc(i, settings))
        );
        sendResponse({ ok: true, data: enriched });
      } else if (msg?.type === 'PARSE_TEXT') {
        const settings = await SOCStorage.getSettings();
        const iocs = SOCParser.extract(msg.text || '', {
          excludePrivateIPs: settings.behavior.excludePrivateIPs,
          requireKnownTLD: settings.behavior.requireKnownTLD,
        });
        sendResponse({ ok: true, data: iocs });
      } else if (msg?.type === 'GET_SETTINGS') {
        sendResponse({ ok: true, data: await SOCStorage.getSettings() });
      } else if (msg?.type === 'SAVE_SETTINGS') {
        const merged = await SOCStorage.saveSettings(msg.settings || {});
        sendResponse({ ok: true, data: merged });
      } else if (msg?.type === 'BUILD_REPORT') {
        const md = SOCReport.buildMarkdown(msg.enrichments || [], msg.opts || {});
        sendResponse({ ok: true, data: md });
      } else if (msg?.type === 'BUILD_COPILOT_PROMPT') {
        const prompt = SOCReport.buildCopilotPrompt(msg.enrichments || [], msg.opts || {});
        sendResponse({ ok: true, data: prompt });
      } else if (msg?.type === 'OPEN_COPILOT') {
        chrome.tabs.create({ url: `https://copilot.microsoft.com/?q=${encodeURIComponent((msg.prompt || '').slice(0, 1500))}` });
        sendResponse({ ok: true });
      } else {
        sendResponse({ ok: false, error: 'unknown message type' });
      }
    } catch (err) {
      sendResponse({ ok: false, error: err.message || String(err) });
    }
  })();
  return true; // async
});

// ─── Clipboard via offscreen (service worker can't touch clipboard directly) ─
async function copyToClipboardViaOffscreen(text) {
  try {
    await chrome.offscreen?.createDocument?.({
      url: 'offscreen.html',
      reasons: ['CLIPBOARD'],
      justification: 'Write enrichment report to clipboard',
    });
  } catch (_) { /* already exists */ }
  await chrome.runtime.sendMessage({ type: 'OFFSCREEN_COPY', text }).catch(() => {});
}
