(function () {
  'use strict';
  const $ = (s) => document.querySelector(s);

  document.addEventListener('DOMContentLoaded', async () => {
    const { pendingCopilotPrompt = '' } = await chrome.storage.local.get('pendingCopilotPrompt');
    $('#prompt').value = pendingCopilotPrompt;
    updateCount();
    $('#prompt').addEventListener('input', updateCount);
    $('#copy').addEventListener('click', copy);
    $('#copy-open').addEventListener('click', copyAndOpen);
    // Clear the pending prompt so it doesn't reappear next time
    chrome.storage.local.remove('pendingCopilotPrompt');
    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') copyAndOpen();
      if (e.key === 'Escape') window.close();
    });
  });

  function updateCount() {
    $('#chars').textContent = $('#prompt').value.length.toLocaleString();
  }

  async function copy() {
    await navigator.clipboard.writeText($('#prompt').value);
    toast('Copied');
  }
  async function copyAndOpen() {
    await navigator.clipboard.writeText($('#prompt').value);
    await chrome.tabs.create({ url: 'https://copilot.microsoft.com/' });
    toast('Copied, paste with Ctrl+V');
    setTimeout(() => window.close(), 600);
  }

  function toast(msg) {
    const el = $('#toast');
    el.textContent = msg;
    el.hidden = false;
    clearTimeout(toast._t);
    toast._t = setTimeout(() => { el.hidden = true; }, 1400);
  }
})();
