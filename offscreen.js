chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.type === 'OFFSCREEN_COPY' && typeof msg.text === 'string') {
    (async () => {
      try {
        await navigator.clipboard.writeText(msg.text);
        sendResponse({ ok: true });
      } catch (e) {
        // Fallback via textarea
        const ta = document.createElement('textarea');
        ta.value = msg.text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        ta.remove();
        sendResponse({ ok: true });
      }
    })();
    return true;
  }
});
