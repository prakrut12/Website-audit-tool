async function getActiveTabHtml() {
  // Execute script in the active tab to get document HTML
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error('No active tab');
  const [{ result }] = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => document.documentElement.outerHTML,
  });
  return result;
}

async function sendToBackend(html, notes, baseUrl) {
  const url = (baseUrl || 'http://127.0.0.1:8080').replace(/\/$/, '') + '/ai_fix';
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ html, notes })
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.error) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

async function main() {
  const backendEl = document.getElementById('backend');
  const notesEl = document.getElementById('notes');
  const sendBtn = document.getElementById('send');

  // Load last backend URL from storage
  chrome.storage.sync.get(['backendUrl'], ({ backendUrl }) => {
    if (backendUrl) backendEl.value = backendUrl;
  });

  sendBtn.addEventListener('click', async () => {
    sendBtn.disabled = true; sendBtn.textContent = 'Sending...';
    try {
      const html = await getActiveTabHtml();
      const notes = (notesEl.value || '').trim();
      const base = (backendEl.value || '').trim();
      if (base) chrome.storage.sync.set({ backendUrl: base });
      const out = await sendToBackend(html, notes, base);
      const corrected = out?.corrected_html || '';
      // Copy corrected HTML to clipboard for convenience
      try { await navigator.clipboard.writeText(corrected); } catch (e) {}
      // Open a new tab showing the corrected HTML
      if (corrected) {
        const url = 'data:text/html;charset=utf-8,' + encodeURIComponent(corrected);
        chrome.tabs.create({ url });
      }
      sendBtn.textContent = 'Sent ✓';
      setTimeout(() => { sendBtn.disabled = false; sendBtn.textContent = 'Capture & Send'; }, 1200);
    } catch (e) {
      alert('Failed: ' + e.message);
      sendBtn.disabled = false; sendBtn.textContent = 'Capture & Send';
    }
  });
}

document.addEventListener('DOMContentLoaded', main);
