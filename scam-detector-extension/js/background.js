const API_BASE_URL = 'http://localhost:8000';

// Initialize context menu on install/update
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: 'analyze-selection',
    title: 'Analyze for Scam',
    contexts: ['selection', 'link', 'page'],
  });
});

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'analyze-selection') {
    const content = info.selectionText || info.linkUrl || tab.url;
    const inputType = info.selectionText ? 'text' : 'url';

    try {
      // Send to backend
      const response = await fetch(`${API_BASE_URL}/api/scans`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          input_type: inputType,
          content: content,
        }),
      });

      if (!response.ok) throw new Error('Analysis failed');
      const result = await response.json();

      // Inject warning if high risk
      if (result.verdict === 'likely_scam') {
        await injectWarningBanner(tab.id, result);
      }

      // Save to history
      await saveToHistory(tab.url, result);

      // Show notification
      showNotification(result);

      // Open popup with results
      chrome.action.openPopup();
    } catch (error) {
      console.error('Error analyzing:', error);
      showNotification({
        verdict: 'error',
        message: 'Error: ' + error.message,
      });
    }
  }
});

// Inject warning banner
async function injectWarningBanner(tabId, result) {
  try {
    await chrome.scripting.executeScript({
      target: { tabId: tabId },
      function: (verdict, confidence) => {
        // Remove existing banner
        const existing = document.getElementById('scam-detector-banner');
        if (existing) existing.remove();

        // Create banner
        const banner = document.createElement('div');
        banner.id = 'scam-detector-banner';
        banner.innerHTML = `
          <div style="
            background: linear-gradient(135deg, #ff0055, #ff6699);
            color: white;
            padding: 16px 20px;
            text-align: center;
            font-weight: 700;
            box-shadow: 0 4px 20px rgba(255, 0, 85, 0.4);
            font-family: 'Inter', sans-serif;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 999999;
          ">
            ⚠️ WARNING: This page may be a phishing scam (${Math.round(confidence * 100)}% confidence)
          </div>
        `;
        document.body.prepend(banner);
        document.body.style.paddingTop = '60px';
      },
      args: [result.verdict, result.confidence],
    });
  } catch (error) {
    console.error('Error injecting banner:', error);
  }
}

// Show notification
async function showNotification(result) {
  const titles = {
    safe: '✅ Safe',
    suspicious: '⚠️ Suspicious',
    likely_scam: '🚨 Likely Scam',
    error: '❌ Error',
  };

  const message = result.message || `${Math.round(result.confidence * 100)}% confidence`;

  chrome.notifications.create('scam-detector-result', {
    type: 'basic',
    iconUrl: chrome.runtime.getURL('images/icon-128.png'),
    title: titles[result.verdict] || 'Scam Detector',
    message: message,
    priority: 2,
  });
}

// Save to history
async function saveToHistory(url, result) {
  const data = await chrome.storage.local.get('scanHistory');
  const history = data.scanHistory || [];

  history.unshift({
    url: url,
    result: result,
    timestamp: new Date().toISOString(),
  });

  // Keep only last 10
  history.splice(10);
  await chrome.storage.local.set({ scanHistory: history });
}

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getHistory') {
    chrome.storage.local.get('scanHistory', (data) => {
      sendResponse({ history: data.scanHistory || [] });
    });
    return true;
  }
});
