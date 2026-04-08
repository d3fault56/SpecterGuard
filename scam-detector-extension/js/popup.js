const API_BASE_URL = 'http://localhost:8000';

class PopupManager {
  constructor() {
    this.currentUrl = '';
    this.currentResult = null;
    this.setupEventListeners();
    this.initializeState();
  }

  setupEventListeners() {
    document.getElementById('analyze-btn').addEventListener('click', () => this.analyze());
    document.getElementById('history-btn').addEventListener('click', () => this.showHistory());
    document.getElementById('close-btn').addEventListener('click', () => window.close());
  }

  async initializeState() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      this.currentUrl = tab.url;
      
      // Check if we have a cached result for this URL
      const cached = await this.getCachedResult(this.currentUrl);
      if (cached) {
        this.displayResults(cached);
      }
    } catch (error) {
      console.error('Error initializing:', error);
    }
  }

  async analyze() {
    try {
      // Get the current tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const url = tab.url;

      // Show loading state
      this.showLoading();

      // Get selected text or use URL
      const selectedText = await this.getSelectedText();
      const content = selectedText || url;
      const inputType = selectedText ? 'text' : 'url';

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

      // Cache the result
      await this.cacheResult(url, result);

      // Display results
      this.displayResults(result);
      this.currentResult = result;

      // If high risk, inject warning banner
      if (result.verdict === 'likely_scam') {
        await this.injectWarningBanner(result);
      }

      // Save to history
      await this.saveToHistory(result);
    } catch (error) {
      this.showError(error.message);
    }
  }

  async getSelectedText() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const [result] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: () => window.getSelection().toString(),
      });
      return result.result;
    } catch (error) {
      console.error('Error getting selected text:', error);
      return '';
    }
  }

  async injectWarningBanner(result) {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        function: (verdict, confidence) => {
          // Remove existing banner if present
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

          // Add padding to body to avoid content overlap
          document.body.style.paddingTop = '60px';
        },
        args: [result.verdict, result.confidence],
      });
    } catch (error) {
      console.error('Error injecting banner:', error);
    }
  }

  displayResults(result) {
    // Hide empty state and loading
    document.getElementById('empty-state').style.display = 'none';
    document.getElementById('loading-state').style.display = 'none';
    document.getElementById('error-state').style.display = 'none';
    document.getElementById('results-state').style.display = 'block';

    const icons = {
      safe: '✅',
      suspicious: '⚠️',
      likely_scam: '🚨',
    };

    // Status badge
    const badge = document.getElementById('status-badge');
    badge.className = `status-badge ${result.verdict}`;
    badge.innerHTML = `<span>${icons[result.verdict]}</span> ${result.verdict.replace('_', ' ').toUpperCase()}`;

    // Confidence
    const confidence = Math.round(result.confidence * 100);
    document.getElementById('confidence-value').textContent = confidence + '%';
    document.getElementById('confidence-fill').style.width = confidence + '%';

    // Risk breakdown
    document.getElementById('content-risk').textContent = this.calculateContentRisk(result) + '%';
    document.getElementById('url-risk').textContent = this.calculateUrlRisk(result) + '%';
    document.getElementById('auth-risk').textContent = this.calculateAuthRisk(result) + '%';

    // Red flags
    const flagsList = document.getElementById('flags-list');
    flagsList.innerHTML = '';
    if (result.red_flags.length > 0) {
      result.red_flags.slice(0, 6).forEach(flag => {
        const flagEl = document.createElement('div');
        flagEl.className = 'flag-item';

        let icon = '⚠️';
        if (flag.includes('SPF') || flag.includes('DKIM') || flag.includes('DMARC')) {
          icon = '🔒';
          flagEl.classList.add('warning');
        } else if (flag.includes('URL') || flag.includes('domain')) {
          icon = '🌐';
          flagEl.classList.add('info');
        } else if (flag.includes('credential')) {
          icon = '🔑';
        }

        flagEl.innerHTML = `<span class="flag-icon">${icon}</span> <span>${flag}</span>`;
        flagsList.appendChild(flagEl);
      });
    } else {
      const flagEl = document.createElement('div');
      flagEl.className = 'flag-item info';
      flagEl.innerHTML = '<span class="flag-icon">✓</span> <span>No red flags detected</span>';
      flagsList.appendChild(flagEl);
    }

    // Show URL if analyzed as URL
    if (result.input_type === 'url') {
      document.getElementById('url-section').style.display = 'block';
      document.getElementById('url-display').textContent = result.input_type === 'url' ? this.currentUrl : '';
    }
  }

  calculateContentRisk(result) {
    if (result.verdict === 'likely_scam') return 90;
    if (result.verdict === 'suspicious') return 50;
    return 10;
  }

  calculateUrlRisk(result) {
    const flags = result.red_flags.join('').toLowerCase();
    if (flags.includes('url') || flags.includes('domain')) return 80;
    if (flags.includes('ip')) return 70;
    return 20;
  }

  calculateAuthRisk(result) {
    const flags = result.red_flags.join('').toLowerCase();
    if (flags.includes('spf') || flags.includes('dkim') || flags.includes('dmarc')) return 85;
    if (flags.includes('spoofing') || flags.includes('mismatch')) return 70;
    return 10;
  }

  showLoading() {
    document.getElementById('empty-state').style.display = 'none';
    document.getElementById('results-state').style.display = 'none';
    document.getElementById('error-state').style.display = 'none';
    document.getElementById('loading-state').style.display = 'flex';
  }

  showError(message) {
    document.getElementById('empty-state').style.display = 'none';
    document.getElementById('results-state').style.display = 'none';
    document.getElementById('loading-state').style.display = 'none';
    document.getElementById('error-state').style.display = 'block';
    document.getElementById('error-message').textContent = message || 'Unable to analyze. Make sure the backend is running.';
  }

  async saveToHistory(result) {
    const history = await this.getHistory();
    history.unshift({
      url: this.currentUrl,
      result: result,
      timestamp: new Date().toISOString(),
    });
    // Keep only last 10
    history.splice(10);
    await chrome.storage.local.set({ scanHistory: history });
  }

  async getHistory() {
    const data = await chrome.storage.local.get('scanHistory');
    return data.scanHistory || [];
  }

  async getCachedResult(url) {
    const data = await chrome.storage.local.get('urlCache');
    const cache = data.urlCache || {};
    const cached = cache[url];
    if (cached && new Date() - new Date(cached.timestamp) < 3600000) {
      // Cache valid for 1 hour
      return cached.result;
    }
    return null;
  }

  async cacheResult(url, result) {
    const data = await chrome.storage.local.get('urlCache');
    const cache = data.urlCache || {};
    cache[url] = {
      result: result,
      timestamp: new Date().toISOString(),
    };
    // Keep only last 50 cached URLs
    const urls = Object.keys(cache);
    if (urls.length > 50) {
      delete cache[urls[0]];
    }
    await chrome.storage.local.set({ urlCache: cache });
  }

  async showHistory() {
    const history = await this.getHistory();
    const historyHTML = history
      .slice(0, 10)
      .map(
        (item, idx) => `
      <div style="
        padding: 10px;
        background: rgba(51, 65, 85, 0.4);
        border-radius: 4px;
        margin-bottom: 8px;
        font-size: 11px;
        cursor: pointer;
        border-left: 2px solid ${item.result.verdict === 'safe' ? '#00ff88' : item.result.verdict === 'suspicious' ? '#ffa500' : '#ff0055'};
      ">
        <strong>${item.result.verdict.replace('_', ' ')}</strong><br>
        ${Math.round(item.result.confidence * 100)}% - ${new Date(item.timestamp).toLocaleDateString()}<br>
        <span style="color: var(--text-muted);">${item.url.substring(0, 50)}...</span>
      </div>
    `
      )
      .join('');

    document.getElementById('content').innerHTML = `
      <div style="padding: 20px;">
        <h2 style="font-size: 14px; margin-bottom: 15px;">Recent Scans</h2>
        ${historyHTML || '<p style="color: var(--text-muted);">No history yet</p>'}
        <button id="back-btn" style="
          width: 100%;
          margin-top: 15px;
          padding: 8px;
          background: linear-gradient(135deg, var(--accent), #0099ff);
          color: var(--primary);
          border: none;
          border-radius: 6px;
          font-weight: 600;
          cursor: pointer;
        ">Back</button>
      </div>
    `;

    document.getElementById('back-btn').addEventListener('click', () => {
      location.reload();
    });
  }
}

// Initialize popup
new PopupManager();