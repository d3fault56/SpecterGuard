/**
 * Content Script - Runs on every page
 * Handles:
 * - Removing warning banners when user closes them
 * - Listening for user interactions
 * - Communicating with background script
 */

// Remove warning banner function
window.removeScamBanner = function () {
  const banner = document.getElementById('scam-detector-banner');
  if (banner) {
    banner.remove();
    document.body.style.paddingTop = '0';
  }
};

// Make function available globally
window.scamDetectorRemoveBanner = window.removeScamBanner;

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'removeBanner') {
    window.removeScamBanner();
    sendResponse({ success: true });
  }
});

// Optional: Auto-remove banner after 10 seconds if user doesn't interact
let bannerTimeout;
const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    if (mutation.addedNodes.length) {
      mutation.addedNodes.forEach((node) => {
        if (node.id === 'scam-detector-banner') {
          // Banner was added
          clearTimeout(bannerTimeout);
          bannerTimeout = setTimeout(() => {
            // Auto-remove after 10 seconds (optional - remove this if you want persistent banner)
            // window.removeScamBanner();
          }, 10000);
        }
      });
    }
  });
});

// Start observing DOM changes
observer.observe(document.body, {
  childList: true,
  subtree: true,
});

console.log('[Scam Detector] Content script loaded');
