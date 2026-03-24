/**
 * PhishGuard — Anti-Evasion Handler (Phase 7: Reference Logic)
 * ══════════════════════════════════════════════════════════
 * This file serves as a reference for the anti-evasion logic 
 * which is primarily integrated into service-worker.js to 
 * handle CONTENT_SIGNALS from the content script.
 */

const AntiEvasion = {
  // Boost score based on detected evasion techniques
  calculateBoost: (signals) => {
    let boost = 0;
    if (signals.hasBitB) boost += 0.4;
    if (signals.hasBrandImpersonation) boost += 0.3;
    if (signals.domCloaking) boost += 0.2;
    if (signals.rapidDomMutations) boost += 0.1;
    if (signals.fakeSslIndicator) boost += 0.2;
    if (signals.hasClipboardHijack) boost += 0.1;
    return boost;
  },

  // Log detected evasion to background console
  logEvasion: (tabId, signals) => {
    if (signals.hasBitB) {
      console.warn(`[PhishGuard] Tab ${tabId}: BitB ATTACK DETECTED! Score: ${signals.bitbScore}`);
    }
    if (signals.hasBrandImpersonation) {
      console.warn(`[PhishGuard] Tab ${tabId}: BRAND IMPERSONATION (${signals.brandDetected})`);
    }
  }
};

// Export if used in standard module system (or attach to global)
if (typeof module !== 'undefined') module.exports = AntiEvasion;
else self.AntiEvasion = AntiEvasion;
