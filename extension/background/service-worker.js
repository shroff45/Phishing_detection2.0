/**
 * PhishGuard — Service Worker (Manifest V3)
 * 
 * Runs in the background. Responsibilities:
 *   1. Extract 30 lexical features from every navigated URL
 *   2. Run local ONNX inference for instant scoring
 *   3. Escalate ambiguous URLs (score 0.3–0.8) to backend with screenshot
 *   4. Update badge icon based on verdict
 *   5. Periodically sync threat feed rules from backend
 */

// ── ONNX Runtime Setup ────────────────────────────────────────────────────
importScripts("../lib/ort.min.js");

// Point ONNX Runtime at bundled WASM files
ort.env.wasm.wasmPaths = chrome.runtime.getURL("lib/");

let ortSession = null;

async function loadModel() {
  if (ortSession) return ortSession;
  try {
    const modelUrl = chrome.runtime.getURL("models/model.onnx");
    const response = await fetch(modelUrl);
    const buffer = await response.arrayBuffer();
    ortSession = await ort.InferenceSession.create(buffer, {
      executionProviders: ["wasm"],
    });
    console.log("[PhishGuard] ONNX model loaded successfully");
    return ortSession;
  } catch (err) {
    console.error("[PhishGuard] Failed to load ONNX model:", err);
    return null;
  }
}

// Load model on startup
loadModel();

// ── Constants ─────────────────────────────────────────────────────────────
const BACKEND_URL = "http://localhost:8000";

const PHISH_KEYWORDS = [
  "login", "signin", "sign-in", "verify", "account",
  "update", "secure", "banking", "confirm", "password",
  "suspend", "alert", "unusual", "restore", "unlock",
];

const SUSPICIOUS_TLDS = new Set([
  ".xyz", ".icu", ".top", ".tk", ".ml", ".ga", ".cf",
  ".gq", ".buzz", ".club", ".info", ".site", ".online",
  ".website", ".link", ".click", ".surf",
]);

const SHORTENER_DOMAINS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
  "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
]);

// Top legitimate domains — skip analysis entirely
const WHITELIST = new Set([
  "google.com", "www.google.com", "youtube.com", "www.youtube.com",
  "facebook.com", "www.facebook.com", "amazon.com", "www.amazon.com",
  "wikipedia.org", "en.wikipedia.org", "twitter.com", "www.twitter.com",
  "instagram.com", "www.instagram.com", "linkedin.com", "www.linkedin.com",
  "reddit.com", "www.reddit.com", "netflix.com", "www.netflix.com",
  "microsoft.com", "www.microsoft.com", "apple.com", "www.apple.com",
  "github.com", "www.github.com", "stackoverflow.com",
  "yahoo.com", "www.yahoo.com", "bing.com", "www.bing.com",
  "twitch.tv", "www.twitch.tv", "whatsapp.com", "web.whatsapp.com",
  "zoom.us", "spotify.com", "open.spotify.com",
  "adobe.com", "dropbox.com", "slack.com", "paypal.com", "www.paypal.com",
  "ebay.com", "www.ebay.com", "cnn.com", "bbc.com", "bbc.co.uk",
]);

// ── Feature Names (must match training order exactly) ─────────────────────
const FEATURE_NAMES = [
  "f01_urlLength",
  "f02_hostnameLength",
  "f03_pathLength",
  "f04_queryLength",
  "f05_dotCountUrl",
  "f06_dotCountHost",
  "f07_hyphenCountUrl",
  "f08_hyphenCountHost",
  "f09_underscoreCount",
  "f10_atSymbolCount",
  "f11_digitCountUrl",
  "f12_digitCountHost",
  "f13_digitToLetterRatio",
  "f14_subdomainCount",
  "f15_pathDepth",
  "f16_queryParamCount",
  "f17_isIpAddress",
  "f18_entropyUrl",
  "f19_entropyHost",
  "f20_entropyPath",
  "f21_specialCharCount",
  "f22_hasPort",
  "f23_isHttps",
  "f24_hasSuspiciousTld",
  "f25_hasPunycode",
  "f26_isShortener",
  "f27_keywordHits",
  "f28_encodedCharCount",
  "f29_doubleSlashCount",
  "f30_longestSubdomainLen",
];

// ── Helper Functions ──────────────────────────────────────────────────────

function shannonEntropy(text) {
  if (!text) return 0;
  const freq = {};
  for (const ch of text) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  const len = text.length;
  let entropy = 0;
  for (const ch in freq) {
    const p = freq[ch] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Extract 30 lexical features from a raw URL string.
 * This function MUST produce identical values to build_dataset.py's extract_features().
 */
function extractLexicalFeatures(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return null;
  }

  const hostname = parsed.hostname || "";
  const pathname = parsed.pathname || "/";
  const fullUrl = rawUrl;

  // Query length: use URL.search which includes '?' prefix
  const queryLength = parsed.search.length; // 0 if no query, else includes '?'

  // Query param count
  let queryParamCount = 0;
  if (parsed.search.length > 1) {
    const rawQuery = parsed.search.substring(1); // remove '?'
    queryParamCount = rawQuery.split("&").filter(p => p.length > 0).length;
  }

  const hostParts = hostname ? hostname.split(".") : [""];
  const subdomainCount = Math.max(0, hostParts.length - 2);
  const pathSegments = pathname.split("/").filter(s => s.length > 0);

  let digits = 0;
  let letters = 0;
  for (const ch of fullUrl) {
    if (ch >= "0" && ch <= "9") digits++;
    else if ((ch >= "a" && ch <= "z") || (ch >= "A" && ch <= "Z")) letters++;
  }

  const lowerUrl = fullUrl.toLowerCase();
  let keywordHits = 0;
  for (const kw of PHISH_KEYWORDS) {
    if (lowerUrl.includes(kw)) keywordHits++;
  }

  const tld = hostParts.length > 0 ? "." + hostParts[hostParts.length - 1] : "";
  const hasSuspiciousTld = SUSPICIOUS_TLDS.has(tld.toLowerCase()) ? 1 : 0;
  const hasPunycode = hostname.toLowerCase().includes("xn--") ? 1 : 0;

  let isShortener = 0;
  for (const d of SHORTENER_DOMAINS) {
    if (hostname.toLowerCase().endsWith(d)) {
      isShortener = 1;
      break;
    }
  }

  const encodedChars = (fullUrl.match(/%[0-9a-fA-F]{2}/g) || []).length;
  const doubleSlashes = Math.max(0, (fullUrl.match(/\/\//g) || []).length - 1);
  const specialChars = (fullUrl.match(/[!$%^*()+=\{\}\[\]|;:'"<>?]/g) || []).length;

  let longestSubdomain = 0;
  if (hostParts.length > 2) {
    for (let i = 0; i < hostParts.length - 2; i++) {
      longestSubdomain = Math.max(longestSubdomain, hostParts[i].length);
    }
  }

  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  const hexIp = /^0x[\da-fA-F]+$/i.test(hostname);
  const ipv6 = /^\[[\da-fA-F:]+\]$/.test(hostname);
  const isIp = (ipv4 || hexIp || ipv6) ? 1 : 0;

  let digitCountHost = 0;
  for (const ch of hostname) {
    if (ch >= "0" && ch <= "9") digitCountHost++;
  }

  return {
    f01_urlLength: fullUrl.length,
    f02_hostnameLength: hostname.length,
    f03_pathLength: pathname.length,
    f04_queryLength: queryLength,
    f05_dotCountUrl: (fullUrl.match(/\./g) || []).length,
    f06_dotCountHost: (hostname.match(/\./g) || []).length,
    f07_hyphenCountUrl: (fullUrl.match(/-/g) || []).length,
    f08_hyphenCountHost: (hostname.match(/-/g) || []).length,
    f09_underscoreCount: (fullUrl.match(/_/g) || []).length,
    f10_atSymbolCount: (fullUrl.match(/@/g) || []).length,
    f11_digitCountUrl: digits,
    f12_digitCountHost: digitCountHost,
    f13_digitToLetterRatio: letters > 0 ? digits / letters : digits,
    f14_subdomainCount: subdomainCount,
    f15_pathDepth: pathSegments.length,
    f16_queryParamCount: queryParamCount,
    f17_isIpAddress: isIp,
    f18_entropyUrl: shannonEntropy(fullUrl),
    f19_entropyHost: shannonEntropy(hostname),
    f20_entropyPath: shannonEntropy(pathname),
    f21_specialCharCount: specialChars,
    f22_hasPort: parsed.port ? 1 : 0,
    f23_isHttps: parsed.protocol === "https:" ? 1 : 0,
    f24_hasSuspiciousTld: hasSuspiciousTld,
    f25_hasPunycode: hasPunycode,
    f26_isShortener: isShortener,
    f27_keywordHits: keywordHits,
    f28_encodedCharCount: encodedChars,
    f29_doubleSlashCount: doubleSlashes,
    f30_longestSubdomainLen: longestSubdomain,
  };
}

/**
 * Run ONNX inference on a 30-feature vector.
 * Returns phishing probability (0.0 = safe, 1.0 = phishing).
 */
async function runInference(features) {
  const session = await loadModel();
  if (!session) {
    console.warn("[PhishGuard] No model session, returning 0.5");
    return 0.5;
  }

  // Build feature array in exact training order
  const featureArray = new Float32Array(FEATURE_NAMES.length);
  for (let i = 0; i < FEATURE_NAMES.length; i++) {
    const val = features[FEATURE_NAMES[i]];
    featureArray[i] = isFinite(val) ? val : 0;
  }

  const inputTensor = new ort.Tensor("float32", featureArray, [1, 30]);

  try {
    // Input name MUST be "float_input" — set in train_url_model.py
    const results = await session.run({ float_input: inputTensor });

    // Output: probabilities tensor with shape [1, 2] → [p_legit, p_phish]
    const outputNames = Object.keys(results);
    // skl2onnx with zipmap=False outputs "label" and "probabilities"
    const probKey = outputNames.find(k => k.toLowerCase().includes("probabilities")) || outputNames[1] || outputNames[0];
    const probs = results[probKey].data;

    // probs = [p_legit, p_phish]
    const phishProb = probs[1];
    return phishProb;
  } catch (err) {
    console.error("[PhishGuard] Inference failed:", err);
    return 0.5;
  }
}

// ── Badge & Icon Management ───────────────────────────────────────────────

function updateBadge(tabId, verdict, score) {
  let color, text, iconPrefix;

  if (verdict === "safe") {
    color = "#22c55e"; // green
    text = "✓";
    iconPrefix = "safe";
  } else if (verdict === "suspicious") {
    color = "#f59e0b"; // amber
    text = "!";
    iconPrefix = "warning";
  } else if (verdict === "phishing") {
    color = "#ef4444"; // red
    text = "✗";
    iconPrefix = "danger";
  } else {
    color = "#6b7280"; // gray
    text = "?";
    iconPrefix = "default";
  }

  chrome.action.setBadgeBackgroundColor({ tabId, color });
  chrome.action.setBadgeText({ tabId, text });

  // Try to set icon (may fail if icons don't exist yet)
  try {
    chrome.action.setIcon({
      tabId,
      path: {
        16: `icons/${iconPrefix}-16.png`,
        32: `icons/${iconPrefix}-32.png`,
        48: `icons/${iconPrefix}-48.png`,
        128: `icons/${iconPrefix}-128.png`,
      },
    });
  } catch (e) {
    // Icons not yet created — badge alone is fine
  }
}

// Store per-tab results for popup to read
const tabResults = new Map();

function storeResult(tabId, result) {
  tabResults.set(tabId, {
    ...result,
    timestamp: Date.now(),
  });
  // Clean old entries
  if (tabResults.size > 200) {
    const oldest = [...tabResults.entries()]
      .sort((a, b) => a[1].timestamp - b[1].timestamp)
      .slice(0, 50);
    for (const [key] of oldest) {
      tabResults.delete(key);
    }
  }
}

// ── Core Analysis Pipeline ────────────────────────────────────────────────

/**
 * Main analysis function — called on every navigation.
 */
async function analyzeUrl(tabId, url) {
  // Skip non-HTTP URLs
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    updateBadge(tabId, "safe", 0);
    return;
  }

  // Skip chrome://, chrome-extension://, about:, etc.
  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return;
    }

    // Whitelist check
    const hostname = parsed.hostname.toLowerCase();
    if (WHITELIST.has(hostname)) {
      const result = {
        url,
        verdict: "safe",
        score: 0.0,
        source: "whitelist",
        reasons: ["Domain is in the trusted whitelist"],
      };
      storeResult(tabId, result);
      updateBadge(tabId, "safe", 0);
      return;
    }
  } catch {
    return;
  }

  // Extract features
  const features = extractLexicalFeatures(url);
  if (!features) {
    updateBadge(tabId, "safe", 0);
    return;
  }

  // Run local ML inference
  const phishProb = await runInference(features);
  console.log(`[PhishGuard] ${url} → local score: ${phishProb.toFixed(3)}`);

  // Determine verdict from local score
  let verdict;
  if (phishProb >= 0.7) {
    verdict = "phishing";
  } else if (phishProb >= 0.3) {
    verdict = "suspicious";
  } else {
    verdict = "safe";
  }

  let result = {
    url,
    verdict,
    score: phishProb,
    source: "local_ml",
    reasons: [],
  };

  // If ambiguous (0.3–0.8), escalate to backend for full analysis
  if (phishProb >= 0.3 && phishProb <= 0.8) {
    try {
      const backendResult = await escalateToBackend(tabId, url, phishProb);
      if (backendResult) {
        result = {
          url,
          verdict: backendResult.verdict,
          score: backendResult.score,
          source: "backend",
          reasons: backendResult.reasons || [],
          visual: backendResult.visual_analysis || null,
          signals: backendResult.signals || [],
        };
        verdict = backendResult.verdict;
      }
    } catch (err) {
      console.warn("[PhishGuard] Backend escalation failed:", err.message);
      // Keep local verdict
    }
  }

  // Add reasons based on features
  if (features.f17_isIpAddress) result.reasons.push("URL uses IP address");
  if (features.f24_hasSuspiciousTld) result.reasons.push("Suspicious TLD detected");
  if (features.f25_hasPunycode) result.reasons.push("Punycode/IDN domain");
  if (features.f26_isShortener) result.reasons.push("URL shortener detected");
  if (features.f27_keywordHits >= 3) result.reasons.push("Multiple phishing keywords in URL");

  storeResult(tabId, result);
  updateBadge(tabId, verdict, result.score);

  // If phishing, show warning notification
  if (verdict === "phishing") {
    try {
      chrome.notifications.create(`phish-${tabId}`, {
        type: "basic",
        iconUrl: chrome.runtime.getURL("icons/danger-128.png"),
        title: "⚠️ Phishing Warning",
        message: `This page may be a phishing attempt!\n${url.substring(0, 80)}`,
        priority: 2,
      });
    } catch (e) {
      // Notifications may not be available
    }
  }
}

/**
 * Escalate to backend with optional screenshot for visual analysis.
 */
async function escalateToBackend(tabId, url, clientScore) {
  let screenshotBase64 = null;

  // Try to capture screenshot for visual analysis
  try {
    const dataUrl = await chrome.tabs.captureVisibleTab(null, {
      format: "png",
      quality: 70,
    });
    screenshotBase64 = dataUrl; // includes data:image/png;base64, prefix
  } catch (err) {
    console.debug("[PhishGuard] Screenshot capture failed:", err.message);
  }

  const body = {
    url,
    client_score: clientScore,
    screenshot_base64: screenshotBase64,
  };

  const response = await fetch(`${BACKEND_URL}/api/v1/analyze/full`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(10000), // 10s timeout
  });

  if (!response.ok) {
    throw new Error(`Backend returned ${response.status}`);
  }

  return await response.json();
}

// ── Navigation Listener ───────────────────────────────────────────────────

chrome.webNavigation.onCompleted.addListener(
  (details) => {
    // Only analyze main frame navigations
    if (details.frameId === 0) {
      analyzeUrl(details.tabId, details.url);
    }
  },
  { url: [{ schemes: ["http", "https"] }] }
);

// Also analyze on tab activation (switching tabs)
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url) {
      // Check if we already have a cached result
      const cached = tabResults.get(activeInfo.tabId);
      if (cached && cached.url === tab.url) {
        updateBadge(activeInfo.tabId, cached.verdict, cached.score);
      } else {
        analyzeUrl(activeInfo.tabId, tab.url);
      }
    }
  } catch (e) {
    // Tab may have been closed
  }
});

// Clean up when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  tabResults.delete(tabId);
});

// ── Message Handler (for popup & content scripts) ─────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_RESULT") {
    const tabId = message.tabId;
    const result = tabResults.get(tabId) || {
      verdict: "unknown",
      score: 0,
      reasons: ["Page not yet analyzed"],
    };
    sendResponse(result);
    return true; // async response
  }

  if (message.type === "CONTENT_SIGNALS") {
    // Receive additional signals from content script
    const tabId = sender.tab?.id;
    if (tabId) {
      const existing = tabResults.get(tabId);
      if (existing) {
        // Merge content script signals
        if (message.signals) {
          existing.contentSignals = message.signals;
          // Boost score if content script found suspicious elements
          if (message.signals.hasBitB) {
            existing.score = Math.min(1.0, existing.score + 0.2);
            existing.reasons.push("Browser-in-the-Browser (BitB) attack detected");
            existing.verdict = existing.score >= 0.7 ? "phishing" : "suspicious";
            updateBadge(tabId, existing.verdict, existing.score);
          }
          storeResult(tabId, existing);
        }
      }
    }
    sendResponse({ ok: true });
    return true;
  }

  if (message.type === "REANALYZE") {
    const tabId = message.tabId;
    chrome.tabs.get(tabId, (tab) => {
      if (tab && tab.url) {
        analyzeUrl(tabId, tab.url);
      }
    });
    sendResponse({ ok: true });
    return true;
  }
});

// ── Threat Feed Sync ──────────────────────────────────────────────────────

async function syncThreatFeed() {
  try {
    // First trigger backend to update its feeds
    await fetch(`${BACKEND_URL}/api/v1/feed/update`, { method: "POST" });

    // Then fetch the generated rules
    const response = await fetch(`${BACKEND_URL}/api/v1/feed/rules`);
    if (!response.ok) return;

    const data = await response.json();
    const rules = data.rules || [];

    if (rules.length === 0) return;

    // Get existing dynamic rules
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const existingIds = existing.map(r => r.id);

    // Remove old rules and add new ones
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existingIds,
      addRules: rules.slice(0, 4999), // Chrome limit is 5000
    });

    console.log(`[PhishGuard] Synced ${rules.length} threat feed rules`);
  } catch (err) {
    console.debug("[PhishGuard] Feed sync failed:", err.message);
  }
}

// Sync feeds every hour
chrome.alarms.create("syncFeeds", { periodInMinutes: 60 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "syncFeeds") {
    syncThreatFeed();
  }
});

// Initial sync on install/startup
chrome.runtime.onInstalled.addListener(() => {
  console.log("[PhishGuard] Extension installed/updated");
  syncThreatFeed();
});

chrome.runtime.onStartup.addListener(() => {
  loadModel();
  syncThreatFeed();
});
