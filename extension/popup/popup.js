/**
 * PhishGuard — Popup Script
 * Displays analysis results for the current tab.
 */

document.addEventListener("DOMContentLoaded", async () => {
  const loading = document.getElementById("loading");
  const content = document.getElementById("content");
  const statusCard = document.getElementById("statusCard");
  const statusIcon = document.getElementById("statusIcon");
  const statusLabel = document.getElementById("statusLabel");
  const scoreFill = document.getElementById("scoreFill");
  const scoreText = document.getElementById("scoreText");
  const urlDisplay = document.getElementById("urlDisplay");
  const detailsSection = document.getElementById("detailsSection");
  const reasonList = document.getElementById("reasonList");
  const sourceLabel = document.getElementById("sourceLabel");
  const btnReanalyze = document.getElementById("btnReanalyze");
  const headerIcon = document.getElementById("headerIcon");

  // Get current tab
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!tab || !tab.id) {
    showResult({
      verdict: "unknown",
      score: 0,
      reasons: ["Unable to access current tab"],
      source: "error",
    });
    return;
  }

  // Show URL
  urlDisplay.textContent = tab.url || "Unknown URL";

  // Request result from service worker
  chrome.runtime.sendMessage(
    { type: "GET_RESULT", tabId: tab.id },
    (result) => {
      if (chrome.runtime.lastError) {
        showResult({
          verdict: "unknown",
          score: 0,
          reasons: ["Extension not ready. Try refreshing the page."],
          source: "error",
        });
        return;
      }
      showResult(result || {
        verdict: "unknown",
        score: 0,
        reasons: ["Page not yet analyzed"],
      });
    }
  );

  // Re-analyze button
  btnReanalyze.addEventListener("click", () => {
    loading.style.display = "";
    content.style.display = "none";

    chrome.runtime.sendMessage(
      { type: "REANALYZE", tabId: tab.id },
      () => {
        // Wait a moment then re-fetch
        setTimeout(() => {
          chrome.runtime.sendMessage(
            { type: "GET_RESULT", tabId: tab.id },
            (result) => {
              showResult(result || { verdict: "unknown", score: 0, reasons: [] });
            }
          );
        }, 2000);
      }
    );
  });

  function showResult(result) {
    loading.style.display = "none";
    content.style.display = "";

    const verdict = result.verdict || "unknown";
    const score = result.score || 0;
    const reasons = result.reasons || [];
    const source = result.source || "unknown";

    // Status card styling
    statusCard.className = `status-card ${verdict}`;
    scoreFill.className = `score-fill ${verdict}`;
    scoreFill.style.width = `${Math.round(score * 100)}%`;

    // Icons and labels
    switch (verdict) {
      case "safe":
        statusIcon.textContent = "🛡️";
        statusLabel.textContent = "Safe";
        headerIcon.src = "../icons/safe-32.png";
        break;
      case "suspicious":
        statusIcon.textContent = "⚠️";
        statusLabel.textContent = "Suspicious";
        headerIcon.src = "../icons/warning-32.png";
        break;
      case "phishing":
        statusIcon.textContent = "🚫";
        statusLabel.textContent = "Phishing Detected";
        headerIcon.src = "../icons/danger-32.png";
        break;
      default:
        statusIcon.textContent = "🔍";
        statusLabel.textContent = "Unknown";
        headerIcon.src = "../icons/default-32.png";
    }

    scoreText.textContent = `Threat score: ${(score * 100).toFixed(0)}%`;

    // Source label
    const sourceMap = {
      whitelist: "Trusted domain",
      local_ml: "Local ML analysis",
      backend: "Full backend analysis",
      error: "Error",
    };
    sourceLabel.textContent = sourceMap[source] || source;

    // Reasons
    if (reasons.length > 0) {
      detailsSection.style.display = "";
      reasonList.innerHTML = "";
      for (const reason of reasons) {
        const li = document.createElement("li");
        li.textContent = reason;
        reasonList.appendChild(li);
      }
    } else {
      detailsSection.style.display = "none";
    }
  }
});
