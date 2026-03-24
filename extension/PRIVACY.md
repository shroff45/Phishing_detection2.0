# PhishGuard Privacy Policy

**Last Updated:** 2025

## What PhishGuard Does

PhishGuard is a browser extension that detects phishing websites
in real time using machine learning and threat intelligence.

## Data We Collect

### By Default (Local-Only Mode)
- **Zero data leaves your browser.** All URL analysis and page
  scanning happens entirely on your device using a locally
  bundled machine learning model.
- Scan results are cached in your browser's session storage
  and automatically cleared when you close the browser.
- Aggregate statistics (pages scanned, threats blocked) are
  stored locally and never transmitted.

### When Backend Escalation Is Enabled
If you choose to enable "Backend Escalation" in settings,
the following data may be sent to our analysis server **only**
for URLs that the local model cannot confidently classify:
- The URL being analyzed
- A screenshot of the page (for visual similarity analysis)
- Pre-extracted feature scores (numerical values, not page content)

This data is:
- Used solely to determine if the page is phishing
- **Not stored** after analysis is complete (default retention: 0 seconds)
- **Not shared** with any third party
- **Not used** for advertising, tracking, or profiling

### What We Never Collect
- Your browsing history
- Your personal information
- Cookies or session tokens
- Form input data or passwords
- Data from pages classified as safe (never sent to backend)

## Third-Party Services

When backend escalation is enabled, the server may query:
- **Google Safe Browsing API** — to check if a URL is in Google's
  threat database. Only the URL is sent. Google's privacy policy
  applies to their processing.
- **VirusTotal API** — to check multi-engine scan results.
  Only the URL is sent.
- **WHOIS databases** — to check domain registration age.
  Only the domain name is queried.

## Your Controls

You can at any time:
- **Disable backend escalation** — all analysis stays local
- **Clear cached data** — removes all stored scan results
- **Export your data** — download everything stored locally
- **Uninstall the extension** — all local data is automatically deleted

## Open Source

PhishGuard is open source. You can inspect every line of code
to verify these privacy claims.

## Contact

For privacy concerns, contact: [your-email@vit.ac.in]
