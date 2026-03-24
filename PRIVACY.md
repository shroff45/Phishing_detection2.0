# PhishGuard — Privacy Architecture (Phase 8)

## Design Principles
PhishGuard follows a **local-first, privacy-by-design** architecture. User browsing data never leaves the device unless strictly necessary for security analysis.

## Data Flow
```
User browses → Extension extracts URL features (LOCAL)
                    ↓
            ONNX ML inference (LOCAL, in-browser)
                    ↓
            Score < 0.3 → SAFE (no data sent anywhere)
            Score > 0.8 → BLOCK (no data sent anywhere)
            Score 0.3-0.8 → Escalate to backend (OPTIONAL)
```

## What Data MAY Be Sent to Backend
Only when the local ML score is **ambiguous** (0.3–0.8):
- **URL**: For threat feed lookup (stateless API)
- **Client ML score**: Meta-classifier input
- **Screenshot (optional)**: For brand impersonation (processed in-memory only)

## What Data Is NEVER Collected
- ❌ Browsing history
- ❌ Cookies or session tokens
- ❌ Form input content (passwords, emails)
- ❌ Personal identifiable information (PII)
- ❌ IP addresses (backend does not log client IPs)

## Compliance
- **GDPR**: No personal data processed.
- **CCPA**: No personal information sold.
- **Chrome Web Store**: Compliant with User Data Policy.
