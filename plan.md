


# COMPLETE EXTENDED RESEARCH AND BUILD ROADMAP: REAL-TIME PHISHING DETECTION BROWSER EXTENSION

---

## PART ONE: EXTENDED RESEARCH PAPER ANALYSIS AND LITERATURE SYNTHESIS

Your existing research covers the 2024–2025 surface comprehensively. What follows is the deeper substrate — the foundational papers, the interconnections between them, the evolution of ideas, and the critical gaps that no single paper has addressed. Every section below is designed to give you intellectual ammunition that directly informs architectural decisions for your extension.

---

### 1.1 THE HISTORICAL EVOLUTION OF PHISHING DETECTION RESEARCH (2004–2025)

Understanding where the field has been is non-negotiable for understanding where it needs to go. Phishing detection research follows a clear evolutionary arc with five distinct generations, each building on the failures of the previous one.

**Generation One — Static Blacklists (2004–2008)**

The earliest anti-phishing mechanisms were pure blacklists. The Anti-Phishing Working Group (APWG), founded in 2003, began aggregating reported phishing URLs into centralized databases. Google Safe Browsing launched in 2005 with this exact approach — maintaining a hash-prefix list of known malicious URLs that browsers could query. The fundamental paper here is Sheng et al. (2009), "An Empirical Analysis of Phishing Blacklists" (Carnegie Mellon CyLab), which demonstrated that blacklists catch only 20% of phishing sites at the zero-hour mark. The average delay between a phishing site going live and appearing on a blacklist was 12.8 hours in 2009. In 2025, sophisticated phishing kits rotate domains every 15–45 minutes, making this gap catastrophically worse. Your previous research acknowledges that blacklists are "largely obsolete," but this paper quantifies exactly why and establishes the mathematical justification for real-time heuristic detection.

**Generation Two — Heuristic and Content-Based Analysis (2007–2013)**

The seminal work here is CANTINA (Zhang, Hong, Cranor — Carnegie Mellon, 2007). CANTINA was the first system to apply Information Retrieval techniques to phishing detection. It computed TF-IDF (Term Frequency-Inverse Document Frequency) scores from the text content of a webpage and submitted the top-N terms to a search engine. If the legitimate domain did not appear in the top search results, the page was classified as phishing. This was groundbreaking because it moved detection from "have we seen this exact URL before" to "does this page's content match what this domain should contain."

CANTINA+ (Xiang et al., 2011) extended this by integrating HTML-level features (presence of forms, password fields, iframes), URL-level features, and visual features alongside the TF-IDF search engine approach. It achieved 92% true positive rate with under 1% false positives using a machine learning filter that combined all these feature streams. The critical insight from CANTINA+ that directly impacts your extension is that multi-modal detection (combining URL + content + visual signals) consistently outperforms any single modality. This finding has been replicated in every major study since.

**Generation Three — Machine Learning Classification (2013–2019)**

This era saw the systematic application of supervised learning. The landmark dataset paper is Mohammad, Badarna, and Gunn (2015), "Intelligent Phishing Detection System Using Resemblance in Uniform Resource Locators" — which produced the UCI Phishing Websites dataset containing 30 features extracted from 11,055 instances. Virtually every ML-based phishing paper between 2015 and 2020 used some variant of this dataset or a closely related one. The features they established (IP address in URL, URL length, presence of @ symbol, double slash redirecting, prefix/suffix usage, subdomain count, SSL certificate status, domain registration length, favicon analysis, port analysis, HTTPS token placement, request URL percentages, URL of anchor tags, links in meta/script/link tags, server form handler anomalies, abnormal URL patterns, website forwarding count, status bar customization through JavaScript, disabling right-click, using pop-up windows, iframe redirection, and domain age) became the canonical feature set that informed all subsequent work, including the Phish-Shield and SecureSense repositories you have already identified.

The connection point to your existing research is that the 30+ features extracted by Phish-Shield and the 48 features used by SecureSense are direct descendants and expansions of this 2015 feature set. Understanding this lineage matters because it reveals a potential weakness: these features were designed to catch 2015-era phishing. Attackers in 2025 are aware of every single one of these features and actively design their kits to pass all of them. This is exactly why your extension must go beyond pure feature engineering.

**Generation Four — Deep Learning and Representation Learning (2018–2023)**

URLNet (Le, Pham, Le — 2018) was the first paper to apply deep learning directly to URL strings without manual feature engineering. It used a CNN architecture that operated simultaneously at character-level and word-level embeddings of the URL, learning discriminative patterns automatically. URLNet achieved 99.77% accuracy on a balanced dataset, demonstrating that deep learning could extract features that human engineers had not explicitly identified. The breakthrough insight was that the model learned to identify character-level patterns like specific encoding sequences, suspicious n-gram combinations, and structural anomalies in path segments that no manually defined feature set captured.

Texception (Le et al., 2019) advanced this by replacing the CNN with a modified Inception architecture adapted for text, treating URLs as one-dimensional "images" of characters. This model demonstrated superior performance on out-of-distribution samples — URLs from entirely new phishing campaigns not represented in training data.

PhishZoo (Afroz and Greenstadt, 2011) pioneered profile-based visual matching using fuzzy hashing of page screenshots. While primitive compared to Phishpedia, it established the principle that visual similarity could be computed efficiently enough for real-time detection. The fuzzy hash approach (using algorithms like ssdeep) is actually still useful for your extension as a lightweight pre-filter before invoking heavy deep learning models.

VisualPhishNet (Abdelnabi et al., 2020) used a triplet CNN architecture trained with triplet loss to learn visual embeddings of webpages. Given an anchor image (legitimate site), a positive sample (phishing clone), and a negative sample (unrelated site), the model learned to map visually similar pages to nearby points in embedding space. This is architecturally significant for your extension because triplet loss-based models can be fine-tuned incrementally — as new brand targets emerge, you can add them to the reference database without retraining the entire model.

**Generation Five — Foundation Models, Multimodal AI, and Adversarial Arms Race (2023–2025)**

This is the current era and where your extension must operate. The papers you have already identified (Phishpedia, PhishIntention, PhishOracle, LLM benchmarking) are central. What needs to be added is the work on Adversary-in-the-Middle (AiTM) frameworks and how they fundamentally break certain detection paradigms.

---

### 1.2 CRITICAL RESEARCH PAPERS NOT YET COVERED AND THEIR IMPLICATIONS

**Paper: "Catching Phishers with FIDO2" and "Passwords and FIDO2 Are Meant to Be Secret" (arXiv, 2024-2025)**

These papers examine how WebAuthn/FIDO2 credentials are inherently phishing-resistant because they are cryptographically bound to the origin domain. A FIDO2 authenticator will simply refuse to respond to a challenge from a domain that does not match the registered relying party. The implication for your extension is that you should detect and flag credential submission events on sites that do NOT support FIDO2 when the user has FIDO2 credentials available for that brand — this is a zero-false-positive signal that the site is suspicious.

**Paper: "PhishTime: Continuous Longitudinal Measurement of the Effectiveness of Anti-phishing Blacklists" (USENIX Security 2021, Bijmans et al.)**

This paper conducted the first continuous longitudinal measurement of blacklist effectiveness across Google Safe Browsing, PhishTank, and OpenPhish. Key findings: Google Safe Browsing detected 81.8% of phishing sites within 12 hours but only 55.6% at zero-hour. PhishTank detected 57.4% overall but had a median delay of 2 hours 44 minutes. The critical insight for your extension is that you should use blacklists as a fast first-pass filter (they catch known threats quickly) but never as your primary detection mechanism. Your ML models must handle the 44.4% of zero-hour phishing that blacklists miss.

**Paper: "Phishing URL Detection via CNN and Attention-Based Hierarchical RNN" (He et al., 2023)**

This paper introduces an attention mechanism into URL analysis, allowing the model to weight different parts of the URL differently depending on context. For example, the model learns that the path component matters more when the domain appears legitimate but the full path contains suspicious patterns. The attention weights provide interpretability — you can show users WHY the URL was flagged, which is critical for trust and adoption of your extension.

**Paper: "Evilginx2 and the Rise of Transparent Reverse Proxy Phishing" (Gretzky, 2018–ongoing)**

Evilginx2 is not a paper but an open-source tool and the associated body of research around it is essential. Evilginx2 acts as a transparent reverse proxy that sits between the victim and the legitimate website. The victim interacts with the real website's content, sees the real UI, and the proxy captures credentials AND session tokens in real-time. Because the content is the real website's content served through the proxy, content-based and visual similarity detection FAILS — the page looks exactly like the legitimate site because it IS the legitimate site's content. The URL is the only detectable indicator, and attackers use convincing domains with valid SSL certificates.

This is arguably the most important attack vector your extension must address, because Evilginx-style AiTM attacks bypass every detection method except URL analysis and traffic pattern analysis. Your extension must specifically look for proxy indicators: unusual TLS certificate chains, response timing anomalies (the additional latency introduced by the proxy hop), and domain analysis.

**Paper: "Browser-in-the-Browser (BitB) Attack" (mr.d0x, 2022)**

This attack creates a completely fake browser window within the existing browser window using HTML/CSS. The fake window includes a spoofed address bar showing a legitimate URL, login forms, and browser chrome. To the user, it appears they have a legitimate pop-up authentication window (like OAuth). Your extension must detect BitB attacks by inspecting the DOM for elements that visually replicate browser UI components. Specifically, look for: iframes or divs with position:fixed that render address-bar-like elements, elements containing URL strings within rendered text that don't correspond to the actual window.location, and shadow DOM elements that hide the real structure.

**Paper: "Adversarial Examples Against a Computer Vision-based Phishing Attack Detection" (Lin et al., 2022)**

This paper systematically generated adversarial examples against visual phishing detectors by modifying logo colors, adding transparent overlays, applying geometric transformations, and using style transfer. Key finding: FGSM (Fast Gradient Sign Method) attacks reduced detection accuracy of CNN-based logo matchers from 95% to below 30% with perturbations invisible to the human eye. The defense recommendation was adversarial training (training models on both clean and perturbed examples) which restored accuracy to 82%. Your extension must implement adversarial training in its pipeline or use ensemble vision models where different models have different vulnerability profiles.

**Paper: "Graph-based Phishing Detection Using GNN" (multiple papers, 2023-2025)**

Several papers have applied Graph Neural Networks to phishing detection by constructing heterogeneous graphs of the web ecosystem. Nodes represent domains, IP addresses, WHOIS registrants, and hosting ASNs. Edges represent relationships (resolves-to, registered-by, hosted-on, links-to). GNNs can detect phishing infrastructure clusters — even if a specific URL has never been seen before, its graph neighborhood (shared IP with known phishing, registered by same entity, linked from same spam source) provides powerful signals. For your extension, this means your backend should maintain a graph database (Neo4j) of domain relationships and query it as part of the scoring pipeline.

**Paper: "Federated Learning for Phishing Detection" (multiple papers, 2024-2025)**

These papers propose training phishing detection models across multiple clients (browser extension instances) without centralizing the raw browsing data. Each client trains on its local observations and uploads only model weight updates to a central server, which aggregates them. This approach solves the privacy problem of sending user URLs to a backend for analysis. For your extension, implementing federated learning would be a significant differentiator — it allows the model to continuously improve from real-world data without ever seeing any individual user's browsing history. However, it also introduces the risk of poisoning attacks through malicious federated clients, requiring robust aggregation algorithms like Byzantine-fault-tolerant federated averaging.

**Paper: "PhishLang: A Lightweight Language Model for Phishing Detection" (2024)**

PhishLang proposes using a small, distilled language model (under 50MB) specifically fine-tuned for phishing URL and content classification. Unlike full-scale LLMs that require API calls, PhishLang can run entirely within a browser extension using ONNX Runtime Web. It achieved 95.4% accuracy with less than 100ms inference time. This is directly applicable to your extension — it represents the sweet spot between full LLM capability and client-side deployment constraints.

**Paper: "Exploring the Dark Side of AI: Advanced Phishing Attack Design and Deployment Using ChatGPT" (Heiding et al., 2024)**

This paper had participants use ChatGPT to design phishing campaigns and measured their effectiveness. AI-generated spear phishing emails were 135% more effective than manually crafted ones. The paper demonstrates that AI-generated phishing is not a theoretical concern but a practical, measured reality. The direct implication for your extension is that you cannot rely on linguistic error detection (grammar, spelling) as a phishing signal anymore.

---

### 1.3 SYNTHESIS: CONNECTING ALL RESEARCH PAPERS INTO A UNIFIED UNDERSTANDING

When you lay all these papers end-to-end, a clear picture emerges:

**The Detection Stack Must Be Layered, Not Singular**

No single detection technique achieves acceptable performance across all attack types. The research overwhelmingly proves:
- Blacklists catch ~56-82% of known threats but zero percent of zero-day threats
- URL feature engineering catches ~94-99% in controlled datasets but drops to 80-85% against adversarial URLs
- Deep learning on URLs catches more sophisticated patterns but requires significant compute
- Visual similarity catches ~83% of brand spoofing but drops to ~14% under adversarial perturbation
- Content analysis catches form-based credential harvesting but misses proxy attacks
- Behavioral analysis catches delayed execution but introduces latency

The only architecture that achieves >99% real-world detection is a multi-layered ensemble that fuses ALL of these signals through a meta-classifier.

**The Attacker Always Has the Advantage of First Move**

Every defensive technique has been countered within 12-24 months of publication. This means your extension must be architecturally designed for continuous model updates, not static deployment. The update mechanism is as important as the initial model.

**Privacy and Performance Are Not Negotiable Constraints — They Are Primary Design Requirements**

MV3's restrictions are not obstacles to work around; they reflect genuine user expectations. Any architecture that sends every URL to a remote server for analysis will face adoption resistance and regulatory challenges (GDPR, DPDPA in India). The ideal architecture does as much as possible locally and only escalates to the backend for genuinely ambiguous cases.

---

## PART TWO: GLOBAL CYBERSECURITY LOOPHOLES — A HACKER'S PERSPECTIVE

As you asked me to think like an expert senior cybersecurity hacker, here are the systemic vulnerabilities in the global internet infrastructure that phishing exploits, organized from deepest infrastructure to end-user layer.

---

### 2.1 DNS INFRASTRUCTURE VULNERABILITIES

**The Core Problem:** The Domain Name System was designed in 1983 with zero authentication. DNS responses can be spoofed, cached poisoning can redirect traffic, and DNS-over-HTTPS (DoH) — while protecting user privacy — has actually made it harder for enterprise security tools to monitor DNS queries for suspicious resolutions.

**Specific Exploitable Weaknesses:**

- **Dangling DNS Records and Subdomain Takeover:** When organizations decommission cloud services (Azure, AWS, Heroku) but forget to remove the DNS CNAME record pointing to the now-released cloud endpoint, an attacker can claim that endpoint and serve phishing content from a seemingly legitimate subdomain (e.g., login.company.com). Your extension should check for subdomain anomalies where the subdomain's IP infrastructure differs radically from the parent domain.

- **DNS Rebinding Attacks:** An attacker controls a domain that initially resolves to a public IP (passing security checks) but then rebinds to an internal IP address (127.0.0.1 or 192.168.x.x) after the security check passes. This can bypass your extension's URL analysis if the DNS resolution changes between the check and the page load.

- **Newly Registered Domain (NRD) Abuse:** Over 70% of newly registered domains observed by security firms in 2024 were used for malicious purposes within their first 72 hours. Your extension must integrate domain age as a high-weight feature, treating any domain less than 30 days old with elevated suspicion.

---

### 2.2 CERTIFICATE AUTHORITY AND TLS TRUST MODEL FLAWS

**The Core Problem:** The browser's trust model assumes that any certificate signed by any of the ~150+ trusted root CAs is equally trustworthy. This creates a massive attack surface.

**Specific Exploitable Weaknesses:**

- **Free DV Certificate Abuse:** Let's Encrypt and ZeroSSL issue free Domain Validation certificates automatically. In 2024, over 83% of phishing sites used valid HTTPS with legitimate certificates. The padlock icon in the browser, which users were trained for decades to associate with safety, now means nothing about the legitimacy of the site's content. Your extension must explicitly educate users that HTTPS does not equal safety and should NOT use certificate presence as a positive trust signal.

- **Certificate Transparency Log Monitoring:** All publicly trusted CAs must log certificates to CT logs. By monitoring CT logs in real-time (using feeds from crt.sh or CertStream), your backend can detect when a certificate is issued for a domain that looks like a known brand (e.g., paypa1-login.com). This pre-detection capability means your extension can block a phishing domain BEFORE any victim visits it, purely from the certificate issuance event.

- **Homograph Certificates:** Attackers register internationalized domain names (IDNs) using Punycode that visually resemble Latin characters (Cyrillic "а" looks identical to Latin "a"). Certificate authorities issue valid certificates for these domains because they are technically distinct domains. Your extension must normalize all domains to their Punycode representation and flag IDN homographs of known brands.

---

### 2.3 EMAIL INFRASTRUCTURE GAPS

**The Core Problem:** Email authentication (SPF, DKIM, DMARC) adoption remains incomplete globally. Even when deployed, misconfiguration is rampant.

**Specific Exploitable Weaknesses:**

- **DMARC Non-Enforcement:** As of 2025, only ~35% of the world's domains have DMARC policies set to "reject" or "quarantine." The rest use "none" (monitoring only) or have no DMARC record at all. The Echospoofing attack you mentioned in your research exploited this by relaying millions of perfectly SPF-aligned spoofed emails through misconfigured legitimate email gateways.

- **Brand Indicators for Message Identification (BIMI) Gap:** BIMI allows brands to display their verified logo next to authenticated emails. Adoption is under 5% globally. Without BIMI, users cannot visually distinguish authenticated brand emails from spoofed ones.

- **How This Connects to Your Extension:** While your extension is browser-based, many phishing journeys begin with an email. If your extension can detect that a user arrived at a page via an email link (checking the HTTP Referer header for webmail domains like mail.google.com, outlook.live.com), it should apply HEIGHTENED scrutiny to the destination page. Email-to-web transition is a high-probability phishing indicator.

---

### 2.4 BROWSER AND WEB PLATFORM EXPLOITABLE GAPS

**Open Redirect Abuse on Trusted Domains**

Major platforms (Google, Microsoft, Facebook, LinkedIn, Adobe) have URL redirect endpoints that can be abused to redirect users from a trusted domain to a malicious one. For example: `https://www.google.com/url?q=https://evil-phishing-site.com` — the URL starts with google.com, which passes many naive URL checks. Your extension must follow redirect chains to their final destination and evaluate the terminal URL, not just the initial one.

**JavaScript-Based Credential Harvesting Without Traditional Forms**

Modern phishing kits no longer use standard HTML `<form>` elements with `<input type="password">`. Instead, they use JavaScript event listeners on styled `<div>` elements to capture keystrokes, then exfiltrate credentials via `fetch()`, `XMLHttpRequest`, WebSocket connections, or even by encoding data into DNS queries (DNS exfiltration). Your extension must monitor for: any `keydown`/`keypress` event listeners on elements that visually resemble input fields, any outbound network requests triggered after text input, and WebSocket connections initiated on pages displaying login-like UIs.

**Progressive Web App (PWA) Phishing**

Attackers can prompt users to "install" a phishing site as a PWA. Once installed, the PWA runs in its own window WITHOUT an address bar, making it impossible for the user to verify the domain. Furthermore, PWAs can display custom splash screens with brand logos during loading, cache content for offline use (surviving network disconnection), and send push notifications that re-engage the victim later. Your extension should detect and warn when a suspicious site attempts to trigger the PWA install prompt (`beforeinstallprompt` event).

**WebAssembly Obfuscation**

Phishing kits are beginning to compile their credential-harvesting logic into WebAssembly (WASM) binaries, which are opaque to JavaScript-level DOM analysis. A content script that only inspects JavaScript cannot see what WASM code is doing. Your extension must detect WASM module instantiation on login-like pages and treat it as a suspicious signal.

---

### 2.5 EMERGING ATTACK VECTORS (2025-2026)

**QR Code Phishing (Quishing)**

QR codes embedded in emails, PDFs, and even physical media direct users to phishing sites. Because QR codes bypass email link scanners (the link is an image, not text), they have seen a 587% increase in 2024. While your browser extension cannot scan QR codes directly, it WILL see the destination URL when the user navigates to it from their phone's browser. If you build a mobile-compatible version, this becomes relevant.

**AI Voice Cloning Combined with Browser Phishing**

Emerging attacks combine a deepfake voice call (claiming to be IT support) with a simultaneous browser phishing page. The voice directs the victim to enter credentials on the phishing page. Your extension cannot detect the voice component, but it can detect the browser component — the phishing page itself still needs to harvest credentials through the browser.

**OAuth/Consent Phishing**

Instead of stealing passwords, attackers create malicious OAuth applications that request broad permissions (read email, access files) from the victim's Google/Microsoft account. The victim sees a legitimate Google/Microsoft consent screen and the authorization happens on the real Google/Microsoft domain. Your extension should maintain a database of known malicious OAuth application client IDs and detect consent URLs with suspicious `client_id` parameters.

**Session Token Theft Post-MFA**

AiTM attacks using tools like Evilginx2, Modlishka, and Muraena steal session cookies AFTER the user has completed MFA on the legitimate site through the proxy. These attacks make MFA partially ineffective. Your extension is positioned to detect these because the proxy domain will differ from the legitimate domain — even though the content is identical.

---

## PART THREE: COMPLETE BUILD ROADMAP — FROM ZERO TO DEPLOYED EXTENSION

This roadmap covers every component, every API, every library, every data flow, and every connection point. Follow this sequentially.

---

### PHASE 0: PROJECT FOUNDATION AND ENVIRONMENT SETUP

**Duration:** 1–2 weeks

**0.1 Development Machine Requirements**
- Operating System: Ubuntu 22.04 LTS or macOS (Windows with WSL2 is acceptable but adds friction)
- RAM: Minimum 16GB (32GB recommended for model training)
- GPU: NVIDIA GPU with CUDA support (for model training — not needed for extension development itself)
- Storage: Minimum 100GB free (datasets, model weights, node_modules, Python environments)

**0.2 Accounts You Must Create**
- GitHub account (version control, CI/CD with GitHub Actions)
- Google Cloud Platform account (for Chrome Web Store publishing, optional Cloud Vision API, Google Safe Browsing API key)
- VirusTotal account (free tier gives 4 requests/minute, sufficient for development)
- URLScan.io account (free API key, 100 scans/day)
- WhoisXML API account (free tier gives 500 queries/month)
- PhishTank account (free API access to known phishing URL database)
- OpenPhish account (free community feed access)
- Cloudflare account (for backend deployment and DNS)
- Docker Hub account (container registry)
- Supabase or PlanetScale account (managed database, free tier)
- Redis Cloud account (managed Redis, free tier for caching)

**0.3 Software to Install**
- Node.js v20+ LTS (extension frontend build tooling)
- Python 3.11+ (ML model training and backend)
- Docker and Docker Compose (containerized deployment)
- Chrome browser (latest stable, for extension testing)
- Chrome Extension development tools (chrome://extensions in developer mode)
- VS Code with extensions: ESLint, Prettier, Python, Jupyter, Docker
- Git
- Postman or Insomnia (API testing)
- Wireshark (network traffic analysis during testing)

**0.4 Repository Structure**

```
phishing-shield/
├── extension/                    # Chrome extension (MV3)
│   ├── manifest.json
│   ├── background/
│   │   └── service-worker.js
│   ├── content/
│   │   └── content-script.js
│   ├── offscreen/
│   │   ├── offscreen.html
│   │   └── offscreen.js
│   ├── popup/
│   │   ├── popup.html
│   │   ├── popup.css
│   │   └── popup.js
│   ├── models/                   # Bundled ML models (ONNX/TFLite)
│   ├── rules/                    # declarativeNetRequest rule files
│   ├── assets/                   # Icons, brand logo reference DB
│   └── lib/                      # Bundled WASM/JS libraries
├── backend/                      # FastAPI backend server
│   ├── app/
│   │   ├── main.py
│   │   ├── api/
│   │   ├── ml/
│   │   ├── vision/
│   │   ├── threat_intel/
│   │   ├── database/
│   │   └── utils/
│   ├── models/                   # Trained model files
│   ├── Dockerfile
│   └── requirements.txt
├── ml-training/                  # Model training pipeline
│   ├── notebooks/
│   ├── data/
│   ├── scripts/
│   └── configs/
├── data-collection/              # Dataset building scripts
├── tests/
├── docs/
├── docker-compose.yml
└── README.md
```

---

### PHASE 1: DATA COLLECTION AND DATASET CONSTRUCTION

**Duration:** 2–3 weeks

This is the most critical phase. Your models are only as good as your data. The research papers conclusively demonstrate that dataset quality is the single largest determinant of real-world performance.

**1.1 Data Sources for Phishing URLs**

| Source | What It Provides | Access Method | Volume |
|--------|-----------------|---------------|--------|
| PhishTank | Verified community-reported phishing URLs | REST API + bulk download (CSV) | ~75,000 verified active URLs |
| OpenPhish | Curated phishing URLs with metadata | Feed download (free community) | ~5,000–10,000 active URLs |
| Phishing.Database (GitHub) | Aggregated phishing domains, URLs, IPs | Git clone / raw file download | ~500,000+ historical entries |
| URLhaus (abuse.ch) | Malware distribution URLs | REST API + CSV feed | ~1,000,000+ entries |
| CertStream | Real-time certificate transparency logs | WebSocket stream (certstream.calidog.io) | Continuous stream, ~millions/day |
| APWG eCrime Database | Academic phishing dataset | Requires APWG membership | ~500,000+ entries |

**1.2 Data Sources for Legitimate URLs**

| Source | What It Provides | Access Method |
|--------|-----------------|---------------|
| Tranco List | Research-grade top domain ranking (replaces Alexa) | CSV download from tranco-list.eu |
| Common Crawl | Web archive with URL metadata | S3 bucket access |
| Chrome UX Report (CrUX) | Real user experience data for top domains | BigQuery public dataset |
| Majestic Million | Top 1 million domains by referring subnets | CSV download |

**1.3 Feature Extraction Pipeline**

For each URL (both phishing and legitimate), extract the following features. This is a superset of all features identified across the research papers:

**Category A: Pure Lexical Features (extractable locally in-extension, zero network calls)**
1. URL total length (characters)
2. Hostname length
3. Path length
4. Query string length
5. Fragment length
6. Number of dots in URL
7. Number of dots in hostname
8. Number of hyphens in URL
9. Number of hyphens in hostname
10. Number of underscores in URL
11. Number of @ symbols
12. Number of digits in URL
13. Number of digits in hostname
14. Digit-to-letter ratio
15. Number of subdomains
16. Subdomain length (longest)
17. Number of path directories (count of /)
18. Number of query parameters (count of & + 1)
19. Number of fragments
20. Presence of IP address instead of domain name (regex detection)
21. Is IP address in decimal/octal/hex format
22. Shannon entropy of full URL
23. Shannon entropy of hostname
24. Shannon entropy of path
25. Number of special characters (!$%^*()+={}[]|;:'",<>?)
26. Has port number in URL
27. Port number value if present
28. Uses URL shortening service (check against known shorteners list)
29. Number of redirections in URL structure (//)
30. Contains "login," "signin," "account," "verify," "update," "secure," "banking," "confirm" keywords
31. Contains brand name in subdomain but not in registered domain
32. Punycode detected (xn-- prefix)
33. Suspicious TLD (.xyz, .icu, .top, .tk, .ml, .ga, .cf, .gq, .buzz, .club, .info, .site, .online, .website)
34. Double TLD (e.g., .com.br.phishing.com)
35. Ratio of consonants to vowels (DGA detection)
36. Longest consonant sequence (DGA detection)
37. URL contains encoded characters (%xx) — count
38. URL depth (number of path segments)
39. Is HTTPS (boolean)

**Category B: Host-Based Features (require network lookups — cached or API)**
40. Domain age (days since registration — WHOIS)
41. Domain expiry (days until expiration — WHOIS)
42. Registrar name
43. Registrant country
44. DNS record count (A, AAAA, MX, NS, TXT)
45. Has SPF record (boolean)
46. Has DMARC record (boolean)
47. IP geolocation country
48. IP belongs to known hosting provider / CDN
49. ASN (Autonomous System Number) and ASN organization
50. Number of resolved IP addresses
51. Reverse DNS match (PTR record matches domain)
52. SSL certificate issuer
53. SSL certificate age (days since issuance)
54. SSL certificate validity period
55. SSL certificate is wildcard (boolean)
56. SSL certificate subject alternative names (SAN) count
57. SSL certificate matches domain (boolean)
58. Google Safe Browsing status
59. VirusTotal detection count
60. PhishTank listed (boolean)
61. Domain is on Tranco top 10K/100K/1M (rank or boolean tiers)
62. PageRank or similar authority score

**Category C: Content-Based Features (require page load — content script extraction)**
63. Page title length
64. Page title contains brand name not matching domain
65. Number of external links
66. Number of internal links
67. External-to-internal link ratio
68. Number of `<form>` elements
69. Form action URL — is it external/empty/JavaScript/about:blank
70. Has password input field
71. Has hidden input fields (count)
72. Number of `<iframe>` elements
73. Has invisible iframes (0x0 px or display:none)
74. Number of `<script>` elements
75. External-to-internal script ratio
76. Uses `eval()` or `Function()` constructor
77. Has `onmouseover` event handlers (status bar manipulation)
78. Disables right-click (oncontextmenu="return false")
79. Has pop-up windows (window.open calls)
80. Number of redirections on page load
81. Favicon URL — does it load from external domain
82. Has meta refresh tag
83. Uses data: URI scheme in any element
84. robots.txt blocks indexing (meta robots or robots.txt noindex)
85. Page uses WebSocket connections (count)
86. Page loads WebAssembly modules (boolean)
87. Login form present but no registration/help links
88. Copyright text year or company name mismatches domain
89. Has excessive use of CSS position:absolute/fixed overlays
90. Page requests camera/microphone/location permissions

**Category D: Visual Features (require screenshot — offscreen document processing)**
91. Logo detected (boolean)
92. Logo brand identification (predicted brand name)
93. Logo-to-domain consistency (match/mismatch)
94. Visual similarity score against reference brand page
95. Color palette matches known brand (cosine similarity of color histograms)
96. Page layout similarity score (structural similarity index — SSIM)
97. OCR-extracted text from logo
98. OCR-extracted text matches domain (boolean)
99. Favicon visual similarity to known brands
100. Screenshot perceptual hash distance from reference

**1.4 Dataset Balancing Strategy**

Based on the PhreshPhish paper's recommendations and the research gap identified in your existing report regarding unrealistic base rates:

- For MODEL TRAINING: Use a 60/40 split (60% legitimate, 40% phishing) to avoid extreme class imbalance while still representing the scarcity of phishing
- For MODEL EVALUATION: Use a realistic 99/1 split (99% legitimate, 1% phishing) to accurately measure precision and false positive rates in production conditions
- Apply SMOTE (Synthetic Minority Over-sampling Technique) or ADASYN for the training set if needed
- Maintain completely separate temporal splits — train on data from months 1-3, validate on month 4, test on months 5-6 — NO temporal overlap

**1.5 Automated Data Collection Pipeline**

Build a pipeline using:
- **Scrapy** (Python web scraping framework) — to crawl and archive phishing pages from feeds before they go down
- **Playwright** (headless browser automation) — to render pages fully (including JavaScript execution) and capture screenshots
- **CertStream Python library** — to monitor certificate transparency logs for suspicious domain registrations in real-time
- **Schedule/APScheduler** — to run collection jobs every 6 hours
- Store everything in **PostgreSQL** (structured data) and **MinIO/S3** (screenshots, HTML snapshots)

---

### PHASE 2: MACHINE LEARNING MODEL DEVELOPMENT

**Duration:** 3–4 weeks

**2.1 Model Architecture — The Layered Detection Engine**

You will train FIVE distinct models, each handling a different detection layer. Their outputs will be fused by a meta-classifier.

**Model 1: Lightweight URL Classifier (Client-Side — runs in extension)**
- Algorithm: XGBoost or LightGBM
- Input: Features 1-39 (Category A — pure lexical, zero network calls)
- Output: Probability score (0.0 to 1.0) of phishing
- Target inference time: <5ms
- Model size: <2MB (serialized to ONNX format)
- Training framework: Scikit-learn + XGBoost Python library
- Deployment format: ONNX (converted using skl2onnx or onnxmltools)
- Runtime in extension: ONNX Runtime Web (ort-wasm.js bundled in extension)

**Model 2: Deep URL Analyzer (Backend — API call for ambiguous URLs)**
- Architecture: Character-level CNN + Attention (inspired by URLNet + attention paper)
- Input: Raw URL string, character-embedded to fixed length (200 characters)
- Output: Probability score + attention weights (for explainability)
- Target inference time: <50ms on GPU backend
- Training framework: PyTorch
- Deployment: TorchServe or FastAPI with ONNX Runtime GPU

**Model 3: Content Analyzer (Client-Side — runs in content script + offscreen doc)**
- Algorithm: Random Forest or Gradient Boosting
- Input: Features 63-90 (Category C — content-based)
- Output: Probability score
- Target inference time: <10ms
- Deployment: ONNX in offscreen document

**Model 4: Visual Similarity Engine (Backend — API call)**
- Architecture: Siamese Network with ResNet50 backbone (similar to Phishpedia approach)
- Input: Screenshot of current page + reference brand logo database
- Output: Detected brand name + similarity score + bounding box
- Training: PyTorch + torchvision
- Reference database: 500+ brand logos (build from publicly available brand asset pages)
- Deployment: FastAPI backend with GPU inference

**Model 5: Meta-Classifier (Backend — final fusion)**
- Algorithm: Logistic Regression or small neural network
- Input: Outputs from Models 1-4 + threat intelligence signals (features 58-62)
- Output: Final binary decision (SAFE / PHISHING) + confidence score + explanation vector
- This model learns the optimal weighting between the sub-models

**2.2 Training Pipeline Details**

For each model:

Step 1: Data Preprocessing
- Library: Pandas, NumPy
- Handle missing values (WHOIS data often unavailable — use median imputation or "unknown" category)
- Normalize numerical features using StandardScaler or MinMaxScaler
- Encode categorical features using LabelEncoder or one-hot encoding

Step 2: Feature Selection
- Apply Mutual Information scoring to rank features by information gain
- Apply Recursive Feature Elimination (RFE) with cross-validation
- For the client-side model, apply feature importance from XGBoost and remove features with <1% importance to minimize model size

Step 3: Training
- Split: 80% train, 10% validation, 10% test (temporal split)
- Hyperparameter tuning: Optuna library (Bayesian optimization)
- For XGBoost: tune max_depth (3-12), n_estimators (100-1000), learning_rate (0.01-0.3), subsample (0.6-1.0), colsample_bytree (0.6-1.0), min_child_weight (1-10), gamma (0-5)
- For PyTorch models: tune learning_rate, batch_size, dropout_rate, number_of_layers, hidden_dim
- Use early stopping based on validation loss

Step 4: Evaluation
- Metrics: Accuracy, Precision, Recall, F1-Score, AUC-ROC, AUC-PR (Precision-Recall curve is MORE important than ROC for imbalanced data)
- Evaluate on the realistic 99/1 test set
- Calculate false positive rate per 10,000 legitimate pages (target: <5 false positives per 10,000)
- Adversarial evaluation: test against PhishOracle-generated adversarial samples

Step 5: Export
- XGBoost/sklearn models → ONNX format using `skl2onnx`
- PyTorch models → ONNX format using `torch.onnx.export()`
- Quantize models using ONNX Runtime quantization tools (int8 quantization reduces model size by 4x with <1% accuracy loss)

**2.3 Specific Libraries Required for ML Pipeline**

| Library | Version | Purpose |
|---------|---------|---------|
| scikit-learn | 1.4+ | Feature engineering, classic ML models, preprocessing |
| xgboost | 2.0+ | Primary URL classifier |
| lightgbm | 4.0+ | Alternative to XGBoost (slightly faster inference) |
| pytorch | 2.2+ | Deep learning models (URL CNN, Siamese network) |
| torchvision | 0.17+ | Pre-trained ResNet50 backbone for visual similarity |
| transformers (Hugging Face) | 4.40+ | DistilBERT/PhishLang for NLP features |
| onnx | 1.15+ | Model interchange format |
| onnxruntime | 1.17+ | Backend inference engine |
| skl2onnx | 1.16+ | sklearn-to-ONNX converter |
| optuna | 3.5+ | Hyperparameter optimization |
| pandas | 2.2+ | Data manipulation |
| numpy | 1.26+ | Numerical computation |
| matplotlib/seaborn | Latest | Visualization of results |
| imbalanced-learn | 0.12+ | SMOTE and other resampling techniques |
| shap | 0.44+ | Model explainability (SHAP values for prediction explanation) |

---

### PHASE 3: CHROME EXTENSION DEVELOPMENT (MANIFEST V3)

**Duration:** 3–4 weeks

This is where everything comes together in the user-facing product. Every architectural decision below is informed by the MV3 constraints analyzed in your existing research.

**3.1 manifest.json — Complete Configuration**

Every permission and declaration explained:

```
Permissions needed:
- "activeTab" — access to the currently active tab's URL and content
- "storage" — local storage for caching threat intelligence and user settings
- "alarms" — for periodic background tasks (model updates, feed refreshes)
- "offscreen" — to create offscreen documents for ML inference
- "declarativeNetRequest" — for static blocklist rule enforcement
- "webNavigation" — to detect navigation events, redirects, and URL changes
- "tabs" — to read tab URLs and manage tab lifecycle
- "scripting" — to programmatically inject content scripts
- "notifications" — to alert users about detected threats
- "identity" — (optional) for user authentication if you add account features

Host permissions:
- "<all_urls>" — needed to analyze any page the user visits
- Your backend API domain specifically listed

web_accessible_resources:
- models/*.onnx (bundled ML models)
- lib/ort-wasm*.wasm (ONNX Runtime WASM files)
- offscreen/offscreen.html
- assets/brand-logos/* (reference logo database)

declarativeNetRequest rulesets:
- rules/phishing-blocklist.json (static rules from threat intelligence feeds)
- rules/known-malicious-patterns.json (regex-based URL patterns)
```

**3.2 Component Architecture and Data Flow**

Here is exactly how data flows through your extension, step by step:

```
USER NAVIGATES TO URL
        │
        ▼
┌─────────────────────────────┐
│   LAYER 0: declarativeNet-  │
│   Request Static Blocklist   │
│   (Runs in browser engine,   │
│   zero extension code)       │
│   Check against ~500K rules  │
│   from PhishTank/OpenPhish   │
├──────────┬──────────────────┘
│          │
│   URL NOT in blocklist
│          │
│          ▼
│  ┌───────────────────────────┐
│  │   SERVICE WORKER          │
│  │   (background.js)         │
│  │                           │
│  │   Event: webNavigation.   │
│  │   onCompleted             │
│  │                           │
│  │   Step 1: Extract URL     │
│  │   Step 2: Check local     │
│  │   cache (IndexedDB)       │
│  │   Step 3: Compute lexical │
│  │   features (1-39)         │
│  │   Step 4: Create/reuse    │
│  │   offscreen document      │
│  │   Step 5: Send features   │
│  │   to offscreen for ONNX   │
│  │   inference (Model 1)     │
│  ├───────────┬───────────────┘
│              │
│     Model 1 returns score
│              │
│     IF score < 0.3 → SAFE → Green icon, no action
│     IF score > 0.8 → PHISHING → Immediate block + warning page
│     IF 0.3 ≤ score ≤ 0.8 → AMBIGUOUS → Continue to deeper analysis
│              │
│              ▼
│  ┌───────────────────────────┐
│  │   CONTENT SCRIPT          │
│  │   (content-script.js)     │
│  │                           │
│  │   Injected into page      │
│  │   Extracts:               │
│  │   - Full DOM structure    │
│  │   - Form elements & attrs │
│  │   - Script behaviors      │
│  │   - Visual screenshot     │
│  │     (html2canvas or       │
│  │     chrome.tabs.          │
│  │     captureVisibleTab)    │
│  │   - Content features      │
│  │     (63-90)               │
│  │                           │
│  │   Sends data to service   │
│  │   worker via              │
│  │   chrome.runtime.         │
│  │   sendMessage()           │
│  ├───────────┬───────────────┘
│              │
│              ▼
│  ┌───────────────────────────┐
│  │   OFFSCREEN DOCUMENT      │
│  │   (offscreen.html)        │
│  │                           │
│  │   Receives content        │
│  │   features                │
│  │   Runs Model 3 (Content   │
│  │   Classifier) via ONNX    │
│  │   Runtime Web             │
│  │                           │
│  │   Returns content score   │
│  ├───────────┬───────────────┘
│              │
│     IF combined (Model 1 + Model 3) score resolves clearly → 
│     block or allow
│     IF still ambiguous → escalate to backend
│              │
│              ▼
│  ┌───────────────────────────┐
│  │   BACKEND API CALL        │
│  │   (FastAPI server)        │
│  │                           │
│  │   Sends:                  │
│  │   - URL (hashed for       │
│  │     privacy, or raw if    │
│  │     user consents)        │
│  │   - Screenshot (base64)   │
│  │   - Extracted features    │
│  │   - Content hash          │
│  │                           │
│  │   Backend runs:           │
│  │   - Model 2 (Deep URL)   │
│  │   - Model 4 (Visual)     │
│  │   - WHOIS lookup          │
│  │   - VirusTotal check      │
│  │   - Graph DB query        │
│  │   - Model 5 (Meta-       │
│  │     classifier fusion)    │
│  │                           │
│  │   Returns:                │
│  │   - Final verdict         │
│  │   - Confidence score      │
│  │   - Explanation reasons   │
│  │   - Brand identified      │
│  ├───────────┬───────────────┘
│              │
│              ▼
│  ┌───────────────────────────┐
│  │   USER NOTIFICATION       │
│  │                           │
│  │   IF PHISHING:            │
│  │   - Inject warning        │
│  │     overlay into page     │
│  │   - Show blocking         │
│  │     interstitial          │
│  │   - Browser notification  │
│  │   - Log to extension      │
│  │     dashboard             │
│  │                           │
│  │   IF SAFE:                │
│  │   - Green shield icon     │
│  │   - Cache result for      │
│  │     24 hours              │
│  └───────────────────────────┘
```

**3.3 Specific Libraries Bundled in Extension**

| Library | Size | Purpose | Bundle Location |
|---------|------|---------|----------------|
| ONNX Runtime Web (ort) | ~3-8MB (WASM backend) | Client-side ML inference | extension/lib/ |
| html2canvas | ~40KB | Screenshot capture from content script | extension/lib/ |
| DOMPurify | ~15KB | Sanitize extracted HTML before processing | extension/lib/ |
| crypto-js (SHA256) | ~20KB | Hash URLs for privacy-preserving cache lookups | extension/lib/ |
| Punycode.js | ~5KB | IDN/Punycode normalization | extension/lib/ |
| tldts (TLD extraction) | ~30KB | Accurate TLD and registered domain extraction | extension/lib/ |

**3.4 declarativeNetRequest Blocklist Management**

Your extension will ship with a static ruleset and support dynamic rule updates:

Static rules (bundled at build time):
- Parse PhishTank verified feed → convert to declarativeNetRequest JSON rules
- Parse Phishing.Database domain list → convert to block rules
- Maximum: 300,000 static rules per extension (Chrome limit)

Dynamic rules (updated via alarms API every 6 hours):
- Service worker wakes on alarm
- Fetches latest feed from your backend API (which aggregates PhishTank, OpenPhish, Phishing.Database, abuse.ch)
- Converts new entries to declarativeNetRequest format
- Uses chrome.declarativeNetRequest.updateDynamicRules()
- Maximum: 30,000 dynamic rules (Chrome limit)
- Implement LRU eviction — remove oldest rules when approaching limit

**3.5 Handling the Service Worker Lifecycle**

The service worker will be killed by Chrome after ~30 seconds of inactivity. You must design for this:

- Use chrome.alarms.create() for periodic tasks (minimum interval: 1 minute)
- Use chrome.storage.session for ephemeral state that survives service worker restarts but not browser restarts
- Use chrome.storage.local for persistent state (cached verdicts, user preferences)
- Use IndexedDB (in the offscreen document) for larger data like the brand logo reference database
- NEVER rely on in-memory variables in the service worker persisting between events

**3.6 Warning UI Design**

When phishing is detected, inject a full-page overlay via the content script:

The overlay should:
- Cover the entire page with a semi-transparent red background
- Display a clear "PHISHING DETECTED" warning with the identified target brand
- Show the specific reasons (e.g., "Domain registered 2 days ago," "Logo matches PayPal but domain is paypa1-security.com," "Page contains credential harvesting form targeting external server")
- Provide two buttons: "Go Back to Safety" (navigates to the legitimate site) and "I understand the risk, proceed anyway" (requires typing a confirmation phrase)
- Be un-closable via simple methods (prevent the page's JavaScript from removing it)

---

### PHASE 4: BACKEND SERVER DEVELOPMENT

**Duration:** 2–3 weeks

**4.1 Technology Stack**

| Component | Technology | Justification |
|-----------|-----------|---------------|
| Web Framework | FastAPI (Python) | Async support, auto-generated OpenAPI docs, high performance |
| ML Serving | ONNX Runtime (CPU) + PyTorch (GPU for visual model) | Optimized inference |
| Database (relational) | PostgreSQL 16 | Structured data, threat intelligence storage |
| Database (graph) | Neo4j Community Edition | Domain relationship graphs |
| Cache | Redis 7 | URL verdict caching, rate limiting |
| Object Storage | MinIO (self-hosted S3-compatible) | Screenshots, model artifacts |
| Task Queue | Celery with Redis broker | Async heavy tasks (WHOIS, VirusTotal, visual analysis) |
| API Gateway | Nginx or Caddy | SSL termination, rate limiting, load balancing |
| Containerization | Docker + Docker Compose | Reproducible deployment |
| Monitoring | Prometheus + Grafana | API latency, model performance tracking |

**4.2 API Endpoints**

| Endpoint | Method | Input | Output | Purpose |
|----------|--------|-------|--------|---------|
| /api/v1/analyze/url | POST | {url, lexical_features, client_score} | {verdict, confidence, reasons} | Quick URL analysis |
| /api/v1/analyze/full | POST | {url, features, screenshot_base64, html_hash} | {verdict, confidence, brand_detected, reasons, visual_score} | Full multi-modal analysis |
| /api/v1/feed/update | GET | (none) | {rules: [...declarativeNetRequest rules]} | Extension fetches updated blocklist rules |
| /api/v1/report | POST | {url, user_verdict, screenshot} | {report_id} | User reports false positive/negative |
| /api/v1/status | GET | (none) | {model_version, feed_version, uptime} | Health check |
| /api/v1/whitelist/check | POST | {domain} | {is_whitelisted, rank, category} | Check against Tranco/known good list |

**4.3 External APIs Your Backend Will Call**

| API | Purpose | Rate Limit (Free Tier) | How It's Used |
|-----|---------|----------------------|---------------|
| Google Safe Browsing Lookup API v4 | Check URL against Google's threat lists | 10,000 requests/day | First-pass check for known threats |
| VirusTotal API v3 | Multi-engine URL/domain scan | 4 requests/minute, 500/day | Deep scan for ambiguous URLs |
| URLScan.io API | Render and analyze URL in sandbox | 100 private scans/day | Visual analysis backup, DOM capture |
| WhoisXML API | Domain registration data (WHOIS) | 500 queries/month | Domain age, registrar info |
| IPQualityScore | URL reputation, fraud scoring | 5,000 lookups/month | Additional reputation signal |
| AbuseIPDB | IP reputation check | 1,000 checks/day | Check if hosting IP is associated with abuse |
| crt.sh API | Certificate Transparency log search | Unlimited (public) | Find all certificates issued for similar domains |
| Shodan API | Infrastructure reconnaissance | 100 queries/month (free) | Identify hosting details, open ports, services |
| PhishTank API | Known phishing URL verification | Unlimited (with API key) | Cross-reference URL against verified reports |
| OpenPhish Community Feed | Latest phishing URLs | Updated every 12 hours (download) | Continuous model retraining data + blocklist |
| Have I Been Pwned API v3 | Check if a domain has been involved in breaches | Rate limited | If a phishing page targets a breached service, increase risk score |

**4.4 Backend Processing Pipeline (detailed flow)**

When a request hits `/api/v1/analyze/full`:

1. **Redis Cache Check** — Hash the URL, check if a verdict exists from the last 24 hours. If cache hit, return immediately (<5ms).

2. **Whitelist Check** — Check URL's registered domain against the Tranco top-100K list stored in PostgreSQL. If the domain ranks in top-10K AND no suspicious subdomain patterns exist AND the certificate is valid for the exact domain, return SAFE immediately.

3. **Parallel Async Tasks** (launched simultaneously via asyncio.gather or Celery group):
   - Task A: WHOIS Lookup → Extract domain age, registrar, registrant country
   - Task B: Google Safe Browsing API check
   - Task C: VirusTotal API check
   - Task D: Model 2 inference (Deep URL CNN) → Returns URL risk score + attention weights
   - Task E: Model 4 inference (Visual Similarity) → Returns detected brand + similarity score
   - Task F: Neo4j graph query → Check if the domain's IP, ASN, or registrant appears in known phishing infrastructure clusters

4. **Feature Aggregation** — Collect all results into a single feature vector.

5. **Model 5 (Meta-Classifier) Inference** — Feed the aggregated feature vector into the meta-classifier. Returns final probability.

6. **Decision Logic**:
   - Probability ≥ 0.7: PHISHING
   - Probability < 0.3: SAFE
   - 0.3 ≤ Probability < 0.7: SUSPICIOUS (shown with yellow warning)

7. **Explanation Generation** — Using SHAP values from the meta-classifier, identify the top 3 contributing factors and generate human-readable explanations.

8. **Cache Result** — Store verdict in Redis with 24-hour TTL.

9. **Return Response** — JSON payload back to extension.

Target total response time: <500ms for the full pipeline (with parallel execution).

**4.5 Graph Database Schema (Neo4j)**

Nodes:
- Domain {name, first_seen, last_seen, is_phishing, phishing_confidence}
- IPAddress {address, geolocation, asn, asn_org}
- Certificate {fingerprint, issuer, issued_date, expiry_date}
- Registrant {name_hash, email_hash, organization}
- ASN {number, organization, country}

Relationships:
- (Domain)-[:RESOLVES_TO]->(IPAddress)
- (Domain)-[:HAS_CERTIFICATE]->(Certificate)
- (Domain)-[:REGISTERED_BY]->(Registrant)
- (IPAddress)-[:BELONGS_TO]->(ASN)
- (Domain)-[:LINKED_FROM]->(Domain)
- (Domain)-[:VISUALLY_SIMILAR_TO]->(Domain)

When a new URL is analyzed, create/update its nodes and query for suspicious patterns:
- Domain resolves to same IP as known phishing domain
- Domain registered by same entity as known phishing domains
- Domain's ASN hosts disproportionate number of phishing sites
- Domain's certificate was issued the same day as domain registration (common in phishing)

---

### PHASE 5: VISUAL SIMILARITY ENGINE (DETAILED)

**Duration:** 2–3 weeks (overlaps with Phase 2)

**5.1 Brand Logo Reference Database Construction**

You need a curated database of brand logos and reference screenshots for the top targeted brands in phishing campaigns.

Top 50 most-phished brands (based on APWG and Phishpedia data):
Microsoft, Google, Apple, Facebook/Meta, Amazon, PayPal, Netflix, LinkedIn, DHL, USPS, FedEx, WhatsApp, Instagram, Dropbox, Chase Bank, Wells Fargo, Bank of America, Citibank, HSBC, Barclays, ING, Crédit Agricole, Sparkasse, Volksbank, Adobe, DocuSign, WeTransfer, Zoom, Slack, Salesforce, GitHub, Coinbase, Binance, MetaMask, Trust Wallet, Outlook, Yahoo, AOL, AT&T, Verizon, Comcast, HDFC Bank, SBI (State Bank of India), ICICI Bank, Axis Bank, Paytm, Flipkart, Swiggy, Jio, Airtel

For Indian audience specifically (since VIT is in India), include Indian banking and service brands prominently.

For each brand, store:
- 5-10 variations of the official logo (different sizes, light/dark variants, with/without text)
- 2-3 reference screenshots of the legitimate login page
- Known legitimate domains (e.g., for Microsoft: microsoft.com, live.com, outlook.com, office.com, office365.com, microsoftonline.com, azure.com, login.microsoftonline.com)
- Brand color palette (primary and secondary colors as hex values)

Storage: Embed brand logo feature vectors (extracted from ResNet50) into a FAISS vector index for fast nearest-neighbor lookup.

**5.2 Visual Pipeline Architecture**

Step 1: Screenshot Capture
- Content script calls `html2canvas(document.body)` or the service worker calls `chrome.tabs.captureVisibleTab()`
- Resize to 224x224 pixels (ResNet50 input size)
- Convert to base64 for transmission

Step 2: Logo Detection (Object Detection)
- Use a YOLO-v8 or Faster R-CNN model fine-tuned on a logo detection dataset
- Input: Full page screenshot
- Output: Bounding boxes of detected logos with confidence scores

Step 3: Logo Recognition (Siamese Network)
- Extract each detected logo region
- Pass through ResNet50 backbone → get 2048-dimensional embedding
- Query FAISS index of brand logo embeddings
- Return closest brand match and cosine similarity score
- Threshold: If similarity > 0.85 → brand identified

Step 4: Domain-Brand Consistency Check
- Compare identified brand with the actual domain
- If brand = "PayPal" but domain ≠ any known PayPal domain → FLAG

Step 5: OCR Verification
- Run OCR (Tesseract via tesseract.js, or backend EasyOCR) on the logo region
- Extract text from the logo
- Cross-reference extracted text with domain

**5.3 Libraries for Visual Pipeline**

| Library | Purpose | Runs Where |
|---------|---------|-----------|
| FAISS (faiss-cpu) | Vector similarity search for logo matching | Backend |
| ultralytics (YOLOv8) | Logo object detection | Backend |
| torchvision (ResNet50) | Logo feature extraction | Backend |
| EasyOCR | Text extraction from logo images | Backend |
| Pillow | Image preprocessing | Both |
| opencv-python | Image manipulation, color analysis | Backend |
| html2canvas (JS) | Client-side screenshot capture | Extension |

---

### PHASE 6: THREAT INTELLIGENCE INTEGRATION

**Duration:** 1–2 weeks (overlaps with Phase 4)

**6.1 Feed Ingestion Pipeline**

Build an automated pipeline that runs every 6 hours:

1. **PhishTank Feed** → Download CSV of verified phishing URLs → Parse → Store in PostgreSQL `phishing_urls` table → Generate declarativeNetRequest rules

2. **OpenPhish Feed** → Download text file of URLs → Same pipeline

3. **Phishing.Database** → Git pull latest → Parse domain and URL lists → Merge into database

4. **abuse.ch URLhaus** → API query for last 24 hours → Parse JSON → Store

5. **CertStream Monitor** (continuous):
   - Connect to `wss://certstream.calidog.io`
   - Filter certificate registrations for domains that have Levenshtein distance <3 from any brand in your database
   - Run Model 1 (URL classifier) on each suspicious domain
   - If score > 0.5 → add to proactive blocklist BEFORE any user visits it
   - This gives you PRE-EMPTIVE detection capability

6. **Aggregate and Deduplicate** → Remove duplicate URLs → Update timestamp for existing entries → Mark stale entries (>30 days old, not re-verified) for archival

7. **Generate Extension Update Package** → Convert active threats to declarativeNetRequest JSON → Make available at `/api/v1/feed/update` endpoint

**6.2 CertStream Integration Details**

This is a critical differentiator for your extension. Most extensions are reactive (they detect phishing when a user visits). CertStream makes you proactive.

The CertStream service provides a real-time WebSocket feed of ALL SSL/TLS certificates being issued globally. You monitor this feed for:

- Domains containing brand names (e.g., "paypal-verify.com")
- Domains using common phishing keywords (login, secure, verify, update, confirm, account, alert, support, help)
- Domains with high Levenshtein similarity to known brands
- Domains with suspicious TLDs (.xyz, .top, .icu, .buzz)
- Domains with high entropy (suggesting DGA)

When a suspicious certificate is detected:
- Immediately add domain to your database as "SUSPICIOUS - PRE-VERIFIED"
- Attempt to crawl the domain (may not be live yet)
- When/if a user visits this domain, the extension already has it flagged

Python library: `certstream` (pip install certstream)

---

### PHASE 7: ANTI-EVASION AND ADVANCED DETECTION MODULES

**Duration:** 2 weeks

**7.1 BitB (Browser-in-the-Browser) Detection**

Your content script should scan for:
- `<div>` or `<iframe>` elements with `position: fixed` and dimensions that approximate browser window chrome
- Elements containing text that looks like a URL (matches URL regex) but is NOT in an actual `<input>` or address bar
- Shadow DOM elements that render address-bar-like UI components
- Any element with `z-index > 9999` that overlays the entire viewport and contains form elements

**7.2 Credential Exfiltration Detection**

Monitor in the content script:
- Any `fetch()`, `XMLHttpRequest`, or `navigator.sendBeacon()` calls that include data from input fields
- Cross-origin form submissions (form action URL differs from page domain)
- WebSocket connections that transmit data correlated with keystrokes
- `keydown`/`keypress` event listeners attached to the document or body (not to actual input fields — this indicates keystroke logging)

**7.3 Redirect Chain Analysis**

Using the `webNavigation.onBeforeNavigate` and `webNavigation.onCompleted` events:
- Track the full chain of redirects from initial URL to final landing page
- Flag chains with more than 3 redirects
- Flag chains that pass through URL shortener services
- Flag chains where the final domain differs significantly from the initial domain
- Flag chains that transit through known open redirect endpoints on legitimate sites

**7.4 JavaScript Behavior Analysis**

The content script should detect:
- Dynamic form injection (forms added to DOM after page load via JavaScript)
- `eval()` or `new Function()` calls with encoded/obfuscated strings
- `document.write()` calls that inject login forms
- Clipboard monitoring (`navigator.clipboard.readText()`)
- Attempts to override browser history (`history.pushState` to show fake URL)
- Disabling paste on password fields (legitimate sites don't do this)
- Auto-redirect after form submission to the legitimate site (common phishing kit behavior to hide evidence)

---

### PHASE 8: PRIVACY ARCHITECTURE

**Duration:** 1 week (design during Phase 0, implement throughout)

Privacy is not optional. It is a fundamental requirement for user trust and regulatory compliance.

**8.1 Privacy Principles**

1. **Local-First Processing:** All fast-path analysis (Model 1, Model 3, blocklist checks) runs entirely on the user's machine. No URL is sent to any server unless the local analysis is inconclusive.

2. **Minimal Data Transmission:** When backend analysis IS needed, send:
   - A SHA-256 hash of the URL (for cache lookup) FIRST
   - Only if the hash is not cached, send the actual URL and screenshot
   - Never send browsing history, cookies, or personal data

3. **User Consent:** Before any backend API call, show a one-time consent prompt explaining what data will be sent and why. Store consent in `chrome.storage.local`.

4. **Data Retention:** Backend deletes submitted URLs and screenshots after analysis (configurable retention period, default: 0 — immediate deletion after verdict caching).

5. **No Tracking:** The extension has no analytics, no telemetry, no user profiling. Consider adding opt-in anonymous aggregate statistics only.

6. **Transparency:** Open-source the extension code. Publish a clear, human-readable privacy policy.

**8.2 Privacy-Preserving API Design**

For maximum privacy, implement a k-anonymity inspired approach:
- Instead of sending the full URL, compute a partial hash (first 4 bytes of SHA-256)
- Send the partial hash to the backend
- Backend returns ALL matching cached verdicts for URLs with that hash prefix
- Client checks locally if its specific full hash matches any returned result
- This way, the backend never knows which specific URL the client is querying (similar to HIBP's k-anonymity model for password checking)

---

### PHASE 9: TESTING AND VALIDATION

**Duration:** 2 weeks

**9.1 Unit Testing**

| Component | Testing Framework | What to Test |
|-----------|------------------|-------------|
| Feature extraction functions | Jest (JS) / Pytest (Python) | Every feature function returns expected values for known URLs |
| ML model inference | Pytest | Model produces consistent outputs, handles edge cases (empty URL, extremely long URL, Unicode URLs) |
| API endpoints | Pytest + httpx | Every endpoint returns correct response codes, handles malformed input |
| Content script | Puppeteer / Playwright | Correctly extracts DOM features from known phishing pages |
| declarativeNetRequest rules | Chrome Extension Testing API | Rules correctly block known bad URLs and allow known good URLs |

**9.2 Integration Testing**

- Build a test harness of 100 known phishing pages (archived via MHTML or WARC) and 100 known legitimate login pages
- Run the complete extension pipeline against each
- Measure: detection rate, false positive rate, end-to-end latency
- Target: >95% detection rate, <0.5% false positive rate, <2 seconds total decision time

**9.3 Adversarial Testing**

- Use PhishOracle to generate adversarial phishing pages
- Manually create 20 evasive phishing pages using techniques from the research:
  - BitB attacks
  - Logo perturbation (color shift, rotation, overlay)
  - Homograph domains (Punycode)
  - HTML smuggling (fragmented payloads assembled via JavaScript)
  - Cloaked pages (serve different content to crawlers vs. browsers)
  - Open redirect chains through Google/Microsoft
- Test extension against each

**9.4 Performance Testing**

- Measure extension's impact on page load time (target: <50ms added latency)
- Measure memory consumption (target: <50MB)
- Measure CPU usage during analysis (target: <5% average, <20% peak)
- Test on low-end hardware (4GB RAM, dual-core CPU)

**9.5 Real-World Beta Testing**

- Deploy to 20-50 beta testers (fellow VIT students)
- Monitor for false positives (legitimate sites blocked) — this is the killer of extension adoption
- Collect feedback on warning UI clarity and trust
- Iterate based on real-world data

---

### PHASE 10: DEPLOYMENT AND DISTRIBUTION

**Duration:** 1–2 weeks

**10.1 Backend Deployment**

Option A (Budget — Free/Low Cost):
- Deploy FastAPI backend on Railway.app or Render.com (free tier with limitations)
- Use Supabase for PostgreSQL (free tier: 500MB)
- Use Upstash for Redis (free tier: 10K commands/day)
- Use Neo4j Aura Free for graph database

Option B (Production):
- Deploy on AWS/GCP/Azure using Docker containers
- Use managed PostgreSQL (RDS/Cloud SQL)
- Use managed Redis (ElastiCache/Memorystore)
- Use Neo4j Aura Professional
- Put behind Cloudflare for DDoS protection and CDN
- Estimated monthly cost: $50-150 for moderate traffic

**10.2 Chrome Web Store Publishing**

Requirements:
- Developer account ($5 one-time fee)
- Detailed privacy policy hosted publicly
- Extension description, screenshots (1280x800), promotional images
- Justification for every permission requested (Chrome review requires this)
- A declared "single purpose" for the extension (phishing detection)
- All code must be human-readable (no obfuscation) or justified
- Review typically takes 1-5 business days
- After approval, updates also require review

**10.3 Firefox Add-on Store (Recommended for broader impact)**

Firefox still supports Manifest V2 (with planned MV3 migration) and is more permissive for security extensions. Port the extension using the WebExtension polyfill library (`webextension-polyfill` on npm). Firefox review is more thorough but generally faster.

**10.4 Edge Add-on Store**

Edge uses the same Chromium engine — your MV3 extension works with minimal changes. Submit to the Microsoft Edge Add-ons store (free, review takes 1-3 days).

---

### PHASE 11: CONTINUOUS IMPROVEMENT AND MAINTENANCE

**Duration:** Ongoing

**11.1 Model Retraining Pipeline**

- Set up a weekly automated retraining pipeline:
  - Pull latest phishing URLs from all feeds
  - Pull latest legitimate URLs from Tranco/CrUX
  - Extract features
  - Retrain Models 1, 2, 3, 5 on updated data
  - Evaluate on hold-out test set
  - If performance ≥ current production model → auto-deploy
  - If performance < current model → flag for manual review
  - Version every model (model_v1, model_v2, etc.)

**11.2 Extension Update Strategy**

- Blocklist rules: Update daily via background sync (chrome.alarms)
- ML models: Update monthly (requires Chrome Web Store review for each extension update)
- Consider using your API to serve model updates dynamically (load model from your server into offscreen document at runtime) — but this requires careful handling under MV3's CSP restrictions. You may need to bundle the model loader and have it fetch weight files declared in web_accessible_resources.

**11.3 Community Feedback Loop**

- Build a simple reporting mechanism in the popup: "Report False Positive" / "Report Missed Phishing"
- Every user report goes to your backend for manual review
- Verified reports are incorporated into the next training cycle
- This creates a virtuous cycle where the model improves with usage

---

### COMPLETE TECHNOLOGY STACK SUMMARY

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Extension Frontend** | HTML5, CSS3, Vanilla JavaScript | Popup UI, warning overlays |
| **Extension Build** | Webpack 5 or Vite | Bundle and optimize extension code |
| **Content Script** | JavaScript (injected) | DOM analysis, feature extraction, screenshot |
| **Service Worker** | JavaScript (background) | Event coordination, caching, message routing |
| **Offscreen Document** | HTML + JavaScript | ML inference (ONNX), heavy processing |
| **Client ML Runtime** | ONNX Runtime Web (WebAssembly) | Run quantized XGBoost/LightGBM locally |
| **Client Screenshot** | html2canvas.js | Render page to canvas for visual analysis |
| **Client URL Parsing** | tldts, Punycode.js | Accurate domain extraction and IDN handling |
| **Backend Framework** | FastAPI (Python 3.11+) | REST API server |
| **Backend ML** | ONNX Runtime, PyTorch | Model inference (URL CNN, Visual Similarity) |
| **Backend Vision** | YOLOv8, ResNet50, EasyOCR | Logo detection, recognition, OCR |
| **Backend Vector Search** | FAISS | Fast logo embedding similarity search |
| **Backend Database** | PostgreSQL 16 | Threat intelligence, URL verdicts, user reports |
| **Backend Graph DB** | Neo4j | Domain relationship analysis |
| **Backend Cache** | Redis 7 | URL verdict caching, rate limiting |
| **Backend Task Queue** | Celery + Redis | Async external API calls |
| **Backend Object Storage** | MinIO | Screenshots, model artifacts |
| **Threat Intel Feeds** | PhishTank, OpenPhish, Phishing.Database, abuse.ch, CertStream | Phishing URL data, proactive detection |
| **External APIs** | Google Safe Browsing, VirusTotal, WhoisXML, URLScan.io, IPQualityScore, AbuseIPDB, crt.sh, Shodan | Multi-source reputation and intelligence |
| **Monitoring** | Prometheus + Grafana | Backend health, model drift detection |
| **Containerization** | Docker + Docker Compose | Reproducible deployment |
| **CI/CD** | GitHub Actions | Automated testing, building, model retraining |
| **Version Control** | Git + GitHub | Code management |

---

### COMPLETE API KEY LIST (WHAT TO REGISTER FOR)

| Service | Registration URL | Free Tier Limits | Required For |
|---------|-----------------|-----------------|-------------|
| Google Safe Browsing | console.cloud.google.com | 10K lookups/day | URL reputation |
| VirusTotal | virustotal.com/gui/join-us | 4 req/min, 500/day | Multi-engine scan |
| WhoisXML API | whoisxmlapi.com | 500 queries/month | Domain age |
| URLScan.io | urlscan.io/user/signup | 100 scans/day | Sandbox analysis |
| PhishTank | phishtank.org/register.php | Unlimited | Known phishing feed |
| IPQualityScore | ipqualityscore.com/create-account | 5K lookups/month | Fraud scoring |
| AbuseIPDB | abuseipdb.com/register | 1K checks/day | IP reputation |
| Shodan | account.shodan.io/register | 100 queries/month | Infrastructure intel |
| Have I Been Pwned | haveibeenpwned.com/API/Key | Rate limited | Breach data |
| CertStream | certstream.calidog.io | Unlimited (WebSocket) | Certificate monitoring |
| Chrome Web Store | chrome.google.com/webstore/devconsole | $5 one-time | Extension publishing |

---

### DEVELOPMENT TIMELINE SUMMARY

| Phase | Duration | Deliverable |
|-------|----------|------------|
| Phase 0: Setup | Week 1-2 | Environment, accounts, repo structure |
| Phase 1: Data Collection | Week 2-4 | 100K+ labeled URLs, feature extraction pipeline |
| Phase 2: ML Models | Week 4-7 | 5 trained models, exported to ONNX |
| Phase 3: Extension | Week 6-9 | Working MV3 extension with client-side detection |
| Phase 4: Backend | Week 8-10 | FastAPI server with all endpoints and external API integration |
| Phase 5: Visual Engine | Week 7-9 | Logo detection + recognition + OCR pipeline |
| Phase 6: Threat Intel | Week 9-10 | Automated feed ingestion + CertStream monitoring |
| Phase 7: Anti-Evasion | Week 10-11 | BitB detection, redirect analysis, JS behavior monitoring |
| Phase 8: Privacy | Throughout | Privacy-preserving architecture implemented |
| Phase 9: Testing | Week 11-12 | Full test suite, adversarial testing, beta deployment |
| Phase 10: Deployment | Week 12-13 | Chrome Web Store submission, backend production deployment |
| Phase 11: Maintenance | Ongoing | Weekly model retraining, daily feed updates |

**Total estimated development time: 13-16 weeks for a single dedicated developer.**

---

### FINAL CRITICAL RECOMMENDATIONS

1. **Start with Model 1 + Blocklist ONLY.** Get a working extension that does client-side URL classification and blocklist checking. This alone will provide significant protection. Then incrementally add layers.

2. **False positives will kill your extension faster than missed phishing.** Users will uninstall immediately if their bank's website is blocked. Err heavily on the side of caution — only block with very high confidence. For borderline cases, warn but don't block.

3. **The Indian context matters.** Indian banking phishing (SBI, HDFC, ICICI, Paytm, UPI scams) has specific patterns different from Western phishing. Build your brand database with comprehensive Indian brand coverage. UPI-related phishing often uses custom apps rather than web pages — your extension catches the web component but consider future mobile expansion.

4. **Publish the research.** Your work at VIT on building this system, especially if you produce novel results on the Indian phishing landscape or on MV3 architectural challenges, is publishable. Target IEEE or ACM conferences. Document everything.

5. **Engage with the security community.** Submit your extension for review by security researchers. Open-source it. The community will find bugs and improvements you missed.

This document gives you everything needed to go from zero to a production-grade phishing detection extension. Every API, every library, every connection, every data flow is mapped. Execute phase by phase, test relentlessly, and ship incrementally.