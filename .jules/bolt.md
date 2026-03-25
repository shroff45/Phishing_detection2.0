
## 2025-03-24 - Async Caching External APIs
**Learning:** `check_threat_feeds` queried VirusTotal and URLHaus for identical URLs across multiple client requests. Found that you can use a simple async-safe `OrderedDict` with TTL inside memory to avoid redundant API queries.
**Action:** When working on backend analytics services, prioritize caching of repetitive, external network requests for deterministic or semi-deterministic outputs using LRU with TTL before making structural changes.
