"""
PhishGuard — Dataset Builder
Collects URLs from public phishing feeds and legitimate sources,
extracts features, and writes a CSV ready for model training.

Run:  python build_dataset.py [--out dataset.csv] [--limit 25000]

IMPORTANT: The WHATWG query functions below MUST stay in sync
with the copies in backend/app/services/threat_intel.py AND
the JS version in extension/service-worker.js.
Run tests/test_feature_parity.py after any modification.
"""

import argparse
import csv
import io
import math
import re
import sys
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx

# ─────────────────────────────────────────────────────────────
# 1. WHATWG-COMPATIBLE QUERY HELPERS
#    (mirrored from backend/app/services/threat_intel.py)
# ─────────────────────────────────────────────────────────────

def get_raw_query_js_compatible(raw_url: str) -> str:
    """
    WHATWG query percent-encode set: encodes C0 controls, space, " < > DEL,
    and non-ASCII.  Preserves @ : / ? = & + and all other ASCII printable.
    Returns the query without the leading '?'.
    """
    fragment_idx = raw_url.find("#")
    url_no_fragment = raw_url[:fragment_idx] if fragment_idx != -1 else raw_url

    scheme_end = url_no_fragment.find("://")
    search_start = (scheme_end + 3) if scheme_end != -1 else 0

    query_idx = url_no_fragment.find("?", search_start)
    if query_idx == -1:
        return ""

    raw_query = url_no_fragment[query_idx + 1:]
    result: list[str] = []
    i = 0
    while i < len(raw_query):
        ch = raw_query[i]
        code = ord(ch)
        if ch == "%" and i + 2 < len(raw_query):
            hex_chars = raw_query[i + 1 : i + 3]
            if all(c in "0123456789abcdefABCDEF" for c in hex_chars):
                result.append("%" + hex_chars.upper())
                i += 3
                continue
            result.append("%25")
            i += 1
        elif code <= 0x1F:
            result.append(f"%{code:02X}"); i += 1
        elif ch == " ":
            result.append("%20"); i += 1
        elif ch == '"':
            result.append("%22"); i += 1
        elif ch == "<":
            result.append("%3C"); i += 1
        elif ch == ">":
            result.append("%3E"); i += 1
        elif code == 0x7F:
            result.append("%7F"); i += 1
        elif code > 0x7E:
            for b in ch.encode("utf-8"):
                result.append(f"%{b:02X}")
            i += 1
        else:
            result.append(ch); i += 1
    return "".join(result)


def _js_compatible_search_length(raw_url: str) -> int:
    """Matches JS URL.search.length — includes leading '?' when query exists."""
    raw_query = get_raw_query_js_compatible(raw_url)
    return len(raw_query) + 1 if raw_query else 0


def _count_query_params(raw_query: str) -> int:
    if not raw_query:
        return 0
    return len([p for p in raw_query.split("&") if p])


# ─────────────────────────────────────────────────────────────
# 2. FEATURE EXTRACTION  (must match service-worker.js exactly)
# ─────────────────────────────────────────────────────────────

_PHISH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "account",
    "update", "secure", "banking", "confirm", "password",
    "suspend", "alert", "unusual", "restore", "unlock",
]

_SUSPICIOUS_TLDS = {
    ".xyz", ".icu", ".top", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".buzz", ".club", ".info", ".site", ".online",
    ".website", ".link", ".click", ".surf",
}

_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
}

# These are the 30 feature names used in CSV headers AND model training.
# The order matters — the model expects features in this exact order.
FEATURE_NAMES = [
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
]


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def extract_features(raw_url: str) -> Optional[dict]:
    """
    Extract all 30 lexical features.  Identical logic to the extension's
    extractLexicalFeatures() in service-worker.js.
    Returns None if URL is unparseable.
    """
    try:
        parsed = urlparse(raw_url)
    except Exception:
        return None

    hostname: str = parsed.hostname or ""
    pathname: str = parsed.path if parsed.path else "/"
    full_url: str = raw_url
    js_query: str = get_raw_query_js_compatible(raw_url)

    host_parts = hostname.split(".") if hostname else [""]
    subdomain_count = max(0, len(host_parts) - 2)
    path_segments = [seg for seg in pathname.split("/") if seg]

    digits = sum(1 for ch in full_url if ch.isdigit())
    letters = sum(1 for ch in full_url if ch.isalpha())
    lower_url = full_url.lower()
    keyword_hits = sum(1 for kw in _PHISH_KEYWORDS if kw in lower_url)

    tld = "." + host_parts[-1] if host_parts else ""
    has_suspicious_tld = 1 if tld.lower() in _SUSPICIOUS_TLDS else 0
    has_punycode = 1 if "xn--" in hostname.lower() else 0
    is_shortener = 1 if any(hostname.lower().endswith(d) for d in _SHORTENER_DOMAINS) else 0

    encoded_chars = len(re.findall(r"%[0-9a-fA-F]{2}", full_url))
    double_slashes = full_url.count("//") - 1
    special_chars = len(re.findall(r"[!$%^*()+=\{\}\[\]|;:\'\"<>?]", full_url))
    longest_subdomain = (
        max((len(p) for p in host_parts[:-2]), default=0)
        if len(host_parts) > 2 else 0
    )

    is_ip = bool(
        re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname)
        or re.match(r"^0x[\da-fA-F]+$", hostname, re.IGNORECASE)
        or re.match(r"^\[[\da-fA-F:]+\]$", hostname)
    )

    return {
        "f01_urlLength":          len(full_url),
        "f02_hostnameLength":     len(hostname),
        "f03_pathLength":         len(pathname),
        "f04_queryLength":        _js_compatible_search_length(raw_url),
        "f05_dotCountUrl":        full_url.count("."),
        "f06_dotCountHost":       hostname.count("."),
        "f07_hyphenCountUrl":     full_url.count("-"),
        "f08_hyphenCountHost":    hostname.count("-"),
        "f09_underscoreCount":    full_url.count("_"),
        "f10_atSymbolCount":      full_url.count("@"),
        "f11_digitCountUrl":      digits,
        "f12_digitCountHost":     sum(1 for ch in hostname if ch.isdigit()),
        "f13_digitToLetterRatio": (digits / letters) if letters > 0 else float(digits),
        "f14_subdomainCount":     subdomain_count,
        "f15_pathDepth":          len(path_segments),
        "f16_queryParamCount":    _count_query_params(js_query),
        "f17_isIpAddress":        1 if is_ip else 0,
        "f18_entropyUrl":         round(_shannon_entropy(full_url), 6),
        "f19_entropyHost":        round(_shannon_entropy(hostname), 6),
        "f20_entropyPath":        round(_shannon_entropy(pathname), 6),
        "f21_specialCharCount":   special_chars,
        "f22_hasPort":            1 if parsed.port else 0,
        "f23_isHttps":            1 if parsed.scheme == "https" else 0,
        "f24_hasSuspiciousTld":   has_suspicious_tld,
        "f25_hasPunycode":        has_punycode,
        "f26_isShortener":        is_shortener,
        "f27_keywordHits":        keyword_hits,
        "f28_encodedCharCount":   encoded_chars,
        "f29_doubleSlashCount":   max(0, double_slashes),
        "f30_longestSubdomainLen": longest_subdomain,
    }


# ─────────────────────────────────────────────────────────────
# 3. DATA SOURCES
# ─────────────────────────────────────────────────────────────

# Multiple phishing feeds for redundancy
PHISHING_FEEDS = [
    # OpenPhish free feed (plain text, one URL per line) — most reliable
    ("openphish", "https://openphish.com/feed.txt"),
    # PhishTank verified online CSV (may require API key for high volume)
    ("phishtank", "https://data.phishtank.com/data/online-valid.csv"),
    # PhishStats API — recent phishing URLs
    ("phishstats", "https://phishstats.info/phish_score.csv"),
]

# Tranco list — research-grade ranking combining Alexa, Umbrella, Majestic, etc.
TRANCO_CSV_URL = "https://tranco-list.eu/top-1m.csv.zip"
# Fallback: Umbrella top 1M
UMBRELLA_URL = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"


def _fetch_text(url: str, timeout: float = 60.0) -> Optional[str]:
    """Fetch URL as text with generous timeout."""
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.text
    except Exception as exc:
        print(f"  WARN: failed to fetch {url}: {exc}", file=sys.stderr)
        return None


def _fetch_bytes(url: str, timeout: float = 120.0) -> Optional[bytes]:
    """Fetch URL as bytes (for zip files)."""
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.content
    except Exception as exc:
        print(f"  WARN: failed to fetch {url}: {exc}", file=sys.stderr)
        return None


def _collect_phishing(limit: int) -> list[str]:
    """Collect phishing URLs from multiple feeds until we hit the limit."""
    urls: list[str] = []
    seen: set[str] = set()

    for feed_name, feed_url in PHISHING_FEEDS:
        if len(urls) >= limit:
            break

        print(f"  Fetching {feed_name}: {feed_url}")
        text = _fetch_text(feed_url)
        if not text:
            continue

        count_before = len(urls)

        if feed_name == "phishtank" and "phish_id" in text[:500]:
            # PhishTank CSV format
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                u = row.get("url", "").strip()
                if u and u not in seen:
                    seen.add(u)
                    urls.append(u)
                if len(urls) >= limit:
                    break

        elif feed_name == "phishstats":
            # PhishStats CSV: date, score, url, ip
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("#") or line.startswith("Date"):
                    continue
                parts = line.split(",", 3)
                if len(parts) >= 3:
                    u = parts[2].strip().strip('"')
                    if u.startswith("http") and u not in seen:
                        seen.add(u)
                        urls.append(u)
                if len(urls) >= limit:
                    break

        else:
            # Plain text feed (OpenPhish, etc.)
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("http") and line not in seen:
                    seen.add(line)
                    urls.append(line)
                if len(urls) >= limit:
                    break

        print(f"    → got {len(urls) - count_before} URLs from {feed_name}")

    return urls[:limit]


def _collect_legit(limit: int) -> list[str]:
    """Collect legitimate domain URLs from Tranco (or Umbrella fallback)."""
    urls: list[str] = []

    # Try Tranco first (zip file containing top-1m.csv)
    for source_name, source_url in [("Tranco", TRANCO_CSV_URL), ("Umbrella", UMBRELLA_URL)]:
        if urls:
            break

        print(f"  Fetching {source_name}: {source_url}")
        data = _fetch_bytes(source_url)
        if not data:
            continue

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                # Get the first CSV file in the zip
                csv_name = [n for n in zf.namelist() if n.endswith(".csv")][0]
                csv_text = zf.read(csv_name).decode("utf-8", errors="replace")

                for idx, line in enumerate(csv_text.splitlines(), 1):
                    parts = line.strip().split(",")
                    if len(parts) >= 2:
                        domain = parts[1].strip()
                    elif len(parts) == 1 and parts[0].strip():
                        domain = parts[0].strip()
                    else:
                        continue

                    # Skip numeric-only lines (rank without domain)
                    if domain.replace(".", "").isdigit():
                        continue

                    # Data augmentation for legit domains
                    # 1. Randomly add 'www.' (approx 50%)
                    # 2. Randomly add a common path (approx 30%)
                    final_domain = domain
                    if idx % 2 == 0 and not domain.startswith("www."):
                        final_domain = "www." + domain
                    
                    path = "/"
                    if idx % 3 == 0:
                        paths = ["index.html", "home", "search", "login", "contact", "about", "faq"]
                        path = "/" + paths[idx % len(paths)]
                    
                    # 3. Use both http and https for some variety (mostly https)
                    scheme = "https" if idx % 10 != 0 else "http"
                    
                    urls.append(f"{scheme}://{final_domain}{path}")
                    if len(urls) >= limit:
                        break

                print(f"    → got {len(urls)} domains from {source_name}")

        except Exception as exc:
            print(f"  WARN: failed to parse {source_name} zip: {exc}", file=sys.stderr)
            continue

    # Hardcoded fallback if feeds are unreachable
    if len(urls) < 100:
        print("  Using hardcoded fallback domains...")
        fallback = [
            "google.com", "youtube.com", "facebook.com", "amazon.com",
            "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com",
            "reddit.com", "netflix.com", "microsoft.com", "apple.com",
            "github.com", "stackoverflow.com", "yahoo.com", "bing.com",
            "twitch.tv", "whatsapp.com", "zoom.us", "adobe.com",
            "spotify.com", "salesforce.com", "dropbox.com", "slack.com",
            "paypal.com", "ebay.com", "cnn.com", "bbc.com",
            "nytimes. NYT", "washingtonpost.com", "forbes.com", "reuters.com",
            "medium.com", "quora.com", "pinterest.com", "tumblr.com",
            "wordpress.com", "blogger.com", "cloudflare.com", "aws.amazon.com",
            "azure.microsoft.com", "cloud.google.com", "oracle.com", "ibm.com",
            "intel.com", "nvidia.com", "amd.com", "samsung.com",
            "dell.com", "hp.com",
        ]
        for d in fallback:
            urls.append(f"https://{d}/")

    return urls[:limit]


# ─────────────────────────────────────────────────────────────
# 4. MAIN
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Build PhishGuard training dataset")
    parser.add_argument("--out", default="dataset.csv", help="Output CSV path")
    parser.add_argument("--limit", type=int, default=25000,
                        help="Max URLs per class (phish + legit)")
    args = parser.parse_args()

    print("=" * 50)
    print("  PhishGuard Dataset Builder")
    print("=" * 50)
    print(f"Target: up to {args.limit} phishing + {args.limit} legitimate URLs\n")

    # ── Collect URLs ──────────────────────────────────────────
    print("[1/4] Collecting phishing URLs...")
    phish_urls = _collect_phishing(args.limit)
    print(f"  Total phishing URLs: {len(phish_urls)}\n")

    print("[2/4] Collecting legitimate URLs...")
    legit_urls = _collect_legit(args.limit)
    print(f"  Total legitimate URLs: {len(legit_urls)}\n")

    if not phish_urls and not legit_urls:
        print("ERROR: No URLs collected! Check your internet connection.", file=sys.stderr)
        sys.exit(1)

    # ── Extract features ─────────────────────────────────────
    print("[3/4] Extracting features...")
    rows: list[dict] = []
    errors = 0
    total = len(phish_urls) + len(legit_urls)

    all_samples = [(u, 1) for u in phish_urls] + [(u, 0) for u in legit_urls]

    for idx, (url, label) in enumerate(all_samples):
        feats = extract_features(url)
        if feats is not None:
            feats["label"] = label
            feats["url"] = url
            rows.append(feats)
        else:
            errors += 1

        if (idx + 1) % 5000 == 0 or idx + 1 == total:
            print(f"  {idx + 1:>6}/{total} processed  ({errors} errors)")

    print(f"  Valid feature rows: {len(rows)}\n")

    if not rows:
        print("ERROR: No valid feature rows! Check URL formats.", file=sys.stderr)
        sys.exit(1)

    # ── Write CSV ─────────────────────────────────────────────
    print(f"[4/4] Writing {args.out}...")
    out_path = Path(__file__).parent / args.out

    # Column order: features first, then label, then url (url is for reference only)
    fieldnames = FEATURE_NAMES + ["label", "url"]

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    phish_count = sum(1 for r in rows if r["label"] == 1)
    legit_count = sum(1 for r in rows if r["label"] == 0)

    print()
    print("=" * 50)
    print("  Dataset Build Complete!")
    print("=" * 50)
    print(f"  Phishing rows  : {phish_count:>6}")
    print(f"  Legitimate rows: {legit_count:>6}")
    print(f"  Total rows     : {len(rows):>6}")
    print(f"  Errors skipped : {errors:>6}")
    print(f"  Output file    : {out_path}")
    print()
    print("Next step: python train_url_model.py")


if __name__ == "__main__":
    main()
