"""
PhishGuard ML v4.1 — Dataset Downloader
Downloads real phishing URLs from public feeds and legitimate domains from Tranco.
"""

import csv
import io
import sys
import zipfile
from pathlib import Path
from typing import Optional

import httpx

from config import DATA_DIR


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Data Sources
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PHISHING_FEEDS = [
    ("openphish", "https://openphish.com/feed.txt"),
    ("phishtank", "https://data.phishtank.com/data/online-valid.csv"),
    ("phishstats", "https://phishstats.info/phish_score.csv"),
]

TRANCO_CSV_URL = "https://tranco-list.eu/top-1m.csv.zip"
UMBRELLA_URL = "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"


def _fetch_text(url: str, timeout: float = 60.0) -> Optional[str]:
    """Fetch URL as text with generous timeout."""
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.text
    except Exception as exc:
        print(f"  ⚠ Failed to fetch {url}: {exc}", file=sys.stderr)
        return None


def _fetch_bytes(url: str, timeout: float = 120.0) -> Optional[bytes]:
    """Fetch URL as bytes (for zip files)."""
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.content
    except Exception as exc:
        print(f"  ⚠ Failed to fetch {url}: {exc}", file=sys.stderr)
        return None


def collect_phishing(limit: int = 50000) -> list:
    """Collect phishing URLs from multiple feeds."""
    urls: list = []
    seen: set = set()

    for feed_name, feed_url in PHISHING_FEEDS:
        if len(urls) >= limit:
            break

        print(f"  Fetching {feed_name}: {feed_url}")
        text = _fetch_text(feed_url)
        if not text:
            continue

        count_before = len(urls)

        if feed_name == "phishtank" and "phish_id" in text[:500]:
            reader = csv.DictReader(io.StringIO(text))
            for row in reader:
                u = row.get("url", "").strip()
                if u and u not in seen:
                    seen.add(u)
                    urls.append(u)
                if len(urls) >= limit:
                    break

        elif feed_name == "phishstats":
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
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("http") and line not in seen:
                    seen.add(line)
                    urls.append(line)
                if len(urls) >= limit:
                    break

        print(f"    → got {len(urls) - count_before} URLs from {feed_name}")

    return urls[:limit]


def collect_legitimate(limit: int = 50000) -> list:
    """Collect legitimate domain URLs from Tranco (or Umbrella fallback)."""
    urls: list = []

    for source_name, source_url in [
        ("Tranco", TRANCO_CSV_URL),
        ("Umbrella", UMBRELLA_URL),
    ]:
        if urls:
            break

        print(f"  Fetching {source_name}: {source_url}")
        data = _fetch_bytes(source_url)
        if not data:
            continue

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
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

                    if domain.replace(".", "").isdigit():
                        continue

                    final_domain = domain
                    if idx % 2 == 0 and not domain.startswith("www."):
                        final_domain = "www." + domain

                    path = "/"
                    if idx % 3 == 0:
                        augment_paths = [
                            "index.html", "home", "search",
                            "login", "contact", "about", "faq",
                        ]
                        path = "/" + augment_paths[idx % len(augment_paths)]

                    scheme = "https" if idx % 10 != 0 else "http"
                    urls.append(f"{scheme}://{final_domain}{path}")

                    if len(urls) >= limit:
                        break

                print(f"    → got {len(urls)} domains from {source_name}")

        except Exception as exc:
            print(f"  ⚠ Failed to parse {source_name} zip: {exc}", file=sys.stderr)
            continue

    # Hardcoded fallback
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
            "nytimes.com", "washingtonpost.com", "forbes.com", "reuters.com",
            "medium.com", "quora.com", "pinterest.com", "tumblr.com",
            "wordpress.com", "blogger.com", "cloudflare.com", "aws.amazon.com",
            "azure.microsoft.com", "cloud.google.com", "oracle.com", "ibm.com",
            "fast.com", "vtop.vit.ac.in",
        ]
        for d in fallback:
            urls.append(f"https://{d}/")

    return urls[:limit]


def download():
    """Download all datasets and save to DATA_DIR."""
    print("=" * 60)
    print("PHISHGUARD ML v4.1 — DATASET DOWNLOADER")
    print("=" * 60)

    print("\n[1/2] Collecting phishing URLs...")
    phish_urls = collect_phishing(50000)
    print(f"  Total phishing: {len(phish_urls)}")

    print("\n[2/2] Collecting legitimate URLs...")
    legit_urls = collect_legitimate(50000)
    print(f"  Total legitimate: {len(legit_urls)}")

    # Save raw datasets
    if phish_urls:
        phish_path = DATA_DIR / "phishing_urls.csv"
        with open(phish_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["url", "label"])
            for u in phish_urls:
                writer.writerow([u, 1])
        print(f"\n✓ Phishing saved: {phish_path} ({len(phish_urls)} URLs)")

    if legit_urls:
        legit_path = DATA_DIR / "legitimate_urls.csv"
        with open(legit_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["url", "label"])
            for u in legit_urls:
                writer.writerow([u, 0])
        print(f"✓ Legitimate saved: {legit_path} ({len(legit_urls)} URLs)")

    total = len(phish_urls) + len(legit_urls)
    print(f"\n{'=' * 60}")
    print(f"DOWNLOAD COMPLETE: {total} total URLs")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    download()
