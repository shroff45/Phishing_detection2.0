"""
PhishGuard Backend — Threat Intelligence Feed Manager
─────────────────────────────────────────────────────
Aggregates phishing URLs from multiple open-source feeds,
deduplicates them, converts them to Chrome declarativeNetRequest
rule format, and serves them to the extension.
"""

import asyncio
import csv
import io
import re
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx
import structlog

logger = structlog.get_logger()

# ── Configuration ───────────────────────────────────────────────────────────
CHROME_DYNAMIC_RULE_LIMIT = 30_000
MAX_URLS_PER_SOURCE = 10_000

OPENPHISH_FEED = "https://openphish.com/feed.txt"
PHISHTANK_FEED = "http://data.phishtank.com/data/online-valid.csv"
PHISHING_DB_DOMAINS = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
URLHAUS_FEED = "https://urlhaus.abuse.ch/downloads/text_online/"

FEED_TIMEOUT_SECONDS = 30

# ── Global Whitelist ──
GLOBAL_WHITELIST = {
    "google.com", "github.com", "microsoft.com", "stackoverflow.com",
    "reddit.com", "youtube.com", "linkedin.com", "twitter.com", "x.com",
    "facebook.com", "amazon.com", "apple.com", "localhost", "127.0.0.1"
}

# Module-level state for persistence across refreshes
_cached_rules: list = []
_cached_domains: set = set()
_last_update_time: Optional[str] = None
_last_update_count: int = 0


# ── Internal Feed Fetchers ──────────────────────────────────────────────────

async def _fetch_openphish() -> set:
    domains = set()
    try:
        async with httpx.AsyncClient(timeout=FEED_TIMEOUT_SECONDS) as client:
            response = await client.get(OPENPHISH_FEED)
            response.raise_for_status()
            for line in response.text.strip().split("\n"):
                line = line.strip()
                if line.startswith("http"):
                    try:
                        hostname = urlparse(line).hostname
                        if hostname: domains.add(hostname.lower())
                    except: pass
                if len(domains) >= MAX_URLS_PER_SOURCE: break
        logger.info("feed_fetched", source="openphish", count=len(domains))
    except Exception as e:
        logger.warning("feed_fetch_failed", source="openphish", error=str(e))
    return domains

async def _fetch_phishtank() -> set:
    domains = set()
    try:
        headers = {"User-Agent": "phishguard-research/1.0"}
        async with httpx.AsyncClient(timeout=FEED_TIMEOUT_SECONDS) as client:
            response = await client.get(PHISHTANK_FEED, headers=headers)
            response.raise_for_status()
            reader = csv.reader(io.StringIO(response.text))
            next(reader, None)
            for row in reader:
                if len(row) >= 2 and row[1].startswith("http"):
                    try:
                        hostname = urlparse(row[1]).hostname
                        if hostname: domains.add(hostname.lower())
                    except: pass
                if len(domains) >= MAX_URLS_PER_SOURCE: break
        logger.info("feed_fetched", source="phishtank", count=len(domains))
    except Exception as e:
        logger.warning("feed_fetch_failed", source="phishtank", error=str(e))
    return domains

async def _fetch_phishing_database() -> set:
    domains = set()
    try:
        async with httpx.AsyncClient(timeout=FEED_TIMEOUT_SECONDS) as client:
            response = await client.get(PHISHING_DB_DOMAINS)
            response.raise_for_status()
            for line in response.text.strip().split("\n"):
                domain = line.strip().lower()
                if domain and not domain.startswith("#") and "." in domain:
                    if re.match(r"^[a-z0-9][a-z0-9\-\.]+[a-z0-9]$", domain):
                        domains.add(domain)
                if len(domains) >= MAX_URLS_PER_SOURCE: break
        logger.info("feed_fetched", source="phishing_database", count=len(domains))
    except Exception as e:
        logger.warning("feed_fetch_failed", source="phishing_database", error=str(e))
    return domains

async def _fetch_urlhaus() -> set:
    domains = set()
    try:
        async with httpx.AsyncClient(timeout=FEED_TIMEOUT_SECONDS) as client:
            response = await client.get(URLHAUS_FEED)
            response.raise_for_status()
            for line in response.text.strip().split("\n"):
                line = line.strip()
                if line.startswith("http"):
                    try:
                        hostname = urlparse(line).hostname
                        if hostname: domains.add(hostname.lower())
                    except: pass
                if len(domains) >= MAX_URLS_PER_SOURCE: break
        logger.info("feed_fetched", source="urlhaus", count=len(domains))
    except Exception as e:
        logger.warning("feed_fetch_failed", source="urlhaus", error=str(e))
    return domains


# ── Processing Logic ─────────────────────────────────────────────────────────

def _domain_to_rule(domain: str, rule_id: int) -> dict:
    return {
        "id": rule_id,
        "priority": 1,
        "action": {"type": "block"},
        "condition": {"urlFilter": "||" + domain, "resourceTypes": ["main_frame"]},
    }

async def refresh_threat_feeds() -> dict:
    global _cached_rules, _cached_domains, _last_update_time, _last_update_count
    
    start_time = time.time()
    results = await asyncio.gather(
        _fetch_openphish(), _fetch_phishtank(),
        _fetch_phishing_database(), _fetch_urlhaus(),
        return_exceptions=True
    )
    
    all_domains = set()
    source_counts = {}
    names = ["openphish", "phishtank", "phishing_database", "urlhaus"]
    
    for i, res in enumerate(results):
        name = names[i]
        if isinstance(res, set):
            all_domains.update(res)
            source_counts[name] = len(res)
        else:
            source_counts[name] = 0

    # Filter and sort
    sorted_domains = sorted([d for d in all_domains if "." in d and len(d) > 3])[:CHROME_DYNAMIC_RULE_LIMIT]
    
    _cached_domains = set(sorted_domains)
    _cached_rules = [_domain_to_rule(d, 1000 + i) for i, d in enumerate(sorted_domains)]
    _last_update_time = datetime.now(timezone.utc).isoformat()
    _last_update_count = len(_cached_rules)
    
    summary = {
        "total_domains": len(sorted_domains),
        "sources": source_counts,
        "rules_generated": _last_update_count,
        "elapsed": round(time.time() - start_time, 1)
    }
    logger.info("feed_refresh_complete", **summary)
    return summary


# ── The Feed Manager ────────────────────────────────────────────────────────

class FeedManager:
    """Provides a class-based interface for main.py."""
    
    @property
    def total_rules(self) -> int:
        return _last_update_count

    async def update_feeds(self) -> dict:
        return await refresh_threat_feeds()

    def is_domain_blocked(self, domain: str) -> bool:
        d = domain.lower()
        # Never block whitelisted domains
        for safe in GLOBAL_WHITELIST:
            if d == safe or d.endswith("." + safe):
                return False
        return d in _cached_domains

    def get_rules(self, limit: int = 5000, offset: int = 0) -> list:
        return _cached_rules[offset : offset + limit]

    def get_stats(self) -> dict:
        return {
            "total_rules": _last_update_count,
            "last_update": _last_update_time,
            "is_loaded": len(_cached_domains) > 0
        }

# Global singleton matching main.py imports
feed_manager = FeedManager()
