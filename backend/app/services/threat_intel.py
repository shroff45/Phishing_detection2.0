"""
PhishGuard — Threat Intelligence & Meta-Classifier
───────────────────────────────────────────────────
Combines multiple signals into a final phishing verdict:
  1. Client-side ML score (from extension)
  2. URL heuristic features
  3. Threat feed lookups
  4. Domain age (WHOIS)
  5. Visual similarity analysis
"""

import base64
import math
import re
import hashlib
import asyncio
from collections import Counter
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from urllib.parse import urlparse, parse_qs

import httpx
import whois
import structlog
from app.config import settings

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

logger = structlog.get_logger(__name__)

# ── Configuration ─────────────────────────────────────────

# Known phishing keywords in URLs
PHISH_KEYWORDS: List[str] = [
    "login", "signin", "sign-in", "verify", "account",
    "update", "secure", "banking", "confirm", "password",
    "suspend", "alert", "unusual", "restore", "unlock",
]

# Suspicious TLDs
SUSPICIOUS_TLDS: set = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".top", ".xyz",
    ".club", ".work", ".info", ".wang", ".click", ".link", ".icu",
    ".cam", ".rest", ".monster", ".site", ".online", ".website", ".surf",
}

# ─── Google Safe Browsing ─────────────────────────────────────

async def check_google_safe_browsing(url: str) -> dict:
    result = {"source": "google_safe_browsing", "is_malicious": False, "threat_type": None, "error": None}
    if not settings.GOOGLE_SAFE_BROWSING_KEY:
        result["error"] = "API key not configured"
        return result
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.GOOGLE_SAFE_BROWSING_KEY}"
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(api_url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                if "matches" in data:
                    result["is_malicious"] = True
                    result["threat_type"] = data["matches"][0]["threatType"]
    except Exception as e:
        result["error"] = str(e)
    return result

# ─── VirusTotal ───────────────────────────────────────────────

async def check_virustotal(url: str) -> dict:
    result = {"source": "virustotal", "positives": 0, "total": 0, "is_malicious": False, "error": None}
    if not settings.VIRUSTOTAL_API_KEY:
        result["error"] = "API key not configured"
        return result
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(api_url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                result["positives"] = stats["malicious"] + stats["suspicious"]
                result["total"] = sum(stats.values())
                result["is_malicious"] = result["positives"] >= 3
    except Exception as e:
        result["error"] = str(e)
    return result

# ─── WHOIS / Domain Age ───────────────────────────────────────

async def check_whois(domain: str) -> dict:
    result = {"source": "whois", "domain_age_days": None, "is_newly_registered": False, "error": None}
    try:
        loop = asyncio.get_running_loop()
        w = await loop.run_in_executor(None, whois.whois, domain)
        if not w: return result
        created = w.creation_date
        if isinstance(created, list): created = created[0]
        if isinstance(created, datetime):
            if created.tzinfo is None: created = created.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_days = (now - created).days
            result["domain_age_days"] = age_days
            result["is_newly_registered"] = age_days < 30
    except Exception as e:
        result["error"] = str(e)
    return result

# ─── Aggregators ──────────────────────────────────────────────

async def check_threat_feeds(url: str) -> dict:
    domain = urlparse(url).netloc
    results = await asyncio.gather(
        check_google_safe_browsing(url),
        check_virustotal(url),
        check_whois(domain),
        return_exceptions=True
    )
    res_list = [r if isinstance(r, dict) else {"error": str(r)} for r in results]
    is_threat = any(r.get("is_malicious", False) or r.get("is_newly_registered", False) for r in res_list)
    return {"is_known_threat": bool(is_threat), "results": res_list}

# ─── Meta-Classifier ──────────────────────────────────────────

def compute_meta_score(url: str, client_score: float, threat_feed_result: dict, visual_result: Optional[dict] = None) -> dict:
    """Combines all signals into a final verdict."""
    final_score = client_score * 0.4 
    reasons = []
    
    if threat_feed_result.get("is_known_threat"):
        final_score += 0.5
        reasons.append("Identified in threat feeds")
        
    if visual_result and visual_result.get("is_impersonation"):
        final_score += 0.4
        reasons.append(f"Visual impersonation of {visual_result.get('brand_detected')} detected")
        
    heuristic_score, heuristic_reasons = _extract_url_signals(url)
    final_score += heuristic_score * 0.2
    reasons.extend(heuristic_reasons)
    
    final_score = min(1.0, final_score)
    verdict = "phishing" if final_score >= 0.7 else "suspicious" if final_score >= 0.3 else "safe"
    
    return {
        "final_score": round(float(final_score), 3),
        "verdict": verdict,
        "reasons": list(set(reasons))
    }

def _extract_url_signals(url: str) -> Tuple[float, List[str]]:
    score = 0.0
    reasons = []
    parsed = urlparse(url)
    hostname = parsed.netloc
    
    # Keyword check
    lower_url = url.lower()
    if any(kw in lower_url for kw in PHISH_KEYWORDS):
        score += 0.2
        reasons.append("Phishing keywords in URL")
        
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname):
        score += 0.4
        reasons.append("URL uses IP address")
        
    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 0.2
        reasons.append("Suspicious TLD")
        
    return min(1.0, score), reasons

def _shannon_entropy(text: str) -> float:
    if not text: return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((count/length) * math.log2(count/length) for count in freq.values())

def extract_url_features(raw_url: str) -> Optional[dict]:
    return {"f01_urlLength": len(raw_url)}