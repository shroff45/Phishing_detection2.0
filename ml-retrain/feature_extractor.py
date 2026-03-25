"""
Feature extraction matching service-worker.js f01-f30.
Uses WHATWG-compatible URL parsing (urllib.parse).

Fix H: Extractor completely rewritten to perfectly match service-worker.js
logic line-by-line using exact same regex equivalents.
"""

import re
import math
from urllib.parse import urlparse
from collections import Counter
from config import FEATURE_NAMES, NUM_FEATURES


def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy exactly as JS does."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


PHISH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "account",
    "update", "secure", "banking", "confirm", "password",
    "suspend", "alert", "unusual", "restore", "unlock",
]

SUSPICIOUS_TLDS = {
    ".xyz", ".icu", ".top", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".buzz", ".club", ".info", ".site", ".online",
    ".website", ".link", ".click", ".surf",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
}


def extract(rawUrl: str) -> list[float]:
    """
    Extract 30 lexical features from a raw URL string.
    MUST exactly match service-worker.js extractLexicalFeatures().
    """
    # Ensure URL has scheme for proper parsing like new URL()
    if not rawUrl.startswith(('http://', 'https://', 'ftp://')):
        fullUrl = 'http://' + rawUrl
    else:
        fullUrl = rawUrl

    try:
        parsed = urlparse(fullUrl)
    except Exception:
        return [0.0] * NUM_FEATURES

    hostname = parsed.hostname or ""
    # js pathname is always root if empty, urlparse gives ''
    pathname = parsed.path if parsed.path else "/"
    
    # Query length (JS: parsed.search.length, including ?)
    search = ('?' + parsed.query) if parsed.query else ""
    queryLength = len(search)

    # Query param count
    queryParamCount = 0
    if len(search) > 1:
        rawQuery = search[1:]
        queryParamCount = len([p for p in rawQuery.split("&") if len(p) > 0])

    hostParts = hostname.split(".") if hostname else [""]
    subdomainCount = max(0, len(hostParts) - 2)
    pathSegments = [s for s in pathname.split("/") if len(s) > 0]

    digits = 0
    letters = 0
    for ch in fullUrl:
        if '0' <= ch <= '9':
            digits += 1
        elif ('a' <= ch <= 'z') or ('A' <= ch <= 'Z'):
            letters += 1

    lowerUrl = fullUrl.lower()
    keywordHits = sum(1 for kw in PHISH_KEYWORDS if kw in lowerUrl)

    tld = "." + hostParts[-1] if len(hostParts) > 0 else ""
    hasSuspiciousTld = 1 if tld.lower() in SUSPICIOUS_TLDS else 0
    hasPunycode = 1 if "xn--" in hostname.lower() else 0

    isShortener = 0
    for d in SHORTENER_DOMAINS:
        if hostname.lower().endswith(d):
            isShortener = 1
            break

    encodedChars = len(re.findall(r'%[0-9a-fA-F]{2}', fullUrl))
    # JS: Math.max(0, (fullUrl.match(/\/\//g) || []).length - 1)
    doubleSlashes = max(0, len(re.findall(r'//', fullUrl)) - 1)
    # JS regex: /[!$%^*()+=\{\}\[\]|;:'"<>?]/g
    specialChars = len(re.findall(r'[!$%^*()+={\}\[\]|;:\'"<>?]', fullUrl))

    longestSubdomain = 0
    if len(hostParts) > 2:
        for i in range(len(hostParts) - 2):
            longestSubdomain = max(longestSubdomain, len(hostParts[i]))

    ipv4 = bool(re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname))
    hexIp = bool(re.match(r'^0x[\da-fA-F]+$', hostname, re.IGNORECASE))
    ipv6 = bool(re.match(r'^\[[\da-fA-F:]+\]$', hostname))
    isIp = 1 if (ipv4 or hexIp or ipv6) else 0

    digitCountHost = sum(1 for ch in hostname if '0' <= ch <= '9')

    features = [
        float(len(fullUrl)),                            # f01_urlLength
        float(len(hostname)),                           # f02_hostnameLength
        float(len(pathname)),                           # f03_pathLength
        float(queryLength),                             # f04_queryLength
        float(len(re.findall(r'\.', fullUrl))),         # f05_dotCountUrl
        float(len(re.findall(r'\.', hostname))),        # f06_dotCountHost
        float(len(re.findall(r'-', fullUrl))),          # f07_hyphenCountUrl
        float(len(re.findall(r'-', hostname))),         # f08_hyphenCountHost
        float(len(re.findall(r'_', fullUrl))),          # f09_underscoreCount
        float(len(re.findall(r'@', fullUrl))),          # f10_atSymbolCount
        float(digits),                                  # f11_digitCountUrl
        float(digitCountHost),                          # f12_digitCountHost
        float(digits / letters if letters > 0 else digits), # f13_digitToLetterRatio
        float(subdomainCount),                          # f14_subdomainCount
        float(len(pathSegments)),                       # f15_pathDepth
        float(queryParamCount),                         # f16_queryParamCount
        float(isIp),                                    # f17_isIpAddress
        shannon_entropy(fullUrl),                       # f18_entropyUrl
        shannon_entropy(hostname),                      # f19_entropyHost
        shannon_entropy(pathname),                      # f20_entropyPath
        float(specialChars),                            # f21_specialCharCount
        1.0 if parsed.port else 0.0,                    # f22_hasPort
        1.0 if parsed.scheme == "https" else 0.0,       # f23_isHttps
        float(hasSuspiciousTld),                        # f24_hasSuspiciousTld
        float(hasPunycode),                             # f25_hasPunycode
        float(isShortener),                             # f26_isShortener
        float(keywordHits),                             # f27_keywordHits
        float(encodedChars),                            # f28_encodedCharCount
        float(doubleSlashes),                           # f29_doubleSlashCount
        float(longestSubdomain),                        # f30_longestSubdomainLen
    ]

    assert len(features) == NUM_FEATURES
    for f in features:
        if not math.isfinite(f):
            # JS isFinite check
            features[features.index(f)] = 0.0

    return features


def extract_batch(urls: list[str], show_progress: bool = False) -> list[list[float]]:
    """Extract features for a batch of URLs."""
    return [extract(url) for url in urls]


def extract_features_array(url: str):
    """Alias for extract, used by evaluate.py."""
    return extract(url)


def parse_onnx_probabilities(session, X):
    import numpy as np
    
    input_name = session.get_inputs()[0].name
    X = X.astype(np.float32)
    results = session.run(None, {input_name: X})
    
    # Emulate JS parsing logic:
    # const probKey = outputNames.find(k => k.toLowerCase().includes("probabilities")) || outputNames[1] || outputNames[0];
    output_names = [o.name for o in session.get_outputs()]
    prob_key = None
    for k in output_names:
        if "probabilities" in k.lower():
            prob_key = k
            break
    if not prob_key:
        prob_key = output_names[1] if len(output_names) > 1 else output_names[0]
        
    probas = results[output_names.index(prob_key)]
    
    if isinstance(probas, list):
        probas = np.array(probas)
    
    if len(probas.shape) == 1:
        scores = probas
    elif probas.shape[1] == 2:
        scores = probas[:, 1]
    else:
        # Dictionary format (zipmap=True) fallback
        scores = np.array([p.get(1, p.get(1.0, 0.5)) if isinstance(p, dict) else p for p in probas])
        
    return scores.flatten()
