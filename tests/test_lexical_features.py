import pytest

# Extremely basic lexical feature extraction mimicking JS frontend
def extract_lexical_basic(url: str) -> dict:
    features = {}
    features["urlLength"] = len(url)
    features["atSymbol"] = 1 if "@" in url else 0
    features["isHttps"] = 1 if url.startswith("https") else 0
    
    suspicious_tlds = [".xyz", ".icu", ".top", ".tk", ".ml"]
    features["suspiciousTld"] = 1 if any(tld in url for tld in suspicious_tlds) else 0
    
    return features

def test_extract_length():
    url = "https://example.com"
    features = extract_lexical_basic(url)
    assert features["urlLength"] == 19

def test_extract_at_symbol():
    url1 = "https://example.com"
    url2 = "http://user:pass@example.com"
    
    f1 = extract_lexical_basic(url1)
    f2 = extract_lexical_basic(url2)
    
    assert f1["atSymbol"] == 0
    assert f2["atSymbol"] == 1

def test_extract_https():
    url1 = "https://example.com"
    url2 = "http://example.com"
    
    f1 = extract_lexical_basic(url1)
    f2 = extract_lexical_basic(url2)
    
    assert f1["isHttps"] == 1
    assert f2["isHttps"] == 0

def test_suspicious_tld():
    url1 = "http://my-bank-update.xyz/login"
    url2 = "https://google.com"
    
    f1 = extract_lexical_basic(url1)
    f2 = extract_lexical_basic(url2)
    
    assert f1["suspiciousTld"] == 1
    assert f2["suspiciousTld"] == 0
