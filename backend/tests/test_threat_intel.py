"""
PhishGuard — Unit Tests: Threat Intelligence & Meta-Classifier (Phase 9)
Run:  cd backend && python -m pytest tests/ -v
"""

import pytest
from app.services.threat_intel import compute_meta_score, _extract_url_signals

class TestUrlSignals:
    def test_safe_url(self):
        score, reasons = _extract_url_signals("https://www.google.com/search?q=hello")
        assert score < 0.3

    def test_ip_address_url(self):
        score, reasons = _extract_url_signals("http://192.168.1.1/login.php")
        assert score >= 0.3
        assert any("IP address" in r for r in reasons)

    def test_suspicious_tld(self):
        score, reasons = _extract_url_signals("http://secure-login.xyz/verify")
        assert score >= 0.2

class TestMetaClassifier:
    def test_all_signals_safe(self):
        result = compute_meta_score(url="https://www.google.com/", client_score=0.1, threat_feed_result={"is_known_threat": False})
        assert result["verdict"] == "safe"
        assert result["final_score"] < 0.4

    def test_known_threat(self):
        result = compute_meta_score(url="http://phishing-site.tk/login", client_score=0.8, threat_feed_result={"is_known_threat": True, "source": "urlhaus"})
        assert result["verdict"] == "phishing"
        assert result["final_score"] >= 0.7
