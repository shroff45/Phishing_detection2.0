"""
PhishGuard — Unit Tests: Feed Manager
Tests the public FeedManager API and module-level helpers.
"""

import pytest
from unittest.mock import patch, MagicMock
from app.services.feed_manager import FeedManager, _domain_to_rule, feed_manager


class TestFeedManagerPublicAPI:
    """Tests for FeedManager class public interface."""

    def test_initial_state(self):
        stats = feed_manager.get_stats()
        assert "is_loaded" in stats
        assert "total_rules" in stats
        assert "last_update" in stats

    def test_get_rules_returns_list(self):
        rules = feed_manager.get_rules(limit=10)
        assert isinstance(rules, list)

    def test_get_stats_keys(self):
        stats = feed_manager.get_stats()
        assert "total_rules" in stats
        assert "last_update" in stats
        assert "is_loaded" in stats

    def test_is_domain_blocked_returns_bool(self):
        result = feed_manager.is_domain_blocked("example.com")
        assert isinstance(result, bool)

    def test_whitelisted_domains_never_blocked(self):
        """Whitelisted domains must never be flagged as blocked."""
        for domain in ["google.com", "github.com", "microsoft.com", "apple.com"]:
            assert feed_manager.is_domain_blocked(domain) is False, (
                f"Whitelisted domain {domain} was blocked!"
            )

    def test_total_rules_property(self):
        total = feed_manager.total_rules
        assert isinstance(total, int)
        assert total >= 0


class TestDomainToRule:
    """Tests for the _domain_to_rule helper function."""

    def test_rule_structure(self):
        rule = _domain_to_rule("evil.com", 1001)
        assert rule["id"] == 1001
        assert rule["priority"] == 1
        assert rule["action"]["type"] == "block"
        assert "||evil.com" in rule["condition"]["urlFilter"]
        assert "main_frame" in rule["condition"]["resourceTypes"]

    def test_rule_id_increments(self):
        r1 = _domain_to_rule("a.com", 100)
        r2 = _domain_to_rule("b.com", 101)
        assert r1["id"] == 100
        assert r2["id"] == 101

    def test_url_filter_format(self):
        rule = _domain_to_rule("phishing.xyz", 500)
        assert rule["condition"]["urlFilter"] == "||phishing.xyz"


@pytest.mark.asyncio
class TestFeedUpdate:
    """Tests for feed update lifecycle."""

    async def test_update_feeds_returns_stats(self):
        with patch("app.services.feed_manager._fetch_openphish", return_value={"a.com", "b.com"}), \
             patch("app.services.feed_manager._fetch_phishtank", return_value=set()), \
             patch("app.services.feed_manager._fetch_phishing_database", return_value=set()), \
             patch("app.services.feed_manager._fetch_urlhaus", return_value=set()):
            stats = await feed_manager.update_feeds()
            assert "total_domains" in stats
            assert "sources" in stats
            assert "rules_generated" in stats
            assert "elapsed" in stats

    async def test_rules_available_after_update(self):
        with patch("app.services.feed_manager._fetch_openphish", return_value={"test.com"}), \
             patch("app.services.feed_manager._fetch_phishtank", return_value=set()), \
             patch("app.services.feed_manager._fetch_phishing_database", return_value=set()), \
             patch("app.services.feed_manager._fetch_urlhaus", return_value=set()):
            await feed_manager.update_feeds()
            rules = feed_manager.get_rules(limit=10)
            assert isinstance(rules, list)
