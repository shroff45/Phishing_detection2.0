"""
PhishGuard — Unit Tests: Feed Manager (Phase 9)
"""

import pytest
from app.services.feed_manager import feed_manager

@pytest.mark.asyncio
class TestFeedManager:
    async def test_initial_state(self):
        stats = feed_manager.get_stats()
        assert "is_loaded" in stats

    async def test_get_rules_returns_list(self):
        rules = feed_manager.get_rules(limit=10)
        assert isinstance(rules, list)

    async def test_stats_keys(self):
        stats = feed_manager.get_stats()
        assert "total_rules" in stats
        assert "last_update" in stats
