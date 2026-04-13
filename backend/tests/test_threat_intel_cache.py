import pytest
from app.services.threat_intel import check_threat_feeds, _threat_cache

@pytest.mark.asyncio
async def test_check_threat_feeds_cache():
    url = "https://this-is-a-test-domain.com"

    # Ensure empty
    if url in _threat_cache.cache:
        del _threat_cache.cache[url]

    result1 = await check_threat_feeds(url)
    assert url in _threat_cache.cache

    # Modify cache manually to verify it uses the cache
    _threat_cache.cache[url] = ({"flagged": "MOCKED_CACHE_HIT"}, _threat_cache.cache[url][1])

    result2 = await check_threat_feeds(url)
    assert result2["flagged"] == "MOCKED_CACHE_HIT"
