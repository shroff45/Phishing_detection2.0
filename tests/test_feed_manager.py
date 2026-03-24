import pytest
from unittest.mock import patch, MagicMock
from app.services.feed_manager import FeedManager
import httpx

@pytest.fixture
def feed_manager():
    return FeedManager(redis_url="redis://localhost:6379/1")

def test_deduplicate_domains(feed_manager):
    domains = [
        "example.com",
        "phish.example.com",
        "example.com/",
        "http://example.com/login",
        "other.com"
    ]
    
    clean = feed_manager._deduplicate_domains(domains)
    assert len(clean) == 2
    assert "example.com" in clean
    assert "other.com" in clean

@pytest.mark.asyncio
@patch('httpx.AsyncClient.get')
async def test_fetch_openphish(mock_get, feed_manager):
    # Mock OpenPhish response
    mock_resp = MagicMock()
    mock_resp.text = "http://bad1.com/login\nhttps://bad2.com/secure\n"
    mock_resp.raise_for_status.return_value = None
    mock_get.return_value = mock_resp
    
    domains = await feed_manager._fetch_openphish()
    assert len(domains) == 2
    assert "bad1.com" in domains
    assert "bad2.com" in domains

def test_generate_chrome_rules(feed_manager):
    domains = {"bad1.com", "bad2.com"}
    rules = feed_manager._generate_chrome_rules(domains)
    
    assert len(rules) == 2
    
    # Check rule structure
    rule1 = rules[0]
    assert rule1["id"] == 1
    assert rule1["priority"] == 100
    assert rule1["action"]["type"] == "block"
    assert "bad" in rule1["condition"]["urlFilter"]
    assert "main_frame" in rule1["condition"]["resourceTypes"]
