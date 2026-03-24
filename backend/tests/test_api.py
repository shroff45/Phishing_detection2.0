"""
PhishGuard — Integration Tests: API Endpoints (Phase 9)
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

class TestHealthEndpoint:
    def test_health_returns_200(self):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

class TestQuickAnalyze:
    def test_quick_safe_url(self):
        response = client.post("/api/v1/analyze/quick", json={
            "url": "https://www.google.com/",
            "client_score": 0.1,
        })
        assert response.status_code == 200
        assert "verdict" in response.json()
