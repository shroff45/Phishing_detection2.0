"""
PhishGuard Backend — FastAPI Application
─────────────────────────────────────────
"""
import base64
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import structlog
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# App services
from app.config import settings
from app.services.visual_analyzer import visual_analyzer
from app.services.threat_intel import compute_meta_score, check_threat_feeds
from app.services.feed_manager import feed_manager

# Logging
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.dev.ConsoleRenderer(),
    ],
)
logger = structlog.get_logger(__name__)

app = FastAPI(
    title="PhishGuard API",
    description="Real-time phishing detection with visual similarity analysis",
    version="1.0.0",
)

# Privacy Middleware (Phase 8)
try:
    from app.middleware.privacy import PrivacyMiddleware
    app.add_middleware(PrivacyMiddleware)
    logger.info("privacy_middleware_loaded")
except ImportError:
    logger.debug("privacy_middleware_not_found")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class QuickCheckRequest(BaseModel):
    url: str
    client_score: float = Field(default=0.5, ge=0.0, le=1.0)

class FullAnalysisRequest(BaseModel):
    url: str
    client_score: float = Field(default=0.5, ge=0.0, le=1.0)
    screenshot_base64: Optional[str] = None

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "visual_analyzer": True,
            "threat_intel": True,
            "feed_manager": True,
            "feed_stats": feed_manager.get_stats(),
        },
    }

@app.post("/api/v1/analyze/quick")
async def analyze_quick(request: QuickCheckRequest):
    try:
        threat_result = await check_threat_feeds(request.url)
        parsed = urlparse(request.url)
        domain = parsed.netloc or ""
        if feed_manager.is_domain_blocked(domain):
            threat_result["is_known_threat"] = True
            threat_result["source"] = "phishguard_feed"
        
        meta = compute_meta_score(url=request.url, client_score=request.client_score, threat_feed_result=threat_result)
        return {"url": request.url, "verdict": meta["verdict"], "score": meta["final_score"], "threat_feed": threat_result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/analyze/full")
async def analyze_full(request: FullAnalysisRequest):
    try:
        threat_result = await check_threat_feeds(request.url)
        parsed = urlparse(request.url)
        domain = parsed.netloc or ""
        if feed_manager.is_domain_blocked(domain):
            threat_result["is_known_threat"] = True

        visual_result = None
        if request.screenshot_base64:
            b64_data = request.screenshot_base64
            if "," in b64_data: b64_data = b64_data.split(",", 1)[1]
            visual_result = await visual_analyzer.analyze_screenshot(base64.b64decode(b64_data), domain)

        meta = compute_meta_score(url=request.url, client_score=request.client_score, threat_feed_result=threat_result, visual_result=visual_result)
        return {"url": request.url, "verdict": meta["verdict"], "score": meta["final_score"], "visual_analysis": visual_result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/feed/update")
async def update_feeds():
    stats = await feed_manager.update_feeds()
    return {"success": True, "stats": stats}

@app.get("/api/v1/feed/rules")
async def get_feed_rules(limit: int = 5000, offset: int = 0):
    return {"rules": feed_manager.get_rules(limit, offset), "total": feed_manager.total_rules}

@app.on_event("startup")
async def startup_event():
    try: await feed_manager.update_feeds()
    except: pass

if __name__ == "__main__":
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
