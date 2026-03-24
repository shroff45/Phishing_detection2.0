"""
PhishGuard — Privacy Middleware (Phase 8)
Ensures the backend never logs or stores sensitive user data.
"""

import time
import hashlib
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
import structlog

logger = structlog.get_logger("privacy")

class PrivacyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.monotonic()
        client_ip = request.client.host if request.client else "unknown"
        ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:12]

        logger.debug("request", method=request.method, path=request.url.path, client_hash=ip_hash)
        response = await call_next(request)

        elapsed_ms = (time.monotonic() - start) * 1000
        response.headers["X-Processing-Time-Ms"] = f"{elapsed_ms:.1f}"
        response.headers["X-Privacy"] = "no-tracking"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"

        if "/analyze/" in request.url.path:
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"

        return response
