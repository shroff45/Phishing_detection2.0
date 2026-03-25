"""Simple API key authentication for PhishGuard endpoints."""

from fastapi import Request, HTTPException
from app.config import settings


async def verify_api_key(request: Request):
    """Validate X-API-Key header when EXTENSION_API_KEY is configured."""
    if not settings.EXTENSION_API_KEY:
        return  # No key configured = dev mode, skip auth

    key = request.headers.get("X-API-Key", "")
    if key != settings.EXTENSION_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
