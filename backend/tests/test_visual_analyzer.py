"""
PhishGuard — Unit Tests: Visual Similarity Engine (Phase 9)
"""

import io
import pytest
from PIL import Image
from app.services.visual_analyzer import visual_analyzer

@pytest.mark.asyncio
class TestVisualAnalyzer:
    def _make_solid_image(self, color=(255, 255, 255), size=(200, 200)):
        img = Image.new("RGB", size, color)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    async def test_analyze_blank_image(self):
        image_data = self._make_solid_image((255, 255, 255))
        # FIXED: await the async method
        result = await visual_analyzer.analyze_screenshot(image_data, "https://example.com")
        assert result["is_impersonation"] is False

    async def test_analyze_legitimate_domain_skipped(self):
        # Google blue (approx)
        image_data = self._make_solid_image((66, 133, 244))
        # FIXED: await the async method
        result = await visual_analyzer.analyze_screenshot(image_data, "https://google.com")
        assert result["is_impersonation"] is False
