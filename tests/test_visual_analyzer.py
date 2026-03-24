import pytest
from app.services.visual_analyzer import VisualAnalyzer
from PIL import Image
import numpy as np
import io

@pytest.fixture
def analyzer():
    return VisualAnalyzer()

@pytest.fixture
def sample_image_bytes():
    # Create a simple red 100x100 image
    img = Image.new('RGB', (100, 100), color=(255, 0, 0))
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='JPEG')
    return img_byte_arr.getvalue()

def test_phash_generation(analyzer, sample_image_bytes):
    img = Image.open(io.BytesIO(sample_image_bytes))
    phash = analyzer.calculate_phash(img)
    
    assert isinstance(phash, str)
    assert len(phash) == 64
    assert all(c in '01' for c in phash)

def test_hamming_distance(analyzer):
    hash1 = "11110000" * 8
    hash2 = "00001111" * 8
    hash3 = "11110000" * 8
    
    assert analyzer.hamming_distance(hash1, hash3) == 0
    assert analyzer.hamming_distance(hash1, hash2) == 64
    
    # Distance between strings of different lengths should be max (64)
    assert analyzer.hamming_distance(hash1, "10") == 64

def test_color_extraction(analyzer, sample_image_bytes):
    img = Image.open(io.BytesIO(sample_image_bytes))
    colors = analyzer.extract_colors(img, num_colors=1)
    
    assert len(colors) >= 1
    # Check if we got something close to red (255, 0, 0)
    red_color = colors[0]
    assert red_color[0] > 200 # High red
    assert red_color[1] < 50  # Low green
    assert red_color[2] < 50  # Low blue

def test_color_distance(analyzer):
    c1 = (255, 0, 0)
    c2 = (0, 255, 0)
    c3 = (255, 0, 0)
    
    dist1 = analyzer.color_distance(c1, c2)
    dist2 = analyzer.color_distance(c1, c3)
    
    assert dist2 == 0
    assert dist1 > 300 # sqrt(255^2 + 255^2) approx 360

@pytest.mark.asyncio
async def test_full_analysis_workflow(analyzer, sample_image_bytes):
    url = "http://legit-site.com"
    result = await analyzer.analyze_screenshot(sample_image_bytes, url)
    
    assert "similarity_score" in result
    assert "brand_detected" in result
    assert "is_impersonation" in result
    assert isinstance(result["similarity_score"], float)
