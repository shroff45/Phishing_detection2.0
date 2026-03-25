"""
PhishGuard Backend — Phase 5: Visual Similarity Engine

Handles perceptual hashing, OCR, and color distribution analysis
to detect brand impersonation.
"""

import io
import math
import structlog
from typing import Dict, Any, List, Optional
from PIL import Image
import numpy as np

# Lazy load EasyOCR
easyocr = None

logger = structlog.get_logger(__name__)

# Simulated Database of Protected Brands
PROTECTED_BRANDS = {
    "google": {
        "phash": "1110001110111000100011111010000110001111101000011011100011100011",
        "colors": [(255, 255, 255), (66, 133, 244), (234, 67, 53), (251, 188, 5)],
        "keywords": ["google", "sign in", "workspace", "gmail"]
    },
    "microsoft": {
        "phash": "1111111110000001100000011000000110000001100000011000000111111111",
        "colors": [(255, 255, 255), (242, 80, 34), (127, 186, 0), (0, 164, 239), (255, 185, 0)],
        "keywords": ["microsoft", "sign in", "outlook", "onedrive", "office"]
    },
    "paypal": {
        "phash": "0011110001111110011001101100001111000011111111100111111000111100",
        "colors": [(0, 48, 135), (0, 121, 193), (255, 255, 255), (0, 207, 255)],
        "keywords": ["paypal", "log in", "send money", "checkout"]
    }
}

class VisualAnalyzer:
    def __init__(self):
        self.reader = None
        self.brands = PROTECTED_BRANDS
        
    def _init_ocr(self):
        global easyocr
        if easyocr is None:
            try:
                import easyocr
            except ImportError:
                logger.warning("easyocr not installed. OCR disabled.")
                return False
                
        if self.reader is None:
            try:
                logger.info("Initializing EasyOCR (CPU/GPU)")
                self.reader = easyocr.Reader(['en'], gpu=False) # CPU by default for stability
            except Exception as e:
                logger.error("Failed to initialize EasyOCR", error=str(e))
                return False
        return True

    def calculate_phash(self, image: Image.Image, hash_size: int = 8) -> str:
        """Calculate Perceptual Hash (pHash) using DCT."""
        try:
            # 1. Reduce size and convert to grayscale
            img = image.convert("L").resize((hash_size * 4, hash_size * 4), Image.Resampling.LANCZOS)
            pixels = np.asarray(img, dtype=np.float32)
            
            # 2. Compute 2D DCT
            from scipy.fftpack import dct
            dct_rows = dct(pixels, axis=1, norm='ortho')
            dct_data = dct(dct_rows, axis=0, norm='ortho')
            
            # 3. Extract top-left 8x8 (excluding DC term at [0,0])
            dct_8x8 = dct_data[0:hash_size, 0:hash_size]
            
            # 4. Compute median (excluding DC term)
            med = np.median(dct_8x8[1:])
            
            # 5. Build hash string
            hash_str = ""
            for i in range(hash_size):
                for j in range(hash_size):
                    hash_str += "1" if dct_8x8[i, j] > med else "0"
                    
            return hash_str
        except Exception as e:
            logger.error("pHash calculation failed", error=str(e))
            # Fallback aHash if scipy is missing
            return self._calculate_ahash(image, hash_size)
            
    def _calculate_ahash(self, image: Image.Image, hash_size: int = 8) -> str:
        """Fallback Average Hash."""
        img = image.convert("L").resize((hash_size, hash_size), Image.Resampling.LANCZOS)
        pixels = np.asarray(img)
        avg = pixels.mean()
        return "".join(["1" if p > avg else "0" for p in pixels.flatten()])

    def hamming_distance(self, hash1: str, hash2: str) -> int:
        """Calculate Hamming distance between two binary string hashes."""
        if len(hash1) != len(hash2):
            return 64 # Max distance
        return sum(c1 != c2 for c1, c2 in zip(hash1, hash2))

    def extract_colors(self, image: Image.Image, num_colors: int = 5) -> List[tuple]:
        """Extract dominant colors using K-Means clustering algorithm."""
        try:
            # Shrink image for faster processing
            img = image.copy()
            img.thumbnail((150, 150))
            
            # Convert to RGB array
            pixels = np.asarray(img.convert('RGB'))
            pixels = pixels.reshape(-1, 3)
            
            # Remove near-white and near-black (background colors)
            mask = np.any((pixels < 240) & (pixels > 15), axis=1)
            filtered = pixels[mask]
            
            if len(filtered) == 0:
                filtered = pixels # Fallback if image is mostly B/W
                
            # Perform K-Means (Simplified manual implementation to avoid sklearn dependency)
            k = min(num_colors, len(filtered))
            indices = np.random.choice(len(filtered), k, replace=False)
            centroids = filtered[indices].astype(float)
            
            for _ in range(5): # Max iterations
                # Assign pixels to nearest centroid
                distances = np.sqrt(((filtered - centroids[:, np.newaxis])**2).sum(axis=2))
                labels = np.argmin(distances, axis=0)
                
                # Update centroids
                new_centroids = np.array([filtered[labels == i].mean(axis=0) if np.any(labels == i) else centroids[i] for i in range(k)])
                if np.allclose(centroids, new_centroids):
                    break
                centroids = new_centroids
                
            # Return as standard Python tuples (R, G, B)
            return [tuple(map(int, c)) for c in centroids]
            
        except Exception as e:
            logger.error("Color extraction failed", error=str(e))
            return []

    def color_distance(self, color1: tuple, color2: tuple) -> float:
        """Calculate Euclidean distance between two RGB colors (0 to 441)."""
        return math.sqrt(sum((c1 - c2) ** 2 for c1, c2 in zip(color1, color2)))

    def extract_text(self, image: Image.Image) -> str:
        """Extract text from image using OCR."""
        if not self._init_ocr():
            return ""
            
        try:
            # EasyOCR expects numpy array or file path
            img_np = np.asarray(image)
            results = self.reader.readtext(img_np, detail=0)
            return " ".join(results).lower()
        except Exception as e:
            logger.error("OCR extraction failed", error=str(e))
            return ""

    async def analyze_screenshot(self, image_bytes: bytes, url: str) -> Dict[str, Any]:
        """
        Main entry point for analyzing a screenshot against known brands.
        """
        try:
            img = Image.open(io.BytesIO(image_bytes))
            
            # Calculate features
            phash = self.calculate_phash(img)
            dominant_colors = self.extract_colors(img)
            extracted_text = self.extract_text(img)
            
            logger.info("Visual features extracted", 
                       phash=phash, 
                       colors_found=len(dominant_colors),
                       text_len=len(extracted_text))
            
            # Compare against protected brands
            best_match = None
            highest_score = 0.0
            match_details = {}
            
            for brand_name, brand_profile in self.brands.items():
                score = 0.0
                details = {}
                
                # 1. pHash similarity (Max 0.4)
                dist = self.hamming_distance(phash, brand_profile["phash"])
                sim_ratio = max(0, (64 - dist) / 64)
                if sim_ratio > 0.8: # Must be fairly close to get points
                    phash_score = (sim_ratio - 0.8) * 2 * 0.4 
                    score += phash_score
                    details["phash_similarity"] = round(sim_ratio, 3)
                
                # 2. Color similarity (Max 0.3)
                color_hits = 0
                for bc in brand_profile["colors"]:
                    for c in dominant_colors:
                        if self.color_distance(bc, c) < 50: # Tolerance
                            color_hits += 1
                            break
                            
                color_score = min(1.0, color_hits / max(1, len(brand_profile["colors"]))) * 0.3
                score += color_score
                details["color_match_ratio"] = round(color_hits / max(1, len(brand_profile["colors"])), 3)
                
                # 3. OCR Keyword Matching (Max 0.3)
                keyword_hits = sum(1 for kw in brand_profile["keywords"] if kw in extracted_text)
                text_score = min(1.0, keyword_hits / 2) * 0.3 # 2 keywords = max score
                score += text_score
                details["keyword_hits"] = keyword_hits
                
                if score > highest_score:
                    highest_score = score
                    best_match = brand_name
                    match_details = details
            
            # Determine if impersonating
            # If domain obviously contains the brand name, it might be legit (Need deeper check, but for MVP)
            is_legit = best_match and best_match in url.lower()
            
            result = {
                "similarity_score": round(highest_score, 3),
                "brand_detected": best_match if highest_score > 0.4 else None,
                "is_impersonation": bool(highest_score > 0.45 and not is_legit),
                "confidence": round(highest_score, 3) if highest_score > 0.45 else 0.0,
                "details": match_details
            }
            
            return result
            
        except Exception as e:
            logger.error("Screenshot analysis failed", error=str(e), exc_info=True)
            return {"error": "Visual analysis failed"}

# Global singleton
visual_analyzer = VisualAnalyzer()
