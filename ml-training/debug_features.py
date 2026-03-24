import sys
from pathlib import Path
import json

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))
from build_dataset import extract_features, FEATURE_NAMES

urls = [
    "https://www.google.com/",
    "https://www.amazon.com/dp/B08N5WRWNW",
    "http://secure-paypal-login.verify-account.xyz/signin",
]

for url in urls:
    print(f"\nURL: {url}")
    feats = extract_features(url)
    if feats:
        # Print features that are often suspicious
        suspicious_keys = [
            'f01_urlLength', 'f04_queryLength', 'f11_digitCountUrl', 
            'f14_subdomainCount', 'f17_isIpAddress', 'f23_isHttps', 
            'f24_hasSuspiciousTld', 'f27_keywordHits'
        ]
        for k in suspicious_keys:
            print(f"  {k:20}: {feats.get(k)}")
        
        # Also print any non-zero features from f24 to f30
        for k in FEATURE_NAMES[23:]: # f24 onwards
            if feats.get(k):
                print(f"  {k:20}: {feats.get(k)}")
    else:
        print("  FAILED TO EXTRACT")
