"""
Quick verification script — loads the ONNX model and tests it
against known phishing and legitimate URLs.

Run:  python verify_model.py
"""

import sys
from pathlib import Path

import numpy as np

# Add parent to path so we can import build_dataset's feature extractor
sys.path.insert(0, str(Path(__file__).parent))
from build_dataset import extract_features, FEATURE_NAMES

try:
    import onnxruntime as ort
except ImportError:
    print("ERROR: pip install onnxruntime")
    sys.exit(1)


# Test URLs — should be clearly phishing or clearly legitimate
TEST_CASES = [
    # (url, expected_label, description)
    ("https://www.google.com/", 0, "Google homepage"),
    ("https://github.com/features", 0, "GitHub features page"),
    ("https://en.wikipedia.org/wiki/Phishing", 0, "Wikipedia article"),
    ("https://stackoverflow.com/questions", 0, "StackOverflow"),
    ("https://www.amazon.com/dp/B08N5WRWNW", 0, "Amazon product"),
    ("http://192.168.1.1/login.php", 1, "IP-based login"),
    ("http://secure-paypal-login.verify-account.xyz/signin", 1, "Fake PayPal"),
    ("http://account-update-confirm.tk/banking/verify.html?id=12345", 1, "Suspicious TLD + keywords"),
    ("http://bit.ly/3xR4Tq2", 1, "URL shortener (suspicious)"),
    ("http://login-microsoft-secure.ml/verify/password/reset", 1, "Fake Microsoft"),
    ("https://apple.com/", 0, "Apple homepage"),
    ("http://xn--80ak6aa92e.com/login/verify/account/secure", 1, "Punycode + keywords"),
]


def main():
    # Find the model
    model_paths = [
        Path(__file__).parent.parent / "extension" / "models" / "model.onnx",
        Path(__file__).parent / "model.onnx",
    ]

    model_path = None
    for p in model_paths:
        if p.exists():
            model_path = p
            break

    if model_path is None:
        print("ERROR: model.onnx not found!")
        print("Run  python train_url_model.py  first.")
        print(f"Searched: {[str(p) for p in model_paths]}")
        return

    print(f"Loading model: {model_path}")
    sess = ort.InferenceSession(str(model_path))

    input_name = sess.get_inputs()[0].name
    print(f"Input name: {input_name}")
    print(f"Input shape: {sess.get_inputs()[0].shape}")
    print()

    # Verify input name matches what service-worker.js expects
    if input_name != "float_input":
        print(f"WARNING: Input name is '{input_name}', expected 'float_input'")
        print("The extension's service-worker.js may need to be updated!")
        print()

    print("=" * 70)
    print(f"{'URL':<55s} {'Expect':>6s} {'Pred':>6s} {'Prob':>6s} {'OK?':>4s}")
    print("=" * 70)

    correct = 0
    total = len(TEST_CASES)

    for url, expected, desc in TEST_CASES:
        feats = extract_features(url)
        if feats is None:
            print(f"  SKIP: {url} (unparseable)")
            total -= 1
            continue

        # Build feature vector in correct order
        feature_vec = np.array(
            [[feats[name] for name in FEATURE_NAMES]],
            dtype=np.float32,
        )

        # Run inference
        results = sess.run(None, {input_name: feature_vec})
        probabilities = results[1][0]  # [p_legit, p_phish]
        predicted = 1 if probabilities[1] > 0.5 else 0
        phish_prob = probabilities[1]

        is_correct = predicted == expected
        if is_correct:
            correct += 1

        label_str = "PHISH" if expected == 1 else "LEGIT"
        pred_str = "PHISH" if predicted == 1 else "LEGIT"
        ok_str = "  ✓" if is_correct else " ✗✗"

        # Truncate URL for display
        display_url = url[:52] + "..." if len(url) > 55 else url
        print(f"{display_url:<55s} {label_str:>6s} {pred_str:>6s} {phish_prob:>6.3f} {ok_str}")

    print("=" * 70)
    print(f"Accuracy on test cases: {correct}/{total} ({100 * correct / max(total, 1):.0f}%)")

    if correct == total:
        print("\n✓ All test cases passed!")
    else:
        print(f"\n⚠ {total - correct} test case(s) failed.")
        print("This may be normal — the model uses statistical features,")
        print("not hardcoded rules. Check the training data quality.")


if __name__ == "__main__":
    main()
