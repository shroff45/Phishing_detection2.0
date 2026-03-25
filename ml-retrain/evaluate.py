"""
PhishGuard ML v4.1 — Evaluation
Per-class evaluation, known-URL verification, and comprehensive reporting.

Fix 16/17: This module was completely missing before.
"""

import json
import numpy as np
import onnxruntime as ort
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, precision_recall_curve, average_precision_score,
)
from config import (
    PREPARED_DIR, MODELS_DIR, REPORTS_DIR,
    NUM_FEATURES, FEATURE_NAMES,
)
from feature_extractor import extract_features_array, parse_onnx_probabilities


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Known-URL Verification Suite
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

KNOWN_SAFE = [
    ("https://www.google.com/", "Google"),
    ("https://fast.com/", "Fast.com (Netflix)"),
    ("https://vtop.vit.ac.in/vtop/login", "VIT VTop"),
    ("https://github.com/login", "GitHub Login"),
    ("https://accounts.google.com/signin", "Google Sign-in"),
    ("https://www.amazon.com/", "Amazon"),
    ("https://stackoverflow.com/questions", "Stack Overflow"),
    ("https://login.microsoftonline.com/common/oauth2", "Microsoft Login"),
]

KNOWN_PHISHING = [
    ("http://g00gle-login.tk/verify", "Typosquatting Google"),
    ("http://45.67.89.123/login.php", "IP-based phishing"),
    ("https://paypal-verify.secure-login.xyz/account", "Subdomain abuse"),
    ("https://secure-bank.com@evil.xyz/login", "@ trick"),
    ("https://amaz0n-secure.buzz/verify", "Brand impersonation"),
    ("http://192.0.2.1:8080/signin", "Public IP phishing"),
]


def evaluate():
    """Run full evaluation suite."""
    print("=" * 60)
    print("PHISHGUARD ML v4.1 — EVALUATION")
    print("=" * 60)

    # Load test data
    X_test = np.load(PREPARED_DIR / "X_test.npy")
    y_test = np.load(PREPARED_DIR / "y_test.npy")
    src_test = np.load(PREPARED_DIR / "src_test.npy", allow_pickle=True)

    # Load model
    model_path = MODELS_DIR / "phishing_model_v4.onnx"
    if not model_path.exists():
        model_path = MODELS_DIR / "phishing_model_v4_raw.onnx"
        if not model_path.exists():
            print("✗ No model found! Run train_model.py first.")
            return

    session = ort.InferenceSession(str(model_path))
    print(f"Model: {model_path.name}")
    print(f"Input: {session.get_inputs()[0].name} {session.get_inputs()[0].shape}")

    # Load training report for threshold
    report_path = REPORTS_DIR / "training_report.json"
    if report_path.exists():
        with open(report_path) as f:
            train_report = json.load(f)
        threshold = train_report.get("optimal_threshold", 0.5)
    else:
        threshold = 0.5

    # Test set evaluation
    print(f"\n{'─' * 60}")
    print("TEST SET EVALUATION")
    print(f"{'─' * 60}")

    y_prob = parse_onnx_probabilities(session, X_test)
    y_pred = (y_prob >= threshold).astype(int)

    print(f"\nThreshold: {threshold:.4f}")
    print(classification_report(
        y_test, y_pred,
        target_names=["Legitimate", "Phishing"], digits=4,
    ))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    print(f"  TN={tn:>5}  FP={fp:>5}")
    print(f"  FN={fn:>5}  TP={tp:>5}")
    print(f"\n  FPR: {fpr:.4f} ({fpr * 100:.2f}%)")
    print(f"  FNR: {fnr:.4f} ({fnr * 100:.2f}%)")

    # Per-source evaluation
    print(f"\n{'─' * 60}")
    print("PER-SOURCE ACCURACY")
    print(f"{'─' * 60}")

    unique_sources = np.unique(src_test)
    for source in sorted(unique_sources):
        mask = src_test == source
        if mask.sum() < 5:
            continue
        src_pred = y_pred[mask]
        src_true = y_test[mask]
        acc = float(np.mean(src_pred == src_true))
        count = int(mask.sum())
        label = "phish" if src_true.mean() > 0.5 else "legit"
        print(f"  {source:<25} {acc:.4f} ({count:>5} samples, {label})")

    # Known-URL verification
    print(f"\n{'─' * 60}")
    print("KNOWN-URL VERIFICATION")
    print(f"{'─' * 60}")

    all_pass = True

    print("\n  Known SAFE URLs:")
    for url, desc in KNOWN_SAFE:
        features = extract_features_array(url)
        if features is None:
            print(f"    ✗ {desc}: parse failed")
            all_pass = False
            continue
        X = np.array([features], dtype=np.float32)
        prob = float(parse_onnx_probabilities(session, X)[0])
        pred = "PHISHING" if prob >= threshold else "SAFE"
        icon = "✓" if pred == "SAFE" else "✗"
        print(f"    {icon} {desc:<30} → {pred} ({prob:.4f})")
        if pred != "SAFE":
            all_pass = False

    print("\n  Known PHISHING URLs:")
    for url, desc in KNOWN_PHISHING:
        features = extract_features_array(url)
        if features is None:
            print(f"    ✗ {desc}: parse failed")
            all_pass = False
            continue
        X = np.array([features], dtype=np.float32)
        prob = float(parse_onnx_probabilities(session, X)[0])
        pred = "PHISHING" if prob >= threshold else "SAFE"
        icon = "✓" if pred == "PHISHING" else "✗"
        print(f"    {icon} {desc:<30} → {pred} ({prob:.4f})")
        if pred != "PHISHING":
            all_pass = False

    # Summary
    print(f"\n{'=' * 60}")
    if all_pass:
        print("✓ ALL KNOWN-URL CHECKS PASSED")
    else:
        print("⚠ SOME KNOWN-URL CHECKS FAILED")
    print(f"{'=' * 60}")

    # Save eval report
    eval_report = {
        "test_accuracy": float(np.mean(y_pred == y_test)),
        "test_fpr": fpr,
        "test_fnr": fnr,
        "test_auc": float(roc_auc_score(y_test, y_prob)),
        "threshold": threshold,
        "known_url_pass": all_pass,
    }
    with open(REPORTS_DIR / "evaluation_report.json", "w") as f:
        json.dump(eval_report, f, indent=2)

    print(f"\n✓ Report saved to {REPORTS_DIR / 'evaluation_report.json'}")


if __name__ == "__main__":
    evaluate()
