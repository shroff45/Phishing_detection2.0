"""
PhishGuard ML v4.1 — Deployment
Copies model+config to extension and backend directories.

Fix 13: No input() — fully automated for CI/CD compatibility.
"""

import json
import shutil
from pathlib import Path
from config import (
    MODELS_DIR, REPORTS_DIR,
    EXTENSION_DIR, BACKEND_MODEL_DIR,
    NUM_FEATURES, FEATURE_NAMES,
)


def deploy():
    """Deploy model to extension and backend."""
    print("=" * 60)
    print("PHISHGUARD ML v4.1 — DEPLOYMENT")
    print("=" * 60)

    # Find best model
    model_path = MODELS_DIR / "phishing_model_v4.onnx"
    if not model_path.exists():
        model_path = MODELS_DIR / "phishing_model_v4_raw.onnx"
    if not model_path.exists():
        print("✗ No model found! Run train_model.py first.")
        return

    print(f"Model: {model_path.name} ({model_path.stat().st_size / 1024:.1f} KB)")

    # Load training report for threshold
    report_path = REPORTS_DIR / "training_report.json"
    threshold = 0.5
    if report_path.exists():
        with open(report_path) as f:
            report = json.load(f)
        threshold = report.get("optimal_threshold", 0.5)

    # Create model_config.json for the extension
    model_config = {
        "model_version": "4.1",
        "input_name": "float_input",
        "num_features": NUM_FEATURES,
        "feature_names": FEATURE_NAMES,
        "optimal_threshold": threshold,
        "output_classes": ["legitimate", "phishing"],
    }

    # Deploy to extension
    deployed = []
    if EXTENSION_DIR and EXTENSION_DIR.exists():
        ext_model_dir = EXTENSION_DIR / "models"
        ext_model_dir.mkdir(parents=True, exist_ok=True)

        target = ext_model_dir / "model.onnx"
        shutil.copy2(model_path, target)
        deployed.append(target)
        print(f"  ✓ Extension: {target}")

        config_path = ext_model_dir / "model_config.json"
        with open(config_path, "w") as f:
            json.dump(model_config, f, indent=2)
        print(f"  ✓ Config:    {config_path}")
    else:
        print("  ⚠ Extension directory not found — skipped")

    # Deploy to backend
    if BACKEND_MODEL_DIR.parent.exists():
        BACKEND_MODEL_DIR.mkdir(parents=True, exist_ok=True)

        target = BACKEND_MODEL_DIR / "model.onnx"
        shutil.copy2(model_path, target)
        deployed.append(target)
        print(f"  ✓ Backend:   {target}")

        config_path = BACKEND_MODEL_DIR / "model_config.json"
        with open(config_path, "w") as f:
            json.dump(model_config, f, indent=2)
        print(f"  ✓ Config:    {config_path}")
    else:
        print("  ⚠ Backend directory not found — skipped")

    print(f"\n{'=' * 60}")
    print(f"DEPLOYED: {len(deployed)} targets | Threshold: {threshold:.4f}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    deploy()
