"""
PhishGuard — Automated Model Retraining Pipeline

This script is designed to run weekly (via cron or GitHub Actions).
It fetches the latest phishing URLs, rebuilds the dataset,
retrains the model, validates it against the current production model,
and (if improved) exports the new model for deployment.

Usage:
    python retrain_pipeline.py

    # Or via cron (every Sunday at 2 AM):
    0 2 * * 0 cd /path/to/ml-training && python retrain_pipeline.py
"""

import json
import os
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

# Ensure ml-training scripts are importable
sys.path.insert(0, str(Path(__file__).parent))


def main():
    print("=" * 60)
    print("PhishGuard — Automated Retraining Pipeline")
    print("Started at:", datetime.utcnow().isoformat())
    print("=" * 60)

    start_time = time.time()

    # ── Step 1: Fetch fresh data ──
    print("\n[Step 1/6] Fetching fresh phishing and legitimate URLs...")
    from build_dataset import main as build_dataset
    build_dataset()

    dataset_path = Path("data/phishing_dataset.csv")
    if not dataset_path.exists():
        print("ERROR: Dataset not generated. Aborting.")
        return

    # ── Step 2: Train new model ──
    print("\n[Step 2/6] Training new model...")
    from train_url_model import (
        load_dataset,
        split_data,
        train_with_cv,
        train_final_model,
        evaluate_model,
        export_to_onnx,
        validate_onnx,
    )

    df = load_dataset()
    X_train, X_test, y_train, y_test = split_data(df)
    cv_scores = train_with_cv(X_train, y_train)
    model = train_final_model(X_train, y_train, X_test, y_test)
    new_metrics = evaluate_model(model, X_test, y_test)

    # ── Step 3: Compare with current production model ──
    print("\n[Step 3/6] Comparing with production model...")

    production_model_path = Path("../extension/models/url_classifier.onnx")
    production_metrics_path = Path("reports/metrics.json")

    should_deploy = True
    improvement_reason = "No previous model found — deploying new model"

    if production_metrics_path.exists():
        with open(production_metrics_path) as f:
            old_metrics = json.load(f)

        old_auc_pr = old_metrics.get("auc_pr", 0)
        new_auc_pr = new_metrics.get("auc_pr", 0)
        old_f1 = old_metrics.get("f1_score", 0)
        new_f1 = new_metrics.get("f1_score", 0)

        print("  Current model  — AUC-PR: {:.4f}, F1: {:.4f}".format(
            old_auc_pr, old_f1
        ))
        print("  New model      — AUC-PR: {:.4f}, F1: {:.4f}".format(
            new_auc_pr, new_f1
        ))

        # Deploy only if the new model is better or equal on BOTH metrics
        if new_auc_pr >= old_auc_pr and new_f1 >= old_f1:
            if new_auc_pr > old_auc_pr or new_f1 > old_f1:
                improvement_reason = (
                    "New model improves AUC-PR by {:.4f} and F1 by {:.4f}".format(
                        new_auc_pr - old_auc_pr, new_f1 - old_f1
                    )
                )
            else:
                improvement_reason = "New model matches current performance with fresh data"
        else:
            should_deploy = False
            print("\n  ⚠️ New model does NOT improve on current model.")
            print("  Skipping deployment. Manual review recommended.")

    # ── Step 4: Export and deploy ──
    if should_deploy:
        print("\n[Step 4/6] Exporting new model...")
        print("  Reason:", improvement_reason)

        export_to_onnx(model)
        validate_onnx(X_test, y_test, model)

        # Copy to extension directory
        new_model_path = Path("../extension/models/url_classifier.onnx")
        if new_model_path.exists():
            # Archive the old model
            archive_dir = Path("model_archive")
            archive_dir.mkdir(exist_ok=True)
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            archive_name = "url_classifier_{}.onnx".format(timestamp)
            shutil.copy2(new_model_path, archive_dir / archive_name)
            print("  Archived old model as", archive_name)

        # The export_to_onnx function already writes to ../extension/models/
        print("  New model deployed to extension/models/")

        # Also copy to backend
        backend_model_path = Path("../backend/models/url_classifier.onnx")
        if backend_model_path.parent.exists():
            shutil.copy2(new_model_path, backend_model_path)
            print("  New model deployed to backend/models/")
    else:
        print("\n[Step 4/6] Skipped — model not deployed.")

    # ── Step 5: Save retraining log ──
    print("\n[Step 5/6] Saving retraining log...")
    log_dir = Path("retrain_logs")
    log_dir.mkdir(exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "dataset_size": len(df),
        "cv_scores": {
            k: {"mean": float(sum(v) / len(v)), "std": float(
                (sum((x - sum(v) / len(v)) ** 2 for x in v) / len(v)) ** 0.5
            )}
            for k, v in cv_scores.items()
        },
        "test_metrics": {
            "accuracy": new_metrics["accuracy"],
            "precision": new_metrics["precision"],
            "recall": new_metrics["recall"],
            "f1_score": new_metrics["f1_score"],
            "auc_pr": new_metrics["auc_pr"],
            "auc_roc": new_metrics["auc_roc"],
        },
        "deployed": should_deploy,
        "deployment_reason": improvement_reason,
        "elapsed_seconds": round(time.time() - start_time, 1),
    }

    log_file = log_dir / "retrain_{}.json".format(timestamp)
    with open(log_file, "w") as f:
        json.dump(log_entry, f, indent=2)

    print("  Log saved to", log_file)

    # ── Step 6: Summary ──
    elapsed = round(time.time() - start_time, 1)
    print("\n[Step 6/6] Summary")
    print("  Dataset size:", len(df))
    print("  AUC-PR:", round(new_metrics["auc_pr"], 4))
    print("  F1-Score:", round(new_metrics["f1_score"], 4))
    print("  Deployed:", should_deploy)
    print("  Total time:", elapsed, "seconds")
    print("=" * 60)


if __name__ == "__main__":
    main()
