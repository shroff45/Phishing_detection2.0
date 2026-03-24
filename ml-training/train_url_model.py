"""
PhishGuard — Model Trainer
Trains a Random Forest on dataset.csv and exports to ONNX for browser extension.

Run:  python train_url_model.py [--data dataset.csv] [--out model.onnx]

The exported ONNX model:
  - Input name:  "float_input"  (matches service-worker.js)
  - Input shape:  [batch_size, 30]   (30 lexical features)
  - Output:  probabilities array [[p_legit, p_phish]]
"""

import argparse
import pickle
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report,
    accuracy_score,
    confusion_matrix,
    roc_auc_score,
)

# ONNX conversion
from skl2onnx import to_onnx
from skl2onnx.common.data_types import FloatTensorType

# Import feature definition from dataset builder to ensure perfect sync
from build_dataset import FEATURE_NAMES


def main():
    parser = argparse.ArgumentParser(
        description="Train PhishGuard URL classifier and export to ONNX"
    )
    parser.add_argument("--data", default="dataset.csv", help="Input CSV from build_dataset.py")
    parser.add_argument("--out", default="model.onnx", help="Output ONNX filename")
    parser.add_argument("--trees", type=int, default=100, help="Number of trees in Random Forest")
    parser.add_argument("--depth", type=int, default=15, help="Max tree depth")
    parser.add_argument("--test-size", type=float, default=0.2, help="Test split ratio")
    args = parser.parse_args()

    data_path = Path(__file__).parent / args.data
    if not data_path.exists():
        print(f"ERROR: {data_path} not found.")
        print("Run  python build_dataset.py  first to create the dataset.")
        return

    # ── Load data ─────────────────────────────────────────────
    print(f"Loading data from {data_path}...")
    df = pd.read_csv(data_path)

    # Verify all feature columns exist
    missing_cols = [c for c in FEATURE_NAMES if c not in df.columns]
    if missing_cols:
        print(f"ERROR: Missing columns in CSV: {missing_cols}")
        print(f"Available columns: {list(df.columns)}")
        return

    X = df[FEATURE_NAMES].values.astype(np.float32)
    y = df["label"].values.astype(np.int64)

    # Replace any NaN/inf with 0
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    n_phish = int(np.sum(y == 1))
    n_legit = int(np.sum(y == 0))
    print(f"Total samples : {len(X)}")
    print(f"  Phishing    : {n_phish}")
    print(f"  Legitimate  : {n_legit}")
    print(f"  Ratio       : {n_phish / max(n_legit, 1):.2f}")
    print()

    if len(X) < 100:
        print("WARNING: Very small dataset. Model quality will be poor.")
        print("Try running build_dataset.py with a working internet connection.\n")

    # ── Train/test split ──────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=args.test_size,
        random_state=42,
        stratify=y,
    )
    print(f"Train samples: {len(X_train)}")
    print(f"Test samples : {len(X_test)}")
    print()

    # ── Train Random Forest ───────────────────────────────────
    print(f"Training Random Forest ({args.trees} trees, max_depth={args.depth})...")
    clf = RandomForestClassifier(
        n_estimators=args.trees,
        max_depth=args.depth,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",  # Handle class imbalance
    )
    clf.fit(X_train, y_train)
    print("Training complete.\n")

    # ── Evaluate ──────────────────────────────────────────────
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)

    accuracy = accuracy_score(y_test, y_pred)
    try:
        auc = roc_auc_score(y_test, y_prob[:, 1])
    except Exception:
        auc = 0.0

    print("=" * 50)
    print("  Model Evaluation")
    print("=" * 50)
    print(f"Accuracy : {accuracy:.4f}")
    print(f"ROC AUC  : {auc:.4f}")
    print()
    print("Classification Report:")
    print(classification_report(
        y_test, y_pred,
        target_names=["Legitimate", "Phishing"],
    ))
    print("Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"  TN={cm[0][0]:>5}  FP={cm[0][1]:>5}")
    print(f"  FN={cm[1][0]:>5}  TP={cm[1][1]:>5}")
    print()

    # ── Feature importance ────────────────────────────────────
    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    print("Top 10 Most Important Features:")
    for i in range(min(10, len(sorted_idx))):
        idx = sorted_idx[i]
        print(f"  {i + 1:>2}. {FEATURE_NAMES[idx]:<30s} {importances[idx]:.4f}")
    print()

    # ── Cross-validation ──────────────────────────────────────
    if len(X) >= 500:
        print("Running 5-fold cross-validation...")
        cv_scores = cross_val_score(clf, X, y, cv=5, scoring="accuracy", n_jobs=-1)
        print(f"  CV Accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
        print()

    # ── Export to ONNX ────────────────────────────────────────
    print("Exporting model to ONNX format...")

    # The input tensor name MUST be "float_input" to match service-worker.js
    initial_type = [("float_input", FloatTensorType([None, 30]))]

    onx = to_onnx(
        clf,
        initial_types=initial_type,
        target_opset=12,
        options={id(clf): {"zipmap": False}},  # Output raw probabilities, not dict
    )

    # Save to extension/models/
    ext_model_dir = Path(__file__).parent.parent / "extension" / "models"
    ext_model_dir.mkdir(parents=True, exist_ok=True)
    onnx_path = ext_model_dir / args.out

    with open(onnx_path, "wb") as f:
        f.write(onx.SerializeToString())

    # Save to backend/app/models/
    backend_model_dir = Path(__file__).parent.parent / "backend" / "app" / "models"
    backend_model_dir.mkdir(parents=True, exist_ok=True)
    backend_onnx_path = backend_model_dir / args.out
    with open(backend_onnx_path, "wb") as f:
        f.write(onx.SerializeToString())

    # Also save locally for verification
    local_onnx = Path(__file__).parent / args.out
    with open(local_onnx, "wb") as f:
        f.write(onx.SerializeToString())

    # Save pickle for Python-side verification
    pkl_path = Path(__file__).parent / "model.pkl"
    with open(pkl_path, "wb") as f:
        pickle.dump(clf, f)

    # Save model metadata (useful for the extension)
    metadata = {
        "feature_names": FEATURE_NAMES,
        "n_features": 30,
        "input_name": "float_input",
        "output_classes": ["legitimate", "phishing"],
        "accuracy": round(accuracy, 4),
        "auc": round(auc, 4),
        "n_trees": args.trees,
        "max_depth": args.depth,
        "training_samples": len(X_train),
        "test_samples": len(X_test),
    }
    meta_path = Path(__file__).parent / "model_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    # ── Verify ONNX ──────────────────────────────────────────
    print("\nVerifying ONNX model...")
    try:
        import onnxruntime as ort

        sess = ort.InferenceSession(str(onnx_path))
        input_name = sess.get_inputs()[0].name
        input_shape = sess.get_inputs()[0].shape
        output_names = [o.name for o in sess.get_outputs()]

        print(f"  Input name  : {input_name}")
        print(f"  Input shape : {input_shape}")
        print(f"  Output names: {output_names}")

        # Test inference with a sample
        test_input = X_test[:3].astype(np.float32)
        ort_results = sess.run(None, {input_name: test_input})

        # Compare with sklearn predictions
        sk_probs = clf.predict_proba(test_input)

        print(f"\n  Sample predictions (first 3 test URLs):")
        for i in range(3):
            ort_prob = ort_results[1][i]  # probabilities
            sk_prob = sk_probs[i]
            print(f"    URL {i + 1}: sklearn=[{sk_prob[0]:.4f}, {sk_prob[1]:.4f}]  "
                  f"onnx=[{ort_prob[0]:.4f}, {ort_prob[1]:.4f}]")

        print("\n  ✓ ONNX verification passed!")

    except ImportError:
        print("  WARN: onnxruntime not installed, skipping verification")
    except Exception as e:
        print(f"  WARN: ONNX verification failed: {e}")
        print("  The model file was still saved — try loading it manually.")

    # ── Summary ───────────────────────────────────────────────
    print()
    print("=" * 50)
    print("  Training Complete!")
    print("=" * 50)
    print(f"  ONNX model  : {onnx_path}")
    print(f"  Local copy  : {local_onnx}")
    print(f"  Pickle model: {pkl_path}")
    print(f"  Metadata    : {meta_path}")
    print(f"  Accuracy    : {accuracy:.4f}")
    print(f"  ROC AUC     : {auc:.4f}")
    print()
    print("The extension will load the model from:")
    print(f"  extension/models/{args.out}")
    print()
    print("To run the backend server:")
    print("  cd ../backend && pip install -r requirements.txt && python -m app.main")


if __name__ == "__main__":
    main()
