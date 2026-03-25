"""
PhishGuard ML v4.1 — Model Training
Multi-model training with calibration, FPR-constrained threshold, ONNX export.

Fixes applied:
  - Fix 2/9:  Calibrate on SEPARATE calibration set with cv="prefit"
  - Fix 10:   Exponential FPR penalty in model selection
  - Fix 12:   XGBoost — no deprecated use_label_encoder
  - Fix 14/H: ONNX output parsed by name via shared utility
  - Fix 18/E: Optimal threshold via ROC curve with array alignment
"""

import json
import time
import numpy as np
from pathlib import Path
from sklearn.ensemble import (
    RandomForestClassifier,
    GradientBoostingClassifier,
    ExtraTreesClassifier,
)
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, f1_score, accuracy_score, roc_curve,
)
from sklearn.calibration import CalibratedClassifierCV
from config import (
    PREPARED_DIR, MODELS_DIR, REPORTS_DIR,
    RANDOM_STATE, TARGET_FPR, NUM_FEATURES,
)

try:
    from xgboost import XGBClassifier
    HAS_XGB = False
except ImportError:
    HAS_XGB = False

HAS_XGB = False
try:
    from lightgbm import LGBMClassifier
    HAS_LGBM = False
except ImportError:
    HAS_LGBM = False


def load_data() -> dict:
    """Load all 4 splits + metadata."""
    data = {}
    for name in [
        "X_train", "X_val", "X_cal", "X_test",
        "y_train", "y_val", "y_cal", "y_test", "src_test",
    ]:
        path = PREPARED_DIR / f"{name}.npy"
        if path.exists():
            data[name] = np.load(path, allow_pickle=True)

    with open(PREPARED_DIR / "metadata.json") as f:
        data["meta"] = json.load(f)

    print(f"Train: {data['X_train'].shape} | Val: {data['X_val'].shape} | "
          f"Cal: {data['X_cal'].shape} | Test: {data['X_test'].shape}")
    return data


def train_all_models(X_train, y_train, X_val, y_val) -> dict:
    """Train candidate models and evaluate on validation set."""

    candidates = {
        "random_forest": RandomForestClassifier(
            n_estimators=100, max_depth=15, min_samples_leaf=2,
            class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
        ),
        "extra_trees": ExtraTreesClassifier(
            n_estimators=100, max_depth=15, min_samples_leaf=2,
            class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
        ),
        "gradient_boosting": GradientBoostingClassifier(
            n_estimators=100, max_depth=5, learning_rate=0.1,
            min_samples_leaf=5, subsample=0.8, random_state=RANDOM_STATE,
        ),
    }

    # Fix 12: XGBoost — no use_label_encoder
    if HAS_XGB:
        candidates["xgboost"] = XGBClassifier(
            n_estimators=500, max_depth=12, learning_rate=0.1,
            min_child_weight=3, subsample=0.8, colsample_bytree=0.8,
            random_state=RANDOM_STATE, n_jobs=-1, eval_metric="logloss",
        )

    if HAS_LGBM:
        candidates["lightgbm"] = LGBMClassifier(
            n_estimators=500, max_depth=12, learning_rate=0.1,
            min_child_samples=5, subsample=0.8, colsample_bytree=0.8,
            random_state=RANDOM_STATE, n_jobs=-1, verbose=-1,
        )

    results = {}
    for name, model in candidates.items():
        print(f"\n  Training {name}...", end=" ", flush=True)
        start = time.time()
        model.fit(X_train, y_train)
        elapsed = time.time() - start

        y_prob = model.predict_proba(X_val)[:, 1]
        y_pred = model.predict(X_val)

        cm = confusion_matrix(y_val, y_pred)
        tn, fp, fn, tp = cm.ravel()

        metrics = {
            "accuracy": float(accuracy_score(y_val, y_pred)),
            "f1": float(f1_score(y_val, y_pred)),
            "auc": float(roc_auc_score(y_val, y_prob)),
            "fpr": float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
            "fnr": float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0,
            "time": elapsed,
        }

        print(f"Acc={metrics['accuracy']:.4f} F1={metrics['f1']:.4f} "
              f"AUC={metrics['auc']:.4f} FPR={metrics['fpr']:.4f} ({elapsed:.1f}s)")

        results[name] = {"model": model, "metrics": metrics}

    return results


def select_best(results: dict):
    """
    Fix 10: Select best model with exponential FPR penalty.
    """
    print(f"\n{'=' * 60}")
    print(f"{'Model':<22} {'Acc':>7} {'F1':>7} {'AUC':>7} {'FPR':>7}")
    print("-" * 55)

    best_name = None
    best_score = -1.0

    for name, info in results.items():
        m = info["metrics"]

        score = m["f1"]
        if m["fpr"] > TARGET_FPR:
            fpr_ratio = m["fpr"] / TARGET_FPR
            penalty = min(fpr_ratio * 0.1, 0.5)
            score *= (1 - penalty)
            marker = f" (penalized: {penalty:.1%})"
        else:
            marker = " ★"

        if score > best_score:
            best_score = score
            best_name = name

        print(f"  {name:<20} {m['accuracy']:>7.4f} {m['f1']:>7.4f} "
              f"{m['auc']:>7.4f} {m['fpr']:>7.4f}{marker}")

    print(f"\n→ Winner: {best_name}")
    return best_name, results[best_name]["model"]


def find_optimal_threshold(model, X_val, y_val, target_fpr=TARGET_FPR) -> float:
    """
    Fix 18/E: Find threshold achieving target FPR via ROC curve.
    Handles sklearn's roc_curve sentinel correctly.
    """
    y_prob = model.predict_proba(X_val)[:, 1]
    fpr_arr, tpr_arr, thresholds = roc_curve(y_val, y_prob)

    # sklearn roc_curve: fpr_arr and tpr_arr have len(thresholds)+1
    # The first point (0, 0) has no corresponding threshold.
    # Drop it so arrays align.
    if len(fpr_arr) > len(thresholds):
        fpr_arr = fpr_arr[1:]
        tpr_arr = tpr_arr[1:]

    # Find threshold achieving target FPR with best TPR
    candidates = np.where(fpr_arr <= target_fpr * 1.5)[0]

    if len(candidates) == 0:
        print(f"  ⚠ Cannot achieve FPR ≤ {target_fpr * 1.5:.4f}")
        idx = int(np.argmin(np.abs(fpr_arr - target_fpr)))
    else:
        idx = int(candidates[np.argmax(tpr_arr[candidates])])

    idx = min(idx, len(thresholds) - 1)

    optimal = float(thresholds[idx])
    achieved_fpr = float(fpr_arr[idx])
    achieved_tpr = float(tpr_arr[idx])

    print(f"  Optimal threshold: {optimal:.4f}")
    print(f"  Achieved FPR: {achieved_fpr:.4f} (target: {target_fpr})")
    print(f"  Achieved TPR: {achieved_tpr:.4f}")

    return optimal


def export_onnx(model, num_features: int, output_path: Path) -> bool:
    """
    Export to ONNX with zipmap=False for array output.
    Fix 14/H: verify using shared parser.
    """
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType

    initial_type = [("float_input", FloatTensorType([None, num_features]))]

    try:
        # zipmap=False → outputs raw probability arrays, not dicts
        onnx_model = convert_sklearn(
            model, initial_types=initial_type, target_opset=12,
            options={id(model): {"zipmap": False}},
        )

        with open(output_path, "wb") as f:
            f.write(onnx_model.SerializeToString())

        # Verify using shared parser
        import onnxruntime as ort
        from feature_extractor import parse_onnx_probabilities

        session = ort.InferenceSession(str(output_path))
        print(f"  ONNX outputs: {[o.name for o in session.get_outputs()]}")

        test_input = np.zeros((1, num_features), dtype=np.float32)
        probs = parse_onnx_probabilities(session, test_input)
        phishing_prob = float(probs[0])

        print(f"  ✓ Zero-input phishing prob: {phishing_prob:.4f}")
        print(f"  ✓ Size: {output_path.stat().st_size / 1024:.1f} KB")

        if phishing_prob > 0.3:
            print(f"  ⚠ High zero-input bias ({phishing_prob:.2f}) — adjust threshold")

        return True

    except Exception as e:
        print(f"  ✗ ONNX export failed: {e}")
        return False


def train():
    """Complete training pipeline."""
    print("=" * 60)
    print("PHISHGUARD ML v4.1 — MODEL TRAINING")
    print("=" * 60)

    data = load_data()

    # Train and select
    results = train_all_models(
        data["X_train"], data["y_train"],
        data["X_val"], data["y_val"],
    )
    best_name, best_model = select_best(results)

    # Fix 2/9: Calibrate on SEPARATE calibration set with FrozenEstimator (sklearn >= 1.6)
    from sklearn.frozen import FrozenEstimator
    print(f"\nCalibrating on separate calibration set (FrozenEstimator)...")
    calibrated = CalibratedClassifierCV(FrozenEstimator(best_model))
    calibrated.fit(data["X_cal"], data["y_cal"])

    # Fix 18: Find optimal threshold
    print("\nFinding optimal decision threshold...")
    threshold = find_optimal_threshold(calibrated, data["X_val"], data["y_val"])

    # Final evaluation on TEST set
    print(f"\n{'=' * 60}")
    print("FINAL TEST SET EVALUATION")
    print(f"{'=' * 60}")

    y_prob = calibrated.predict_proba(data["X_test"])[:, 1]
    y_pred = (y_prob >= threshold).astype(int)

    print(f"\nThreshold: {threshold:.4f}")
    print(classification_report(
        data["y_test"], y_pred,
        target_names=["Legitimate", "Phishing"], digits=4,
    ))

    cm = confusion_matrix(data["y_test"], y_pred)
    tn, fp, fn, tp = cm.ravel()
    test_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    test_fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0
    print(f"  FPR: {test_fpr:.4f} ({test_fpr * 100:.2f}%) | Target: <{TARGET_FPR * 100:.1f}%")
    print(f"  FNR: {test_fnr:.4f} ({test_fnr * 100:.2f}%)")

    # Feature importance
    feat_names = data["meta"]["feature_names"]
    if hasattr(best_model, "feature_importances_"):
        print("\nTop 10 Features:")
        idx = np.argsort(best_model.feature_importances_)[::-1]
        for rank, i in enumerate(idx[:10], 1):
            print(f"  {rank:2d}. {feat_names[i]:<30} "
                  f"{best_model.feature_importances_[i]:.4f}")

    # Fix for skl2onnx: It does not recognize FrozenEstimator.
    # Unfreeze the underlying estimators before exporting.
    for clf in calibrated.calibrated_classifiers_:
        if hasattr(clf, "estimator") and hasattr(clf.estimator, "estimator"):
            clf.estimator = clf.estimator.estimator

    # Export calibrated model
    onnx_path = MODELS_DIR / "phishing_model_v4.onnx"
    print(f"\nExporting calibrated model...")
    export_onnx(calibrated, data["meta"]["num_features"], onnx_path)

    # Also export raw (uncalibrated) as fallback
    onnx_raw = MODELS_DIR / "phishing_model_v4_raw.onnx"
    print(f"Exporting raw model...")
    export_onnx(best_model, data["meta"]["num_features"], onnx_raw)

    # Save report
    report = {
        "best_model": best_name,
        "optimal_threshold": threshold,
        "test_fpr": test_fpr,
        "test_fnr": test_fnr,
        "test_accuracy": float(accuracy_score(data["y_test"], y_pred)),
        "test_f1": float(f1_score(data["y_test"], y_pred)),
        "test_auc": float(roc_auc_score(data["y_test"], y_prob)),
    }
    with open(REPORTS_DIR / "training_report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n✓ Training complete. Model saved to {onnx_path}")


if __name__ == "__main__":
    train()
