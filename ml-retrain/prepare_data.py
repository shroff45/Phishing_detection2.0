"""
PhishGuard ML v4.1 — Data Preparation
Merges real + synthetic datasets, extracts features, splits into 4 sets.

Fixes applied:
  - Fix 5:   Float labels (1.0 → 1) handled explicitly
  - Fix 6:   Unknown labels DROPPED, not silently converted to 0
  - Fix 9:   4-way split: train / val / calibration / test
  - Fix 11/D: Stratified balancing with remainder distribution
  - Fix G:   Sources converted to numpy before splitting
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from config import (
    DATA_DIR, SYNTH_DIR, PREPARED_DIR, RANDOM_STATE,
    TEST_SIZE, VAL_SIZE, CALIBRATION_SIZE,
    NUM_FEATURES, FEATURE_NAMES,
)
from feature_extractor import extract_batch


# Labels recognized across datasets
PHISHING_LABELS = {"1", "1.0", "phishing", "bad", "malicious", "yes", "suspicious"}
LEGITIMATE_LABELS = {"0", "0.0", "legitimate", "good", "benign", "safe", "no", "clean"}


def load_csv_safe(path: Path) -> pd.DataFrame:
    """
    Load CSV with robust label handling.
    Fix 5: float labels like 1.0 handled.
    Fix 6: unknown labels DROPPED, not silently mapped to 0.
    """
    if not path.exists():
        return pd.DataFrame()

    try:
        df = pd.read_csv(path, low_memory=False)

        url_col = label_col = None
        for col in df.columns:
            cl = col.lower().strip()
            if cl in ("url", "urls", "uri", "link", "web_url"):
                url_col = col
            if cl in ("label", "labels", "type", "class", "phishing", "status", "result"):
                label_col = col

        if not url_col:
            print(f"  ⚠ No URL column in {path.name}: {list(df.columns[:10])}")
            return pd.DataFrame()

        if not label_col:
            print(f"  ⚠ No label column in {path.name}")
            return pd.DataFrame()

        result = df[[url_col, label_col]].copy()
        result.columns = ["url", "raw_label"]

        def normalize_label(x):
            s = str(x).lower().strip()
            # Fix 5: handle float strings
            if s in ("1.0", "0.0"):
                s = s.split(".")[0]
            if s in PHISHING_LABELS:
                return 1
            if s in LEGITIMATE_LABELS:
                return 0
            return -1  # UNKNOWN

        result["label"] = result["raw_label"].apply(normalize_label)

        # Fix 6: drop rows with unknown labels
        unknown_count = int((result["label"] == -1).sum())
        if unknown_count > 0:
            unknown_vals = result[result["label"] == -1]["raw_label"].unique()[:5]
            print(f"    ⚠ Dropped {unknown_count} rows with unknown labels "
                  f"(values: {unknown_vals})")
            result = result[result["label"] != -1]

        return result[["url", "label"]]

    except Exception as e:
        print(f"  ✗ Error loading {path.name}: {e}")
        return pd.DataFrame()


def merge_datasets() -> pd.DataFrame:
    """
    Merge all datasets with conflict resolution.
    Fix 5: explicit priority order — later sources win on conflicts.
    """
    print("=" * 60)
    print("MERGING ALL DATASETS")
    print("=" * 60)

    frames = []
    load_order = []

    # 1. Synthetic data (lowest priority)
    synth_path = SYNTH_DIR / "synthetic_adversarial.csv"
    if synth_path.exists():
        load_order.append(("synthetic", synth_path))

    # 2. Real datasets (alphabetical for determinism)
    for csv_file in sorted(DATA_DIR.glob("*.csv")):
        load_order.append((csv_file.stem, csv_file))

    for source_name, path in load_order:
        print(f"  Loading: {path.name}")

        if source_name == "synthetic":
            df = pd.read_csv(path)
            if "attack_class" in df.columns:
                df["source"] = df["attack_class"]
            else:
                df["source"] = "synthetic"
        else:
            df = load_csv_safe(path)
            if len(df) == 0:
                continue
            df["source"] = source_name

        frames.append(df)
        phish = int((df["label"] == 1).sum())
        legit = int((df["label"] == 0).sum())
        print(f"    ✓ {len(df)} URLs (phishing: {phish}, legit: {legit})")

    if not frames:
        print("ERROR: No datasets loaded!")
        return pd.DataFrame()

    merged = pd.concat(frames, ignore_index=True)
    merged = merged.drop_duplicates(subset=["url"], keep="last")

    print(f"\n  Total after dedup: {len(merged)}")
    return merged


def balance_stratified(df: pd.DataFrame) -> pd.DataFrame:
    """
    Fix 11/D: Stratified balancing preserves attack class diversity.
    Proportional allocation with remainder distribution.
    """
    print("\nBALANCING (stratified by source)...")

    phishing = df[df["label"] == 1]
    legit = df[df["label"] == 0]
    target = min(len(phishing), len(legit))

    if "source" in df.columns and len(phishing) > target:
        source_counts = phishing["source"].value_counts()
        total_phishing = len(phishing)

        # Fix D: proportional allocation with remainder handling
        allocations = {}
        allocated = 0
        for source, count in source_counts.items():
            proportion = count / total_phishing
            n = int(target * proportion)
            allocations[source] = max(n, 1)
            allocated += allocations[source]

        remainder = target - allocated
        if remainder > 0:
            sorted_sources = source_counts.index.tolist()
            for i in range(remainder):
                src = sorted_sources[i % len(sorted_sources)]
                allocations[src] += 1

        sampled_parts = []
        for source, n_sample in allocations.items():
            source_data = phishing[phishing["source"] == source]
            n_actual = min(n_sample, len(source_data))
            sampled = source_data.sample(n=n_actual, random_state=RANDOM_STATE)
            sampled_parts.append(sampled)

        phishing = pd.concat(sampled_parts)
    elif len(phishing) > target:
        phishing = phishing.sample(n=target, random_state=RANDOM_STATE)

    if len(legit) > target:
        legit = legit.sample(n=target, random_state=RANDOM_STATE)

    balanced = pd.concat([phishing, legit]).sample(frac=1, random_state=RANDOM_STATE)

    actual_phish = int((balanced["label"] == 1).sum())
    actual_legit = int((balanced["label"] == 0).sum())
    print(f"  Phishing: {actual_phish} | Legitimate: {actual_legit}")
    print(f"  Balance ratio: {actual_phish / max(actual_legit, 1):.3f}")

    if "source" in balanced.columns:
        print(f"\n  Per-source distribution:")
        for src, grp in balanced.groupby("source"):
            print(f"    {src:<25} {len(grp):>6}")

    return balanced


def prepare():
    """Full preparation pipeline."""
    df = merge_datasets()
    if df.empty:
        print("ERROR: No data to prepare!")
        return

    # Clean
    df = df.dropna(subset=["url"])
    df = df[df["url"].str.len() >= 5]
    df["url"] = df["url"].apply(
        lambda u: u.strip() if isinstance(u, str) else str(u)
    )

    # Balance with stratification
    df = balance_stratified(df)

    # Extract features
    print(f"\nEXTRACTING {NUM_FEATURES} FEATURES from {len(df)} URLs...")
    urls = df["url"].tolist()
    labels = df["label"].values.astype(np.int32)

    # Fix G: convert sources to numpy array BEFORE splitting
    sources = np.array(
        df["source"].tolist() if "source" in df.columns else ["unknown"] * len(df),
        dtype=object,
    )

    X = extract_batch(urls, show_progress=True)
    y = labels
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # Fix 9: 4-way split — train / val / calibration / test
    X_rest, X_test, y_rest, y_test, src_rest, src_test = train_test_split(
        X, y, sources,
        test_size=TEST_SIZE, stratify=y, random_state=RANDOM_STATE,
    )

    cal_frac = CALIBRATION_SIZE / (1 - TEST_SIZE)
    X_rest2, X_cal, y_rest2, y_cal, src_rest2, src_cal = train_test_split(
        X_rest, y_rest, src_rest,
        test_size=cal_frac, stratify=y_rest, random_state=RANDOM_STATE,
    )

    val_frac = VAL_SIZE / (1 - TEST_SIZE - CALIBRATION_SIZE)
    X_train, X_val, y_train, y_val, src_train, src_val = train_test_split(
        X_rest2, y_rest2, src_rest2,
        test_size=val_frac, stratify=y_rest2, random_state=RANDOM_STATE,
    )

    print(f"\n  Train:       {X_train.shape[0]}")
    print(f"  Validation:  {X_val.shape[0]}")
    print(f"  Calibration: {X_cal.shape[0]}")
    print(f"  Test:        {X_test.shape[0]}")

    # Save
    for name, arr in [
        ("X_train", X_train), ("X_val", X_val), ("X_cal", X_cal), ("X_test", X_test),
        ("y_train", y_train), ("y_val", y_val), ("y_cal", y_cal), ("y_test", y_test),
    ]:
        np.save(PREPARED_DIR / f"{name}.npy", arr)

    np.save(PREPARED_DIR / "src_test.npy", src_test)

    meta = {
        "num_features": NUM_FEATURES,
        "feature_names": FEATURE_NAMES,
        "train_size": int(X_train.shape[0]),
        "val_size": int(X_val.shape[0]),
        "cal_size": int(X_cal.shape[0]),
        "test_size": int(X_test.shape[0]),
    }
    with open(PREPARED_DIR / "metadata.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\n✓ Saved to {PREPARED_DIR}/")


if __name__ == "__main__":
    prepare()
