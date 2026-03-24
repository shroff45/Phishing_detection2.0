"""
PhishGuard — User Report Integration

Fetches user reports (false positives and missed phishing) from
the backend database and incorporates them into the training dataset.

This script runs as part of the retraining pipeline.
In Phase 11 full implementation, the backend stores user reports
in PostgreSQL. For now, this reads from a local JSON file
that the backend writes to.

Usage:
    python integrate_user_reports.py
"""

import json
from pathlib import Path

import pandas as pd


REPORTS_FILE = Path("data/user_reports.json")
DATASET_FILE = Path("data/phishing_dataset.csv")


def load_reports():
    """Load user reports from the local JSON file."""
    if not REPORTS_FILE.exists():
        print("No user reports found. Skipping integration.")
        return []

    with open(REPORTS_FILE) as f:
        reports = json.load(f)

    print("Loaded {} user reports.".format(len(reports)))
    return reports


def integrate_reports():
    """
    Integrate verified user reports into the training dataset.

    False positives: URLs that were flagged as phishing but are
    actually legitimate → add with target=0
    
    Missed phishing: URLs that were NOT flagged but are actually
    phishing → add with target=1

    Only manually verified reports should be added.
    In production, this verification would be done by a human
    moderator or a high-confidence automated system.
    """
    reports = load_reports()
    if not reports:
        return

    if not DATASET_FILE.exists():
        print("Dataset file not found. Run build_dataset.py first.")
        return

    df = pd.read_csv(DATASET_FILE)
    initial_size = len(df)

    # Import the feature extractor
    from build_dataset import extract_features

    added = 0
    for report in reports:
        url = report.get("url", "")
        report_type = report.get("type", "")
        verified = report.get("verified", False)

        if not verified:
            continue

        if not url.startswith("http"):
            continue

        features = extract_features(url)
        if features is None:
            continue

        if report_type == "false_positive":
            features["target"] = 0
        elif report_type == "missed_phishing":
            features["target"] = 1
        else:
            continue

        features["url"] = url
        features["source"] = "user_report"

        df = pd.concat([df, pd.DataFrame([features])], ignore_index=True)
        added += 1

    if added > 0:
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        df.to_csv(DATASET_FILE, index=False)
        print("Added {} verified reports. Dataset: {} → {} samples.".format(
            added, initial_size, len(df)
        ))
    else:
        print("No verified reports to add.")


if __name__ == "__main__":
    integrate_reports()
