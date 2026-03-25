"""
PhishGuard ML v4.1 — Pipeline Runner
One-click sequential execution of the entire ML pipeline.
"""

import sys
import time
from pathlib import Path

# Ensure ml-retrain is on sys.path
sys.path.insert(0, str(Path(__file__).parent))


def run():
    """Execute all pipeline stages in order."""
    print("╔" + "═" * 58 + "╗")
    print("║  PHISHGUARD ML v4.1 — FULL PIPELINE                      ║")
    print("╚" + "═" * 58 + "╝")
    start = time.time()

    stages = [
        ("1/6", "SYNTHETIC DATA GENERATION", "synth_generator", "generate_all"),
        ("2/6", "DATASET DOWNLOAD", "download_datasets", "download"),
        ("3/6", "DATA PREPARATION", "prepare_data", "prepare"),
        ("4/6", "MODEL TRAINING", "train_model", "train"),
        ("5/6", "EVALUATION", "evaluate", "evaluate"),
        ("6/6", "DEPLOYMENT", "deploy", "deploy"),
    ]

    for step, title, module_name, func_name in stages:
        print(f"\n\n{'━' * 60}")
        print(f"  [{step}] {title}")
        print(f"{'━' * 60}\n")

        stage_start = time.time()
        try:
            module = __import__(module_name)
            func = getattr(module, func_name)
            func()
            elapsed = time.time() - stage_start
            print(f"\n  ✓ {title} — {elapsed:.1f}s")
        except Exception as e:
            elapsed = time.time() - stage_start
            print(f"\n  ✗ {title} FAILED after {elapsed:.1f}s: {e}")
            import traceback
            traceback.print_exc()

            if step.startswith("3") or step.startswith("4"):
                print("\n  FATAL: Cannot continue without data/model.")
                sys.exit(1)

    total = time.time() - start
    print(f"\n\n{'╔' + '═' * 58 + '╗'}")
    print(f"║  PIPELINE COMPLETE — Total: {total:.0f}s                        ║")
    print(f"{'╚' + '═' * 58 + '╝'}")


if __name__ == "__main__":
    run()
