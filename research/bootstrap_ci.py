#!/usr/bin/env python3
"""
SecuraX Research — Bootstrap Confidence Intervals (T8 Option A)
==============================================================
Calculates 95% bootstrap confidence intervals (1,000 resamples) for evaluation metrics
(Macro-F1, Precision, Recall) and paired differences (SecuraX vs Baselines)
using the pre-registered percentile method on individual observation vectors.

Pre-registration: docs/research/E2_HYPOTHESIS.md (Lines 107-113)

Usage:
    python research/bootstrap_ci.py --input results_with_ci/e1_risk_validation/
    python research/bootstrap_ci.py --input results_with_ci/e2_risk_validation/
    python research/bootstrap_ci.py --all results_with_ci/

Author:  Abdallah Benaicha <Abdallahbenaichatech@gmail.com>
Version: 1.0.0
"""

import argparse
import json
import os
import sys
from pathlib import Path
import numpy as np

# Fix Windows cp1252 encoding for Unicode output
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf-8-sig"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

RISK_LEVELS = ["minimal", "low", "medium", "high", "critical"]
N_BOOTSTRAP = 1000
DEFAULT_SEED = 42


def compute_macro_metrics(predictions: list[str], ground_truth: list[str]) -> dict:
    """Compute per-class and macro-averaged metrics on a single sample."""
    f1_list = []
    prec_list = []
    rec_list = []

    for cls in RISK_LEVELS:
        tp = sum(1 for p, g in zip(predictions, ground_truth) if p == cls and g == cls)
        fp = sum(1 for p, g in zip(predictions, ground_truth) if p == cls and g != cls)
        fn = sum(1 for p, g in zip(predictions, ground_truth) if p != cls and g == cls)

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

        prec_list.append(prec)
        rec_list.append(rec)
        f1_list.append(f1)

    return {
        "macro_precision": float(np.mean(prec_list)),
        "macro_recall": float(np.mean(rec_list)),
        "macro_f1": float(np.mean(f1_list)),
    }


def run_bootstrap(preds_log: dict, n_resamples: int = N_BOOTSTRAP, seed: int = DEFAULT_SEED) -> dict:
    """Run paired bootstrap resampling over observations."""
    ground_truth = np.array(preds_log["ground_truth"])
    n_samples = len(ground_truth)
    methods = preds_log["predictions"]
    method_names = list(methods.keys())

    rng = np.random.RandomState(seed)

    # Point estimates on full sample
    point_estimates = {}
    for name in method_names:
        preds = methods[name]
        point_estimates[name] = compute_macro_metrics(preds, ground_truth)

    # Bootstrap storage
    boot_metrics = {name: {"macro_f1": [], "macro_precision": [], "macro_recall": []} for name in method_names}
    boot_diffs = {name: [] for name in method_names if name != "SecuraX"}

    # Resampling loop
    for _ in range(n_resamples):
        idx = rng.choice(n_samples, size=n_samples, replace=True)
        gt_resampled = ground_truth[idx].tolist()

        resampled_f1s = {}
        for name in method_names:
            preds_resampled = np.array(methods[name])[idx].tolist()
            m = compute_macro_metrics(preds_resampled, gt_resampled)
            boot_metrics[name]["macro_f1"].append(m["macro_f1"])
            boot_metrics[name]["macro_precision"].append(m["macro_precision"])
            boot_metrics[name]["macro_recall"].append(m["macro_recall"])
            resampled_f1s[name] = m["macro_f1"]

        # Paired differences: SecuraX - Baseline
        if "SecuraX" in resampled_f1s:
            for name in boot_diffs:
                boot_diffs[name].append(resampled_f1s["SecuraX"] - resampled_f1s[name])

    # Summary statistics
    results = {
        "n_resamples": n_resamples,
        "sample_size": n_samples,
        "seed": seed,
        "methods": {},
        "paired_differences_vs_securax": {},
    }

    for name in method_names:
        results["methods"][name] = {
            "point_estimate": point_estimates[name],
            "macro_f1": {
                "mean": round(float(np.mean(boot_metrics[name]["macro_f1"])), 4),
                "std_err": round(float(np.std(boot_metrics[name]["macro_f1"])), 4),
                "ci_95": [
                    round(float(np.percentile(boot_metrics[name]["macro_f1"], 2.5)), 4),
                    round(float(np.percentile(boot_metrics[name]["macro_f1"], 97.5)), 4),
                ],
            },
            "macro_precision": {
                "mean": round(float(np.mean(boot_metrics[name]["macro_precision"])), 4),
                "std_err": round(float(np.std(boot_metrics[name]["macro_precision"])), 4),
                "ci_95": [
                    round(float(np.percentile(boot_metrics[name]["macro_precision"], 2.5)), 4),
                    round(float(np.percentile(boot_metrics[name]["macro_precision"], 97.5)), 4),
                ],
            },
            "macro_recall": {
                "mean": round(float(np.mean(boot_metrics[name]["macro_recall"])), 4),
                "std_err": round(float(np.std(boot_metrics[name]["macro_recall"])), 4),
                "ci_95": [
                    round(float(np.percentile(boot_metrics[name]["macro_recall"], 2.5)), 4),
                    round(float(np.percentile(boot_metrics[name]["macro_recall"], 97.5)), 4),
                ],
            },
        }

    for name, diff_samples in boot_diffs.items():
        diff_arr = np.array(diff_samples)
        ci_lower = round(float(np.percentile(diff_arr, 2.5)), 4)
        ci_upper = round(float(np.percentile(diff_arr, 97.5)), 4)
        pt_diff = round(point_estimates["SecuraX"]["macro_f1"] - point_estimates[name]["macro_f1"], 4)

        results["paired_differences_vs_securax"][name] = {
            "point_difference_f1": pt_diff,
            "mean_difference": round(float(np.mean(diff_arr)), 4),
            "std_err": round(float(np.std(diff_arr)), 4),
            "ci_95": [ci_lower, ci_upper],
            "significant_at_95": bool(ci_lower > 0 or ci_upper < 0),
        }

    return results


def process_directory(dir_path: Path, n_resamples: int = N_BOOTSTRAP, seed: int = DEFAULT_SEED) -> None:
    """Process a single experiment results directory."""
    log_file = dir_path / "predictions_log.json"
    if not log_file.exists():
        print(f"[ERROR] No predictions_log.json found in {dir_path}")
        print("        Run experiments with prediction logging first.")
        return

    print(f"\n[INFO] Running Bootstrap CI on {dir_path.name} (N_resamples={n_resamples}, seed={seed})...")
    preds_log = json.loads(log_file.read_text(encoding="utf-8"))

    ci_results = run_bootstrap(preds_log, n_resamples=n_resamples, seed=seed)

    out_file = dir_path / "bootstrap_ci.json"
    out_file.write_text(json.dumps(ci_results, indent=2), encoding="utf-8")
    print(f"[OUT] Written bootstrap results to {out_file}")

    # Print formatted table
    sep = "=" * 80
    print(f"\n{sep}")
    print(f"  Bootstrap 95% Confidence Intervals (1,000 resamples) — {dir_path.name}")
    print(f"{sep}")
    print(f"{'Method':<25} {'Macro-F1 (Point)':>16} {'95% CI':>20} {'Std Err':>12}")
    print("-" * 80)
    for name, data in ci_results["methods"].items():
        pt = data["point_estimate"]["macro_f1"]
        ci = f"[{data['macro_f1']['ci_95'][0]:.4f}, {data['macro_f1']['ci_95'][1]:.4f}]"
        se = data["macro_f1"]["std_err"]
        print(f"{name:<25} {pt:>16.4f} {ci:>20} {se:>12.4f}")

    print("-" * 80)
    print(f"  Paired Differences (SecuraX minus Baseline)")
    print("-" * 80)
    print(f"{'Comparison':<30} {'Point Diff':>12} {'95% CI':>20} {'Significant?':>14}")
    print("-" * 80)
    for name, diff in ci_results["paired_differences_vs_securax"].items():
        pt = diff["point_difference_f1"]
        ci = f"[{diff['ci_95'][0]:.4f}, {diff['ci_95'][1]:.4f}]"
        sig = "YES" if diff["significant_at_95"] else "NO (includes 0)"
        comp = f"SecuraX vs {name}"
        print(f"{comp:<30} {pt:>+12.4f} {ci:>20} {sig:>14}")
    print(f"{sep}\n")


def main():
    parser = argparse.ArgumentParser(description="Calculate Bootstrap Confidence Intervals")
    parser.add_argument("--input", "-i", help="Directory containing predictions_log.json")
    parser.add_argument("--all", "-a", help="Parent directory containing experiment subdirectories")
    parser.add_argument("--resamples", "-n", type=int, default=N_BOOTSTRAP, help="Number of resamples (default: 1000)")
    parser.add_argument("--seed", "-s", type=int, default=DEFAULT_SEED, help="Random seed (default: 42)")

    args = parser.parse_args()

    if args.input:
        process_directory(Path(args.input), n_resamples=args.resamples, seed=args.seed)
    elif args.all:
        parent = Path(args.all)
        for sub in sorted(parent.iterdir()):
            if sub.is_dir() and (sub / "predictions_log.json").exists():
                process_directory(sub, n_resamples=args.resamples, seed=args.seed)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
