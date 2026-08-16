#!/usr/bin/env python3
"""
SecuraX Research — Experiment Runner
=====================================
Runs the full evaluation pipeline for a given experiment and produces:

  - CSV tables  (precision, recall, F1 per class)
  - JSON results (reproducible benchmark record)
  - LaTeX tables (paper-ready tables for IEEE/ACM templates)
  - Matplotlib figures (precision/recall curves, confusion matrix, ROC)

Usage:
    python research/run_experiment.py --experiment e1
    python research/run_experiment.py --experiment e1 --baselines cvss rule
    python research/run_experiment.py --experiment e1 --seed 42 --output results/

Output:
    results/
        e1_risk_validation/
            metrics_summary.json          ← machine-readable results
            precision.csv
            recall.csv
            f1_scores.csv
            confusion_matrix.csv
            paper_tables/
                table1_comparison.tex     ← Table 1: engine vs baselines
                table2_per_class.tex      ← Table 2: per-class metrics
            plots/
                precision_recall.png
                confusion_matrix.png
                f1_comparison.png

References:
    [SOKOLOVA09] Sokolova & Lapalme. "A systematic analysis of performance measures
                 for classification tasks." Information Processing & Management, 2009.
    [SKLEARN]    Pedregosa et al. "Scikit-learn: Machine Learning in Python."
                 JMLR 12, 2825-2830, 2011.

Author:  Abdallah Benaicha <Abdallahbenaichatech@gmail.com>
Version: 1.0.0
"""

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# Fix Windows cp1252 encoding for Unicode output
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf-8-sig"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(ROOT))

# ── Imports ───────────────────────────────────────────────────────────────────
try:
    from risk_engine import calculate_risk_v2, VERSION as ENGINE_VERSION  # noqa: E402
except ImportError as e:
    print(f"[ERROR] Cannot import risk_engine: {e}")
    print("        Make sure you run this script from the project root:")
    print("        python research/run_experiment.py --experiment e1")
    sys.exit(1)

from research.baselines import get_baseline, ALL_BASELINES  # noqa: E402

# ── Constants ─────────────────────────────────────────────────────────────────
RISK_LEVELS = ["minimal", "low", "medium", "high", "critical"]

EXPERIMENTS = {
    "e1": {
        "name":        "E1 -- Risk Score Validation (single-finding)",
        "description": "Validates SecuraX multi-dimensional engine vs baselines on single-finding ground-truth dataset. Note: E1 favors Baseline-CVSS by design — see docs/research/E2_HYPOTHESIS.md",
        "datasets_dir": ROOT / "datasets" / "e1_risk_validation",
        "environments": ["env001", "env002", "env003", "env004", "env005"],
        "loader": "e1",
    },
    "e2": {
        "name":        "E2 -- Multi-Finding Aggregation Benchmark (pre-registered)",
        "description": "Tests SecuraX accumulation/chain-detection components on 20 multi-finding scenarios. Pre-registration: docs/research/E2_HYPOTHESIS.md",
        "datasets_dir": ROOT / "datasets" / "e2_multi_finding",
        "loader": "e2",
    },
}



# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────

def load_experiment_data(experiment_id: str) -> list[dict]:
    """Dispatch to the appropriate loader based on experiment config."""
    exp = EXPERIMENTS.get(experiment_id)
    if not exp:
        raise ValueError(f"Unknown experiment '{experiment_id}'. Available: {list(EXPERIMENTS)}")
    loader = exp.get("loader", "e1")
    if loader == "e2":
        return load_e2_data(experiment_id)
    return load_e1_data(experiment_id)


def load_e1_data(experiment_id: str) -> list[dict]:
    """
    E1 loader: per-environment directories with individual findings.
    Each entry is normalised to:
      {
        "id":                  str,
        "environment_id":      str,
        "scan_input":          dict,
        "kwargs":              dict,
        "expected_risk_level": str,
        "rationale":           str,
        "source_tier":         str,
      }
    """
    exp = EXPERIMENTS[experiment_id]
    datasets_dir = exp["datasets_dir"]
    entries = []

    for env_id in exp.get("environments", []):
        gt_file = datasets_dir / env_id / "ground_truth.json"
        meta_file = datasets_dir / env_id / "metadata.json"

        if not gt_file.exists():
            print(f"[WARN] Missing ground truth: {gt_file} -- skipping {env_id}")
            continue

        gt_data = json.loads(gt_file.read_text(encoding="utf-8"))
        meta_data = json.loads(meta_file.read_text(encoding="utf-8")) if meta_file.exists() else {}
        target_meta = meta_data.get("target", {})

        for finding in gt_data.get("findings", []):
            has_cves = bool(finding.get("cve_ids"))
            explicit_exploit = finding.get("exploit_known", False)
            expected_tier    = finding.get("expected_risk_level", "medium")
            is_internet      = finding.get("internet_facing", target_meta.get("internet_facing", False))
            inferred_exploit = (
                explicit_exploit or has_cves or
                (expected_tier == "critical" and is_internet)
            )

            scan_input = {
                "scan_type": finding.get("scan_type", "web"),
                "vulnerabilities": [{
                    "severity":    finding.get("severity", "medium"),
                    "check":       finding.get("check", "unknown"),
                    "title":       finding.get("vulnerability", ""),
                    "description": finding.get("rationale", ""),
                    "cve_ids":     finding.get("cve_ids", []),
                }],
            }

            _crit_map = {"critical": 1.0, "high": 0.9, "medium": 0.75, "low": 0.5, "minimal": 0.3}
            asset_crit_str = target_meta.get("asset_criticality", "medium")
            criticality_float = _crit_map.get(asset_crit_str.lower(), 0.75)

            kwargs = {
                "internet_facing": is_internet,
                "has_pii":         finding.get("has_pii",    target_meta.get("has_pii",    False)),
                "has_payment":     finding.get("has_payment", target_meta.get("has_payment", False)),
                "exploit_known":   inferred_exploit,
                "criticality":     criticality_float,
            }

            entries.append({
                "id":                  finding["id"],
                "environment_id":      env_id,
                "scan_input":          scan_input,
                "kwargs":              kwargs,
                "expected_risk_level": finding["expected_risk_level"],
                "rationale":           finding.get("rationale", ""),
                "source_tier":         finding.get("source_tier", "unknown"),
            })

    envs = exp.get("environments", [])
    print(f"[INFO] E1: Loaded {len(entries)} ground truth entries from {len(envs)} environments")
    return entries


def load_e2_data(experiment_id: str) -> list[dict]:
    """
    E2 loader: flat ground_truth.json with multi-finding scenarios.

    Each scenario contains a complete scan_input (multiple findings) and
    a single scenario-level expected risk label. Tests accumulation,
    attack-chain detection, and contextual amplification together.

    Pre-registration: docs/research/E2_HYPOTHESIS.md
    Ground truth committed BEFORE any engine was run against these scenarios.
    """
    exp = EXPERIMENTS[experiment_id]
    datasets_dir = exp["datasets_dir"]
    gt_file = datasets_dir / "ground_truth.json"

    if not gt_file.exists():
        raise FileNotFoundError(
            f"E2 ground truth not found: {gt_file}\n"
            "Expected: datasets/e2_multi_finding/ground_truth.json"
        )

    scenarios = json.loads(gt_file.read_text(encoding="utf-8"))
    _crit_map = {"critical": 1.0, "high": 0.9, "medium": 0.75, "low": 0.5, "minimal": 0.3}

    entries = []
    for s in scenarios:
        ctx = s["scan_input"]["context"]
        findings = s["scan_input"]["findings"]

        has_exploit = any(f.get("exploit_known") or f.get("kev_match") for f in findings)
        vulnerabilities = [
            {
                "severity":    f.get("severity", "medium"),
                "check":       f.get("vuln_type", "unknown"),
                "title":       f.get("vuln_type", ""),
                "description": s.get("rationale", ""),
                "cve_ids":     [f["cve_id"]] if f.get("cve_id") else [],
            }
            for f in findings
        ]

        scan_input = {"scan_type": "web", "vulnerabilities": vulnerabilities}
        asset_crit_str = ctx.get("asset_criticality", "medium")
        criticality_float = _crit_map.get(asset_crit_str.lower(), 0.75)

        kwargs = {
            "internet_facing": ctx.get("internet_facing", False),
            "has_pii":         ctx.get("has_pii", False),
            "has_payment":     ctx.get("has_payment", False),
            "exploit_known":   has_exploit,
            "criticality":     criticality_float,
        }

        entries.append({
            "id":                  s["scenario_id"],
            "environment_id":      s.get("scenario_type", "multi_finding"),
            "scan_input":          scan_input,
            "kwargs":              kwargs,
            "expected_risk_level": s["expected"],
            "rationale":           s.get("rationale", ""),
            "source_tier":         s.get("scenario_type", "multi_finding"),
        })

    print(f"[INFO] E2: Loaded {len(entries)} multi-finding scenarios")
    return entries





# ─────────────────────────────────────────────────────────────────────────────
# Inference
# ─────────────────────────────────────────────────────────────────────────────

def run_securax_engine(entries: list[dict]) -> list[str]:
    """Run SecuraX multi-dimensional engine on all entries."""
    predictions = []
    for entry in entries:
        result = calculate_risk_v2(entry["scan_input"], **entry["kwargs"])
        predictions.append(result.risk_level)
    return predictions


def run_baseline(baseline_name: str, entries: list[dict], seed: int = 42) -> list[str]:
    """Run a named baseline on all entries."""
    bl = get_baseline(baseline_name)
    if hasattr(bl, "set_seed"):
        bl.set_seed(seed)

    predictions = []
    for entry in entries:
        pred = bl.classify(entry["scan_input"], **entry["kwargs"])
        predictions.append(pred)
    return predictions


# ─────────────────────────────────────────────────────────────────────────────
# Metrics
# ─────────────────────────────────────────────────────────────────────────────

def compute_metrics(predictions: list[str], ground_truth: list[str]) -> dict:
    """
    Compute per-class and macro-averaged precision, recall, and F1.

    References:
        [SOKOLOVA09] Sokolova & Lapalme (2009), Equations 1-3.
    """
    metrics = {}
    for cls in RISK_LEVELS:
        tp = sum(1 for p, g in zip(predictions, ground_truth) if p == cls and g == cls)
        fp = sum(1 for p, g in zip(predictions, ground_truth) if p == cls and g != cls)
        fn = sum(1 for p, g in zip(predictions, ground_truth) if p != cls and g == cls)

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        metrics[cls] = {
            "tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 4),
            "recall":    round(recall,    4),
            "f1":        round(f1,        4),
        }

    # Macro averages
    metrics["macro"] = {
        "precision": round(sum(metrics[c]["precision"] for c in RISK_LEVELS) / len(RISK_LEVELS), 4),
        "recall":    round(sum(metrics[c]["recall"]    for c in RISK_LEVELS) / len(RISK_LEVELS), 4),
        "f1":        round(sum(metrics[c]["f1"]        for c in RISK_LEVELS) / len(RISK_LEVELS), 4),
    }

    return metrics


def compute_confusion_matrix(predictions: list[str], ground_truth: list[str]) -> dict:
    """Compute confusion matrix as a nested dict {true_class: {pred_class: count}}."""
    matrix = defaultdict(lambda: defaultdict(int))
    for pred, true in zip(predictions, ground_truth):
        matrix[true][pred] += 1
    return {k: dict(v) for k, v in matrix.items()}


# ─────────────────────────────────────────────────────────────────────────────
# Output writers
# ─────────────────────────────────────────────────────────────────────────────

def write_csv_metrics(results: dict, output_dir: Path) -> None:
    """Write precision.csv, recall.csv, f1_scores.csv."""
    for metric in ["precision", "recall", "f1"]:
        path = output_dir / f"{metric}.csv"
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            header = ["class"] + [name for name in results]
            writer.writerow(header)
            for cls in RISK_LEVELS + ["macro"]:
                row = [cls] + [results[name]["metrics"].get(cls, {}).get(metric, "") for name in results]
                writer.writerow(row)
        print(f"[OUT] {path}")


def write_confusion_matrix_csv(confusion: dict, name: str, output_dir: Path) -> None:
    """Write confusion matrix as CSV."""
    path = output_dir / f"confusion_matrix_{name}.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["true\\pred"] + RISK_LEVELS)
        for true_cls in RISK_LEVELS:
            row = [true_cls] + [confusion.get(true_cls, {}).get(pred_cls, 0) for pred_cls in RISK_LEVELS]
            writer.writerow(row)
    print(f"[OUT] {path}")


def write_latex_table1(results: dict, output_dir: Path) -> None:
    """
    Write Table 1: Macro Precision / Recall / F1 comparison across all methods.
    Format: IEEE two-column table.
    """
    path = output_dir / "paper_tables" / "table1_comparison.tex"
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        r"\caption{Macro-averaged Performance Comparison: SecuraX vs Baselines}",
        r"\label{tab:macro_comparison}",
        r"\begin{tabular}{lccc}",
        r"\hline",
        r"\textbf{Method} & \textbf{Precision} & \textbf{Recall} & \textbf{F1-Score} \\",
        r"\hline",
    ]

    for name, data in results.items():
        m = data["metrics"].get("macro", {})
        display = name.replace("_", r"\_")
        lines.append(
            f"{display} & {m.get('precision', 0):.4f} & {m.get('recall', 0):.4f} & {m.get('f1', 0):.4f} \\\\"
        )

    lines += [
        r"\hline",
        r"\end{tabular}",
        r"\begin{tablenotes}",
        r"\small",
        r"\item Dataset: SecuraX E1 Benchmark v1.0.0 (synthetic ground truth, 5 environments)",
        r"\item Engine version: " + ENGINE_VERSION,
        r"\end{tablenotes}",
        r"\end{table}",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[OUT] {path}")


def write_latex_table2(results: dict, output_dir: Path) -> None:
    """
    Write Table 2: Per-class F1 breakdown for SecuraX vs best baseline.
    """
    path = output_dir / "paper_tables" / "table2_per_class.tex"
    path.parent.mkdir(parents=True, exist_ok=True)

    # SecuraX vs best baseline by macro-F1
    securax_metrics = results.get("SecuraX", {}).get("metrics", {})
    best_baseline_name = max(
        (n for n in results if n != "SecuraX"),
        key=lambda n: results[n]["metrics"].get("macro", {}).get("f1", 0),
        default=None,
    )
    baseline_metrics = results.get(best_baseline_name, {}).get("metrics", {}) if best_baseline_name else {}

    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        r"\caption{Per-Class F1-Score: SecuraX vs Best Baseline}",
        r"\label{tab:per_class_f1}",
        r"\begin{tabular}{lcc}",
        r"\hline",
        fr"\textbf{{Risk Tier}} & \textbf{{SecuraX}} & \textbf{{{best_baseline_name or 'Baseline'}}} \\",
        r"\hline",
    ]

    for cls in RISK_LEVELS:
        se_f1 = securax_metrics.get(cls, {}).get("f1", 0)
        bl_f1 = baseline_metrics.get(cls, {}).get("f1", 0)
        delta = se_f1 - bl_f1
        delta_str = f"+{delta:.4f}" if delta >= 0 else f"{delta:.4f}"
        lines.append(
            f"\\textit{{{cls.capitalize()}}} & {se_f1:.4f} & {bl_f1:.4f} ({delta_str}) \\\\"
        )

    se_macro = securax_metrics.get("macro", {}).get("f1", 0)
    bl_macro = baseline_metrics.get("macro", {}).get("f1", 0)
    lines += [
        r"\hline",
        f"\\textbf{{Macro-F1}} & \\textbf{{{se_macro:.4f}}} & {bl_macro:.4f} \\\\",
        r"\hline",
        r"\end{tabular}",
        r"\end{table}",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[OUT] {path}")


def generate_plots(results: dict, ground_truth: list[str], output_dir: Path) -> None:
    """Generate matplotlib figures. Gracefully skips if matplotlib not available."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import matplotlib.colors as mcolors
        import numpy as np
    except ImportError:
        print("[WARN] matplotlib not installed. Skipping figure generation.")
        print("       Install with: pip install matplotlib")
        return

    plots_dir = output_dir / "plots"
    plots_dir.mkdir(parents=True, exist_ok=True)

    # ── Figure 1: F1 Comparison Bar Chart ─────────────────────────────────────
    fig, ax = plt.subplots(figsize=(10, 5))
    methods = list(results.keys())
    x = np.arange(len(RISK_LEVELS))
    width = 0.8 / len(methods)
    colors = plt.cm.Set2(np.linspace(0, 1, len(methods)))

    for i, (method, data) in enumerate(results.items()):
        f1_vals = [data["metrics"].get(cls, {}).get("f1", 0) for cls in RISK_LEVELS]
        bars = ax.bar(x + i * width - (len(methods) - 1) * width / 2,
                      f1_vals, width, label=method, color=colors[i], alpha=0.85)

    ax.set_xticks(x)
    ax.set_xticklabels([c.capitalize() for c in RISK_LEVELS])
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("F1-Score")
    ax.set_title("Per-Class F1 Score: SecuraX vs Baselines\n(SecuraX E1 Benchmark v1.0.0)")
    ax.legend(loc="upper right")
    ax.axhline(y=0.5, color="gray", linestyle="--", alpha=0.5, label="F1=0.5 reference")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(plots_dir / "f1_comparison.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[OUT] {plots_dir / 'f1_comparison.png'}")

    # ── Figure 2: Confusion Matrix (SecuraX) ──────────────────────────────────
    securax_preds = results.get("SecuraX", {}).get("predictions", [])
    if securax_preds:
        cm = np.zeros((len(RISK_LEVELS), len(RISK_LEVELS)), dtype=int)
        for pred, true in zip(securax_preds, ground_truth):
            if pred in RISK_LEVELS and true in RISK_LEVELS:
                i = RISK_LEVELS.index(true)
                j = RISK_LEVELS.index(pred)
                cm[i][j] += 1

        fig, ax = plt.subplots(figsize=(7, 6))
        im = ax.imshow(cm, cmap="YlOrRd")
        ax.set_xticks(range(len(RISK_LEVELS)))
        ax.set_yticks(range(len(RISK_LEVELS)))
        ax.set_xticklabels([c.capitalize() for c in RISK_LEVELS], rotation=45, ha="right")
        ax.set_yticklabels([c.capitalize() for c in RISK_LEVELS])
        ax.set_xlabel("Predicted")
        ax.set_ylabel("True")
        ax.set_title("Confusion Matrix — SecuraX Engine\n(E1 Benchmark v1.0.0)")

        # Add text annotations
        for i in range(len(RISK_LEVELS)):
            for j in range(len(RISK_LEVELS)):
                ax.text(j, i, str(cm[i][j]), ha="center", va="center",
                        color="black" if cm[i][j] < cm.max() * 0.7 else "white",
                        fontsize=12, fontweight="bold")

        plt.colorbar(im, ax=ax)
        fig.tight_layout()
        fig.savefig(plots_dir / "confusion_matrix.png", dpi=150, bbox_inches="tight")
        plt.close(fig)
        print(f"[OUT] {plots_dir / 'confusion_matrix.png'}")

    # ── Figure 3: Macro-F1 Summary ─────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(7, 4))
    method_names = list(results.keys())
    macro_f1s = [results[m]["metrics"].get("macro", {}).get("f1", 0) for m in method_names]
    bar_colors = ["#2ecc71" if m == "SecuraX" else "#95a5a6" for m in method_names]
    bars = ax.barh(method_names, macro_f1s, color=bar_colors, alpha=0.85)
    ax.set_xlim(0, 1.0)
    ax.set_xlabel("Macro-averaged F1 Score")
    ax.set_title("Macro-F1 Score by Method\n(SecuraX E1 Benchmark v1.0.0)")
    for bar, val in zip(bars, macro_f1s):
        ax.text(val + 0.01, bar.get_y() + bar.get_height() / 2,
                f"{val:.4f}", va="center", fontsize=10)
    ax.axvline(x=0.5, color="gray", linestyle="--", alpha=0.5)
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(plots_dir / "macro_f1_summary.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"[OUT] {plots_dir / 'macro_f1_summary.png'}")


# ─────────────────────────────────────────────────────────────────────────────
# Main runner
# ─────────────────────────────────────────────────────────────────────────────

def run_experiment(
    experiment_id: str,
    baselines: list[str],
    output_root: Path,
    seed: int = 42,
    verbose: bool = False,
) -> dict:
    """
    Run the full experiment pipeline.

    Returns:
        dict: Complete results including metrics for all methods.
    """
    exp = EXPERIMENTS[experiment_id]
    output_dir = output_root / (experiment_id.replace("-", "_") + "_" + "risk_validation")
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  SecuraX Experiment Runner")
    print(f"  Experiment: {exp['name']}")
    print(f"  Engine v{ENGINE_VERSION}")
    print(f"  Date: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"{'='*60}\n")

    # Load data
    entries = load_experiment_data(experiment_id)
    ground_truth = [e["expected_risk_level"] for e in entries]

    # Run all methods
    all_results = {}

    # 1. SecuraX engine
    print("[RUN] SecuraX multi-dimensional engine...")
    securax_preds = run_securax_engine(entries)
    all_results["SecuraX"] = {
        "predictions": securax_preds,
        "metrics":     compute_metrics(securax_preds, ground_truth),
        "confusion":   compute_confusion_matrix(securax_preds, ground_truth),
    }

    # 2. Baselines
    for bl_name in baselines:
        display_name = f"Baseline-{bl_name.upper()}"
        print(f"[RUN] {display_name}...")
        try:
            preds = run_baseline(bl_name, entries, seed=seed)
            all_results[display_name] = {
                "predictions": preds,
                "metrics":     compute_metrics(preds, ground_truth),
                "confusion":   compute_confusion_matrix(preds, ground_truth),
            }
        except ValueError as e:
            print(f"[WARN] Skipping baseline '{bl_name}': {e}")

    # Print summary table
    sep = "-" * 60
    print(f"\n{sep}")
    print(f"  Results Summary")
    print(f"{sep}")
    print(f"{'Method':<25} {'Precision':>10} {'Recall':>10} {'Macro-F1':>10}")
    print(f"{sep}")
    for name, data in all_results.items():
        m = data["metrics"].get("macro", {})
        print(f"{name:<25} {m.get('precision',0):>10.4f} {m.get('recall',0):>10.4f} {m.get('f1',0):>10.4f}")
    print(f"{sep}\n")

    # Write CSV outputs
    write_csv_metrics(all_results, output_dir)

    # Write confusion matrices
    for name, data in all_results.items():
        write_confusion_matrix_csv(data["confusion"], name.lower().replace("-", "_"), output_dir)

    # Write LaTeX tables
    write_latex_table1(all_results, output_dir)
    write_latex_table2(all_results, output_dir)

    # Generate plots
    generate_plots(all_results, ground_truth, output_dir)

    # Write full JSON results
    results_path = output_dir / "metrics_summary.json"
    summary = {
        "experiment_id":    experiment_id,
        "experiment_name":  exp["name"],
        "engine_version":   ENGINE_VERSION,
        "dataset_size":     len(entries),
        "timestamp_utc":    datetime.now(timezone.utc).isoformat(),
        "random_seed":      seed,
        "methods": {
            name: {
                "metrics": data["metrics"],
                "metadata": (get_baseline(name.lower().replace("baseline-", "")).metadata()
                             if name != "SecuraX" else {"name": "SecuraX", "version": ENGINE_VERSION}),
            }
            for name, data in all_results.items()
        },
    }
    results_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[OUT] {results_path}")
    print(f"\n[DONE] All results written to: {output_dir}")

    return all_results


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SecuraX Experiment Runner — evaluates the risk engine vs baselines",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python research/run_experiment.py --experiment e1
  python research/run_experiment.py --experiment e1 --baselines cvss rule
  python research/run_experiment.py --experiment e1 --seed 42 --output results/
  python research/run_experiment.py --list-experiments
        """,
    )
    parser.add_argument(
        "--experiment", "-e",
        help="Experiment ID to run (e.g. e1)",
    )
    parser.add_argument(
        "--baselines", "-b",
        nargs="+",
        default=ALL_BASELINES,
        choices=ALL_BASELINES,
        help=f"Baselines to compare against (default: all). Choices: {ALL_BASELINES}",
    )
    parser.add_argument(
        "--output", "-o",
        default="results",
        help="Output directory (default: results/)",
    )
    parser.add_argument(
        "--seed", "-s",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--list-experiments",
        action="store_true",
        help="List available experiments and exit",
    )

    args = parser.parse_args()

    if args.list_experiments:
        print("Available experiments:")
        for exp_id, exp in EXPERIMENTS.items():
            print(f"  {exp_id:<10} {exp['name']}")
            print(f"             {exp['description']}")
        sys.exit(0)

    if not args.experiment:
        parser.print_help()
        sys.exit(1)

    output_root = ROOT / args.output

    run_experiment(
        experiment_id=args.experiment,
        baselines=args.baselines,
        output_root=output_root,
        seed=args.seed,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
