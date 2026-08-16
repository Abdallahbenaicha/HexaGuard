#!/usr/bin/env python3
"""
SecuraX Risk Engine — Ablation Study
======================================
Measures the contribution of each component of the multi-dimensional risk
engine by systematically disabling one component at a time and measuring
the drop in macro-F1 score.

Components tested:
  1. Full engine (all components enabled) ← reference
  2. Without Asset Criticality            ← asset_criticality forced to "medium"
  3. Without Exploitability adjustment    ← exploit_known always False, cve_ids always []
  4. Without Exposure factor              ← internet_facing always False
  5. Without Compliance penalties         ← has_pii=False, has_payment=False
  6. Without Threat Context               ← KEV disabled, exploit_known=False, no attack chain bonus

Output:
  results/ablation/
    ablation_results.json
    ablation_table.csv
    ablation_table.tex          ← Table 3 in paper
    plots/
      ablation_radar.png
      ablation_bar.png

Research significance:
    This study answers: "Which components of SecuraX actually matter?"
    A component that does not improve F1 when removed is a candidate for simplification.

References:
    [ABLATION] Meyes et al. "Ablation Studies in Artificial Neural Networks."
               arXiv:1901.08644, 2019.
    [CVSS31]   NIST NVD. CVSS v3.1 Specification. FIRST.Org, 2019.

Author:  Abdallah Benaicha <Abdallahbenaichatech@gmail.com>
Version: 1.0.0
"""

import copy
import json
import sys
import csv
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))
sys.path.insert(0, str(ROOT))

from risk_engine import calculate_risk_v2, VERSION as ENGINE_VERSION  # noqa: E402
from research.run_experiment import load_experiment_data, compute_metrics, RISK_LEVELS  # noqa: E402

ABLATION_COMPONENTS = [
    {
        "id":          "full_engine",
        "name":        "Full Engine (All Components)",
        "description": "Baseline: all components enabled (reference configuration)",
        "kwargs_mask": {},  # no masking
    },
    {
        "id":          "no_asset_criticality",
        "name":        "Without Asset Criticality",
        "description": "criticality forced to 0.75 (medium — neutral multiplier)",
        "kwargs_mask": {"criticality": 0.75},
    },
    {
        "id":          "no_exploitability",
        "name":        "Without Exploitability",
        "description": "exploit_known=False, cve_ids=[] for all findings",
        "kwargs_mask": {"exploit_known": False},
        "scan_input_mask": {"cve_ids": []},
    },
    {
        "id":          "no_exposure",
        "name":        "Without Exposure Factor",
        "description": "internet_facing=False for all (treats all as internal)",
        "kwargs_mask": {"internet_facing": False},
    },
    {
        "id":          "no_compliance",
        "name":        "Without Compliance Penalties",
        "description": "has_pii=False, has_payment=False (GDPR/PCI-DSS removed)",
        "kwargs_mask": {"has_pii": False, "has_payment": False},
    },
    {
        "id":          "no_threat_context",
        "name":        "Without Threat Context",
        "description": "exploit_known=False, cve_ids=[], internet_facing=False (minimal context)",
        "kwargs_mask": {"exploit_known": False, "internet_facing": False},
        "scan_input_mask": {"cve_ids": []},
    },
]


def apply_ablation_mask(entries: list[dict], component: dict) -> list[dict]:
    """
    Return a copy of entries with the ablation component's mask applied.
    """
    masked_entries = []
    kwargs_mask     = component.get("kwargs_mask", {})
    scan_input_mask = component.get("scan_input_mask", {})

    for entry in entries:
        new_entry = copy.deepcopy(entry)

        # Mask kwargs
        for k, v in kwargs_mask.items():
            new_entry["kwargs"][k] = v

        # Mask scan_input (per-vulnerability fields)
        if scan_input_mask:
            for vuln in new_entry["scan_input"].get("vulnerabilities", []):
                for k, v in scan_input_mask.items():
                    vuln[k] = v

        masked_entries.append(new_entry)

    return masked_entries


def run_ablation(experiment_id: str = "e1") -> dict:
    """Run the full ablation study."""
    print(f"\n{'='*60}")
    print(f"  SecuraX Ablation Study")
    print(f"  Engine v{ENGINE_VERSION}")
    print(f"  Experiment: {experiment_id}")
    print(f"{'='*60}\n")

    entries = load_experiment_data(experiment_id)
    ground_truth = [e["expected_risk_level"] for e in entries]

    ablation_results = {}

    for component in ABLATION_COMPONENTS:
        print(f"[ABLATION] {component['name']}...")

        masked = apply_ablation_mask(entries, component)
        predictions = [
            calculate_risk_v2(e["scan_input"], **e["kwargs"]).risk_level
            for e in masked
        ]
        metrics = compute_metrics(predictions, ground_truth)

        ablation_results[component["id"]] = {
            "name":        component["name"],
            "description": component["description"],
            "metrics":     metrics,
        }

    # Compute deltas relative to full engine
    full_macro_f1 = ablation_results["full_engine"]["metrics"]["macro"]["f1"]
    for comp_id, data in ablation_results.items():
        comp_macro_f1 = data["metrics"]["macro"]["f1"]
        data["delta_macro_f1"] = round(comp_macro_f1 - full_macro_f1, 4)
        data["contribution"] = round(full_macro_f1 - comp_macro_f1, 4)  # how much removing hurts

    # Print summary
    sep = "-" * 65
    print(f"\n{sep}")
    print(f"  Ablation Study Results")
    print(f"{sep}")
    print(f"{'Configuration':<35} {'Macro-F1':>10} {'Delta':>10}")
    print(f"{sep}")
    for comp_id, data in ablation_results.items():
        delta_str = f"{data['delta_macro_f1']:+.4f}" if comp_id != "full_engine" else "    ref"
        print(f"{data['name']:<35} {data['metrics']['macro']['f1']:>10.4f} {delta_str:>10}")
    print(f"{sep}\n")

    return ablation_results


def write_ablation_outputs(ablation_results: dict, output_dir: Path) -> None:
    """Write CSV, JSON, LaTeX, and plots."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── JSON ──────────────────────────────────────────────────────────────────
    json_path = output_dir / "ablation_results.json"
    json_path.write_text(json.dumps({
        "engine_version": ENGINE_VERSION,
        "timestamp_utc":  datetime.now(timezone.utc).isoformat(),
        "components":     ablation_results,
    }, indent=2), encoding="utf-8")
    print(f"[OUT] {json_path}")

    # ── CSV ───────────────────────────────────────────────────────────────────
    csv_path = output_dir / "ablation_table.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["component", "name", "macro_f1", "delta", "contribution"])
        for comp_id, data in ablation_results.items():
            writer.writerow([
                comp_id,
                data["name"],
                data["metrics"]["macro"]["f1"],
                data.get("delta_macro_f1", 0),
                data.get("contribution", 0),
            ])
    print(f"[OUT] {csv_path}")

    # ── LaTeX ─────────────────────────────────────────────────────────────────
    tex_path = output_dir / "ablation_table.tex"
    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        r"\caption{Ablation Study: Contribution of Each Risk Engine Component}",
        r"\label{tab:ablation}",
        r"\begin{tabular}{lcc}",
        r"\hline",
        r"\textbf{Configuration} & \textbf{Macro-F1} & \textbf{$\Delta$ F1} \\",
        r"\hline",
    ]
    for comp_id, data in ablation_results.items():
        delta_str = f"{data.get('delta_macro_f1', 0):+.4f}" if comp_id != "full_engine" else "---"
        name = data["name"].replace("&", r"\&")
        lines.append(
            f"{name} & {data['metrics']['macro']['f1']:.4f} & {delta_str} \\\\"
        )
    lines += [
        r"\hline",
        r"\multicolumn{3}{l}{\small $\Delta$ = difference from full engine (negative = component helps)} \\",
        r"\end{tabular}",
        r"\end{table}",
    ]
    tex_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[OUT] {tex_path}")

    # ── Plots ─────────────────────────────────────────────────────────────────
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np

        plots_dir = output_dir / "plots"
        plots_dir.mkdir(parents=True, exist_ok=True)

        comp_names  = [d["name"].replace("Without ", "W/o ") for d in ablation_results.values()]
        macro_f1s   = [d["metrics"]["macro"]["f1"] for d in ablation_results.values()]
        colors = ["#2ecc71" if i == 0 else "#e74c3c" if d.get("delta_macro_f1", 0) < -0.01 else "#e67e22"
                  for i, d in enumerate(ablation_results.values())]

        fig, ax = plt.subplots(figsize=(10, 5))
        bars = ax.barh(comp_names[::-1], macro_f1s[::-1], color=colors[::-1], alpha=0.85)
        ax.set_xlim(0.0, 1.0)
        ax.set_xlabel("Macro-averaged F1 Score")
        ax.set_title("Ablation Study — SecuraX Risk Engine\n(E1 Benchmark v1.0.0)")
        ax.axvline(x=macro_f1s[0], color="green", linestyle="--", alpha=0.7, label="Full Engine")
        for bar, val in zip(bars, macro_f1s[::-1]):
            ax.text(val + 0.005, bar.get_y() + bar.get_height() / 2,
                    f"{val:.4f}", va="center", fontsize=9)
        ax.grid(axis="x", alpha=0.3)
        ax.legend()
        fig.tight_layout()
        fig.savefig(plots_dir / "ablation_bar.png", dpi=150, bbox_inches="tight")
        plt.close(fig)
        print(f"[OUT] {plots_dir / 'ablation_bar.png'}")

    except ImportError:
        print("[WARN] matplotlib not installed. Skipping ablation plots.")


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="SecuraX Ablation Study — measures contribution of each risk engine component"
    )
    parser.add_argument("--experiment", "-e", default="e1", help="Experiment dataset (default: e1)")
    parser.add_argument("--output", "-o", default="results/ablation", help="Output directory")
    args = parser.parse_args()

    ablation_results = run_ablation(args.experiment)
    output_dir = ROOT / args.output
    write_ablation_outputs(ablation_results, output_dir)
    print(f"\n[DONE] Ablation study complete. Results in: {output_dir}")


if __name__ == "__main__":
    main()
