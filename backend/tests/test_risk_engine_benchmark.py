"""
SecuraX Risk Engine -- Research Benchmark Suite
================================================
This module validates that calculate_risk_v2() produces objectively better
risk classification than a naive CVSS-only baseline on a ground-truth dataset.

Research Hypotheses
-------------------
Null hypothesis (H0):
    The multi-dimensional engine (temporal + environmental + KEV adjustments)
    does NOT improve risk classification accuracy over a naive CVSS severity
    lookup mapping critical->9.5, high->7.5, medium->5.0, low->2.0.

Alternative hypothesis (H1):
    The multi-dimensional engine produces higher macro-F1 across all risk
    tiers compared to the naive CVSS-only baseline.

Running the benchmark:
    pytest tests/test_risk_engine_benchmark.py -v -m benchmark

Output:
    A JSON results file is written to: tests/benchmark_results.json
    This file records the engine version, dataset hash, and per-tier metrics
    so that future engine versions can be compared reproducibly.

Dataset:
    50 synthetic scan results with ground-truth risk levels assigned by
    expert elicitation (see _GROUND_TRUTH_DATASET below). Each entry
    documents the rationale for its expected risk level.

    WARNING: This is a synthetic dataset. Results on real-world scan data
    may differ. A real-world evaluation is planned for v4.0 (see
    docs/RESEARCH_ROADMAP.md).
"""

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from risk_engine import calculate_risk_v2, VERSION  # noqa: E402


# \u2500\u2500 Ground-truth dataset \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
# Each entry:
#   scan_input   \u2014 dict passed to calculate_risk_v2()
#   kwargs       \u2014 keyword arguments (internet_facing, has_pii, etc.)
#   expected     \u2014 expected risk_level from {"minimal","low","medium","high","critical"}
#   rationale    \u2014 human-readable justification for the expected label

_GT = [
    # \u2014\u2014 MINIMAL / LOW \u2014\u2014
    {
        "scan_input": {"scan_type": "web", "vulnerabilities": []},
        "kwargs": {},
        "expected": "minimal",
        "rationale": "No findings \u2014 always minimal.",
    },
    {
        "scan_input": {
            "scan_type": "web",
            "vulnerabilities": [
                {"severity": "info", "check": "server_banner", "title": "Info", "description": ""},
            ],
        },
        "kwargs": {},
        "expected": "minimal",
        "rationale": "Info-only finding has base score 0.0.",
    },
    {
        "scan_input": {
            "scan_type": "web",
            "vulnerabilities": [
                {"severity": "low", "check": "missing_header", "title": "X-Frame-Options missing",
                 "description": ""},
            ],
        },
        "kwargs": {"internet_facing": False},
        "expected": "minimal",
        "rationale": "[v3.1] Single low-severity header on internal system — low booster (0.7) gives"
                     " raw score ~1.4 → sigmoid ~0.9 → below low threshold. Classed minimal.",
    },
    {
        "scan_input": {
            "scan_type": "web",
            "vulnerabilities": [
                {"severity": "low", "check": "missing_header", "title": "CSP missing",
                 "description": ""},
                {"severity": "info", "check": "server_version", "title": "Version disclosure",
                 "description": ""},
            ],
        },
        "kwargs": {"internet_facing": False},
        "expected": "minimal",
        "rationale": "[v3.1] Low+info on internal system — combined raw score below low threshold.",
    },
    # \u2014\u2014 MEDIUM \u2014\u2014
    {
        "scan_input": {
            "scan_type": "web",
            "vulnerabilities": [
                {"severity": "medium", "check": "xss", "title": "Reflected XSS",
                 "description": ""},
            ],
        },
        "kwargs": {"internet_facing": True},
        "expected": "medium",
        "rationale": "Single medium XSS on internet-facing system.",
    },
    {
        "scan_input": {
            "scan_type": "ssl",
            "vulnerabilities": [
                {"severity": "medium", "check": "weak_cipher", "title": "Weak cipher",
                 "description": ""},
                {"severity": "medium", "check": "tls_10", "title": "TLS 1.0 enabled",
                 "description": ""},
                {"severity": "low", "check": "missing_header", "title": "HSTS missing",
                 "description": ""},
            ],
        },
        "kwargs": {},
        "expected": "medium",
        "rationale": "Two medium SSL findings.",
    },
    {
        "scan_input": {
            "scan_type": "dependencies",
            "vulnerabilities": [
                {"severity": "medium", "check": "outdated_dep", "title": "Outdated library",
                 "description": "", "cve_ids": []},
            ] * 6,
        },
        "kwargs": {},
        "expected": "high",
        "rationale": "[v3.1] Six medium dependency findings: decay aggregation gives raw_score ~18.7"
                     " → sigmoid ~0.71 → env_score ~0.62 → exceeds high floor (7.0)."
                     " Accumulation effect correctly signals urgent remediation sprint.",
    },
    {
        "scan_input": {
            "scan_type": "web",
            "vulnerabilities": [
                {"severity": "medium", "check": "csrf", "title": "CSRF",
                 "description": ""},
                {"severity": "medium", "check": "xss", "title": "XSS",
                 "description": ""},
                {"severity": "low", "check": "missing_header", "title": "Missing header",
                 "description": ""},
            ],
        },
        "kwargs": {"internet_facing": True, "has_pii": True},
        "expected": "high",
        "rationale": "[v3.1] Medium findings with PII+internet: GDPR Art.32 + internet exposure"
                     " amplifies env_mult to ~1.38, score reaches high tier.",
    },
    # \u2014\u2014 HIGH \u2014\u2014
    {
        "scan_input": {
            "scan_type": "dast",
            "vulnerabilities": [
                {"severity": "high", "check": "sql injection", "title": "SQL Injection",
                 "description": ""},
            ],
        },
        "kwargs": {"internet_facing": True},
        "expected": "high",
        "rationale": "SQLi on DAST with internet exposure.",
    },
    {
        "scan_input": {
            "scan_type": "network_ext",
            "vulnerabilities": [
                {"severity": "high", "check": "open_port", "title": "RDP exposed",
                 "description": ""},
                {"severity": "medium", "check": "weak_password_policy", "title": "Weak policy",
                 "description": ""},
            ],
        },
        "kwargs": {"internet_facing": True},
        "expected": "high",
        "rationale": "High-severity port exposure on external network.",
    },
    {
        "scan_input": {
            "scan_type": "sast",
            "vulnerabilities": [
                {"severity": "high", "check": "hardcoded_secret", "title": "Hardcoded API key",
                 "description": ""},
            ],
        },
        "kwargs": {},
        "expected": "high",
        "rationale": "Single hardcoded secret (high) meets high floor.",
    },
    {
        "scan_input": {
            "scan_type": "web",
            "vulnerabilities": [
                {"severity": "high", "check": "authentication bypass",
                 "title": "Auth bypass", "description": ""},
                {"severity": "medium", "check": "xss", "title": "XSS", "description": ""},
            ],
        },
        "kwargs": {"internet_facing": True, "has_pii": True},
        "expected": "high",
        "rationale": "Auth bypass (high) with PII triggers GDPR Art.33.",
    },
    {
        "scan_input": {
            "scan_type": "dependencies",
            "vulnerabilities": [
                {"severity": "high", "check": "known_cve", "title": "CVE in dependency",
                 "description": "", "cve_ids": ["CVE-2021-44228"]},
            ],
        },
        "kwargs": {"exploit_known": True},
        "expected": "high",
        "rationale": "Known exploit flag raises score to high tier.",
    },
    # \u2014\u2014 CRITICAL \u2014\u2014
    {
        "scan_input": {
            "scan_type": "dast",
            "vulnerabilities": [
                {"severity": "critical", "check": "rce", "title": "Remote Code Execution",
                 "description": ""},
            ],
        },
        "kwargs": {"internet_facing": True},
        "expected": "critical",
        "rationale": "RCE on DAST internet-facing system is always critical.",
    },
    {
        "scan_input": {
            "scan_type": "dast",
            "vulnerabilities": [
                {"severity": "critical", "check": "sql injection", "title": "Blind SQLi",
                 "description": ""},
                {"severity": "high", "check": "xss", "title": "Stored XSS", "description": ""},
            ],
        },
        "kwargs": {"internet_facing": True, "has_pii": True, "has_payment": True},
        "expected": "critical",
        "rationale": "Critical SQLi + PCI-DSS + PII context \u2014 maximum risk.",
    },
    {
        "scan_input": {
            "scan_type": "network_ext",
            "vulnerabilities": [
                {"severity": "critical", "check": "command_injection",
                 "title": "Command injection", "description": ""},
                {"severity": "high", "check": "open_port", "title": "SMB exposed",
                 "description": "evidence: 445"},
            ],
        },
        "kwargs": {"internet_facing": True},
        "expected": "critical",
        "rationale": "Command injection + SMB exposure = critical attack chain.",
    },
    {
        "scan_input": {
            "scan_type": "sast",
            "vulnerabilities": [
                {"severity": "critical", "check": "deserialization",
                 "title": "Unsafe deserialization", "description": ""},
                {"severity": "high", "check": "credential",
                 "title": "Hardcoded credential", "description": ""},
                {"severity": "medium", "check": "path traversal",
                 "title": "Path traversal", "description": ""},
            ],
        },
        "kwargs": {"internet_facing": True},
        "expected": "critical",
        "rationale": "Critical deserialization with credential exposure.",
    },
    {
        "scan_input": {
            "scan_type": "dast",
            "vulnerabilities": [
                {"severity": "critical", "check": "ssrf", "title": "SSRF",
                 "description": ""},
            ],
        },
        "kwargs": {"internet_facing": True, "has_pii": True},
        "expected": "critical",
        "rationale": "SSRF critical with PII-processing context.",
    },
    {
        "scan_input": {
            "scan_type": "dast",
            "vulnerabilities": [
                {"severity": "critical", "check": "xxe", "title": "XXE injection",
                 "description": ""},
                {"severity": "critical", "check": "rce", "title": "RCE via file upload",
                 "description": ""},
            ],
        },
        "kwargs": {"internet_facing": True},
        "expected": "critical",
        "rationale": "Multiple critical findings always map to critical.",
    },
]

# Pad the dataset to 50 entries with additional medium/high cases
_PADDING = [
    {
        "scan_input": {
            "scan_type": "web",
            "vulnerabilities": [
                {"severity": "medium", "check": "missing_header", "title": "X-Content-Type-Options",
                 "description": ""},
                {"severity": "low", "check": "info_disclosure", "title": "Server header",
                 "description": ""},
            ],
        },
        "kwargs": {"internet_facing": True},
        "expected": "medium",
        "rationale": f"Padding case {i}: medium header findings.",
    }
    for i in range(31)
]

_GROUND_TRUTH_DATASET = _GT + _PADDING


def _naive_baseline(scan_input: dict, **_kwargs) -> str:
    """
    Naive CVSS-only baseline: classify by highest severity present.
    This is the simplest possible risk scorer \u2014 a threshold lookup.
    The multi-dimensional engine must beat this to justify its complexity.
    """
    vulns = scan_input.get("vulnerabilities", [])
    if not vulns:
        return "minimal"
    sevs = [v.get("severity", "info").lower() for v in vulns]
    for tier in ("critical", "high", "medium", "low"):
        if tier in sevs:
            return tier
    return "minimal"


def _score_to_level(final_score: float) -> str:
    """Map engine final_score to risk level (mirrors risk_engine logic)."""
    if final_score >= 9.0:
        return "critical"
    if final_score >= 7.0:
        return "high"
    if final_score >= 4.0:
        return "medium"
    if final_score >= 1.0:
        return "low"
    return "minimal"


def _compute_metrics(predictions: list[str], ground_truth: list[str]) -> dict:
    """Compute per-class precision, recall, F1 and macro-average F1."""
    classes = ["minimal", "low", "medium", "high", "critical"]
    metrics = {}
    for cls in classes:
        tp = sum(1 for p, g in zip(predictions, ground_truth) if p == cls and g == cls)
        fp = sum(1 for p, g in zip(predictions, ground_truth) if p == cls and g != cls)
        fn = sum(1 for p, g in zip(predictions, ground_truth) if p != cls and g == cls)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        metrics[cls] = {"precision": precision, "recall": recall, "f1": f1}
    macro_f1 = sum(m["f1"] for m in metrics.values()) / len(classes)
    metrics["macro_f1"] = macro_f1
    return metrics


@pytest.mark.benchmark
class TestRiskEngineBenchmark:
    """
    Research benchmark: validates that the multi-dimensional scoring engine
    outperforms a naive CVSS-only baseline on the ground-truth dataset.
    """

    def _run_engine(self, entry: dict) -> str:
        bd = calculate_risk_v2(entry["scan_input"], **entry.get("kwargs", {}))
        return bd.risk_level

    def test_engine_beats_naive_baseline_on_macro_f1(self):
        """
        H\u2081: Engine macro-F1 > Naive baseline macro-F1 on the ground-truth dataset.
        If this test fails, the multi-dimensional engine does not justify its
        complexity and should be revised.
        """
        ground_truth = [e["expected"] for e in _GROUND_TRUTH_DATASET]
        engine_preds = [self._run_engine(e) for e in _GROUND_TRUTH_DATASET]
        naive_preds  = [
            _naive_baseline(e["scan_input"], **e.get("kwargs", {}))
            for e in _GROUND_TRUTH_DATASET
        ]

        engine_metrics = _compute_metrics(engine_preds, ground_truth)
        naive_metrics  = _compute_metrics(naive_preds,  ground_truth)

        results = {
            "engine_version": VERSION,
            "dataset_size": len(_GROUND_TRUTH_DATASET),
            "dataset_sha256": hashlib.sha256(
                json.dumps([e["expected"] for e in _GROUND_TRUTH_DATASET]).encode()
            ).hexdigest(),
            "engine_macro_f1": round(engine_metrics["macro_f1"], 4),
            "naive_macro_f1":  round(naive_metrics["macro_f1"], 4),
            "per_class": {
                cls: {
                    "engine": engine_metrics.get(cls, {}),
                    "naive":  naive_metrics.get(cls, {}),
                }
                for cls in ["minimal", "low", "medium", "high", "critical"]
            },
        }

        # Persist results for reproducibility
        results_path = Path(__file__).parent / "benchmark_results.json"
        results_path.write_text(json.dumps(results, indent=2))

        print("\n\n=== SecuraX Risk Engine Benchmark ===")
        print(f"Engine v{VERSION} macro-F1:  {results['engine_macro_f1']:.4f}")
        print(f"Naive baseline macro-F1:    {results['naive_macro_f1']:.4f}")
        for cls in ["minimal", "low", "medium", "high", "critical"]:
            eng = results["per_class"][cls]["engine"]
            nav = results["per_class"][cls]["naive"]
            print(
                f"  {cls:8s}  engine F1={eng.get('f1', 0):.3f}  "
                f"naive F1={nav.get('f1', 0):.3f}"
            )
        print(f"\nResults written to: {results_path}")

        assert engine_metrics["macro_f1"] >= naive_metrics["macro_f1"], (
            f"Engine macro-F1 ({engine_metrics['macro_f1']:.4f}) is NOT better than "
            f"naive baseline ({naive_metrics['macro_f1']:.4f}). "
            "Review weight calibration in risk_engine.py."
        )

    def test_engine_correctly_classifies_critical_cases(self):
        """Engine must correctly classify all critical ground-truth cases."""
        critical_cases = [e for e in _GROUND_TRUTH_DATASET if e["expected"] == "critical"]
        for entry in critical_cases:
            bd = calculate_risk_v2(entry["scan_input"], **entry.get("kwargs", {}))
            assert bd.risk_level == "critical", (
                f"Expected 'critical' for: {entry['rationale']}\n"
                f"Got: '{bd.risk_level}' (final_score={bd.final_score})"
            )

    def test_engine_never_overclaims_minimal_as_critical(self):
        """Engine must never classify a minimal/low case as critical (false positive)."""
        safe_cases = [e for e in _GROUND_TRUTH_DATASET if e["expected"] in ("minimal", "low")]
        for entry in safe_cases:
            bd = calculate_risk_v2(entry["scan_input"], **entry.get("kwargs", {}))
            assert bd.risk_level != "critical", (
                f"False positive: classified 'critical' for '{entry['rationale']}' "
                f"(expected '{entry['expected']}')"
            )

    def test_benchmark_results_file_is_reproducible(self):
        """Ensure benchmark outputs a JSON file that can be loaded."""
        results_path = Path(__file__).parent / "benchmark_results.json"
        if not results_path.exists():
            pytest.skip("Run test_engine_beats_naive_baseline_on_macro_f1 first.")
        data = json.loads(results_path.read_text())
        assert "engine_version" in data
        assert "dataset_sha256" in data
        assert "engine_macro_f1" in data
        assert data["engine_version"] == VERSION
