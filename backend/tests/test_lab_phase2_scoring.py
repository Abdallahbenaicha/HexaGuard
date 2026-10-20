"""SecuraX Evaluation Lab — Phase 2 Scoring, Ground Truth & Eligibility Tests.

Verifies all non-negotiable requirements of Master Specification v5 Phase 2:
  - Exact Golden Test 1: 100 eligible, 70 TP, 30 FN, 10 confirmed FP
      -> Recall 70.0%, Precision 87.5%, F1 ~77.8%, FN 30, FP 10.
  - Exact Golden Test 2: 100 eligible, 10 TP, 5 FP (90 FN)
      -> Recall 10.0%, Precision 66.7%, F1 ~17.4%.
  - Location matching: +-3 lines code tolerance, URL/param, port, package.
  - CWE family normalization (e.g. "sqli", "89", "cwe-89" -> "CWE-89").
  - Duplicate suppression with provenance preservation.
  - Eligibility: fixed BEFORE run; unsupported cases are NEVER false negatives.
  - Absolute recall vs in-scope recall honestly separated.
  - Truth states: UNKNOWN never becomes clean (bucketed as UNVERIFIED).
  - UNREVIEWED findings: lower bound vs optimistic upper bound precision.
  - Negative controls: FPR computed ONLY on eligible negative controls; N/A when 0.
  - Zero-denominator protection: explicit N/A with reason (never 0% or 100%).
  - Two distinct statuses: execution_status vs benchmark_status.
  - PARTIAL execution never promoted to PASS; PASS requires coverage == 1.0.
  - Wilson 95% confidence intervals on binomial proportions.
  - Scanner non-determinism stats (n, mean, sd) over repeated runs.
  - Threshold evaluation against thresholds.yaml; critical FN/FP mandatory review flags.
  - Held-out split isolation.
  - Additive database persistence for ground truth and benchmark scorecards.
"""

from __future__ import annotations

import json
import math
import os
from unittest.mock import patch

import pytest
import yaml

from database import init_db
from db.lab import (
    get_benchmark_scorecard,
    get_ground_truth_case_by_id,
    init_lab_tables,
    list_benchmark_scorecards,
    list_ground_truth_cases_db,
    save_benchmark_scorecard,
    seed_ground_truth_cases,
)
from lab.ground_truth import (
    evaluate_case_eligibility,
    get_ground_truth_case,
    load_ground_truth_cases,
    parse_ground_truth_case,
    partition_cases_for_engine,
)
from lab.matcher import (
    are_cwes_compatible,
    is_location_match,
    match_findings_to_ground_truth,
    normalize_cwe,
    suppress_duplicate_findings,
)
from lab.models import (
    BenchmarkScorecard,
    BenchmarkStatus,
    CandidateFinding,
    DatasetSplit,
    EligibilityStatus,
    ExecutionStatus,
    FindingBucket,
    GroundTruthCase,
    MetricValue,
    TruthState,
)
from lab.scoring import (
    compute_coverage,
    compute_execution_error_rate,
    compute_f1_score,
    compute_false_discovery_share,
    compute_fpr_on_negative_controls,
    compute_precision_bounds,
    compute_recall,
    compute_repeated_run_stats,
    compute_severity_weighted_recall,
    evaluate_benchmark_decision,
    wilson_score_interval,
)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Exact Golden Tests (Master Spec v5 Phase 2)
# ══════════════════════════════════════════════════════════════════════════════

def test_golden_test_1():
    """Exact Golden Test 1:
    100 eligible, 70 TP, 30 FN, 10 confirmed FP
    -> Recall 70%, Precision 87.5%, F1 ~77.8%, FN 30, FP 10.
    """
    tp = 70
    fn = 30
    confirmed_fp = 10
    total_eligible = tp + fn  # 100

    recall = compute_recall(tp=tp, fn=fn)
    assert not recall.is_na
    assert recall.value == pytest.approx(0.70, abs=1e-4)
    assert recall.raw_num == 70
    assert recall.raw_denom == 100

    prec_lower, prec_upper = compute_precision_bounds(tp=tp, confirmed_fp=confirmed_fp, unreviewed=0)
    assert not prec_upper.is_na
    # 70 / (70 + 10) = 70 / 80 = 0.875
    assert prec_upper.value == pytest.approx(0.875, abs=1e-4)
    assert prec_upper.raw_num == 70
    assert prec_upper.raw_denom == 80

    # F1 = 2 * 0.70 * 0.875 / (0.70 + 0.875) = 1.225 / 1.575 = 0.777777...
    f1 = compute_f1_score(precision_val=prec_upper.value, recall_val=recall.value)
    assert not f1.is_na
    assert f1.value == pytest.approx(0.777778, abs=1e-4)


def test_golden_test_2():
    """Exact Golden Test 2:
    100 eligible, 10 TP, 5 FP (90 FN)
    -> Recall 10%, Precision 66.7%, F1 ~17.4%.
    """
    tp = 10
    fn = 90
    confirmed_fp = 5

    recall = compute_recall(tp=tp, fn=fn)
    assert not recall.is_na
    assert recall.value == pytest.approx(0.10, abs=1e-4)
    assert recall.raw_num == 10
    assert recall.raw_denom == 100

    prec_lower, prec_upper = compute_precision_bounds(tp=tp, confirmed_fp=confirmed_fp, unreviewed=0)
    assert not prec_upper.is_na
    # 10 / (10 + 5) = 10 / 15 = 0.666667
    assert prec_upper.value == pytest.approx(0.666667, abs=1e-4)

    # F1 = 2 * 0.10 * 0.666667 / (0.10 + 0.666667) = 0.133333 / 0.766667 = 0.173913
    f1 = compute_f1_score(precision_val=prec_upper.value, recall_val=recall.value)
    assert not f1.is_na
    assert f1.value == pytest.approx(0.173913, abs=1e-4)


# ══════════════════════════════════════════════════════════════════════════════
# 2. Matcher: Location Tolerance, CWE Normalization & Duplicates
# ══════════════════════════════════════════════════════════════════════════════

def test_cwe_family_normalization():
    """Verify CWE normalization maps aliases and numbers to standard family."""
    assert normalize_cwe("89") == "CWE-89"
    assert normalize_cwe("cwe-89") == "CWE-89"
    assert normalize_cwe("CWE_89") == "CWE-89"
    assert normalize_cwe("sqli") == "CWE-89"
    assert normalize_cwe("sql_injection") == "CWE-89"
    assert normalize_cwe("943") == "CWE-89"

    assert normalize_cwe("78") == "CWE-78"
    assert normalize_cwe("os_command_injection") == "CWE-78"

    assert normalize_cwe("79") == "CWE-79"
    assert normalize_cwe("xss") == "CWE-79"

    assert normalize_cwe("798") == "CWE-798"
    assert normalize_cwe("hardcoded_secret") == "CWE-798"

    assert are_cwes_compatible("sqli", "CWE-89")
    assert are_cwes_compatible("943", "89")
    assert not are_cwes_compatible("CWE-89", "CWE-78")


def test_location_tolerance_code_files():
    """Verify code line matching tolerance is exact normalized location (+-3 lines)."""
    gt_loc = {"type": "file_line", "file": "app/models/user.py", "line": 50}

    # Exact line match
    is_m, conf = is_location_match({"file": "app/models/user.py", "line": 50}, gt_loc)
    assert is_m is True
    assert conf == 1.0

    # Line +-1, +-2, +-3 should match
    for offset in [-3, -2, -1, 1, 2, 3]:
        is_m, conf = is_location_match({"file": "app/models/user.py", "line": 50 + offset}, gt_loc)
        assert is_m is True, f"Failed to match at offset {offset}"
        assert conf > 0.70

    # Line +-4 should NOT match (outside +-3 tolerance)
    for offset in [-4, 4, 10]:
        is_m, _ = is_location_match({"file": "app/models/user.py", "line": 50 + offset}, gt_loc)
        assert is_m is False, f"Should not match at offset {offset}"

    # Different file should NOT match
    is_m, _ = is_location_match({"file": "app/views/user.py", "line": 50}, gt_loc)
    assert is_m is False


def test_location_matching_web_network_package():
    """Verify URL+param, network port, and package location matching."""
    # Web URL + Param
    gt_web = {"type": "url_param", "url": "/api/v1/search", "param": "q"}
    assert is_location_match({"url": "/api/v1/search?extra=1", "param": "q"}, gt_web)[0] is True
    assert is_location_match({"url": "/api/v1/search", "param": "sort"}, gt_web)[0] is False
    assert is_location_match({"url": "/api/v1/login", "param": "q"}, gt_web)[0] is False

    # Port / Service
    gt_net = {"type": "port", "port": 8080}
    assert is_location_match({"port": 8080}, gt_net)[0] is True
    assert is_location_match({"port": 9090}, gt_net)[0] is False

    # Package
    gt_pkg = {"type": "package", "package": "urllib3"}
    assert is_location_match({"package": "urllib3"}, gt_pkg)[0] is True
    assert is_location_match({"package": "requests"}, gt_pkg)[0] is False


def test_duplicate_suppression_with_provenance():
    """Verify duplicate suppression preserves all original finding IDs."""
    f1 = CandidateFinding("F-01", "sast", "target_1", "CWE-89", "high", {"file": "a.py", "line": 10})
    f2 = CandidateFinding("F-02", "sast", "target_1", "sqli",   "high", {"file": "a.py", "line": 10})
    f3 = CandidateFinding("F-03", "sast", "target_1", "CWE-78", "critical", {"file": "b.py", "line": 20})

    deduped, provenance = suppress_duplicate_findings([f1, f2, f3])
    assert len(deduped) == 2
    assert deduped[0].finding_id == "F-01"
    assert deduped[1].finding_id == "F-03"

    # Provenance tracks original findings
    assert provenance["F-01"] == ["F-01", "F-02"]
    assert provenance["F-03"] == ["F-03"]


# ══════════════════════════════════════════════════════════════════════════════
# 3. Eligibility & In-Scope vs Absolute Recall
# ══════════════════════════════════════════════════════════════════════════════

def test_unsupported_cases_are_not_false_negatives():
    """Unsupported cases must NEVER be counted as false negatives.

    100 total reference cases:
      - 80 eligible
      - 20 unsupported
    On the 80 eligible:
      - 56 TP
      - 24 FN
    Results:
      - In-scope recall = 56 / 80 = 70.0%
      - Absolute recall = 56 / 100 = 56.0%
      - Excluded portion reported as 20 unsupported cases.
    """
    total_reference = 100
    eligible_count = 80
    unsupported_count = 20
    tp = 56
    fn = 24  # on eligible only

    in_scope_recall = compute_recall(tp=tp, fn=fn)
    assert not in_scope_recall.is_na
    assert in_scope_recall.value == pytest.approx(0.70, abs=1e-4)

    absolute_recall = compute_recall(tp=tp, fn=fn, total_in_pool=total_reference, is_absolute=True)
    assert not absolute_recall.is_na
    assert absolute_recall.value == pytest.approx(0.56, abs=1e-4)

    assert unsupported_count == total_reference - eligible_count


def test_evaluate_case_eligibility_recording():
    """Verify eligibility evaluates correctly based on engine declaration and configuration."""
    case = GroundTruthCase(
        case_id="TEST-01",
        dataset_id="test",
        dataset_version="1.0",
        split=DatasetSplit.DEV,
        target_id="target_1",
        vulnerability_type="SQL Injection",
        cwe="CWE-89",
        truth_state=TruthState.CONFIRMED_VULNERABLE,
        expected_severity="high",
        location={"file": "a.py", "line": 10},
        expected_evidence="",
        verification_method="audit",
        eligible_engines=["sast", "semgrep"],
    )

    assert evaluate_case_eligibility(case, "sast") == EligibilityStatus.ELIGIBLE
    assert evaluate_case_eligibility(case, "dast") == EligibilityStatus.NOT_SUPPORTED

    # Blocked by config
    config = {"disabled_cwes": ["CWE-89"]}
    assert evaluate_case_eligibility(case, "sast", config) == EligibilityStatus.BLOCKED_BY_CONFIGURATION


# ══════════════════════════════════════════════════════════════════════════════
# 4. Truth States: UNKNOWN Never Becomes Clean
# ══════════════════════════════════════════════════════════════════════════════

def test_unknown_truth_state_never_becomes_clean():
    """UNKNOWN truth state must bucket as UNVERIFIED, never assuming clean/benign."""
    case_unknown = GroundTruthCase(
        case_id="UNKNOWN-01",
        dataset_id="test",
        dataset_version="1.0",
        split=DatasetSplit.DEV,
        target_id="target_1",
        vulnerability_type="Ambiguous Injection",
        cwe="CWE-89",
        truth_state=TruthState.UNKNOWN,
        expected_severity="medium",
        location={"file": "a.py", "line": 10},
        expected_evidence="",
        verification_method="manual",
        eligible_engines=["sast"],
    )

    finding = CandidateFinding(
        finding_id="F-10",
        engine_id="sast",
        target_id="target_1",
        cwe="CWE-89",
        severity="medium",
        location={"file": "a.py", "line": 10},
    )

    matches, matched_cases, matched_findings = match_findings_to_ground_truth(
        findings=[finding],
        ground_truth_cases=[case_unknown],
        engine_id="sast",
    )

    assert len(matches) == 1
    assert matches[0].bucket == FindingBucket.UNVERIFIED
    assert matches[0].bucket != FindingBucket.TP
    assert matches[0].bucket != FindingBucket.CONFIRMED_FP


# ══════════════════════════════════════════════════════════════════════════════
# 5. UNREVIEWED Findings: Lower Bound vs Optimistic Upper Bound Precision
# ══════════════════════════════════════════════════════════════════════════════

def test_unreviewed_findings_precision_bounds():
    """UNREVIEWED findings (not in manifest) calculate pessimistic lower and optimistic upper bounds."""
    # 50 TP, 10 confirmed FP, 40 unreviewed findings
    tp = 50
    confirmed_fp = 10
    unreviewed = 40

    pess_lower, opt_upper = compute_precision_bounds(tp=tp, confirmed_fp=confirmed_fp, unreviewed=unreviewed)

    # Upper bound = 50 / (50 + 10) = 50 / 60 = 0.8333
    assert not opt_upper.is_na
    assert opt_upper.value == pytest.approx(50 / 60, abs=1e-4)

    # Lower bound = 50 / (50 + 10 + 40) = 50 / 100 = 0.50
    assert not pess_lower.is_na
    assert pess_lower.value == pytest.approx(0.50, abs=1e-4)
    assert "40 unreviewed" in pess_lower.reason


def test_unreviewed_finding_bucketing():
    """Findings with no match in ground truth manifest bucket as UNREVIEWED."""
    case = GroundTruthCase(
        case_id="GT-01",
        dataset_id="test",
        dataset_version="1.0",
        split=DatasetSplit.DEV,
        target_id="target_1",
        vulnerability_type="SQL Injection",
        cwe="CWE-89",
        truth_state=TruthState.CONFIRMED_VULNERABLE,
        expected_severity="high",
        location={"file": "db.py", "line": 20},
        expected_evidence="",
        verification_method="audit",
        eligible_engines=["sast"],
    )

    # Scanner emits finding on completely different file
    finding = CandidateFinding(
        finding_id="F-99",
        engine_id="sast",
        target_id="target_1",
        cwe="CWE-79",
        severity="medium",
        location={"file": "views/home.py", "line": 80},
    )

    matches, _, _ = match_findings_to_ground_truth([finding], [case], "sast")
    assert len(matches) == 1
    assert matches[0].bucket == FindingBucket.UNREVIEWED
    assert matches[0].matched_case is None


# ══════════════════════════════════════════════════════════════════════════════
# 6. Negative Controls & False Positive Rate
# ══════════════════════════════════════════════════════════════════════════════

def test_fpr_without_negative_controls_is_explicit_na():
    """Without an explicit set of eligible negative controls, FPR is N/A (never 0% or population-wide)."""
    fpr_metric = compute_fpr_on_negative_controls(tn=0, fp_on_neg=0, eligible_negative_controls=0)
    assert fpr_metric.is_na is True
    assert "No eligible negative controls" in fpr_metric.reason
    assert fpr_metric.value is None


def test_fpr_with_explicit_negative_controls():
    """FPR computed ONLY on explicit negative controls."""
    # 20 negative controls evaluated: 2 False Positives, 18 True Negatives
    fpr_metric = compute_fpr_on_negative_controls(tn=18, fp_on_neg=2, eligible_negative_controls=20)
    assert fpr_metric.is_na is False
    assert fpr_metric.value == pytest.approx(2 / 20, abs=1e-4)  # 10%
    assert fpr_metric.raw_num == 2
    assert fpr_metric.raw_denom == 20
    assert "FPR on 20 negative controls" in fpr_metric.reason


# ══════════════════════════════════════════════════════════════════════════════
# 7. Zero-Denominator Safety
# ══════════════════════════════════════════════════════════════════════════════

def test_zero_denominators_return_explicit_na_with_reason():
    """Zero denominators must NEVER return 0% or 100%; they return explicit N/A with reason."""
    # Zero vulnerable cases
    rec = compute_recall(tp=0, fn=0)
    assert rec.is_na is True
    assert rec.value is None
    assert "Zero" in rec.reason

    # Zero emitted findings
    pess, opt = compute_precision_bounds(tp=0, confirmed_fp=0, unreviewed=0)
    assert pess.is_na is True
    assert pess.value is None
    assert opt.is_na is True
    assert opt.value is None

    # Zero planned cases
    cov = compute_coverage(executed=0, planned=0)
    assert cov.is_na is True
    assert cov.value is None

    # Zero attempted cases
    err = compute_execution_error_rate(failed=0, attempted=0)
    assert err.is_na is True
    assert err.value is None

    # Zero deduplicated findings
    fds = compute_false_discovery_share(confirmed_fp=0, deduplicated_findings=0)
    assert fds.is_na is True
    assert fds.value is None


# ══════════════════════════════════════════════════════════════════════════════
# 8. Disconnected Execution Status vs Benchmark Status
# ══════════════════════════════════════════════════════════════════════════════

def test_execution_completed_can_still_fail_benchmark():
    """A run can complete execution and still FAIL benchmark if recall is below threshold."""
    thresholds = {
        "min_in_scope_recall": 0.70,
        "max_fpr_negative_controls": 0.15,
        "min_case_coverage": 1.00,
    }

    # Low recall (0.50 < 0.70)
    in_scope_recall = MetricValue(value=0.50, is_na=False, raw_num=50, raw_denom=100)
    fpr_on_neg = MetricValue(value=0.05, is_na=False, raw_num=1, raw_denom=20)
    case_coverage = MetricValue(value=1.00, is_na=False, raw_num=100, raw_denom=100)
    error_rate = MetricValue(value=0.00, is_na=False, raw_num=0, raw_denom=100)

    decision, reasons, flags = evaluate_benchmark_decision(
        execution_status=ExecutionStatus.COMPLETED,
        in_scope_recall=in_scope_recall,
        fpr_on_neg=fpr_on_neg,
        case_coverage=case_coverage,
        error_rate=error_rate,
        critical_fn=0,
        critical_fp=0,
        thresholds=thresholds,
    )

    assert decision == BenchmarkStatus.FAIL
    assert any("below minimum threshold" in r for r in reasons)


def test_partial_execution_never_promoted_to_pass():
    """A PARTIAL execution is NEVER promoted to PASS, even if recall on executed cases is 100%."""
    thresholds = {
        "min_in_scope_recall": 0.70,
        "max_fpr_negative_controls": 0.15,
        "min_case_coverage": 1.00,
    }

    # 100% recall on the subset that ran, but execution was PARTIAL
    in_scope_recall = MetricValue(value=1.00, is_na=False, raw_num=50, raw_denom=50)
    fpr_on_neg = MetricValue(value=0.00, is_na=False, raw_num=0, raw_denom=10)
    case_coverage = MetricValue(value=0.50, is_na=False, raw_num=50, raw_denom=100)
    error_rate = MetricValue(value=0.00, is_na=False, raw_num=0, raw_denom=50)

    decision, reasons, _ = evaluate_benchmark_decision(
        execution_status=ExecutionStatus.PARTIAL,
        in_scope_recall=in_scope_recall,
        fpr_on_neg=fpr_on_neg,
        case_coverage=case_coverage,
        error_rate=error_rate,
        critical_fn=0,
        critical_fp=0,
        thresholds=thresholds,
    )

    assert decision == BenchmarkStatus.PARTIAL
    assert decision != BenchmarkStatus.PASS
    assert any("partial runs cannot be promoted to benchmark PASS" in r for r in reasons)


# ══════════════════════════════════════════════════════════════════════════════
# 9. Wilson Confidence Intervals & Scanner Non-Determinism
# ══════════════════════════════════════════════════════════════════════════════

def test_wilson_confidence_interval():
    """Wilson 95% score interval computation."""
    lo, hi = wilson_score_interval(successes=70, trials=100)
    assert lo is not None and hi is not None
    assert 0.0 < lo < 0.70 < hi < 1.0
    # Standard Wilson interval for 70/100 is approx [0.604, 0.781]
    assert lo == pytest.approx(0.604, abs=0.01)
    assert hi == pytest.approx(0.781, abs=0.01)

    # Edge cases
    lo_0, hi_0 = wilson_score_interval(0, 100)
    assert lo_0 == 0.0
    assert hi_0 > 0.0

    lo_none, hi_none = wilson_score_interval(0, 0)
    assert lo_none is None and hi_none is None


def test_repeated_runs_scanner_nondeterminism_stats():
    """Repeated runs measure scanner non-determinism ONLY (report n, mean, sd)."""
    # 3 runs: 70%, 72%, 68%
    stats = compute_repeated_run_stats([0.70, 0.72, 0.68])
    assert stats["n"] == 3
    assert stats["mean"] == pytest.approx(0.70, abs=1e-4)
    # Variance = ((0)^2 + (0.02)^2 + (-0.02)^2) / 2 = 0.0008 / 2 = 0.0004 -> sd = 0.02
    assert stats["sd"] == pytest.approx(0.02, abs=1e-4)

    # Single run
    stats_single = compute_repeated_run_stats([0.85])
    assert stats_single["n"] == 1
    assert stats_single["mean"] == 0.85
    assert stats_single["sd"] == 0.0


# ══════════════════════════════════════════════════════════════════════════════
# 10. Severity-Weighted Recall & Critical Review Mandates
# ══════════════════════════════════════════════════════════════════════════════

def test_severity_weighted_recall():
    """Severity-weighted recall with documented weights (critical=4, high=3, medium=2, low=1, info=0.5)."""
    case_results = [
        {"case_id": "C-1", "truth_state": "CONFIRMED_VULNERABLE", "expected_severity": "critical", "bucket": "TP"},
        {"case_id": "C-2", "truth_state": "CONFIRMED_VULNERABLE", "expected_severity": "critical", "bucket": "FN"},
        {"case_id": "C-3", "truth_state": "CONFIRMED_VULNERABLE", "expected_severity": "high", "bucket": "TP"},
        {"case_id": "C-4", "truth_state": "CONFIRMED_VULNERABLE", "expected_severity": "medium", "bucket": "TP"},
    ]
    # Weights: 4 + 4 + 3 + 2 = 13.0
    # Detected weights: 4 (C-1) + 3 (C-3) + 2 (C-4) = 9.0
    # Weighted recall = 9.0 / 13.0 = 0.6923
    sw_recall = compute_severity_weighted_recall(case_results)
    assert not sw_recall.is_na
    assert sw_recall.value == pytest.approx(9.0 / 13.0, abs=1e-4)


def test_critical_fn_and_fp_trigger_mandatory_review():
    """Critical-severity False Negatives and False Positives trigger mandatory review flags."""
    thresholds = {"min_in_scope_recall": 0.70, "min_case_coverage": 1.00}
    recall = MetricValue(value=0.80, is_na=False)
    fpr = MetricValue(is_na=True)
    cov = MetricValue(value=1.00, is_na=False)
    err = MetricValue(value=0.00, is_na=False)

    decision, reasons, flags = evaluate_benchmark_decision(
        execution_status=ExecutionStatus.COMPLETED,
        in_scope_recall=recall,
        fpr_on_neg=fpr,
        case_coverage=cov,
        error_rate=err,
        critical_fn=2,
        critical_fp=1,
        thresholds=thresholds,
    )

    assert len(flags) == 2
    assert any("2 critical-severity False Negative" in f for f in flags)
    assert any("1 critical-severity False Positive" in f for f in flags)


# ══════════════════════════════════════════════════════════════════════════════
# 11. Ground Truth Seed Data & Split Isolation
# ══════════════════════════════════════════════════════════════════════════════

def test_ground_truth_seed_loading_and_split_isolation():
    """Seed loader defaults to split='dev' and isolates heldout split from dev split (F-01)."""
    # 1. Default without split argument MUST return only dev cases
    cases_default = load_ground_truth_cases()
    assert len(cases_default) > 0
    assert all(c.split == DatasetSplit.DEV for c in cases_default)
    assert not any(c.split == DatasetSplit.HELDOUT for c in cases_default)

    # 2. Filter dev explicitly
    cases_dev = load_ground_truth_cases(split="dev")
    assert len(cases_dev) == len(cases_default)
    assert all(c.split == DatasetSplit.DEV for c in cases_dev)

    # 3. Filter heldout explicitly
    cases_heldout = load_ground_truth_cases(split="heldout")
    assert len(cases_heldout) > 0
    assert all(c.split == DatasetSplit.HELDOUT for c in cases_heldout)

    # 4. Filter 'all' explicitly returns dev + heldout
    cases_all = load_ground_truth_cases(split="all")
    assert len(cases_all) == len(cases_dev) + len(cases_heldout)

    # 5. Confirm heldout is completely disjoint from dev
    dev_ids = {c.case_id for c in cases_dev}
    heldout_ids = {c.case_id for c in cases_heldout}
    assert dev_ids.isdisjoint(heldout_ids)

    # 6. Single case retrieval finds case across all splits
    case_heldout = get_ground_truth_case("CASE-HELDOUT-SQLI-001")
    assert case_heldout is not None
    assert case_heldout.split == DatasetSplit.HELDOUT


# ══════════════════════════════════════════════════════════════════════════════
# 12. Pre-Committed Acceptance Thresholds File
# ══════════════════════════════════════════════════════════════════════════════

def test_thresholds_yaml_structure_and_classes():
    """Verify lab/thresholds.yaml is valid YAML with all required engine classes."""
    yaml_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "lab",
        "thresholds.yaml",
    )
    assert os.path.exists(yaml_path), "thresholds.yaml not found"

    with open(yaml_path, "r", encoding="utf-8") as f:
        t_data = yaml.safe_load(f)

    assert t_data.get("version") == "1.0.0"
    classes = t_data.get("engine_classes", {})
    required_classes = ["sast", "dast", "sca", "secret", "server", "docker", "network"]
    for rc in required_classes:
        assert rc in classes, f"Missing engine class: {rc}"
        cfg = classes[rc]
        assert "min_in_scope_recall" in cfg
        assert "min_precision_lower_bound" in cfg
        assert "max_fpr_negative_controls" in cfg
        assert "min_case_coverage" in cfg
        assert cfg["min_case_coverage"] == 1.00  # Spec: 100% case coverage required for PASS


# ══════════════════════════════════════════════════════════════════════════════
# 13. Database Persistence: lab_ground_truth & lab_benchmarks
# ══════════════════════════════════════════════════════════════════════════════

def test_database_persistence_roundtrip(tmp_path, monkeypatch):
    """Verify seeding and round-trip persistence in lab_ground_truth and lab_benchmarks."""
    test_db = str(tmp_path / "test_lab_phase2_db.db")
    monkeypatch.setenv("DB_PATH", test_db)

    init_db()
    init_lab_tables()

    # 1. Seed Ground Truth
    count = seed_ground_truth_cases()
    assert count >= 8

    # 2. Query Ground Truth
    case_sqli = get_ground_truth_case_by_id("CASE-SAST-SQLI-001")
    assert case_sqli is not None
    assert case_sqli["cwe"] == "CWE-89"
    assert case_sqli["truth_state"] == "CONFIRMED_VULNERABLE"
    assert isinstance(case_sqli["location"], dict)
    assert case_sqli["location"]["line"] == 42
    assert isinstance(case_sqli["eligible_engines"], list)
    assert "sast" in case_sqli["eligible_engines"]

    # 3. DB Split Isolation (F-01)
    db_dev_cases = list_ground_truth_cases_db()
    assert len(db_dev_cases) > 0
    assert all(c["split"] == "dev" for c in db_dev_cases)
    assert not any(c["split"] == "heldout" for c in db_dev_cases)

    db_heldout_cases = list_ground_truth_cases_db(split="heldout")
    assert len(db_heldout_cases) > 0
    assert all(c["split"] == "heldout" for c in db_heldout_cases)

    db_all_cases = list_ground_truth_cases_db(split="all")
    assert len(db_all_cases) == len(db_dev_cases) + len(db_heldout_cases)

    # 4. Save & Retrieve Benchmark Scorecard
    scorecard_payload = {
        "benchmark_id": "bench_test_001",
        "protocol_version": "1.0.0",
        "engine_id": "sast_semgrep",
        "target_id": "fixture_sast_python",
        "dataset_id": "hexaguard_bench_core",
        "dataset_version": "1.0.0",
        "execution_status": "COMPLETED",
        "benchmark_status": "PASS",
        "status_reasons": ["All committed thresholds satisfied."],
        "counts": {
            "tp": 70,
            "fn": 30,
            "confirmed_fp": 10,
        },
        "metrics": {
            "in_scope_recall": {"value": 0.70, "percentage": "70.0%"},
            "precision_optimistic_upper_bound": {"value": 0.875, "percentage": "87.5%"},
            "f1_score": {"value": 0.7778, "percentage": "77.8%"},
        },
        "critical_review_flags": [],
        "repeated_run_stats": {"n": 3, "mean": 0.70, "sd": 0.02},
    }

    saved_id = save_benchmark_scorecard(scorecard_payload)
    assert saved_id == "bench_test_001"

    retrieved = get_benchmark_scorecard("bench_test_001")
    assert retrieved is not None
    assert retrieved["engine_id"] == "sast_semgrep"
    assert retrieved["benchmark_status"] == "PASS"
    assert retrieved["summary_counts"]["tp"] == 70
    assert retrieved["metrics"]["in_scope_recall"]["value"] == 0.70

    scorecards_list = list_benchmark_scorecards(engine_id="sast_semgrep")
    assert len(scorecards_list) == 1
    assert scorecards_list[0]["benchmark_id"] == "bench_test_001"


def test_mysql_compatible_table_schemas(tmp_path, monkeypatch):
    """Verify table creation statements use bounded VARCHAR types for primary keys and indexed columns (F-02)."""
    test_db = str(tmp_path / "test_schema_check.db")
    monkeypatch.setenv("DB_PATH", test_db)

    # Verify multiple initializations run idempotently without error
    init_db()
    init_lab_tables()
    init_lab_tables()

    import sqlite3
    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()

    for table_name in ["lab_targets", "lab_ground_truth", "lab_benchmarks"]:
        row = cursor.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        ).fetchone()
        assert row is not None, f"Table {table_name} not found in sqlite_master"
        sql = row[0]
        # Primary key and indexed columns must be bounded VARCHAR (not bare unbounded TEXT PRIMARY KEY)
        assert "VARCHAR(" in sql, f"Table {table_name} does not use bounded VARCHAR in SQL: {sql}"
