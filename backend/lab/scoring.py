"""SecuraX Evaluation Lab — Pure Scoring Service (v1.0.0).

Governed strictly by Master Specification v5 Phase 2:
  - Honest metric separation: Recall, Precision, F1, False Discovery Share,
    Case Coverage, Execution Error Rate, Negative Control FPR.
  - Negative controls: FPR computed ONLY over an explicit, versioned set of
    negative controls the engine was eligible to test. N/A if none.
  - Never produce a single composite score.
  - Zero denominators return explicit N/A with human-readable reason (never 0% or 100%).
  - Two distinct statuses: execution_status vs benchmark_status.
  - A run can complete and still FAIL. A PARTIAL run is never promoted.
  - Wilson 95% confidence intervals on proportions.
  - Scanner non-determinism stats (n, mean, sd) over repeated runs.
  - Critical-severity FN and FP trigger mandatory review.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple

from lab.models import (
    BenchmarkScorecard,
    BenchmarkStatus,
    ExecutionStatus,
    FindingBucket,
    MetricValue,
)


def wilson_score_interval(
    successes: int,
    trials: int,
    confidence: float = 0.95,
) -> Tuple[Optional[float], Optional[float]]:
    """Compute Wilson score confidence interval for a binomial proportion.

    z = 1.95996 for 95% confidence.
    Returns: (lower_bound, upper_bound) or (None, None) if trials == 0.
    """
    if trials <= 0 or successes < 0 or successes > trials:
        return None, None

    z = 1.959964  # standard normal quantile for 95% two-sided
    p = successes / trials
    z2 = z * z
    n = trials

    center = (p + z2 / (2 * n)) / (1 + z2 / n)
    margin = (z / (1 + z2 / n)) * math.sqrt((p * (1 - p) / n) + (z2 / (4 * n * n)))

    lower = max(0.0, center - margin)
    upper = min(1.0, center + margin)
    return lower, upper


def compute_recall(
    tp: int,
    fn: int,
    total_in_pool: Optional[int] = None,
    is_absolute: bool = False,
) -> MetricValue:
    """Compute Recall = TP / (TP + FN).

    Zero denominator returns explicit N/A with reason.
    """
    denom = tp + fn if total_in_pool is None else total_in_pool
    label = "absolute" if is_absolute else "in-scope"

    if denom <= 0:
        return MetricValue(
            value=None,
            is_na=True,
            reason=f"Zero {label} vulnerable cases in evaluation pool",
            raw_num=tp,
            raw_denom=denom,
        )

    val = tp / denom
    lo, hi = wilson_score_interval(tp, denom)
    return MetricValue(
        value=val,
        is_na=False,
        reason=None,
        raw_num=tp,
        raw_denom=denom,
        ci_lower=lo,
        ci_upper=hi,
    )


def compute_precision_bounds(
    tp: int,
    confirmed_fp: int,
    unreviewed: int = 0,
) -> Tuple[MetricValue, MetricValue]:
    """Compute Precision bounds.

    Lower bound: pessimistic assumption treating unreviewed findings as extra/false findings.
                 Precision_lower = TP / (TP + confirmed_fp + unreviewed)
    Upper bound: optimistic assumption evaluating against evaluated cases only.
                 Precision_upper = TP / (TP + confirmed_fp)

    Returns: (precision_lower_bound, precision_optimistic_upper_bound)
    """
    # Optimistic Upper Bound
    opt_denom = tp + confirmed_fp
    if opt_denom <= 0:
        opt_val = MetricValue(
            value=None,
            is_na=True,
            reason="Zero emitted findings matching evaluated cases",
            raw_num=tp,
            raw_denom=opt_denom,
        )
    else:
        val = tp / opt_denom
        lo, hi = wilson_score_interval(tp, opt_denom)
        opt_val = MetricValue(
            value=val,
            is_na=False,
            reason=None,
            raw_num=tp,
            raw_denom=opt_denom,
            ci_lower=lo,
            ci_upper=hi,
        )

    # Pessimistic Lower Bound
    pess_denom = tp + confirmed_fp + unreviewed
    if pess_denom <= 0:
        pess_val = MetricValue(
            value=None,
            is_na=True,
            reason="Zero total emitted findings",
            raw_num=tp,
            raw_denom=pess_denom,
        )
    else:
        val = tp / pess_denom
        lo, hi = wilson_score_interval(tp, pess_denom)
        pess_val = MetricValue(
            value=val,
            is_na=False,
            reason=f"Pessimistic lower bound assuming {unreviewed} unreviewed findings are non-TP" if unreviewed > 0 else None,
            raw_num=tp,
            raw_denom=pess_denom,
            ci_lower=lo,
            ci_upper=hi,
        )

    return pess_val, opt_val


def compute_f1_score(
    precision_val: Optional[float],
    recall_val: Optional[float],
) -> MetricValue:
    """Compute F1 = 2 * P * R / (P + R)."""
    if precision_val is None or recall_val is None:
        return MetricValue(
            value=None,
            is_na=True,
            reason="Precision or Recall is N/A",
        )

    sum_pr = precision_val + recall_val
    if sum_pr <= 0:
        return MetricValue(
            value=0.0,
            is_na=False,
            reason="Precision + Recall is zero",
        )

    f1 = 2 * (precision_val * recall_val) / sum_pr
    return MetricValue(
        value=f1,
        is_na=False,
        reason=None,
    )


def compute_fpr_on_negative_controls(
    tn: int,
    fp_on_neg: int,
    eligible_negative_controls: int,
) -> MetricValue:
    """Compute False Positive Rate ONLY on an explicit, versioned set of negative controls.

    Spec: 'TN and FPR are computed ONLY over an explicitly defined, versioned set of
    negative controls the engine was eligible to test, displayed as FPR on N negative
    controls. Without such a set they are N/A. Never present FPR as a population-wide rate.'
    """
    if eligible_negative_controls <= 0:
        return MetricValue(
            value=None,
            is_na=True,
            reason="No eligible negative controls defined for engine",
            raw_num=fp_on_neg,
            raw_denom=0,
        )

    denom = tn + fp_on_neg
    if denom <= 0:
        return MetricValue(
            value=None,
            is_na=True,
            reason="No negative controls evaluated",
            raw_num=fp_on_neg,
            raw_denom=0,
        )

    fpr = fp_on_neg / denom
    lo, hi = wilson_score_interval(fp_on_neg, denom)
    return MetricValue(
        value=fpr,
        is_na=False,
        reason=f"FPR on {denom} negative controls",
        raw_num=fp_on_neg,
        raw_denom=denom,
        ci_lower=lo,
        ci_upper=hi,
    )


def compute_false_discovery_share(
    confirmed_fp: int,
    deduplicated_findings: int,
) -> MetricValue:
    """Compute False Discovery Share = confirmed FP / deduplicated emitted findings."""
    if deduplicated_findings <= 0:
        return MetricValue(
            value=None,
            is_na=True,
            reason="Zero deduplicated findings emitted",
            raw_num=confirmed_fp,
            raw_denom=0,
        )

    val = confirmed_fp / deduplicated_findings
    lo, hi = wilson_score_interval(confirmed_fp, deduplicated_findings)
    return MetricValue(
        value=val,
        is_na=False,
        raw_num=confirmed_fp,
        raw_denom=deduplicated_findings,
        ci_lower=lo,
        ci_upper=hi,
    )


def compute_coverage(
    executed: int,
    planned: int,
    label: str = "case",
) -> MetricValue:
    """Compute coverage ratio = executed / planned."""
    if planned <= 0:
        return MetricValue(
            value=None,
            is_na=True,
            reason=f"Zero planned {label}s",
            raw_num=executed,
            raw_denom=planned,
        )

    val = executed / planned
    return MetricValue(
        value=val,
        is_na=False,
        raw_num=executed,
        raw_denom=planned,
    )


def compute_execution_error_rate(
    failed: int,
    attempted: int,
) -> MetricValue:
    """Compute execution error rate = failed / attempted."""
    if attempted <= 0:
        return MetricValue(
            value=None,
            is_na=True,
            reason="Zero attempted cases",
            raw_num=failed,
            raw_denom=attempted,
        )

    val = failed / attempted
    return MetricValue(
        value=val,
        is_na=False,
        raw_num=failed,
        raw_denom=attempted,
    )


def compute_severity_weighted_recall(
    case_results: list[dict[str, Any]],
    severity_weights: Optional[dict[str, float]] = None,
) -> MetricValue:
    """Compute Severity-Weighted Recall over vulnerable cases.

    weights default: critical=4.0, high=3.0, medium=2.0, low=1.0, info=0.5
    """
    weights = severity_weights or {
        "critical": 4.0,
        "high": 3.0,
        "medium": 2.0,
        "low": 1.0,
        "info": 0.5,
    }

    total_weight = 0.0
    detected_weight = 0.0

    for c in case_results:
        # Only evaluate vulnerable cases
        if c.get("is_negative_control") or c.get("truth_state") != "CONFIRMED_VULNERABLE":
            continue

        sev = (c.get("expected_severity") or "medium").lower()
        w = weights.get(sev, 1.0)
        total_weight += w

        if c.get("bucket") == FindingBucket.TP.value or c.get("bucket") == FindingBucket.TP:
            detected_weight += w

    if total_weight <= 0:
        return MetricValue(
            value=None,
            is_na=True,
            reason="Zero weighted vulnerable cases",
        )

    val = detected_weight / total_weight
    return MetricValue(
        value=val,
        is_na=False,
        reason=f"Weighted recall (total weight: {total_weight:.1f})",
    )


def compute_repeated_run_stats(
    run_recalls: list[float],
) -> dict[str, Any]:
    """Compute scanner non-determinism stats over repeated identical runs.

    Spec: 'repeated runs (default 3 when cheap) measure scanner non-determinism ONLY: report n, mean, sd'
    """
    n = len(run_recalls)
    if n == 0:
        return {"n": 0, "mean": None, "sd": None}
    if n == 1:
        return {"n": 1, "mean": round(run_recalls[0], 4), "sd": 0.0}

    mean = sum(run_recalls) / n
    variance = sum((x - mean) ** 2 for x in run_recalls) / (n - 1)
    sd = math.sqrt(variance)

    return {
        "n": n,
        "mean": round(mean, 4),
        "sd": round(sd, 4),
    }


def evaluate_benchmark_decision(
    execution_status: ExecutionStatus,
    in_scope_recall: MetricValue,
    fpr_on_neg: MetricValue,
    case_coverage: MetricValue,
    error_rate: MetricValue,
    critical_fn: int,
    critical_fp: int,
    thresholds: dict[str, Any],
) -> Tuple[BenchmarkStatus, list[str], list[str]]:
    """Determine benchmark PASS/PARTIAL/FAIL status against committed thresholds.

    Rules:
      1. A run can complete execution and still FAIL benchmark.
      2. A PARTIAL execution is NEVER promoted to PASS.
      3. PASS requires all planned eligible cases to be executed (coverage == 1.0).
      4. Critical FN and FP trigger mandatory review flags.
    """
    reasons: list[str] = []
    review_flags: list[str] = []

    # Check critical alerts
    if critical_fn > 0:
        review_flags.append(f"MANDATORY_REVIEW: {critical_fn} critical-severity False Negative(s) detected.")
    if critical_fp > 0:
        review_flags.append(f"MANDATORY_REVIEW: {critical_fp} critical-severity False Positive(s) detected.")

    # Execution failure or blocked
    if execution_status in (ExecutionStatus.FAILED, ExecutionStatus.BLOCKED, ExecutionStatus.CANCELLED):
        reasons.append(f"Execution did not succeed ({execution_status.value}).")
        return BenchmarkStatus.ERROR, reasons, review_flags

    # Partial execution rule
    if execution_status == ExecutionStatus.PARTIAL:
        reasons.append("Execution was partial; partial runs cannot be promoted to benchmark PASS.")
        return BenchmarkStatus.PARTIAL, reasons, review_flags

    min_recall = float(thresholds.get("min_in_scope_recall", 0.70))
    max_fpr    = float(thresholds.get("max_fpr_negative_controls", 0.20))
    min_cov    = float(thresholds.get("min_case_coverage", 1.00))

    passed = True

    # 1. Coverage
    if case_coverage.value is None or case_coverage.value < min_cov:
        passed = False
        reasons.append(f"Case coverage ({case_coverage.value}) below mandatory threshold ({min_cov}).")

    # 2. Recall
    if in_scope_recall.value is None or in_scope_recall.value < min_recall:
        passed = False
        reasons.append(f"In-scope recall ({in_scope_recall.value}) below minimum threshold ({min_recall}).")

    # 3. FPR on negative controls (if negative controls existed)
    if not fpr_on_neg.is_na and fpr_on_neg.value is not None:
        if fpr_on_neg.value > max_fpr:
            passed = False
            reasons.append(f"FPR on negative controls ({fpr_on_neg.value}) exceeded maximum threshold ({max_fpr}).")

    final_status = BenchmarkStatus.PASS if passed else BenchmarkStatus.FAIL
    if final_status == BenchmarkStatus.PASS:
        reasons.append("All committed benchmark acceptance thresholds satisfied.")

    return final_status, reasons, review_flags
