"""SecuraX Evaluation Lab Package.

Conforms to Master Specification v5 Phase 1 (Foundations):
  - LAB_MODE feature flag & profile isolation
  - Target Registry & Seed Loader
  - Fail-Closed Scope & Target Gate
"""

from __future__ import annotations

from lab.config import is_demo_profile, is_lab_2fa_enforced, is_lab_mode_enabled, is_lab_remote_scanning_enabled
from lab.gate import evaluate_lab_gate
from lab.models import (
    BenchmarkScorecard,
    BenchmarkStatus,
    CandidateFinding,
    DatasetSplit,
    DeltaLossReason,
    EMPTY_RESULT_WORDING,
    EligibilityStatus,
    ExecutionStatus,
    FindingBucket,
    GateDecision,
    GroundTruthCase,
    LabGateResult,
    LabTarget,
    LostFindingItem,
    MatchResult,
    MetricValue,
    ScanCoverageTelemetry,
    TargetKind,
    TruthState,
    WrapperDeltaReport,
    WrapperDeltaStage,
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

from lab.runner import (
    compute_wrapper_delta,
    extract_coverage_telemetry,
    resolve_target_address,
    run_bandit_engine,
    run_lab_benchmark,
)

__all__ = [
    # Phase 1
    "is_lab_mode_enabled",
    "is_demo_profile",
    "is_lab_remote_scanning_enabled",
    "is_lab_2fa_enforced",
    "evaluate_lab_gate",
    "TargetKind",
    "GateDecision",
    "LabTarget",
    "LabGateResult",
    # Phase 2 Models
    "TruthState",
    "DatasetSplit",
    "EligibilityStatus",
    "FindingBucket",
    "ExecutionStatus",
    "BenchmarkStatus",
    "MetricValue",
    "GroundTruthCase",
    "CandidateFinding",
    "MatchResult",
    "BenchmarkScorecard",
    # Phase 2 Ground Truth
    "load_ground_truth_cases",
    "get_ground_truth_case",
    "evaluate_case_eligibility",
    "partition_cases_for_engine",
    "parse_ground_truth_case",
    # Phase 2 Matcher
    "normalize_cwe",
    "are_cwes_compatible",
    "is_location_match",
    "suppress_duplicate_findings",
    "match_findings_to_ground_truth",
    # Phase 2 Scoring
    "wilson_score_interval",
    "compute_recall",
    "compute_precision_bounds",
    "compute_f1_score",
    "compute_fpr_on_negative_controls",
    "compute_false_discovery_share",
    "compute_coverage",
    "compute_execution_error_rate",
    "compute_severity_weighted_recall",
    "compute_repeated_run_stats",
    "evaluate_benchmark_decision",
    # Phase 3 & 4 Runner
    "run_lab_benchmark",
    "run_bandit_engine",
    "resolve_target_address",
    "compute_wrapper_delta",
    "extract_coverage_telemetry",
    "EMPTY_RESULT_WORDING",
    "DeltaLossReason",
    "ScanCoverageTelemetry",
    "LostFindingItem",
    "WrapperDeltaStage",
    "WrapperDeltaReport",
]
