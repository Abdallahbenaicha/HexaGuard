"""SecuraX Evaluation Lab — Domain Models & Enums.

Conforms to Master Specification v5 Phase 1:
  - Distinct target kinds: bundled_fixture, local_source_project, local_container,
    public_permitted, public_reference.
  - Fail-closed gate evaluation results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class TargetKind(str, Enum):
    BUNDLED_FIXTURE      = "bundled_fixture"
    LOCAL_SOURCE_PROJECT = "local_source_project"
    LOCAL_CONTAINER      = "local_container"
    PUBLIC_PERMITTED     = "public_permitted"
    PUBLIC_REFERENCE     = "public_reference"


class GateDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY  = "DENY"


@dataclass
class LabTarget:
    id: str
    name: str
    kind: TargetKind
    scanners: list[str] = field(default_factory=list)
    address: Optional[str] = None
    source_url: Optional[str] = None
    license: Optional[str] = None
    legal_note: Optional[str] = None
    permitted_scan_types: list[str] = field(default_factory=list)
    rate_limit: int = 10
    max_concurrency: int = 1
    enabled: bool = True
    manifest_path: Optional[str] = None
    difficulty: str = "medium"
    resource_needs: dict[str, Any] = field(default_factory=dict)
    setup_status: str = "ready"
    last_health_check: Optional[str] = None
    auth_source_url: Optional[str] = None
    auth_verified_at: Optional[str] = None
    auth_expires_at: Optional[str] = None
    expected_fingerprint: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id":                   self.id,
            "name":                 self.name,
            "kind":                 self.kind.value if isinstance(self.kind, TargetKind) else str(self.kind),
            "scanners":             self.scanners,
            "address":              self.address,
            "source_url":           self.source_url,
            "license":              self.license,
            "legal_note":           self.legal_note,
            "permitted_scan_types": self.permitted_scan_types,
            "rate_limit":           self.rate_limit,
            "max_concurrency":      self.max_concurrency,
            "enabled":              bool(self.enabled),
            "manifest_path":        self.manifest_path,
            "difficulty":           self.difficulty,
            "resource_needs":       self.resource_needs,
            "setup_status":         self.setup_status,
            "last_health_check":    self.last_health_check,
            "auth_source_url":      self.auth_source_url,
            "auth_verified_at":     self.auth_verified_at,
            "auth_expires_at":      self.auth_expires_at,
            "expected_fingerprint": self.expected_fingerprint,
            "is_executable":        self.is_executable(),
        }

    def is_executable(self) -> bool:
        """public_reference is NEVER executable under any circumstances."""
        if self.kind == TargetKind.PUBLIC_REFERENCE or str(self.kind) == "public_reference":
            return False
        return bool(self.enabled)


@dataclass
class LabGateResult:
    decision: GateDecision
    allowed: bool
    reason_code: str
    message: str
    target_id: str
    scanner: str
    scan_type: str
    verified_address: Optional[str] = None
    rate_limit: int = 10
    audit_logged: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision":         self.decision.value,
            "allowed":          self.allowed,
            "reason_code":      self.reason_code,
            "message":          self.message,
            "target_id":        self.target_id,
            "scanner":          self.scanner,
            "scan_type":        self.scan_type,
            "verified_address": self.verified_address,
            "rate_limit":       self.rate_limit,
            "audit_logged":     self.audit_logged,
        }


# ══════════════════════════════════════════════════════════════════════════════
# Phase 2 — Ground Truth, Eligibility & Scoring Models (Master Spec v5)
# ══════════════════════════════════════════════════════════════════════════════

class TruthState(str, Enum):
    CONFIRMED_VULNERABLE = "CONFIRMED_VULNERABLE"
    CONFIRMED_CLEAN      = "CONFIRMED_CLEAN"
    UNKNOWN              = "UNKNOWN"
    NOT_APPLICABLE       = "NOT_APPLICABLE"


class DatasetSplit(str, Enum):
    DEV     = "dev"
    HELDOUT = "heldout"


class EligibilityStatus(str, Enum):
    ELIGIBLE                 = "ELIGIBLE"
    NOT_SUPPORTED            = "NOT_SUPPORTED"
    NOT_APPLICABLE           = "NOT_APPLICABLE"
    BLOCKED_BY_CONFIGURATION = "BLOCKED_BY_CONFIGURATION"
    NOT_EXECUTED             = "NOT_EXECUTED"
    EXECUTION_ERROR          = "EXECUTION_ERROR"


class FindingBucket(str, Enum):
    TP           = "TP"
    FN           = "FN"
    CONFIRMED_FP = "CONFIRMED_FP"
    UNREVIEWED   = "UNREVIEWED"
    UNVERIFIED   = "UNVERIFIED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ExecutionStatus(str, Enum):
    COMPLETED = "COMPLETED"
    PARTIAL   = "PARTIAL"
    FAILED    = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"
    BLOCKED   = "BLOCKED"


class BenchmarkStatus(str, Enum):
    PASS          = "PASS"
    PARTIAL       = "PARTIAL"
    FAIL          = "FAIL"
    INCONCLUSIVE  = "INCONCLUSIVE"
    ERROR         = "ERROR"
    NOT_EVALUATED = "NOT_EVALUATED"


@dataclass
class MetricValue:
    """Explicit container for metrics, supporting honest N/A with reason and Wilson CIs."""
    value: Optional[float] = None
    is_na: bool = False
    reason: Optional[str] = None
    raw_num: Optional[int] = None
    raw_denom: Optional[int] = None
    ci_lower: Optional[float] = None
    ci_upper: Optional[float] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": round(self.value, 4) if self.value is not None else None,
            "percentage": f"{self.value * 100:.1f}%" if self.value is not None else "N/A",
            "is_na": self.is_na,
            "reason": self.reason,
            "raw_num": self.raw_num,
            "raw_denom": self.raw_denom,
            "ci_95": [round(self.ci_lower, 4), round(self.ci_upper, 4)] if self.ci_lower is not None else None,
        }


@dataclass
class GroundTruthCase:
    """Curated, versioned ground truth case."""
    case_id: str
    dataset_id: str
    dataset_version: str
    split: DatasetSplit
    target_id: str
    vulnerability_type: str
    cwe: str
    truth_state: TruthState
    expected_severity: str
    location: dict[str, Any]
    expected_evidence: str
    verification_method: str
    eligible_engines: list[str]
    preconditions: dict[str, Any] = field(default_factory=dict)
    difficulty: int = 1
    hint: str = ""
    explanation: str = ""
    learn_ref: str = ""
    is_negative_control: bool = False
    source_license: str = ""
    checksum: str = ""
    reviewers: list[str] = field(default_factory=list)
    last_validated: str = ""

    def is_eligible_for_engine(self, engine_id: str) -> bool:
        return engine_id in self.eligible_engines

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "dataset_id": self.dataset_id,
            "dataset_version": self.dataset_version,
            "split": self.split.value if isinstance(self.split, DatasetSplit) else str(self.split),
            "target_id": self.target_id,
            "vulnerability_type": self.vulnerability_type,
            "cwe": self.cwe,
            "truth_state": self.truth_state.value if isinstance(self.truth_state, TruthState) else str(self.truth_state),
            "expected_severity": self.expected_severity,
            "location": self.location,
            "expected_evidence": self.expected_evidence,
            "verification_method": self.verification_method,
            "eligible_engines": self.eligible_engines,
            "preconditions": self.preconditions,
            "difficulty": self.difficulty,
            "hint": self.hint,
            "explanation": self.explanation,
            "learn_ref": self.learn_ref,
            "is_negative_control": self.is_negative_control,
            "source_license": self.source_license,
            "checksum": self.checksum,
            "reviewers": self.reviewers,
            "last_validated": self.last_validated,
        }


@dataclass
class CandidateFinding:
    """Normalized finding emitted by a scanner adapter during evaluation."""
    finding_id: str
    engine_id: str
    target_id: str
    cwe: str
    severity: str
    location: dict[str, Any]
    evidence: str = ""
    raw_payload: Optional[dict[str, Any]] = None
    rule_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "engine_id": self.engine_id,
            "target_id": self.target_id,
            "cwe": self.cwe,
            "severity": self.severity,
            "location": self.location,
            "evidence": self.evidence,
            "rule_id": self.rule_id,
        }


@dataclass
class MatchResult:
    """Pairing between a candidate finding and a ground truth case."""
    finding: CandidateFinding
    matched_case: Optional[GroundTruthCase]
    bucket: FindingBucket
    match_confidence: float
    notes: str = ""


EMPTY_RESULT_WORDING = "No findings within the verified scope and coverage shown"


class DeltaLossReason(str, Enum):
    """Reason codes for findings transformations or losses between pipeline stages (Phase 4)."""
    PARSE_ERROR            = "PARSE_ERROR"
    SEVERITY_FILTER        = "SEVERITY_FILTER"
    POLICY_FILTER          = "POLICY_FILTER"
    DEDUPLICATION          = "DEDUPLICATION"
    LOCATION_NORMALIZATION = "LOCATION_NORMALIZATION"
    VALIDATION_REJECTION   = "VALIDATION_REJECTION"
    TRUNCATION             = "TRUNCATION"
    TIMEOUT                = "TIMEOUT"
    STORED_BUT_HIDDEN      = "STORED_BUT_HIDDEN"
    WRONG_MERGE            = "WRONG_MERGE"
    GROUND_TRUTH_MATCH     = "GROUND_TRUTH_MATCH"
    UNREVIEWED_ROUTING     = "UNREVIEWED_ROUTING"
    UNAVAILABLE            = "WRAPPER_DELTA_UNAVAILABLE"


@dataclass
class ScanCoverageTelemetry:
    """Optional adapter coverage and scan telemetry metadata (Phase 4).

    Master Spec v5 Phase 4:
      - Every adapter reports status and coverage via new OPTIONAL fields (old consumers unaffected).
      - Crashed, timed-out or zero-coverage scan never displays as success.
      - Empty result wording: 'No findings within the verified scope and coverage shown', never 'secure'.
    """
    urls_visited: list[str] = field(default_factory=list)
    params_visited: list[str] = field(default_factory=list)
    routes_skipped: list[str] = field(default_factory=list)
    auth_status: str = "not_applicable"  # success | failure | not_applicable
    files_analyzed: list[str] = field(default_factory=list)
    languages_analyzed: list[str] = field(default_factory=list)
    packages_inspected: int = 0
    ports_probed: list[int] = field(default_factory=list)
    rules_executed: list[str] = field(default_factory=list)
    requests_attempted: int = 0
    requests_completed: int = 0
    timeouts_errors: list[str] = field(default_factory=list)
    scope_exclusions: list[str] = field(default_factory=list)
    lines_of_code: int = 0
    empty_result_wording: str = EMPTY_RESULT_WORDING
    zero_coverage: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "urls_visited": self.urls_visited,
            "params_visited": self.params_visited,
            "routes_skipped": self.routes_skipped,
            "auth_status": self.auth_status,
            "files_analyzed": self.files_analyzed,
            "languages_analyzed": self.languages_analyzed,
            "packages_inspected": self.packages_inspected,
            "ports_probed": self.ports_probed,
            "rules_executed": self.rules_executed,
            "requests_attempted": self.requests_attempted,
            "requests_completed": self.requests_completed,
            "timeouts_errors": self.timeouts_errors,
            "scope_exclusions": self.scope_exclusions,
            "lines_of_code": self.lines_of_code,
            "empty_result_wording": self.empty_result_wording,
            "zero_coverage": self.zero_coverage,
        }


@dataclass
class LostFindingItem:
    """Individual finding lost, suppressed, or transformed between pipeline stages."""
    finding_id: str
    rule_id: str
    stage_from: str
    stage_to: str
    reason_code: DeltaLossReason | str
    location: dict[str, Any] = field(default_factory=dict)
    root_cause: str = "suspected"
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        reason_val = self.reason_code.value if isinstance(self.reason_code, DeltaLossReason) else str(self.reason_code)
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "stage_from": self.stage_from,
            "stage_to": self.stage_to,
            "reason_code": reason_val,
            "location": self.location,
            "root_cause": self.root_cause,
            "details": self.details,
        }


@dataclass
class WrapperDeltaStage:
    """Findings count and transitions at a single pipeline stage."""
    stage_name: str
    count: int
    delta_from_previous: int = 0
    lost_items: list[LostFindingItem] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage_name": self.stage_name,
            "count": self.count,
            "delta_from_previous": self.delta_from_previous,
            "lost_items": [item.to_dict() for item in self.lost_items],
        }


@dataclass
class WrapperDeltaReport:
    """Wrapper Delta across the four stages of the evaluation pipeline (Phase 4).

    Stages:
      1. Raw Tool Output (raw native CLI/scanner stdout JSON)
      2. Adapter Output (normalized CandidateFinding objects)
      3. Persisted Findings (stored in benchmark scorecard & database)
      4. API & UI Displayed Findings (returned to clients & rendered in HTML view)
    """
    stage_1_raw: WrapperDeltaStage
    stage_2_adapter: WrapperDeltaStage
    stage_3_persisted: WrapperDeltaStage
    stage_4_displayed: WrapperDeltaStage
    total_raw_count: int
    total_displayed_count: int
    total_net_delta: int
    has_unexplained_loss: bool = False
    warning_flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stages": {
                "stage_1_raw": self.stage_1_raw.to_dict(),
                "stage_2_adapter": self.stage_2_adapter.to_dict(),
                "stage_3_persisted": self.stage_3_persisted.to_dict(),
                "stage_4_displayed": self.stage_4_displayed.to_dict(),
            },
            "summary": {
                "total_raw_count": self.total_raw_count,
                "total_displayed_count": self.total_displayed_count,
                "total_net_delta": self.total_net_delta,
                "has_unexplained_loss": self.has_unexplained_loss,
                "warning_flags": self.warning_flags,
            },
        }


@dataclass
class BenchmarkScorecard:
    """Complete, honestly separated benchmark scorecard."""
    protocol_version: str
    engine_id: str
    target_id: str
    dataset_id: str
    dataset_version: str
    execution_status: ExecutionStatus
    benchmark_status: BenchmarkStatus
    status_reasons: list[str]

    # Counts
    total_reference_cases: int
    eligible_cases: int
    unsupported_cases: int
    executed_eligible: int
    planned_eligible: int
    attempted_eligible: int
    failed_eligible: int

    # Core Buckets
    tp_count: int
    fn_count: int
    confirmed_fp_count: int
    unreviewed_count: int
    unverified_count: int
    inconclusive_count: int

    # Negative Controls
    eligible_negative_controls: int
    tn_count: int
    fp_on_negative_controls: int

    # Metrics
    in_scope_recall: MetricValue
    absolute_recall: MetricValue
    precision_lower_bound: MetricValue
    precision_optimistic_upper_bound: MetricValue
    f1_score: MetricValue
    false_discovery_share: MetricValue
    fpr_on_negative_controls: MetricValue
    case_coverage: MetricValue
    execution_error_rate: MetricValue
    severity_weighted_recall: MetricValue

    # Details
    per_cwe_metrics: dict[str, Any] = field(default_factory=dict)
    per_severity_metrics: dict[str, Any] = field(default_factory=dict)
    critical_review_flags: list[str] = field(default_factory=list)
    repeated_run_stats: Optional[dict[str, Any]] = None
    missed_cases: list[dict[str, Any]] = field(default_factory=list)
    unreviewed_queue: list[dict[str, Any]] = field(default_factory=list)
    negative_control_evaluations: list[dict[str, Any]] = field(default_factory=list)
    matched_cases: list[dict[str, Any]] = field(default_factory=list)
    benchmark_id: Optional[str] = None

    # Phase 4 Completeness & Wrapper Delta (Optional fields, old consumers unaffected)
    coverage_telemetry: Optional[dict[str, Any]] = None
    wrapper_delta: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark_id": self.benchmark_id,
            "protocol_version": self.protocol_version,
            "engine_id": self.engine_id,
            "target_id": self.target_id,
            "dataset_id": self.dataset_id,
            "dataset_version": self.dataset_version,
            "execution_status": self.execution_status.value,
            "benchmark_status": self.benchmark_status.value,
            "status_reasons": self.status_reasons,
            "counts": {
                "total_reference_cases": self.total_reference_cases,
                "eligible_cases": self.eligible_cases,
                "unsupported_cases": self.unsupported_cases,
                "executed_eligible": self.executed_eligible,
                "planned_eligible": self.planned_eligible,
                "tp": self.tp_count,
                "fn": self.fn_count,
                "confirmed_fp": self.confirmed_fp_count,
                "unreviewed": self.unreviewed_count,
                "unverified": self.unverified_count,
                "inconclusive": self.inconclusive_count,
                "eligible_negative_controls": self.eligible_negative_controls,
                "tn": self.tn_count,
                "fp_on_negative_controls": self.fp_on_negative_controls,
            },
            "metrics": {
                "in_scope_recall": self.in_scope_recall.to_dict(),
                "absolute_recall": self.absolute_recall.to_dict(),
                "precision_lower_bound": self.precision_lower_bound.to_dict(),
                "precision_optimistic_upper_bound": self.precision_optimistic_upper_bound.to_dict(),
                "f1_score": self.f1_score.to_dict(),
                "false_discovery_share": self.false_discovery_share.to_dict(),
                "fpr_on_negative_controls": self.fpr_on_negative_controls.to_dict(),
                "case_coverage": self.case_coverage.to_dict(),
                "execution_error_rate": self.execution_error_rate.to_dict(),
                "severity_weighted_recall": self.severity_weighted_recall.to_dict(),
            },
            "per_cwe": self.per_cwe_metrics,
            "per_severity": self.per_severity_metrics,
            "critical_review_flags": self.critical_review_flags,
            "repeated_run_stats": self.repeated_run_stats,
            "missed_cases": self.missed_cases,
            "unreviewed_queue": self.unreviewed_queue,
            "negative_control_evaluations": self.negative_control_evaluations,
            "matched_cases": self.matched_cases,
            "coverage_telemetry": self.coverage_telemetry,
            "wrapper_delta": self.wrapper_delta,
        }
