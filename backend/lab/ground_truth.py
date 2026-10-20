"""SecuraX Evaluation Lab — Ground Truth Registry & Eligibility Service.

Governed strictly by Master Specification v5 Phase 2:
  - Curated, versioned ground truth cases.
  - Truth states: CONFIRMED_VULNERABLE, CONFIRMED_CLEAN, UNKNOWN, NOT_APPLICABLE.
  - UNKNOWN never becomes clean; ground truth is independent of scanners.
  - Fixed eligibility per (engine x case) recorded BEFORE the run:
    ELIGIBLE | NOT_SUPPORTED | NOT_APPLICABLE | BLOCKED_BY_CONFIGURATION | NOT_EXECUTED | EXECUTION_ERROR.
  - Unsupported cases are NEVER false negatives.
  - Dev vs held-out split isolation.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from lab.models import (
    DatasetSplit,
    EligibilityStatus,
    GroundTruthCase,
    TruthState,
)

logger = logging.getLogger(__name__)

# Default seed data path
_DEFAULT_SEED_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "ground_truth_seed.json",
)


def parse_ground_truth_case(raw: dict[str, Any]) -> GroundTruthCase:
    """Parse raw dictionary into typed GroundTruthCase domain model."""
    split_str = raw.get("split", "dev").lower()
    split = DatasetSplit.HELDOUT if split_str == "heldout" else DatasetSplit.DEV

    truth_str = raw.get("truth_state", "CONFIRMED_VULNERABLE").upper()
    try:
        truth_state = TruthState(truth_str)
    except ValueError:
        truth_state = TruthState.UNKNOWN

    return GroundTruthCase(
        case_id=str(raw["case_id"]),
        dataset_id=str(raw.get("dataset_id", "hexaguard_bench_core")),
        dataset_version=str(raw.get("dataset_version", "1.0.0")),
        split=split,
        target_id=str(raw.get("target_id", "")),
        vulnerability_type=str(raw.get("vulnerability_type", "")),
        cwe=str(raw.get("cwe", "CWE-UNKNOWN")),
        truth_state=truth_state,
        expected_severity=str(raw.get("expected_severity", "medium")).lower(),
        location=dict(raw.get("location", {})),
        expected_evidence=str(raw.get("expected_evidence", "")),
        verification_method=str(raw.get("verification_method", "manual_audit")),
        eligible_engines=list(raw.get("eligible_engines", [])),
        preconditions=dict(raw.get("preconditions", {})),
        difficulty=int(raw.get("difficulty", 1)),
        hint=str(raw.get("hint", "")),
        explanation=str(raw.get("explanation", "")),
        learn_ref=str(raw.get("learn_ref", "")),
        is_negative_control=bool(raw.get("is_negative_control", False)),
        source_license=str(raw.get("source_license", "")),
        checksum=str(raw.get("checksum", "")),
        reviewers=list(raw.get("reviewers", [])),
        last_validated=str(raw.get("last_validated", "")),
    )


def load_ground_truth_cases(
    seed_file_path: Optional[str] = None,
    split: Optional[str] = "dev",
    target_id: Optional[str] = None,
    dataset_id: Optional[str] = None,
    dataset_version: Optional[str] = None,
) -> list[GroundTruthCase]:
    """Load ground truth cases from seed JSON file, with optional filtering.

    Default split is 'dev' to prevent unintentional leakage of held-out benchmark cases.
    Pass split='heldout' for held-out evaluation, or split='all' (or None) to load all splits.
    """
    path = seed_file_path or _DEFAULT_SEED_PATH
    if not os.path.exists(path):
        logger.warning("Ground truth seed file not found: %s", path)
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_cases = json.load(f)
    except Exception as exc:
        logger.error("Failed to load ground truth seed file %s: %s", path, exc)
        return []

    cases: list[GroundTruthCase] = []
    for raw in raw_cases:
        case = parse_ground_truth_case(raw)
        if split and str(split).lower() != "all" and case.split.value != str(split).lower():
            continue
        if target_id and case.target_id != target_id:
            continue
        if dataset_id and case.dataset_id != dataset_id:
            continue
        if dataset_version and case.dataset_version != dataset_version:
            continue
        cases.append(case)

    return cases


def get_ground_truth_case(
    case_id: str,
    seed_file_path: Optional[str] = None,
) -> Optional[GroundTruthCase]:
    """Retrieve a single ground truth case by its unique case_id across all splits."""
    cases = load_ground_truth_cases(seed_file_path=seed_file_path, split="all")
    for c in cases:
        if c.case_id == case_id:
            return c
    return None


def evaluate_case_eligibility(
    case: GroundTruthCase,
    engine_id: str,
    engine_config: Optional[dict[str, Any]] = None,
) -> EligibilityStatus:
    """Evaluate and fix eligibility per (engine x case) BEFORE the run.

    Spec:
      - Fixed and recorded BEFORE the run.
      - Unsupported cases are NEVER false negatives.
      - A hard case is NEVER made ineligible after a miss.
    """
    # 1. Engine support check
    if not case.is_eligible_for_engine(engine_id):
        return EligibilityStatus.NOT_SUPPORTED

    # 2. Configuration check if engine config provided
    if engine_config:
        enabled_types = engine_config.get("enabled_vulnerability_types")
        if enabled_types and case.vulnerability_type not in enabled_types:
            return EligibilityStatus.BLOCKED_BY_CONFIGURATION

        disabled_cwes = engine_config.get("disabled_cwes", [])
        if case.cwe in disabled_cwes:
            return EligibilityStatus.BLOCKED_BY_CONFIGURATION

    return EligibilityStatus.ELIGIBLE


def partition_cases_for_engine(
    cases: list[GroundTruthCase],
    engine_id: str,
    engine_config: Optional[dict[str, Any]] = None,
) -> Tuple[list[GroundTruthCase], list[GroundTruthCase]]:
    """Partition reference cases into eligible and unsupported sets.

    Returns: (eligible_cases, unsupported_cases)
    """
    eligible: list[GroundTruthCase] = []
    unsupported: list[GroundTruthCase] = []

    for c in cases:
        status = evaluate_case_eligibility(c, engine_id, engine_config)
        if status == EligibilityStatus.ELIGIBLE:
            eligible.append(c)
        else:
            unsupported.append(c)

    return eligible, unsupported
