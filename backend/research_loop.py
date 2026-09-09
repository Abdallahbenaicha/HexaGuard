"""SecuraX Research Loop — E3 Human Disagreement Dataset Recorder.

Captures analyst disagreements (False Positives, Missed Findings, Severity Disputes)
during Shadow Manual Pass and Triage into datasets/e3_human_disagreement/ground_truth.json
in compliance with datasets/VERSIONING.md.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

try:
    from vuln_taxonomy import normalize_check_to_vuln_type, VULN_TAXONOMY
except ImportError:
    from backend.vuln_taxonomy import normalize_check_to_vuln_type, VULN_TAXONOMY

logger = logging.getLogger(__name__)

_DATASET_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "datasets", "e3_human_disagreement")
)
_GROUND_TRUTH_PATH = os.path.join(_DATASET_DIR, "ground_truth.json")
_METADATA_PATH = os.path.join(_DATASET_DIR, "metadata.json")

_DATASET_LOCK = threading.Lock()

VALID_DISAGREEMENT_TYPES = {
    "false_positive",
    "missed_by_scanner",
    "severity_dispute",
}


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_human_disagreement(
    report_token: str,
    vuln_type: str,
    disagreement_type: str,
    scanner_id: str = "manual",
    rationale: str = "",
    evidence: str = "",
    target: str = "",
    user_id: Optional[int] = None,
) -> dict[str, Any]:
    """Persist a human disagreement record into the E3 research dataset.

    Raises:
        ValueError: If disagreement_type or vuln_type is invalid, or rationale is empty.
    """
    dtype = str(disagreement_type).strip().lower()
    if dtype not in VALID_DISAGREEMENT_TYPES:
        raise ValueError(
            f"Invalid disagreement_type '{disagreement_type}'. Must be one of {sorted(VALID_DISAGREEMENT_TYPES)}."
        )

    v_type = normalize_check_to_vuln_type(vuln_type)
    rat = str(rationale).strip()
    if not rat:
        raise ValueError("Rationale is required when recording a research disagreement.")

    record_id = f"e3-{int(time.time() * 1000)}-{os.urandom(2).hex()}"
    ts = _utcnow_iso()

    entry = {
        "id": record_id,
        "timestamp": ts,
        "report_token": str(report_token).strip(),
        "target": str(target).strip() or "unknown",
        "vuln_type": v_type,
        "scanner_id": str(scanner_id).strip() or "manual",
        "disagreement_type": dtype,
        "rationale": rat,
        "evidence": str(evidence).strip(),
        "user_id": int(user_id) if user_id is not None else None,
    }

    with _DATASET_LOCK:
        # 1. Read existing ground_truth.json
        gt_data = {"disagreements": []}
        if os.path.isfile(_GROUND_TRUTH_PATH):
            try:
                with open(_GROUND_TRUTH_PATH, "r", encoding="utf-8") as f:
                    gt_data = json.load(f)
            except Exception as exc:
                logger.warning("Failed to read %s, initializing new: %s", _GROUND_TRUTH_PATH, exc)
                gt_data = {"disagreements": []}

        if "disagreements" not in gt_data or not isinstance(gt_data["disagreements"], list):
            gt_data["disagreements"] = []

        gt_data["disagreements"].append(entry)

        # Write atomically
        os.makedirs(_DATASET_DIR, exist_ok=True)
        tmp_gt = _GROUND_TRUTH_PATH + ".tmp"
        with open(tmp_gt, "w", encoding="utf-8") as f:
            json.dump(gt_data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_gt, _GROUND_TRUTH_PATH)

        # 2. Update metadata.json counts
        meta_data = {}
        if os.path.isfile(_METADATA_PATH):
            try:
                with open(_METADATA_PATH, "r", encoding="utf-8") as f:
                    meta_data = json.load(f)
            except Exception:
                meta_data = {}

        meta_data["last_updated"] = ts
        total = len(gt_data["disagreements"])
        meta_data["total_records"] = total

        types_count: dict[str, int] = {k: 0 for k in VALID_DISAGREEMENT_TYPES}
        for item in gt_data["disagreements"]:
            dt = item.get("disagreement_type")
            if dt in types_count:
                types_count[dt] += 1
        meta_data["disagreement_types"] = types_count

        tmp_meta = _METADATA_PATH + ".tmp"
        with open(tmp_meta, "w", encoding="utf-8") as f:
            json.dump(meta_data, f, indent=2, ensure_ascii=False)
        os.replace(tmp_meta, _METADATA_PATH)

    logger.info("Recorded human disagreement %s (%s, %s)", record_id, v_type, dtype)
    return entry


def get_human_disagreements(limit: int = 100) -> dict[str, Any]:
    """Return summary and recent human disagreement records from E3 dataset."""
    with _DATASET_LOCK:
        if not os.path.isfile(_GROUND_TRUTH_PATH):
            return {"total": 0, "disagreements": [], "summary_by_type": {}}

        try:
            with open(_GROUND_TRUTH_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            logger.error("Failed to read %s: %s", _GROUND_TRUTH_PATH, exc)
            return {"total": 0, "disagreements": [], "summary_by_type": {}}

        items = data.get("disagreements", [])
        summary: dict[str, int] = {k: 0 for k in VALID_DISAGREEMENT_TYPES}
        for item in items:
            dt = item.get("disagreement_type")
            if dt in summary:
                summary[dt] += 1

        recent = items[-limit:]
        recent.reverse()

        return {
            "total": len(items),
            "summary_by_type": summary,
            "disagreements": recent,
        }
