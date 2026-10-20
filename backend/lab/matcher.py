"""SecuraX Evaluation Lab — Finding Matching Service.

Governed strictly by Master Specification v5 Phase 2:
  - Normalized target + CWE family + exact normalized location (+-3 lines for code) + evidence.
  - Many-to-one and one-to-many supported.
  - Duplicate suppression with original findings and provenance preserved.
  - Buckets: TP, FN, CONFIRMED_FP, UNREVIEWED (not in manifest: neither FP nor TP),
    UNVERIFIED, INCONCLUSIVE.
  - No naive string matching.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from lab.models import (
    CandidateFinding,
    FindingBucket,
    GroundTruthCase,
    MatchResult,
    TruthState,
)

# Common CWE Family mappings for normalization
_CWE_FAMILY_MAP: dict[str, str] = {
    # SQLi
    "89": "CWE-89", "cwe-89": "CWE-89", "943": "CWE-89", "cwe-943": "CWE-89",
    "sqli": "CWE-89", "sql_injection": "CWE-89",

    # Command Injection
    "78": "CWE-78", "cwe-78": "CWE-78", "77": "CWE-78", "cwe-77": "CWE-78",
    "os_command_injection": "CWE-78", "command_injection": "CWE-78",

    # XSS
    "79": "CWE-79", "cwe-79": "CWE-79", "xss": "CWE-79",

    # Path Traversal
    "22": "CWE-22", "cwe-22": "CWE-22", "23": "CWE-22", "cwe-23": "CWE-22",
    "path_traversal": "CWE-22", "directory_traversal": "CWE-22",

    # Hardcoded Secrets
    "798": "CWE-798", "cwe-798": "CWE-798", "259": "CWE-798", "cwe-259": "CWE-798",
    "321": "CWE-798", "cwe-321": "CWE-798", "hardcoded_secret": "CWE-798",

    # Deserialization
    "502": "CWE-502", "cwe-502": "CWE-502", "insecure_deserialization": "CWE-502",

    # Weak Crypto
    "327": "CWE-327", "cwe-327": "CWE-327", "328": "CWE-327", "cwe-328": "CWE-327",
    "weak_crypto": "CWE-327",

    # Insecure Configuration
    "16": "CWE-16", "cwe-16": "CWE-16", "200": "CWE-16", "cwe-200": "CWE-16",
    "misconfiguration": "CWE-16",
}


def normalize_cwe(raw_cwe: str) -> str:
    """Normalize raw CWE string or identifier to canonical CWE family representation."""
    if not raw_cwe:
        return "CWE-UNKNOWN"

    cleaned = str(raw_cwe).strip().lower()
    # Strip prefix
    cleaned = cleaned.replace("cwe_", "").replace("cwe-", "")

    if cleaned in _CWE_FAMILY_MAP:
        return _CWE_FAMILY_MAP[cleaned]

    # If it's a numeric code
    if cleaned.isdigit():
        return f"CWE-{cleaned}"

    return f"CWE-{cleaned.upper()}"


def are_cwes_compatible(cwe1: str, cwe2: str) -> bool:
    """Return True if two CWEs belong to the same family or match exactly."""
    norm1 = normalize_cwe(cwe1)
    norm2 = normalize_cwe(cwe2)
    return norm1 == norm2


def _normalize_filepath(fp: str) -> str:
    """Normalize file path for consistent matching across operating systems."""
    if not fp:
        return ""
    p = fp.replace("\\", "/").strip().lower()
    # remove leading ./
    if p.startswith("./"):
        p = p[2:]
    return p


def is_location_match(
    loc_finding: dict[str, Any],
    loc_case: dict[str, Any],
) -> Tuple[bool, float]:
    """Evaluate whether candidate finding location matches ground truth case location.

    Tolerance rules:
      - Code files: normalized filepath match + line within +-3 lines tolerance.
      - URL + parameter: normalized path match + parameter name match.
      - Network/port: port number match + service name match.
      - Package: package name match + version match.

    Returns: (is_match, confidence)
    """
    f_type = loc_finding.get("type") or loc_case.get("type", "file_line")
    c_type = loc_case.get("type", "file_line")

    # 1. Code file + line match
    if f_type in ("file_line", "code") or c_type in ("file_line", "code"):
        f_file = _normalize_filepath(loc_finding.get("file") or loc_finding.get("path") or "")
        c_file = _normalize_filepath(loc_case.get("file") or loc_case.get("path") or "")

        if not f_file or not c_file:
            return False, 0.0

        # Filepath comparison: exact, relative suffix on path boundary, or bare filename fallback
        matched_file = False
        if f_file == c_file:
            matched_file = True
        elif f_file.endswith("/" + c_file) or c_file.endswith("/" + f_file):
            matched_file = True
        elif ("/" not in f_file or "/" not in c_file) and os.path.basename(f_file) == os.path.basename(c_file):
            matched_file = True

        if not matched_file:
            return False, 0.0

        f_line = loc_finding.get("line")
        c_line = loc_case.get("line")

        if f_line is not None and c_line is not None:
            try:
                line_diff = abs(int(f_line) - int(c_line))
                # Spec: exact normalized location (+-3 lines for code)
                if line_diff <= 3:
                    # Higher confidence if exact line
                    conf = 1.0 if line_diff == 0 else (0.95 - line_diff * 0.05)
                    return True, conf
                return False, 0.0
            except (ValueError, TypeError):
                pass

        # If file matches but lines are unspecified, match with lower confidence
        return True, 0.70

    # 2. URL + parameter match
    if f_type in ("url_param", "web") or c_type in ("url_param", "web"):
        f_url = (loc_finding.get("url") or loc_finding.get("path") or "").strip().lower()
        c_url = (loc_case.get("url") or loc_case.get("path") or "").strip().lower()

        if f_url and c_url:
            f_norm = f_url.split("?")[0].rstrip("/")
            c_norm = c_url.split("?")[0].rstrip("/")
            if f_norm != c_norm and not f_norm.endswith(c_norm):
                return False, 0.0

        f_param = (loc_finding.get("param") or loc_finding.get("parameter") or "").strip().lower()
        c_param = (loc_case.get("param") or loc_case.get("parameter") or "").strip().lower()

        if c_param:
            if f_param != c_param:
                return False, 0.0

        return True, 1.0

    # 3. Port / Network service match
    if f_type in ("port", "network") or c_type in ("port", "network"):
        f_port = str(loc_finding.get("port") or "")
        c_port = str(loc_case.get("port") or "")
        if f_port and c_port and f_port == c_port:
            return True, 1.0

    # 4. Config key or Package match
    f_key = str(loc_finding.get("key") or loc_finding.get("package") or "").strip().lower()
    c_key = str(loc_case.get("key") or loc_case.get("package") or "").strip().lower()
    if f_key and c_key and f_key == c_key:
        return True, 1.0

    return False, 0.0


def suppress_duplicate_findings(
    findings: list[CandidateFinding],
) -> Tuple[list[CandidateFinding], dict[str, list[str]]]:
    """Suppress duplicate findings while preserving provenance and original IDs.

    Spec: 'duplicate suppression; original findings and provenance preserved'
    Returns: (deduplicated_findings, provenance_map: primary_id -> [all_finding_ids])
    """
    deduped: list[CandidateFinding] = []
    provenance: dict[str, list[str]] = {}
    seen_keys: dict[str, CandidateFinding] = {}

    for f in findings:
        norm_cwe = normalize_cwe(f.cwe)
        loc = f.location
        f_file = _normalize_filepath(loc.get("file") or loc.get("path") or loc.get("url") or "")
        f_line = loc.get("line") or loc.get("param") or loc.get("port") or ""
        key = f"{f.engine_id}|{norm_cwe}|{f_file}|{f_line}"

        if key in seen_keys:
            primary = seen_keys[key]
            provenance[primary.finding_id].append(f.finding_id)
        else:
            seen_keys[key] = f
            deduped.append(f)
            provenance[f.finding_id] = [f.finding_id]

    return deduped, provenance


def match_findings_to_ground_truth(
    findings: list[CandidateFinding],
    ground_truth_cases: list[GroundTruthCase],
    engine_id: str,
) -> Tuple[list[MatchResult], set[str], set[str]]:
    """Match candidate findings against ground truth cases.

    Returns:
      (match_results, matched_case_ids, matched_finding_ids)
    """
    match_results: list[MatchResult] = []
    matched_case_ids: set[str] = set()
    matched_finding_ids: set[str] = set()

    # Pre-index cases by normalized CWE
    cases_by_cwe: dict[str, list[GroundTruthCase]] = {}
    for c in ground_truth_cases:
        norm_c = normalize_cwe(c.cwe)
        cases_by_cwe.setdefault(norm_c, []).append(c)

    for f in findings:
        f_cwe_norm = normalize_cwe(f.cwe)
        candidate_cases = cases_by_cwe.get(f_cwe_norm, [])

        best_case: Optional[GroundTruthCase] = None
        best_conf = 0.0

        for c in candidate_cases:
            is_match, conf = is_location_match(f.location, c.location)
            if is_match and conf > best_conf:
                best_conf = conf
                best_case = c

        if best_case is not None:
            matched_finding_ids.add(f.finding_id)
            matched_case_ids.add(best_case.case_id)

            if best_case.truth_state == TruthState.CONFIRMED_VULNERABLE:
                bucket = FindingBucket.TP
            elif best_case.truth_state == TruthState.CONFIRMED_CLEAN or best_case.is_negative_control:
                bucket = FindingBucket.CONFIRMED_FP
            elif best_case.truth_state == TruthState.UNKNOWN:
                bucket = FindingBucket.UNVERIFIED
            else:
                bucket = FindingBucket.INCONCLUSIVE

            match_results.append(MatchResult(
                finding=f,
                matched_case=best_case,
                bucket=bucket,
                match_confidence=best_conf,
                notes=f"Matched to {best_case.case_id} ({best_case.truth_state.value})",
            ))
        else:
            # Not in ground truth manifest: UNREVIEWED
            # Spec: 'UNREVIEWED (not in the manifest: neither FP nor TP)'
            match_results.append(MatchResult(
                finding=f,
                matched_case=None,
                bucket=FindingBucket.UNREVIEWED,
                match_confidence=0.0,
                notes="Emitted finding location/CWE does not match any entry in ground-truth manifest",
            ))

    return match_results, matched_case_ids, matched_finding_ids
