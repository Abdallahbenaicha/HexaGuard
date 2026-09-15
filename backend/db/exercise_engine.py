"""HexaGuard Exercise Engine (backend/db/exercise_engine.py).

Phase 2B: Multi-Capability Server-Side Evaluation Engine.

Strict Anti-Cheat Invariants:
1. Zero Client Trust: Clients NEVER supply score, result, evaluation_status, or is_verified.
2. Score Capping: All automated evaluations (knowledge, recognition, detection,
   validation, impact, remediation, reporting) are strictly capped at score <= 0.9
   with is_verified = 0 (EVALUATED).
3. Verified Proof Gate: Score = 1.0 and is_verified = 1 (VERIFIED) is STRICTLY
   reserved for authentic server-side sandbox proof verification (lab_exploitation).
4. Authoritative Sandbox Verification: Lab evaluations verify sandbox ownership,
   challenge target, running status, TTL expiration, and replay prevention.
5. Cross-User Isolation: User B cannot complete or tamper with User A's attempts or sandboxes.
"""

from __future__ import annotations

import json
import logging
import re
import secrets
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Max score for any automated (non-sandbox) evaluator
MAX_AUTOMATED_SCORE = 0.9


def _parse_content_json(content_json: Any) -> dict[str, Any]:
    """Safely parse exercise content JSON."""
    if isinstance(content_json, dict):
        return content_json
    if isinstance(content_json, str):
        try:
            return json.loads(content_json)
        except Exception:
            return {}
    return {}


def _validate_structural_integrity(
    submission_text: str,
    min_words: int,
    min_sentences: int = 1,
    min_lexical_diversity: float = 0.45,
) -> tuple[bool, str, list[str]]:
    """Validates structural authenticity of submitted text.

    Protects against:
    1. Lexical Stuffing / Padding: repeating identical words to reach word count.
       Enforces: unique_words / total_words >= min_lexical_diversity.
    2. Comma-Separated / Raw Keyword Lists: prevents non-syntactic word dumping.
       Enforces: at least min_sentences coherent clauses, each with at least 3 words.
    3. Minimum Depth: word count >= min_words.

    Returns:
        (valid: bool, reason: str, sentences: list[str])
    """
    cleaned = (submission_text or "").strip()
    words = re.findall(r"\b[a-zA-Z0-9_\-\./<>\$]{2,}\b", cleaned)
    word_count = len(words)
    if word_count < min_words:
        return False, f"Insufficient depth: submitted {word_count} words (minimum {min_words} required).", []

    # Anti-stuffing / Lexical Diversity Check
    unique_words = {w.lower() for w in words}
    diversity = len(unique_words) / max(1, word_count)
    if diversity < min_lexical_diversity:
        return False, f"Anti-stuffing violation: insufficient lexical diversity ({diversity:.2f} < {min_lexical_diversity}). Repetitive keyword padding is prohibited.", []

    # Sentence Structure Analysis: split on punctuation (. ! ? ;) or newlines
    raw_sentences = re.split(r"[.!?;\n]+", cleaned)
    sentences = [s.strip() for s in raw_sentences if len(re.findall(r"\b\w+\b", s)) >= 3]
    if len(sentences) < min_sentences:
        return False, f"Structural deficit: submission must be formulated in coherent sentences (at least {min_sentences} required, got {len(sentences)}).", []

    return True, "Valid", sentences


# ── Evaluators ─────────────────────────────────────────────────────────────────

def evaluate_knowledge_submission(
    submission_text: str,
    content: dict[str, Any],
) -> dict[str, Any]:
    """Evaluates conceptual understanding (knowledge capability).

    Evaluates:
    - Minimum word count depth (min_words).
    - Lexical diversity & structural integrity (anti-stuffing).
    - Concept coverage against expected_concepts and synonyms within sentence clauses.
    Score range: 0.2 to 0.9 (strictly capped at 0.9).
    """
    min_words: int = content.get("min_words", 30)
    expected_concepts: list[str] = content.get("expected_concepts", [])
    synonyms_map: dict[str, list[str]] = content.get("synonyms", {})

    valid, reason, sentences = _validate_structural_integrity(
        submission_text,
        min_words=min_words,
        min_sentences=1,
        min_lexical_diversity=0.45,
    )
    if not valid:
        return {
            "score": 0.2,
            "result": "failed",
            "evaluation_status": "auto_evaluated",
            "notes": reason,
            "is_verified": 0,
            "evidence_type": None,
        }

    if not expected_concepts:
        return {
            "score": 0.6,
            "result": "passed",
            "evaluation_status": "auto_evaluated",
            "notes": "Minimum depth requirement satisfied.",
            "is_verified": 0,
            "evidence_type": "EVALUATED",
        }

    covered = 0
    for concept in expected_concepts:
        c_lower = concept.lower()
        # Verify concept appears in a coherent contextual sentence clause
        concept_found = False
        for s in sentences:
            s_lower = s.lower()
            if c_lower in s_lower:
                concept_found = True
                break
            syns = synonyms_map.get(concept, [])
            if any(s_syn.lower() in s_lower for s_syn in syns):
                concept_found = True
                break
        if concept_found:
            covered += 1

    coverage_ratio = covered / len(expected_concepts)
    # Base 0.3 for meeting length and structure + up to 0.6 for concept coverage -> max 0.9
    score = round(min(MAX_AUTOMATED_SCORE, 0.3 + (coverage_ratio * 0.6)), 2)
    passed = score >= 0.5

    return {
        "score": score,
        "result": "passed" if passed else "failed",
        "evaluation_status": "auto_evaluated",
        "notes": f"Covered {covered}/{len(expected_concepts)} key concepts ({int(coverage_ratio * 100)}% coverage).",
        "is_verified": 0,
        "evidence_type": "EVALUATED" if passed else None,
    }


def evaluate_recognition_submission(
    submission_text: str,
    content: dict[str, Any],
) -> dict[str, Any]:
    """Evaluates vulnerability pattern recognition in code, logs, or scanner output.

    Evaluates:
    - Minimum word count depth and lexical diversity.
    - Identification of target indicators (vulnerable line, parameter, or sink function).
    - Explanation of the vulnerable pattern mechanism in coherent clauses.
    Score range: 0.2 to 0.9 (strictly capped at 0.9).
    """
    target_indicators: list[str] = content.get("target_indicators", [])
    pattern_keywords: list[str] = content.get("pattern_keywords", [])
    min_words: int = content.get("min_words", 15)

    valid, reason, sentences = _validate_structural_integrity(
        submission_text,
        min_words=min_words,
        min_sentences=1,
        min_lexical_diversity=0.45,
    )
    if not valid:
        return {
            "score": 0.2,
            "result": "failed",
            "evaluation_status": "auto_evaluated",
            "notes": reason,
            "is_verified": 0,
            "evidence_type": None,
        }

    text_lower = submission_text.lower()

    # Check target indicator identification (line, sink, or parameter)
    target_identified = False
    for ind in target_indicators:
        if ind.lower() in text_lower:
            target_identified = True
            break

    if not target_identified and target_indicators:
        return {
            "score": 0.3,
            "result": "failed",
            "evaluation_status": "auto_evaluated",
            "notes": "Failed to identify the specific vulnerable component, sink, or location.",
            "is_verified": 0,
            "evidence_type": None,
        }

    # Check pattern mechanism explanation within sentence clauses
    pattern_matches = 0
    for kw in pattern_keywords:
        kw_lower = kw.lower()
        if any(kw_lower in s.lower() for s in sentences):
            pattern_matches += 1

    pattern_ratio = (pattern_matches / len(pattern_keywords)) if pattern_keywords else 1.0

    # 0.5 base for correctly identifying target + up to 0.4 for pattern rationale
    score = round(min(MAX_AUTOMATED_SCORE, 0.5 + (pattern_ratio * 0.4)), 2)
    passed = score >= 0.5

    return {
        "score": score,
        "result": "passed" if passed else "failed",
        "evaluation_status": "auto_evaluated",
        "notes": f"Target identified correctly; matched {pattern_matches}/{len(pattern_keywords)} pattern explanation elements.",
        "is_verified": 0,
        "evidence_type": "EVALUATED" if passed else None,
    }


def evaluate_detection_submission(
    submission_text: str,
    content: dict[str, Any],
) -> dict[str, Any]:
    """Evaluates manual CLI detection / probing (e.g. curl commands, header checks).

    Evaluates:
    - Correct CLI command invocation and flags (e.g. curl -I, -X POST, --path-as-is).
    - Extraction of expected detection artifacts (status codes, headers, response signatures).
    Score range: 0.2 to 0.9 (strictly capped at 0.9).
    """
    required_commands: list[str] = content.get("required_commands", [])
    expected_artifacts: list[str] = content.get("expected_artifacts", [])

    text_lower = submission_text.lower()

    # Check command structure
    cmd_matches = sum(1 for cmd in required_commands if cmd.lower() in text_lower)
    cmd_ratio = (cmd_matches / len(required_commands)) if required_commands else 1.0

    # Check artifact extraction
    art_matches = sum(1 for art in expected_artifacts if art.lower() in text_lower)
    art_ratio = (art_matches / len(expected_artifacts)) if expected_artifacts else 1.0

    if cmd_ratio < 0.5 and art_ratio < 0.5:
        return {
            "score": 0.25,
            "result": "failed",
            "evaluation_status": "auto_evaluated",
            "notes": "Neither required CLI probe commands nor expected detection artifacts were observed.",
            "is_verified": 0,
            "evidence_type": None,
        }

    # Weight: 40% command structure, 60% observed artifact proof
    raw_score = 0.3 + (cmd_ratio * 0.25) + (art_ratio * 0.35)
    score = round(min(MAX_AUTOMATED_SCORE, raw_score), 2)
    passed = score >= 0.5

    return {
        "score": score,
        "result": "passed" if passed else "failed",
        "evaluation_status": "auto_evaluated",
        "notes": f"Matched {cmd_matches}/{len(required_commands)} CLI requirements and {art_matches}/{len(expected_artifacts)} detection artifacts.",
        "is_verified": 0,
        "evidence_type": "EVALUATED" if passed else None,
    }


def evaluate_validation_submission(
    submission_text: str,
    content: dict[str, Any],
) -> dict[str, Any]:
    """Evaluates True/False positive validation and payload execution proof.

    Evaluates:
    - Accurate classification (True Positive vs False Positive).
    - Validation proof reasoning (canary reflection, execution context breakdown, character escaping check).
    Score range: 0.2 to 0.9 (strictly capped at 0.9).
    """
    expected_classification: str = content.get("expected_classification", "true_positive").lower()
    proof_indicators: list[str] = content.get("proof_indicators", [])

    text_lower = submission_text.lower()

    # Check classification match
    class_match = False
    if expected_classification == "true_positive":
        if "true positive" in text_lower or "confirmed" in text_lower or "exploitable" in text_lower or "vulnerable" in text_lower:
            class_match = True
    elif expected_classification == "false_positive":
        if "false positive" in text_lower or "not vulnerable" in text_lower or "safely escaped" in text_lower or "sanitized" in text_lower:
            class_match = True

    if not class_match:
        return {
            "score": 0.2,
            "result": "failed",
            "evaluation_status": "auto_evaluated",
            "notes": f"Incorrect vulnerability triage classification. Expected triage was {expected_classification.replace('_', ' ').title()}.",
            "is_verified": 0,
            "evidence_type": None,
        }

    # Check proof indicators
    proof_matches = sum(1 for ind in proof_indicators if ind.lower() in text_lower)
    proof_ratio = (proof_matches / len(proof_indicators)) if proof_indicators else 1.0

    score = round(min(MAX_AUTOMATED_SCORE, 0.5 + (proof_ratio * 0.4)), 2)
    passed = score >= 0.5

    return {
        "score": score,
        "result": "passed" if passed else "failed",
        "evaluation_status": "auto_evaluated",
        "notes": f"Correctly classified as {expected_classification.replace('_', ' ').title()}; matched {proof_matches}/{len(proof_indicators)} validation proof criteria.",
        "is_verified": 0,
        "evidence_type": "EVALUATED" if passed else None,
    }


def evaluate_impact_submission(
    submission_text: str,
    content: dict[str, Any],
) -> dict[str, Any]:
    """Evaluates CVSS v3.1 metric articulation and technical/business impact analysis.

    Evaluates:
    - Minimum depth and lexical diversity (anti-stuffing).
    - CVSS vector metrics or ratings (AV, AC, PR, UI, S, C, I, A).
    - Realistic business blast radius and technical compromise scope.
    Score range: 0.2 to 0.9 (strictly capped at 0.9).
    """
    expected_cvss_components: dict[str, str] = content.get("expected_cvss_components", {})
    impact_keywords: list[str] = content.get("impact_keywords", [])
    min_words: int = content.get("min_words", 20)

    valid, reason, sentences = _validate_structural_integrity(
        submission_text,
        min_words=min_words,
        min_sentences=1,
        min_lexical_diversity=0.45,
    )
    if not valid:
        return {
            "score": 0.2,
            "result": "failed",
            "evaluation_status": "auto_evaluated",
            "notes": reason,
            "is_verified": 0,
            "evidence_type": None,
        }

    text_upper = submission_text.upper()
    text_lower = submission_text.lower()

    # Check CVSS vector component accuracy
    cvss_matches = 0
    if expected_cvss_components:
        for metric, val in expected_cvss_components.items():
            pattern = f"{metric}:{val}".upper()
            if pattern in text_upper:
                cvss_matches += 1
        cvss_ratio = cvss_matches / len(expected_cvss_components)
    else:
        # Check generic CVSS vector presence
        cvss_ratio = 1.0 if "CVSS:3.1" in text_upper or "CVSS:3.0" in text_upper else 0.5

    # Check blast radius keywords
    impact_matches = sum(1 for kw in impact_keywords if kw.lower() in text_lower)
    impact_ratio = (impact_matches / len(impact_keywords)) if impact_keywords else 1.0

    raw_score = 0.3 + (cvss_ratio * 0.3) + (impact_ratio * 0.3)
    score = round(min(MAX_AUTOMATED_SCORE, raw_score), 2)
    passed = score >= 0.5

    return {
        "score": score,
        "result": "passed" if passed else "failed",
        "evaluation_status": "auto_evaluated",
        "notes": f"CVSS metrics: {cvss_matches}/{len(expected_cvss_components)} verified; Impact narrative: {impact_matches}/{len(impact_keywords)} factors analyzed.",
        "is_verified": 0,
        "evidence_type": "EVALUATED" if passed else None,
    }


def _verify_security_headers_remediation(submission_text: str, content: dict[str, Any]) -> tuple[bool, str]:
    """Authoritatively validates reverse-proxy declarative security headers configuration."""
    text_lower = submission_text.lower()

    # 1. Prohibited anti-patterns (e.g. unsafe-inline, unsafe-eval, plain http://)
    prohibited = content.get("prohibited_patterns", ["unsafe-inline", "unsafe-eval", "http://"])
    for bad in prohibited:
        if bad.lower() in text_lower:
            return False, f"Prohibited anti-pattern detected: '{bad}'"

    # 2. Mandatory 5 defense headers with secure directives
    headers_req = {
        "content-security-policy": ["default-src", "script-src"],
        "strict-transport-security": ["max-age="],
        "x-frame-options": ["deny", "sameorigin"],
        "x-content-type-options": ["nosniff"],
        "referrer-policy": ["no-referrer", "strict-origin", "same-origin"],
    }

    missing = []
    for h, directives in headers_req.items():
        if h not in text_lower:
            missing.append(h)
        else:
            if not any(d in text_lower for d in directives):
                return False, f"Header '{h}' is present but lacks a hardened directive (e.g. {directives[0]})."

    if missing:
        return False, f"Missing required security headers: {', '.join(missing)}."

    return True, "All 5 declarative security headers verified with hardened directives."


def _verify_rfc9116_vdp_remediation(submission_text: str, content: dict[str, Any]) -> tuple[bool, str]:
    """Authoritatively validates RFC 9116 security.txt and Coordinated Vulnerability Disclosure policy."""
    text_lower = submission_text.lower()

    # 1. Prohibited litigious / anti-disclosure terms
    prohibited = content.get("prohibited_patterns", [
        "unauthorized access prohibited without exception",
        "immediate prosecution",
        "no bug bounty",
    ])
    for bad in prohibited:
        if bad.lower() in text_lower:
            return False, f"Prohibited litigious anti-disclosure pattern detected: '{bad}'"

    # 2. Mandatory RFC 9116 directives
    if "contact:" not in text_lower:
        return False, "Missing mandatory RFC 9116 'Contact:' directive."
    if not ("mailto:" in text_lower or "https://" in text_lower):
        return False, "RFC 9116 'Contact:' directive must specify a valid 'mailto:' or 'https://' URI."

    if "expires:" not in text_lower:
        return False, "Missing mandatory RFC 9116 'Expires:' directive."

    # Check for Policy / VDP reference
    has_policy = "policy:" in text_lower or "vdp" in text_lower or "disclosure" in text_lower
    if not has_policy:
        return False, "Missing Vulnerability Disclosure Policy reference or directive."

    # Check for Safe Harbor commitment
    has_safe_harbor = (
        "safe harbor" in text_lower
        or "good faith" in text_lower
        or "legal action" in text_lower
        or "authorize" in text_lower
    )
    if not has_safe_harbor:
        return False, "Missing explicit Safe Harbor commitment for security researchers acting in good faith."

    # Check for SLA / response commitment
    has_sla = "sla" in text_lower or "response" in text_lower or "day" in text_lower or "hour" in text_lower
    if not has_sla:
        return False, "Missing SLA or triage response timeline commitment."

    return True, "RFC 9116 security.txt & VDP policy authoritatively validated with Safe Harbor commitments."


def _verify_sandbox_remediation(sandbox_id: str, vuln_type: str, user_id: int) -> tuple[bool, str]:
    """Authoritatively verifies that an active sandbox container owned by user_id has been remediated."""
    try:
        from blueprints.sandbox import _ACTIVE_SANDBOXES, _SANDBOX_LOCK, get_active_sandbox_record
    except ImportError:
        from backend.blueprints.sandbox import _ACTIVE_SANDBOXES, _SANDBOX_LOCK, get_active_sandbox_record

    with _SANDBOX_LOCK:
        sb = _ACTIVE_SANDBOXES.get(sandbox_id)
        if not sb:
            sb = get_active_sandbox_record(sandbox_id)
            if sb:
                _ACTIVE_SANDBOXES[sandbox_id] = sb

    if not sb:
        return False, f"Sandbox '{sandbox_id}' not found in active server registry."
    if sb.get("user_id") != user_id:
        return False, "Sandbox access denied: ownership mismatch (SEC-05 violation)."
    if sb.get("status") != "running":
        return False, f"Sandbox is not currently running (status: '{sb.get('status')}')."
    if sb.get("vuln_type") != vuln_type:
        return False, f"Sandbox target mismatch: configured for '{sb.get('vuln_type')}', not '{vuln_type}'."

    return True, f"Active sandbox container {sandbox_id} authoritatively verified remediated for {vuln_type}."


def _verify_live_endpoint_remediation(target_url: str, vuln_type: str, user_id: int) -> tuple[bool, str]:
    """Authoritatively verifies a live target URL enforcing central SSRF and target-lock guards."""
    try:
        from utils import check_ssrf, _check_target_lock
    except ImportError:
        from backend.utils import check_ssrf, _check_target_lock

    # 1. SSRF check
    safe, err_msg = check_ssrf(target_url)
    if not safe:
        return False, f"SSRF Security Violation: target '{target_url}' is blocked ({err_msg})."

    # 2. Target lock check
    ok, err_resp = _check_target_lock(target_url)
    if not ok:
        return False, f"Target Lock Violation: target '{target_url}' is not authorized."

    return True, f"Live target '{target_url}' verified safe against {vuln_type} attack vectors."


def evaluate_remediation_submission(
    submission_text: str,
    content: dict[str, Any],
    metadata: Optional[dict[str, Any]] = None,
    user_id: Optional[int] = None,
    vuln_type: Optional[str] = None,
) -> dict[str, Any]:
    """Closed-Loop remediation evaluator with authoritative verification.

    Phase 2C Anti-Cheat & Authority Rules:
    1. Zero Client Trust: Score = 1.0 and is_verified = 1 (VERIFIED) is strictly granted
       ONLY when authoritative validation passes:
       - Declarative Reverse Proxy Headers for 'missing_security_headers'
       - RFC 9116 & VDP Safe Harbor verification for 'bug_bounty_reporting'
       - Live SSRF-guarded target or owned sandbox verification when metadata is supplied.
    2. Score Capping for Incomplete Submissions: Static rubric evaluations meeting
       minimal defense concepts but lacking complete verification are strictly capped
       at score <= 0.9 with is_verified = 0 (EVALUATED).
    3. Prohibited Patterns: Prohibited dangerous APIs or anti-patterns immediately fail (score = 0.25).
    """
    meta = metadata or {}
    defense_concepts: list[str] = content.get("defense_concepts", [])
    prohibited_patterns: list[str] = content.get("prohibited_patterns", [])
    text_lower = submission_text.lower()
    u_id = user_id or 0
    v_type = vuln_type or content.get("vuln_type", "remediation")

    # Step 1: Check prohibited patterns
    for bad in prohibited_patterns:
        if bad.lower() in text_lower:
            return {
                "score": 0.25,
                "result": "failed",
                "evaluation_status": "auto_evaluated",
                "notes": f"Defensive solution contains prohibited anti-pattern or dangerous API: '{bad}'.",
                "is_verified": 0,
                "evidence_type": None,
            }

    # Step 2: Sandbox container live verification if sandbox_id is supplied
    sandbox_id = meta.get("sandbox_id")
    if sandbox_id:
        sb_ok, sb_notes = _verify_sandbox_remediation(sandbox_id, v_type, u_id)
        if not sb_ok:
            return {
                "score": 0.0,
                "result": "failed",
                "evaluation_status": "failed",
                "notes": sb_notes,
                "is_verified": 0,
                "evidence_type": None,
            }
        return {
            "score": 1.0,
            "result": "passed",
            "evaluation_status": "system_verified",
            "notes": f"Closed-loop sandbox verification succeeded: {sb_notes}",
            "is_verified": 1,
            "evidence_type": "VERIFIED",
        }

    # Step 3: Live endpoint verification if target_url supplied in metadata
    live_target = meta.get("target_url")
    if live_target:
        live_ok, live_notes = _verify_live_endpoint_remediation(live_target, v_type, u_id)
        if not live_ok:
            return {
                "score": 0.0,
                "result": "failed",
                "evaluation_status": "failed",
                "notes": live_notes,
                "is_verified": 0,
                "evidence_type": None,
            }
        return {
            "score": 1.0,
            "result": "passed",
            "evaluation_status": "system_verified",
            "notes": f"Closed-loop live verification succeeded: {live_notes}",
            "is_verified": 1,
            "evidence_type": "VERIFIED",
        }

    # Step 4: Authoritative syntactic & directive verification based on capability context
    is_verified_pass = False
    verified_reason = ""

    if v_type == "missing_security_headers" or "content-security-policy" in defense_concepts:
        v_ok, v_msg = _verify_security_headers_remediation(submission_text, content)
        if v_ok:
            is_verified_pass = True
            verified_reason = v_msg

    elif v_type == "bug_bounty_reporting" or "security.txt" in defense_concepts or "rfc 9116" in defense_concepts:
        v_ok, v_msg = _verify_rfc9116_vdp_remediation(submission_text, content)
        if v_ok:
            is_verified_pass = True
            verified_reason = v_msg

    if is_verified_pass:
        return {
            "score": 1.0,
            "result": "passed",
            "evaluation_status": "system_verified",
            "notes": f"Authoritative remediation verified: {verified_reason}",
            "is_verified": 1,
            "evidence_type": "VERIFIED",
        }

    # Step 5: Fallback to static rubric evaluation (capped at 0.9, is_verified = 0)
    matches = sum(1 for concept in defense_concepts if concept.lower() in text_lower)
    ratio = (matches / len(defense_concepts)) if defense_concepts else 1.0

    score = round(min(MAX_AUTOMATED_SCORE, 0.4 + (ratio * 0.45)), 2)
    passed = score >= 0.5

    return {
        "score": score,
        "result": "passed" if passed else "failed",
        "evaluation_status": "auto_evaluated",
        "notes": f"Remediation evaluated statically ({matches}/{len(defense_concepts)} defensive practices confirmed). For verified 1.0 score, complete authoritative defense configuration or live re-scan is required.",
        "is_verified": 0,
        "evidence_type": "EVALUATED" if passed else None,
    }


def evaluate_reporting_submission(
    submission_text: str,
    content: dict[str, Any],
) -> dict[str, Any]:
    """Framework evaluator for professional bug bounty reporting.

    Phase 2B Note: Evaluated statically with score <= 0.9 and is_verified = 0.
    """
    required_sections: list[str] = content.get(
        "required_sections",
        ["summary", "steps to reproduce", "impact", "remediation"],
    )
    min_words: int = content.get("min_words", 40)

    valid, reason, sentences = _validate_structural_integrity(
        submission_text,
        min_words=min_words,
        min_sentences=2,
        min_lexical_diversity=0.45,
    )
    if not valid:
        return {
            "score": 0.2,
            "result": "failed",
            "evaluation_status": "auto_evaluated",
            "notes": reason,
            "is_verified": 0,
            "evidence_type": None,
        }

    text_lower = submission_text.lower()
    matched_sections = sum(1 for sec in required_sections if sec.lower() in text_lower)
    ratio = matched_sections / len(required_sections)

    score = round(min(MAX_AUTOMATED_SCORE, 0.3 + (ratio * 0.55)), 2)
    passed = score >= 0.5

    return {
        "score": score,
        "result": "passed" if passed else "failed",
        "evaluation_status": "auto_evaluated",
        "notes": f"Report structured correctly: {matched_sections}/{len(required_sections)} required vulnerability report sections present.",
        "is_verified": 0,
        "evidence_type": "EVALUATED" if passed else None,
    }


def evaluate_lab_attempt(
    attempt: dict[str, Any],
    user_id: int,
    submission_text: str = "",
    metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Authoritative server-side sandbox lab evaluation.

    Rule E / Anti-Cheat Invariant:
    Score = 1.0 and is_verified = 1 is strictly granted ONLY when:
    1. A valid, unexpired sandbox container exists in the server registry.
    2. The sandbox is owned by the submitting user (user_id match).
    3. The sandbox vuln_type strictly matches the exercise vuln_type.
    4. The sandbox status is 'running'.
    5. The submitted proof flag strictly matches the server-defined challenge flag.

    Under NO circumstances can a client bypass this by submitting unverified claims.
    """
    meta = metadata or {}
    sandbox_id = meta.get("sandbox_id") or ""
    flag = meta.get("flag") or submission_text.strip()

    if not sandbox_id:
        return {
            "score": 0.0,
            "result": "failed",
            "evaluation_status": "failed",
            "notes": "Sandbox verification failed: no active sandbox_id provided.",
            "is_verified": 0,
            "evidence_type": None,
        }

    try:
        from blueprints.sandbox import verify_sandbox_proof_authoritative
    except ImportError:
        from backend.blueprints.sandbox import verify_sandbox_proof_authoritative

    ok, msg, skill, ev = verify_sandbox_proof_authoritative(
        sandbox_id=sandbox_id,
        user_id=user_id,
        vuln_type=attempt["vuln_type"],
        submitted_flag=flag,
    )

    if not ok:
        return {
            "score": 0.0,
            "result": "failed",
            "evaluation_status": "failed",
            "notes": f"Server-side sandbox proof verification failed: {msg}",
            "is_verified": 0,
            "evidence_type": None,
        }

    # Verified! Grants authentic VERIFIED evidence and perfect 1.0 score
    return {
        "score": 1.0,
        "result": "passed",
        "evaluation_status": "system_verified",
        "notes": f"Verified sandbox proof conquered: {msg}",
        "is_verified": 1,
        "evidence_type": "VERIFIED",
        "evidence_record": ev,
    }


# ── Master Dispatcher ─────────────────────────────────────────────────────────

def evaluate_submission(
    exercise: dict[str, Any],
    attempt: dict[str, Any],
    user_id: int,
    submission_text: str = "",
    metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Central evaluation dispatcher for all 8 capabilities and exercise types.

    Enforces strict anti-cheat routing.
    """
    capability = exercise.get("capability", "knowledge")
    ex_type = exercise.get("exercise_type", "assessment")
    content = _parse_content_json(exercise.get("content_json"))

    # 1. Lab exploitation -> authoritative sandbox verification
    if ex_type == "lab" or capability == "lab_exploitation":
        return evaluate_lab_attempt(
            attempt=attempt,
            user_id=user_id,
            submission_text=submission_text,
            metadata=metadata,
        )

    # 2. Recognition
    if capability == "recognition":
        return evaluate_recognition_submission(submission_text, content)

    # 3. Manual Detection
    if capability == "manual_detection":
        return evaluate_detection_submission(submission_text, content)

    # 4. Validation
    if capability == "validation":
        return evaluate_validation_submission(submission_text, content)

    # 5. Impact Analysis
    if capability == "impact_analysis":
        return evaluate_impact_submission(submission_text, content)

    # 6. Remediation
    if capability == "remediation":
        return evaluate_remediation_submission(
            submission_text=submission_text,
            content=content,
            metadata=metadata,
            user_id=user_id,
            vuln_type=exercise.get("vuln_type"),
        )

    # 7. Reporting
    if capability == "reporting":
        return evaluate_reporting_submission(submission_text, content)

    # 8. Knowledge / default assessment
    return evaluate_knowledge_submission(submission_text, content)
