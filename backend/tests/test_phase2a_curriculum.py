"""HexaGuard Phase 2A — Curriculum Foundation Test Suite.

Verifies:
  1. The 12 Canonical Foundational Skills exist in VULN_TAXONOMY.
  2. All 16 structured lesson fields exist, are non-empty, and contain deep technical content.
  3. Backward compatibility fields (level 1-4 and deep_dive_links) are preserved.
  4. Localization integrity (Arabic and English fields).
  5. Primary capability mapping strictly adheres to User Rule 8.
  6. Non-containerized vs containerized sandbox configuration.
  7. Prerequisites are valid and acyclic.
  8. Scanner bindings point to registered scanner engines.
  9. GET /api/learn/taxonomy/<id> returns the complete 16-field payload.
  10. normalize_check_to_vuln_type resolves checks to the 12 canonical IDs.
"""

from __future__ import annotations

import pytest

from vuln_taxonomy import (
    VULN_TAXONOMY,
    SCANNERS,
    normalize_check_to_vuln_type,
)
from curriculum import FOUNDATIONAL_SKILLS_12
from app import create_app
from database import init_db


@pytest.fixture
def client(tmp_path, monkeypatch):
    test_db = str(tmp_path / "test_phase2a.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key-phase2a")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")
    init_db()
    app = create_app()
    return app.test_client()


CANONICAL_12_SKILLS = [
    "http_fundamentals",
    "dns_recon",
    "missing_security_headers",
    "broken_auth",
    "idor",
    "xss",
    "sqli",
    "ssrf",
    "path_traversal",
    "file_upload",
    "cve_cvss_epss",
    "bug_bounty_reporting",
]

STRUCTURED_16_FIELDS = [
    "concept",
    "why_it_happens",
    "mental_model",
    "vulnerable_pattern",
    "detection_methodology",
    "evidence_markers",
    "safe_local_practice",
    "manual_validation",
    "hexaguard_scanner_relationship",
    "false_positives_limitations",
    "impact_analysis",
    "remediation_standard",
    "remediation_verification",
    "professional_reporting",
    "assessment_prompt",
    "mastery_criteria",
]

EXPECTED_RULE_8_CAPABILITIES = {
    "http_fundamentals": ["knowledge", "recognition", "manual_detection"],
    "dns_recon": ["recognition", "manual_detection", "impact_analysis"],
    "missing_security_headers": ["recognition", "manual_detection", "remediation"],
    "broken_auth": ["recognition", "validation", "lab_exploitation"],
    "idor": ["recognition", "validation", "lab_exploitation"],
    "xss": ["recognition", "validation", "lab_exploitation"],
    "sqli": ["recognition", "validation", "lab_exploitation"],
    "ssrf": ["recognition", "validation", "lab_exploitation"],
    "path_traversal": ["recognition", "validation", "lab_exploitation"],
    "file_upload": ["recognition", "validation", "lab_exploitation"],
    "cve_cvss_epss": ["knowledge", "impact_analysis", "reporting"],
    "bug_bounty_reporting": ["reporting", "impact_analysis", "remediation"],
}

NON_CONTAINERIZED_SKILLS = {
    "http_fundamentals",
    "dns_recon",
    "missing_security_headers",
    "cve_cvss_epss",
    "bug_bounty_reporting",
}


def test_phase2a_canonical_12_presence():
    """Verify all 12 canonical skills exist in VULN_TAXONOMY with exact IDs."""
    for skill_id in CANONICAL_12_SKILLS:
        assert skill_id in VULN_TAXONOMY, f"Missing canonical skill '{skill_id}' in VULN_TAXONOMY"
        assert VULN_TAXONOMY[skill_id]["id"] == skill_id


def test_phase2a_16_structured_fields_depth():
    """Verify all 16 functional fields exist and contain deep technical content."""
    for skill_id in CANONICAL_12_SKILLS:
        entry = VULN_TAXONOMY[skill_id]
        lesson = entry.get("lesson", {})
        assert isinstance(lesson, dict), f"Skill '{skill_id}' missing lesson dict"

        for field in STRUCTURED_16_FIELDS:
            val = lesson.get(field)
            assert isinstance(val, str), (
                f"Skill '{skill_id}' field '{field}' must be a string, got {type(val)}"
            )
            assert len(val.strip()) >= 50, (
                f"Skill '{skill_id}' field '{field}' is too short ({len(val.strip())} chars; min 50)"
            )

        # Field-specific semantic checks
        assert "```" in lesson["vulnerable_pattern"], (
            f"Skill '{skill_id}' vulnerable_pattern must include a fenced code block"
        )
        assert "?" in lesson["assessment_prompt"], (
            f"Skill '{skill_id}' assessment_prompt must contain an evaluative question mark"
        )
        assert "Mastered:" in lesson["mastery_criteria"], (
            f"Skill '{skill_id}' mastery_criteria must explicitly define Mastered state"
        )
        assert "HexaGuard" in lesson["hexaguard_scanner_relationship"], (
            f"Skill '{skill_id}' hexaguard_scanner_relationship must reference HexaGuard telemetry"
        )


def test_phase2a_backward_compatibility_fields():
    """Verify level_1_foundations_en through level_4_remediation_en and deep_dive_links are preserved."""
    for skill_id in CANONICAL_12_SKILLS:
        lesson = VULN_TAXONOMY[skill_id]["lesson"]
        assert len(lesson.get("level_1_foundations_en", "").strip()) >= 50
        assert len(lesson.get("level_2_detection_en", "").strip()) >= 50
        assert len(lesson.get("level_4_remediation_en", "").strip()) >= 50

        practice = lesson.get("level_3_practice", {})
        assert isinstance(practice, dict)
        assert len(practice.get("guided_prompt_en", "").strip()) >= 30
        assert len(practice.get("challenge_prompt_en", "").strip()) >= 30

        links = lesson.get("deep_dive_links", [])
        assert 1 <= len(links) <= 3
        for link in links:
            assert link.get("label", "").strip()
            assert link.get("url", "").startswith("http")


def test_phase2a_localization_integrity():
    """Verify Arabic and English localized fields are populated across all 12 skills."""
    for skill_id in CANONICAL_12_SKILLS:
        entry = VULN_TAXONOMY[skill_id]
        for field in ["name_en", "name_ar", "description_en", "description_ar", "remediation_en", "remediation_ar"]:
            val = entry.get(field, "")
            assert isinstance(val, str) and len(val.strip()) > 0, (
                f"Skill '{skill_id}' missing or empty localized field '{field}'"
            )


def test_phase2a_rule_8_capability_weighting():
    """Verify capability weighting strictly matches User Rule 8 specification."""
    for skill_id, expected_caps in EXPECTED_RULE_8_CAPABILITIES.items():
        entry = VULN_TAXONOMY[skill_id]
        primary = entry.get("primary_capabilities", [])
        assert primary == expected_caps, (
            f"Skill '{skill_id}' primary_capabilities mismatch: expected {expected_caps}, got {primary}"
        )


def test_phase2a_non_containerized_practice():
    """Verify non-containerized skills specify sandbox_target=None with CLI/code instructions."""
    for skill_id in CANONICAL_12_SKILLS:
        practice = VULN_TAXONOMY[skill_id]["lesson"]["level_3_practice"]
        sb_target = practice.get("sandbox_target")
        if skill_id in NON_CONTAINERIZED_SKILLS:
            assert sb_target is None, (
                f"Skill '{skill_id}' must be non-containerized (sandbox_target=None), got {sb_target}"
            )
            # Verify challenge text explains local CLI / code / inspection practice
            challenge = practice.get("challenge_prompt_en", "").lower()
            assert any(term in challenge for term in ["curl", "script", "query", "audit", "draft", "review", "test"]), (
                f"Non-containerized skill '{skill_id}' challenge prompt must specify safe CLI/code practice"
            )
        else:
            assert sb_target is not None, (
                f"Containerized skill '{skill_id}' must specify a sandbox_target"
            )


def test_phase2a_prerequisites_integrity():
    """Verify all prerequisites exist in VULN_TAXONOMY and form a cycle-free DAG."""
    for skill_id in CANONICAL_12_SKILLS:
        prereqs = VULN_TAXONOMY[skill_id].get("prerequisites", [])
        assert isinstance(prereqs, list)
        for pre in prereqs:
            assert pre in VULN_TAXONOMY, f"Prerequisite '{pre}' of '{skill_id}' not in VULN_TAXONOMY"
            assert pre != skill_id, f"Skill '{skill_id}' has self-referential prerequisite"

    # Cycle check via DFS
    visited: set[str] = set()
    stack: set[str] = set()

    def has_cycle(node: str) -> bool:
        visited.add(node)
        stack.add(node)
        for neighbor in VULN_TAXONOMY.get(node, {}).get("prerequisites", []):
            if neighbor not in visited:
                if has_cycle(neighbor):
                    return True
            elif neighbor in stack:
                return True
        stack.remove(node)
        return False

    for skill_id in CANONICAL_12_SKILLS:
        if skill_id not in visited:
            assert not has_cycle(skill_id), f"Cycle detected in prerequisites starting from '{skill_id}'"


def test_phase2a_scanner_engine_bindings():
    """Verify all 12 skills are mapped to valid HexaGuard scanner identifiers."""
    valid_scanners = {s["id"] for s in SCANNERS}
    for skill_id in CANONICAL_12_SKILLS:
        scanner_id = VULN_TAXONOMY[skill_id].get("scanner")
        assert scanner_id in valid_scanners, (
            f"Skill '{skill_id}' references unknown scanner '{scanner_id}'"
        )


def test_phase2a_api_taxonomy_endpoint(client):
    """Verify GET /api/learn/taxonomy/<id> returns 200 with all 16 fields for each skill."""
    for skill_id in CANONICAL_12_SKILLS:
        resp = client.get(f"/api/learn/taxonomy/{skill_id}")
        assert resp.status_code == 200, f"GET /api/learn/taxonomy/{skill_id} failed with {resp.status_code}"
        data = resp.get_json()
        assert data.get("ok") is True
        topic = data.get("topic", {})
        assert topic.get("id") == skill_id

        lesson = topic.get("lesson", {})
        for field in STRUCTURED_16_FIELDS:
            assert field in lesson, f"API response for '{skill_id}' missing structured field '{field}'"
            assert len(lesson[field]) >= 50


def test_phase2a_check_normalization():
    """Verify normalize_check_to_vuln_type resolves check strings to the 12 canonical IDs."""
    test_cases = [
        ("http_fundamentals", "http_fundamentals"),
        ("http_protocol_check", "http_fundamentals"),
        ("dns_recon", "dns_recon"),
        ("dns_enumeration_check", "dns_recon"),
        ("idor", "idor"),
        ("idor_order_access", "idor"),
        ("file_upload", "file_upload"),
        ("unrestricted_file_upload", "file_upload"),
        ("cve_cvss_epss", "cve_cvss_epss"),
        ("cvss_score_calc", "cve_cvss_epss"),
        ("bug_bounty_reporting", "bug_bounty_reporting"),
        ("bounty_report_triage", "bug_bounty_reporting"),
        ("xss_reflected", "xss"),
        ("sqli_blind", "sqli"),
        ("ssrf_metadata", "ssrf"),
        ("path_traversal", "path_traversal"),
    ]
    for check_str, expected_vuln in test_cases:
        resolved = normalize_check_to_vuln_type(check_str)
        assert resolved == expected_vuln, (
            f"Check '{check_str}' resolved to '{resolved}', expected '{expected_vuln}'"
        )
