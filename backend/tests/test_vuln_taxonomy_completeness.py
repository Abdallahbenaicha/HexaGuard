"""Automated completeness and schema verification for SecuraX Vulnerability Taxonomy.

Enforces strict compliance with:
  - Floor of >= 5 canonical types per scanner engine
  - Floor of >= 10 Blue Team incident types with MITRE ATT&CK mapping
  - Constraint 2: Zero empty sub-fields across all 4 lesson levels
  - Constraint 3: deep_dive_links capped at 3, supplementary only
  - Working sandbox target or explicit justification in Level 3
"""

from collections import Counter
import pytest

from vuln_taxonomy import (
    VULN_TAXONOMY,
    INCIDENT_TAXONOMY,
    DATASET_VULN_TYPES,
    SCANNERS,
    CHECK_MAP,
    normalize_check_to_vuln_type,
)
from blueprints.sandbox import SANDBOX_ALLOWLIST


def test_taxonomy_counts_and_floors():
    """Verify that every scanner engine has at least 5 canonical types and incidents >= 10."""
    scanner_ids = {s["id"] for s in SCANNERS}
    assert len(scanner_ids) == 11

    counts = Counter(v["scanner"] for v in VULN_TAXONOMY.values())
    for sid in scanner_ids:
        assert counts[sid] >= 5, f"Scanner engine '{sid}' has only {counts[sid]} types (minimum required: 5)!"

    assert len(INCIDENT_TAXONOMY) >= 10, f"INCIDENT_TAXONOMY has only {len(INCIDENT_TAXONOMY)} types (minimum required: 10)!"

    # Ground truth invariant
    missing_dataset = DATASET_VULN_TYPES - set(VULN_TAXONOMY.keys())
    assert not missing_dataset, f"Mandatory dataset types missing from taxonomy: {missing_dataset}"


def test_every_lesson_is_complete_and_rigorous():
    """Constraint 2 & 3: Every entry MUST have a fully populated 4-level lesson with no empty fields."""
    all_entries = {**VULN_TAXONOMY, **INCIDENT_TAXONOMY}
    assert len(all_entries) >= 64

    for entry_id, entry in all_entries.items():
        assert entry["id"] == entry_id
        assert entry.get("name_en", "").strip(), f"Entry {entry_id} has empty name_en"
        assert entry.get("name_ar", "").strip(), f"Entry {entry_id} has empty name_ar"
        assert entry.get("description_en", "").strip(), f"Entry {entry_id} has empty description_en"
        assert entry.get("description_ar", "").strip(), f"Entry {entry_id} has empty description_ar"
        assert entry.get("remediation_en", "").strip(), f"Entry {entry_id} has empty remediation_en"
        assert entry.get("remediation_ar", "").strip(), f"Entry {entry_id} has empty remediation_ar"
        assert isinstance(entry.get("prerequisites"), list), f"Entry {entry_id} prerequisites must be a list"

        lesson = entry.get("lesson")
        assert isinstance(lesson, dict), f"Entry {entry_id} missing lesson dict"

        # Level 1 Foundations
        l1 = lesson.get("level_1_foundations_en", "")
        assert isinstance(l1, str) and len(l1.strip()) >= 50, (
            f"Entry {entry_id} Level 1 Foundations is too short or empty: {l1!r}"
        )

        # Level 2 Detection
        l2 = lesson.get("level_2_detection_en", "")
        assert isinstance(l2, str) and len(l2.strip()) >= 50, (
            f"Entry {entry_id} Level 2 Detection is too short or empty: {l2!r}"
        )

        # Level 3 Practice
        practice = lesson.get("level_3_practice")
        assert isinstance(practice, dict), f"Entry {entry_id} missing level_3_practice dict"
        guided = practice.get("guided_prompt_en", "")
        challenge = practice.get("challenge_prompt_en", "")
        assert isinstance(guided, str) and len(guided.strip()) >= 30, (
            f"Entry {entry_id} guided_prompt_en too short or empty: {guided!r}"
        )
        assert isinstance(challenge, str) and len(challenge.strip()) >= 30, (
            f"Entry {entry_id} challenge_prompt_en too short or empty: {challenge!r}"
        )

        # Level 4 Remediation
        l4 = lesson.get("level_4_remediation_en", "")
        assert isinstance(l4, str) and len(l4.strip()) >= 50, (
            f"Entry {entry_id} Level 4 Remediation is too short or empty: {l4!r}"
        )

        # Constraint 3: Deep dive links capped at 3
        links = lesson.get("deep_dive_links", [])
        assert isinstance(links, list), f"Entry {entry_id} deep_dive_links must be a list"
        assert 1 <= len(links) <= 3, f"Entry {entry_id} has {len(links)} links (must be between 1 and 3)"
        for link in links:
            assert link.get("label", "").strip(), f"Entry {entry_id} link missing label"
            assert link.get("url", "").startswith("http"), f"Entry {entry_id} invalid URL {link.get('url')}"


def test_level_3_practice_sandbox_or_explicit_justification():
    """Verify that every entry's Level 3 either targets an allowlisted sandbox or provides explicit justification."""
    for entry_id, entry in VULN_TAXONOMY.items():
        practice = entry["lesson"]["level_3_practice"]
        sb_target = practice.get("sandbox_target")
        if sb_target is not None:
            assert sb_target in SANDBOX_ALLOWLIST, (
                f"Entry '{entry_id}' sandbox_target '{sb_target}' is not in SANDBOX_ALLOWLIST!"
            )
        else:
            # Must have explicit guidance and challenge text explaining how to practice via code/CLI/logs
            challenge = practice.get("challenge_prompt_en", "")
            assert len(challenge) >= 30, (
                f"Entry '{entry_id}' has null sandbox_target but insufficient challenge text."
            )


def test_incident_taxonomy_mitre_mapping():
    """Verify all 10 incident taxonomy entries have documented MITRE ATT&CK techniques."""
    for inc_id, inc in INCIDENT_TAXONOMY.items():
        assert inc.get("mitre_id", "").startswith("T"), f"Incident {inc_id} missing valid MITRE ID"
        assert inc.get("tactic", "").strip(), f"Incident {inc_id} missing tactic"
        assert len(inc.get("log_sources", [])) >= 2, f"Incident {inc_id} requires >= 2 log sources"
        assert len(inc.get("indicators", [])) >= 2, f"Incident {inc_id} requires >= 2 indicators"


def test_check_map_coverage():
    """Verify CHECK_MAP normalizes raw checks to valid canonical types."""
    canonical_offensive = set(VULN_TAXONOMY.keys())
    for raw_check, canonical in CHECK_MAP.items():
        assert canonical in canonical_offensive, (
            f"CHECK_MAP['{raw_check}'] maps to '{canonical}', which is not in VULN_TAXONOMY!"
        )
