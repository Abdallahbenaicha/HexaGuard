"""Repair C — Authoritative Exercise Coverage Invariant Test.

This test is the definitive machine-checkable proof that all 12 foundational
skills in the SecuraX / HexaGuard Learning system have complete 8-capability
exercise coverage (96 exercises total = 12 × 8).

INVARIANT:
  For every skill in FOUNDATIONAL_SKILLS and every capability in ALL_8_CAPABILITIES,
  exactly one active exercise must be present in the learning_exercises table.

ZERO REGRESSIONS: This test MUST PASS after Repair B (SEED_EXERCISES_B) is applied.
If this test fails, Repair B is incomplete or the DB was not re-seeded.

Author: Repair C — Phase 1 HexaGuard Learning Coverage Certification
"""

from __future__ import annotations

import pytest
from database import init_db, _get_db
from seed_learning import seed


# ── Canonical constants (must match seed_learning.py exactly) ─────────────────

FOUNDATIONAL_SKILLS: list[str] = [
    "broken_auth",
    "bug_bounty_reporting",
    "cve_cvss_epss",
    "dns_recon",
    "file_upload",
    "http_fundamentals",
    "idor",
    "missing_security_headers",
    "path_traversal",
    "sqli",
    "ssrf",
    "xss",
]

ALL_8_CAPABILITIES: list[str] = [
    "knowledge",
    "recognition",
    "manual_detection",
    "validation",
    "lab_exploitation",
    "impact_analysis",
    "remediation",
    "reporting",
]

EXPECTED_TOTAL = len(FOUNDATIONAL_SKILLS) * len(ALL_8_CAPABILITIES)  # 96


@pytest.fixture(scope="module")
def seeded_db(tmp_path_factory):
    """Create an isolated in-memory DB, seed it, and return the DB connection."""
    import os

    # Point the DB to a temp file so we don't pollute the real hexaguard.db
    tmp_dir = tmp_path_factory.mktemp("repair_c")
    db_path = str(tmp_dir / "repair_c_coverage.db")
    os.environ["DATABASE_PATH"] = db_path

    # Re-import to pick up the new DATABASE_PATH
    import importlib
    import database as db_module
    importlib.reload(db_module)

    # Seed both batches
    seed()

    db = db_module._get_db()
    yield db

    db.close()
    os.environ.pop("DATABASE_PATH", None)


# ── Primary Coverage Invariant ─────────────────────────────────────────────────

class TestExerciseCoverageInvariant:
    """Repair C: Authoritative 12-skill × 8-capability coverage proof."""

    def test_total_exercise_count_is_96(self, seeded_db):
        """After seeding, the learning_exercises table must contain exactly 96 active exercises."""
        row = seeded_db.execute(
            "SELECT COUNT(*) FROM learning_exercises WHERE is_active = 1"
        ).fetchone()
        actual = row[0]
        assert actual == EXPECTED_TOTAL, (
            f"Expected exactly {EXPECTED_TOTAL} active exercises (12 skills × 8 capabilities), "
            f"but found {actual}. Repair B may be incomplete or the seed was not run."
        )

    def test_exactly_12_foundational_skills_are_covered(self, seeded_db):
        """Exactly the 12 foundational skills must appear in learning_exercises."""
        rows = seeded_db.execute(
            "SELECT DISTINCT vuln_type FROM learning_exercises WHERE is_active = 1 ORDER BY vuln_type"
        ).fetchall()
        actual_skills = {r[0] for r in rows}
        expected_skills = set(FOUNDATIONAL_SKILLS)

        missing = expected_skills - actual_skills
        extra = actual_skills - expected_skills

        assert not missing, f"The following foundational skills are missing exercises: {sorted(missing)}"
        assert not extra, (
            f"Unexpected extra skills found in learning_exercises (not in FOUNDATIONAL_SKILLS): {sorted(extra)}. "
            "If these are intentional, update FOUNDATIONAL_SKILLS."
        )

    @pytest.mark.parametrize("skill", FOUNDATIONAL_SKILLS)
    def test_each_skill_has_all_8_capabilities(self, seeded_db, skill):
        """Each foundational skill must have exactly one exercise per capability (8 total)."""
        rows = seeded_db.execute(
            "SELECT capability FROM learning_exercises WHERE vuln_type = ? AND is_active = 1",
            (skill,),
        ).fetchall()
        actual_caps = {r[0] for r in rows}
        expected_caps = set(ALL_8_CAPABILITIES)

        missing_caps = expected_caps - actual_caps
        assert not missing_caps, (
            f"Skill '{skill}' is missing exercises for capabilities: {sorted(missing_caps)}. "
            f"Present capabilities: {sorted(actual_caps)}"
        )

    @pytest.mark.parametrize("skill", FOUNDATIONAL_SKILLS)
    def test_no_duplicate_capability_per_skill(self, seeded_db, skill):
        """Each (skill, capability) pair must have exactly 1 active exercise — no duplicates."""
        rows = seeded_db.execute(
            """
            SELECT capability, COUNT(*) as cnt
            FROM learning_exercises
            WHERE vuln_type = ? AND is_active = 1
            GROUP BY capability
            HAVING cnt > 1
            """,
            (skill,),
        ).fetchall()
        assert not rows, (
            f"Skill '{skill}' has duplicate active exercises for capabilities: "
            + ", ".join(f"{r[0]} (×{r[1]})" for r in rows)
        )

    @pytest.mark.parametrize("capability", ALL_8_CAPABILITIES)
    def test_each_capability_covered_by_all_12_skills(self, seeded_db, capability):
        """Each of the 8 capabilities must be covered by all 12 foundational skills."""
        rows = seeded_db.execute(
            "SELECT vuln_type FROM learning_exercises WHERE capability = ? AND is_active = 1",
            (capability,),
        ).fetchall()
        actual_skills = {r[0] for r in rows}
        expected_skills = set(FOUNDATIONAL_SKILLS)

        missing_skills = expected_skills - actual_skills
        assert not missing_skills, (
            f"Capability '{capability}' is not covered by skills: {sorted(missing_skills)}"
        )

    def test_all_exercises_have_required_fields(self, seeded_db):
        """Every exercise must have non-empty vuln_type, capability, exercise_type, title_en."""
        rows = seeded_db.execute(
            """
            SELECT id, vuln_type, capability, exercise_type, title_en
            FROM learning_exercises
            WHERE is_active = 1
            """
        ).fetchall()
        for row in rows:
            eid, vuln_type, capability, exercise_type, title_en = row
            assert vuln_type and vuln_type.strip(), f"Exercise id={eid} has empty vuln_type"
            assert capability and capability.strip(), f"Exercise id={eid} has empty capability"
            assert exercise_type and exercise_type.strip(), f"Exercise id={eid} has empty exercise_type"
            assert title_en and title_en.strip(), f"Exercise id={eid} has empty title_en"

    def test_coverage_matrix_completeness_summary(self, seeded_db):
        """Generate and assert a complete 12×8 coverage matrix. Fails with precise gap report."""
        rows = seeded_db.execute(
            "SELECT vuln_type, capability FROM learning_exercises WHERE is_active = 1"
        ).fetchall()
        covered = {(r[0], r[1]) for r in rows}

        gaps = []
        for skill in FOUNDATIONAL_SKILLS:
            for cap in ALL_8_CAPABILITIES:
                if (skill, cap) not in covered:
                    gaps.append((skill, cap))

        assert not gaps, (
            f"Coverage matrix has {len(gaps)} gaps (expected 0):\n"
            + "\n".join(f"  MISSING: {s} / {c}" for s, c in sorted(gaps))
        )
