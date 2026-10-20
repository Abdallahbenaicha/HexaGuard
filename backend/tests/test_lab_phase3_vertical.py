"""SecuraX Evaluation Lab — Phase 3 First Real Vertical Slice Tests.

Governed strictly by Master Specification v5 Phase 3 (THE KEY GATE):
  - Simplest file-based engine: Bandit (proven in Phase 0; zero Docker, zero network).
  - Authored local fixtures with vulnerable cases AND explicit negative controls (safe look-alikes).
  - REAL engine execution through adapter -> normalize -> match -> score -> persist.
  - Minimal UI/API scorecard presenting execution_status and benchmark_status SIDE BY SIDE.
  - MANDATORY ACCEPTANCE PROOF:
      A REAL completed scan that FAILS its benchmark with its missed cases visible!
      L1 simulations never count as proof.
  - Gate fail-closed enforcement and Admin + 2FA security invariants maintained.
  - EXT-A: Tool output recorded as fixture for hermetic replay.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from database import init_db
from db.lab import (
    get_benchmark_scorecard,
    get_lab_target,
    init_lab_tables,
    list_benchmark_scorecards,
    seed_ground_truth_cases,
    seed_lab_targets,
)
from lab.config import is_lab_mode_enabled
from lab.gate import evaluate_lab_gate
from lab.models import (
    BenchmarkScorecard,
    BenchmarkStatus,
    CandidateFinding,
    ExecutionStatus,
    FindingBucket,
    TruthState,
)
from lab.runner import (
    resolve_target_address,
    run_bandit_engine,
    run_lab_benchmark,
)


@pytest.fixture(autouse=True)
def setup_lab_environment(monkeypatch):
    """Ensure clean test database with LAB_MODE enabled and seeds initialized."""
    test_db = "test_phase3_lab.db"
    if os.path.exists(test_db):
        try:
            os.remove(test_db)
        except OSError:
            pass

    monkeypatch.setenv("LAB_MODE", "1")
    monkeypatch.setenv("LAB_REMOTE_SCANNING", "0")
    monkeypatch.setenv("LAB_ENFORCE_2FA", "1")
    monkeypatch.setenv("DEMO_PROFILE", "0")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{test_db}")

    init_db()
    init_lab_tables()
    seed_lab_targets()
    seed_ground_truth_cases()

    yield

    if os.path.exists(test_db):
        try:
            os.remove(test_db)
        except OSError:
            pass


@pytest.fixture
def app(monkeypatch, tmp_path):
    """Create test Flask app with Admin and 2FA configured."""
    test_db = str(tmp_path / "test_phase3_flask.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "phase3-test-secret-key-32-chars-min")
    monkeypatch.setenv("LAB_MODE", "1")
    monkeypatch.setenv("DEPLOYMENT_MODE", "local")

    from app import create_app
    from db.users import create_user, get_user_by_username, update_user_totp

    flask_app = create_app()
    with flask_app.app_context():
        init_db()
        init_lab_tables()
        seed_lab_targets()
        seed_ground_truth_cases()
        u = get_user_by_username("admin")
        if not u:
            create_user("admin", "AdminPass123!@#", role="admin")
            u = get_user_by_username("admin")
        update_user_totp(u["id"], "JBSWY3DPEHPK3PXP", True)
    return flask_app


@pytest.fixture
def client(app):
    """Test client for Flask testing."""
    return app.test_client()


# ══════════════════════════════════════════════════════════════════════════════
# 1. Real Engine Execution on Authored Fixture
# ══════════════════════════════════════════════════════════════════════════════

def test_real_bandit_engine_execution_on_fixture():
    """Verify that the real Bandit scanner runs on the authored fixture and returns parsed candidates."""
    target_addr = "datasets/fixtures/sast/vulnerable_app.py"
    resolved = resolve_target_address(target_addr)
    assert os.path.exists(resolved), f"Fixture not found at {resolved}"

    candidates, raw_data, meta = run_bandit_engine(target_addr)

    # Must have executed real tool
    assert meta["engine"] == "bandit"
    assert meta["exit_code"] in (0, 1), f"Unexpected Bandit exit code: {meta['exit_code']}"
    assert "results" in raw_data
    assert len(candidates) > 0

    # Verify normalization to CandidateFinding
    rule_ids = {c.rule_id for c in candidates}
    assert "bandit_B602" in rule_ids, "Expected B602 (shell=True) finding"
    assert "bandit_B324" in rule_ids or "bandit_B303" in rule_ids, "Expected B324/B303 (MD5) finding"

    for c in candidates:
        assert isinstance(c, CandidateFinding)
        assert c.engine_id == "bandit"
        assert c.location["file"].endswith("vulnerable_app.py")
        assert c.location["line"] > 0
        assert c.cwe.startswith("CWE-")


def test_real_bandit_engine_on_zip_archive():
    """Verify that the real Bandit engine unpacks and scans a zip archive fixture securely."""
    zip_addr = "datasets/fixtures/sast/vulnerable_app.zip"
    try:
        resolved = resolve_target_address(zip_addr)
    except FileNotFoundError:
        pytest.skip("vulnerable_app.zip not bundled yet.")

    candidates, raw_data, meta = run_bandit_engine(zip_addr)
    assert meta["exit_code"] in (0, 1)
    assert len(candidates) > 0


def test_target_path_containment_enforces_datasets_boundary():
    """Hardening B-01: Verify canonical path containment within authorized datasets/ root."""
    # 1. Valid path inside datasets/ succeeds
    valid_addr = "datasets/fixtures/sast/vulnerable_app.py"
    resolved = resolve_target_address(valid_addr)
    assert os.path.exists(resolved)
    assert "datasets" in resolved

    # 2. Directory traversal attempt outside datasets/ is strictly rejected (both existing and non-existing targets)
    traversal_existing = "../backend/app.py"
    with pytest.raises(ValueError, match="escapes the authorized datasets directory"):
        resolve_target_address(traversal_existing)

    traversal_nonexisting = "datasets/../../non_existent_outside_file_987.py"
    with pytest.raises(ValueError, match="escapes the authorized datasets directory"):
        resolve_target_address(traversal_nonexisting)

    # 3. Direct outside path attempt is strictly rejected
    traversal_addr = "datasets/../../backend/app.py"
    with pytest.raises(ValueError, match="escapes the authorized datasets directory"):
        resolve_target_address(traversal_addr)

    # 4. Non-existent path inside datasets/ raises FileNotFoundError (not ValueError)
    with pytest.raises(FileNotFoundError):
        resolve_target_address("datasets/fixtures/non_existent_target_12345.py")


def test_zip_symlink_rejection_before_extraction():
    """Hardening B-02: Verify that ZIP members with symbolic links are rejected before extraction."""
    backend_dir = Path(__file__).resolve().parent.parent
    repo_root = backend_dir.parent
    test_zip = repo_root / "datasets" / "fixtures" / "sast" / "_test_symlink_attack.zip"

    try:
        # Create a malicious zip fixture containing a symlink entry
        with zipfile.ZipFile(test_zip, "w") as zf:
            # Regular safe member
            zf.writestr("safe.py", "x = 1\n")

            # Symlink member with POSIX S_IFLNK (0xA1ED)
            symlink_info = zipfile.ZipInfo("symlink_target.py")
            symlink_info.external_attr = 0xA1ED << 16  # S_IFLNK | 0755
            zf.writestr(symlink_info, "/etc/passwd")

        assert test_zip.exists()

        # Engine execution must reject the zip member before extraction
        with pytest.raises(ValueError, match="Symlink in ZIP rejected: symlink_target.py"):
            run_bandit_engine("datasets/fixtures/sast/_test_symlink_attack.zip")

    finally:
        if test_zip.exists():
            test_zip.unlink()


def test_zip_valid_archive_compatibility():
    """Hardening B-02: Verify that valid ZIP archives with standard file entries extract and scan cleanly."""
    backend_dir = Path(__file__).resolve().parent.parent
    repo_root = backend_dir.parent
    test_zip = repo_root / "datasets" / "fixtures" / "sast" / "_test_valid_clean.zip"

    try:
        with zipfile.ZipFile(test_zip, "w") as zf:
            reg_info = zipfile.ZipInfo("clean_code.py")
            reg_info.external_attr = 0o100644 << 16  # S_IFREG | 0644
            zf.writestr(reg_info, "print('clean')\n")

        assert test_zip.exists()
        candidates, raw_data, meta = run_bandit_engine("datasets/fixtures/sast/_test_valid_clean.zip")
        assert meta["exit_code"] in (0, 1)
        assert meta["engine"] == "bandit"

    finally:
        if test_zip.exists():
            test_zip.unlink()


# ══════════════════════════════════════════════════════════════════════════════
# 2. Mandatory Acceptance Proof: Real Run COMPLETE and FAILS Benchmark
# ══════════════════════════════════════════════════════════════════════════════

def test_mandatory_acceptance_proof_completed_run_fails_benchmark():
    """CRITICAL GATE PROOF (Spec line 97):
    'Acceptance evidence MUST include a real completed scan that FAILS its
    benchmark with its missed cases visible. L1 simulations never count as this proof.'
    """
    target_id = "fixture_sast_python"

    scorecard = run_lab_benchmark(
        target_id=target_id,
        engine_id="bandit",
        dataset_id="hexaguard_bench_core",
        dataset_version="1.0.0",
        split="dev",
        repetitions=1,
        user_id=1,
        username="admin",
    )

    # 1. Dual Status Verification: Execution SUCCESS vs Benchmark FAIL
    assert scorecard.execution_status == ExecutionStatus.COMPLETED, (
        f"Expected ExecutionStatus.COMPLETED, got {scorecard.execution_status}"
    )
    assert scorecard.benchmark_status == BenchmarkStatus.FAIL, (
        f"Expected BenchmarkStatus.FAIL, got {scorecard.benchmark_status}"
    )

    # 2. Reason for Benchmark Failure: In-scope Recall below 70% threshold
    assert any("below minimum threshold" in r for r in scorecard.status_reasons), (
        f"Status reasons should explain recall failure: {scorecard.status_reasons}"
    )

    # 3. Visible Missed Cases (False Negatives)
    assert scorecard.fn_count > 0, "Benchmark must have missed cases (FN > 0)"
    assert len(scorecard.missed_cases) == scorecard.fn_count
    missed_case_ids = [m["case_id"] for m in scorecard.missed_cases]

    # Bandit AST does not flag basic open() concatenation or HTML string formatting
    assert "CASE-SAST-TRAVERSAL-001" in missed_case_ids, (
        "Expected Path Traversal (CWE-22) to be in missed cases list"
    )
    assert "CASE-SAST-XSS-001" in missed_case_ids, (
        "Expected Cross-Site Scripting (CWE-79) to be in missed cases list"
    )

    # Verify diagnostic evidence for each missed case
    for missed in scorecard.missed_cases:
        assert missed["expected_evidence"], "Missed case must include expected evidence snippet"
        assert missed["location"]["line"] > 0
        assert missed["explanation"], "Missed case must include explanation of failure"

    # 4. Verified Negative Controls (True Negatives)
    assert scorecard.eligible_negative_controls == 4
    assert scorecard.tn_count == 4, "All 4 negative controls should be clean true negatives"
    assert scorecard.fp_on_negative_controls == 0
    assert scorecard.fpr_on_negative_controls.value == 0.0

    # 5. UNREVIEWED Queue
    # Bandit reports B404 on `import subprocess` at line 19, which is not in our GT manifest
    assert scorecard.unreviewed_count > 0
    assert len(scorecard.unreviewed_queue) == scorecard.unreviewed_count
    unreviewed_rules = [u["rule_id"] for u in scorecard.unreviewed_queue]
    assert "bandit_B404" in unreviewed_rules

    # 6. Precision Bounds (Honest Handling of UNREVIEWED)
    # Lower bound treats unreviewed as FP; upper bound treats them as non-FP
    lower = scorecard.precision_lower_bound.value
    upper = scorecard.precision_optimistic_upper_bound.value
    assert lower is not None and upper is not None
    assert lower <= upper, f"Lower bound ({lower}) cannot exceed upper bound ({upper})"


def test_repeated_run_non_determinism_stats():
    """Verify scanner non-determinism measurements over repeated runs (Spec line 93)."""
    scorecard = run_lab_benchmark(
        target_id="fixture_sast_python",
        engine_id="bandit",
        repetitions=3,
        user_id=1,
        username="admin",
    )

    stats = scorecard.repeated_run_stats
    assert stats is not None
    assert stats["n"] == 3
    assert stats["mean"] is not None
    assert stats["sd"] is not None
    # Bandit AST is deterministic on fixed files, so standard deviation should be 0.0
    assert stats["sd"] == 0.0


# ══════════════════════════════════════════════════════════════════════════════
# 3. Database Persistence and Retrieval
# ══════════════════════════════════════════════════════════════════════════════

def test_benchmark_persistence_and_retrieval():
    """Verify that benchmark scorecards are properly persisted and retrievable by ID."""
    scorecard = run_lab_benchmark(
        target_id="fixture_sast_python",
        engine_id="bandit",
        user_id=1,
        username="admin",
    )

    bench_id = scorecard.to_dict().get("benchmark_id")
    # Retrieve from DB
    persisted = get_benchmark_scorecard(bench_id)
    assert persisted is not None
    assert persisted["engine_id"] == "bandit"
    assert persisted["execution_status"] == "COMPLETED"
    assert persisted["benchmark_status"] == "FAIL"

    # List benchmarks
    runs = list_benchmark_scorecards(engine_id="bandit")
    assert len(runs) >= 1
    assert any(r["benchmark_id"] == bench_id for r in runs)


# ══════════════════════════════════════════════════════════════════════════════
# 4. Gate Enforcement and Failure Modes
# ══════════════════════════════════════════════════════════════════════════════

def test_benchmark_blocked_when_gate_denies(monkeypatch):
    """Verify that runner returns BLOCKED execution status when Gate denies access."""
    # Turn off LAB_MODE
    monkeypatch.setenv("LAB_MODE", "0")

    scorecard = run_lab_benchmark(
        target_id="fixture_sast_python",
        engine_id="bandit",
        user_id=1,
        username="admin",
    )

    assert scorecard.execution_status == ExecutionStatus.BLOCKED
    assert scorecard.benchmark_status == BenchmarkStatus.ERROR
    assert any("LAB_MODE_DISABLED" in r or "Lab Gate Denied" in r for r in scorecard.status_reasons)


def test_benchmark_blocked_on_unauthorized_target():
    """Verify that attempting to scan an unregistered target returns BLOCKED status."""
    scorecard = run_lab_benchmark(
        target_id="non_existent_target_xyz",
        engine_id="bandit",
        user_id=1,
        username="admin",
    )

    assert scorecard.execution_status == ExecutionStatus.BLOCKED
    assert scorecard.benchmark_status == BenchmarkStatus.ERROR
    assert any("TARGET_NOT_FOUND" in r or "not registered" in r for r in scorecard.status_reasons)


# ══════════════════════════════════════════════════════════════════════════════
# 5. REST API & UI Scorecard Verification
# ══════════════════════════════════════════════════════════════════════════════

def test_api_benchmark_run_sync_endpoint(app, client):
    """Verify POST /api/lab/benchmarks/run synchronous execution with admin+2FA."""
    with client.session_transaction() as sess:
        sess["_user_id"] = "1"
        sess["_fresh"] = True

    response = client.post(
        "/api/lab/benchmarks/run",
        json={
            "target_id": "fixture_sast_python",
            "engine_id": "bandit",
            "sync": True,
        },
    )

    assert response.status_code == 200
    data = response.get_json()
    assert data["ok"] is True
    assert data["sync"] is True

    sc = data["scorecard"]
    assert sc["execution_status"] == "COMPLETED"
    assert sc["benchmark_status"] == "FAIL"
    assert len(sc["missed_cases"]) > 0
    assert len(sc["negative_control_evaluations"]) == 4

    bench_id = sc.get("benchmark_id")

    # Verify GET /api/lab/benchmarks/<id>
    get_res = client.get(f"/api/lab/benchmarks/{bench_id}")
    assert get_res.status_code == 200
    assert get_res.get_json()["ok"] is True

    # Verify GET /api/lab/benchmarks/<id>/view HTML scorecard
    view_res = client.get(f"/api/lab/benchmarks/{bench_id}/view")
    assert view_res.status_code == 200
    html = view_res.data.decode("utf-8")
    assert "SecuraX Evaluation Lab — Benchmark Scorecard" in html
    assert "COMPLETED" in html
    assert "FAIL" in html
    assert "Missed Cases (False Negatives)" in html
    assert "CASE-SAST-TRAVERSAL-001" in html
    assert "Negative Controls Verification" in html
    assert "CLEAN PASS (TN)" in html


def test_api_benchmark_run_async_queue(app, client):
    """Verify POST /api/lab/benchmarks/run async dispatch via job manager."""
    with client.session_transaction() as sess:
        sess["_user_id"] = "1"
        sess["_fresh"] = True

    response = client.post(
        "/api/lab/benchmarks/run",
        json={
            "target_id": "fixture_sast_python",
            "engine_id": "bandit",
            "sync": False,
        },
    )

    assert response.status_code == 202
    data = response.get_json()
    assert data["ok"] is True
    assert "job_id" in data
    assert data["status"] == "queued"


def test_api_benchmark_denies_unauthenticated(client):
    """Verify that unauthenticated requests are strictly rejected (HTTP 401)."""
    response = client.post(
        "/api/lab/benchmarks/run",
        json={"target_id": "fixture_sast_python", "engine_id": "bandit"},
    )
    assert response.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# 6. EXT-A: Tool Output Recorded for Replay
# ══════════════════════════════════════════════════════════════════════════════

def test_ext_a_raw_output_fixture_recorded():
    """Verify EXT-A requirement: raw tool output is recorded for hermetic replay."""
    scorecard = run_lab_benchmark(
        target_id="fixture_sast_python",
        engine_id="bandit",
        record_raw_output=True,
    )

    raw_dir = Path(__file__).resolve().parent.parent / "data" / "recorded_runs"
    assert raw_dir.exists(), "Recorded runs directory should exist"
    recorded_files = list(raw_dir.glob("bandit_fixture_sast_python_*.json"))
    assert len(recorded_files) >= 1, "Expected recorded raw Bandit output fixture"

    with open(recorded_files[0], "r", encoding="utf-8") as f:
        recorded_data = json.load(f)

    assert recorded_data["engine"] == "bandit"
    assert recorded_data["target_id"] == "fixture_sast_python"
    assert "raw_output" in recorded_data
    assert "results" in recorded_data["raw_output"]
