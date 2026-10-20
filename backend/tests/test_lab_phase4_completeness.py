"""SecuraX Evaluation Lab — Phase 4 Completeness & Wrapper Delta Tests.

Governed strictly by Master Specification v5 Phase 4:
  - Coverage & Scan Telemetry: URLs/params visited, routes skipped, auth status,
    files/languages analyzed, packages inspected, ports probed, rules executed,
    timeouts/errors, scope exclusions.
  - Invariant: Crashed, timed-out or zero-coverage scan NEVER displays as success.
  - Invariant: Empty result wording is 'No findings within the verified scope and coverage shown', NEVER 'secure'.
  - Wrapper Delta across 4 stages:
      Stage 1: Raw tool output (native CLI JSON)
      Stage 2: Adapter output (CandidateFinding normalized)
      Stage 3: Persisted findings (deduplicated & stored in database)
      Stage 4: API & UI displayed findings (rendered in client views)
    Tracks lost/suppressed/merged findings with explicit reason codes and root causes.
  - EXT-B: Adapter fault injection testing (truncated output, malformed JSON, timeouts, empty output).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from database import init_db
from db.lab import (
    get_benchmark_scorecard,
    init_lab_tables,
    seed_ground_truth_cases,
    seed_lab_targets,
)
from lab.config import is_lab_mode_enabled
from lab.models import (
    BenchmarkScorecard,
    BenchmarkStatus,
    CandidateFinding,
    DeltaLossReason,
    EMPTY_RESULT_WORDING,
    ExecutionStatus,
    ScanCoverageTelemetry,
    WrapperDeltaReport,
    WrapperDeltaStage,
)
from lab.runner import (
    compute_wrapper_delta,
    extract_coverage_telemetry,
    run_bandit_engine,
    run_lab_benchmark,
)


@pytest.fixture(autouse=True)
def setup_lab_environment(monkeypatch):
    """Ensure clean test database with LAB_MODE enabled and seeds initialized."""
    test_db = "test_phase4_lab.db"
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
    test_db = str(tmp_path / "test_phase4_flask.db")
    monkeypatch.setenv("DB_PATH", test_db)
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SECRET_KEY", "phase4-test-secret-key-32-chars-min")
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
    return app.test_client()


# ══════════════════════════════════════════════════════════════════════════════
# 1. Coverage & Operational Scan Telemetry
# ══════════════════════════════════════════════════════════════════════════════

def test_coverage_telemetry_reporting():
    """Verify that adapter reports operational coverage telemetry fields."""
    scorecard = run_lab_benchmark(
        target_id="fixture_sast_python",
        engine_id="bandit",
        user_id=1,
        username="admin",
    )

    cov = scorecard.coverage_telemetry
    assert cov is not None, "Scorecard must include coverage_telemetry dict"
    assert "vulnerable_app.py" in str(cov.get("files_analyzed"))
    assert "python" in cov.get("languages_analyzed")
    assert cov.get("lines_of_code") > 0
    assert cov.get("zero_coverage") is False
    assert cov.get("auth_status") == "not_applicable"
    assert cov.get("empty_result_wording") == EMPTY_RESULT_WORDING


def test_empty_findings_wording_never_secure():
    """CRITICAL SPEC REQUIREMENT:
    Empty result wording MUST be 'No findings within the verified scope and coverage shown', NEVER 'secure'.
    """
    telemetry = ScanCoverageTelemetry()
    assert "secure" not in telemetry.empty_result_wording.lower(), "Wording must never declare a system 'secure'"
    assert telemetry.empty_result_wording == "No findings within the verified scope and coverage shown"


def test_zero_coverage_scan_flag():
    """Verify that zero coverage scans are flagged zero_coverage=True."""
    raw_empty = {"metrics": {"_totals": {"loc": 0}}}
    meta_failed = {"exit_code": 2}
    telemetry = extract_coverage_telemetry(raw_empty, "target.py", [], meta_failed)
    assert telemetry.zero_coverage is True


# ══════════════════════════════════════════════════════════════════════════════
# 2. Wrapper Delta across 4 Pipeline Stages
# ══════════════════════════════════════════════════════════════════════════════

def test_wrapper_delta_four_stages_trace():
    """Verify 4-stage wrapper delta calculation on live Bandit benchmark run."""
    scorecard = run_lab_benchmark(
        target_id="fixture_sast_python",
        engine_id="bandit",
        user_id=1,
        username="admin",
    )

    delta = scorecard.wrapper_delta
    assert delta is not None, "Scorecard must include wrapper_delta"
    stages = delta.get("stages", {})
    assert "stage_1_raw" in stages
    assert "stage_2_adapter" in stages
    assert "stage_3_persisted" in stages
    assert "stage_4_displayed" in stages

    s1 = stages["stage_1_raw"]
    s2 = stages["stage_2_adapter"]
    s3 = stages["stage_3_persisted"]
    s4 = stages["stage_4_displayed"]

    # In our live fixture run: 3 raw findings (B404, B602, B324) -> 3 candidates -> 3 persisted -> 3 displayed
    assert s1["count"] == 3
    assert s2["count"] == 3
    assert s3["count"] == 3
    assert s4["count"] == 3
    assert delta["summary"]["total_net_delta"] == 0
    assert delta["summary"]["has_unexplained_loss"] is False


def test_wrapper_delta_deduplication_loss_attribution():
    """Verify that duplicate candidate suppression is attributed to DEDUPLICATION reason code."""
    c1 = CandidateFinding(
        finding_id="cand_1", engine_id="bandit", target_id="t1",
        cwe="CWE-78", severity="high", location={"file": "app.py", "line": 10},
    )
    c2 = CandidateFinding(
        finding_id="cand_2", engine_id="bandit", target_id="t1",
        cwe="CWE-78", severity="high", location={"file": "app.py", "line": 10},
    )

    raw_data = {"results": [{"test_id": "B602"}, {"test_id": "B602"}]}
    adapter_candidates = [c1, c2]
    deduped = [c1]
    provenance = {"cand_1": ["cand_1", "cand_2"]}
    matched = [{"case_id": "CASE-1"}]

    report = compute_wrapper_delta(
        raw_data=raw_data,
        adapter_candidates=adapter_candidates,
        deduped_candidates=deduped,
        provenance_map=provenance,
        matched_case_details=matched,
        unreviewed_findings=[],
        confirmed_fp_findings=[],
    )

    s3 = report.stage_3_persisted
    assert s3.count == 1
    assert s3.delta_from_previous == -1
    assert len(s3.lost_items) == 1
    lost = s3.lost_items[0]
    assert lost.reason_code == DeltaLossReason.DEDUPLICATION.value
    assert lost.finding_id == "cand_2"
    assert "duplicate" in lost.root_cause
    assert report.has_unexplained_loss is False


def test_wrapper_delta_normalization_loss_attribution():
    """Verify that unparseable raw tool results are attributed to PARSE_ERROR reason code."""
    raw_data = {"results": [{"test_id": "B602"}, {"test_id": "B000_CORRUPT"}]}
    c1 = CandidateFinding(
        finding_id="cand_1", engine_id="bandit", target_id="t1",
        cwe="CWE-78", severity="high", location={"file": "app.py", "line": 10},
    )
    # Only 1 of 2 normalized
    report = compute_wrapper_delta(
        raw_data=raw_data,
        adapter_candidates=[c1],
        deduped_candidates=[c1],
        provenance_map={"cand_1": ["cand_1"]},
        matched_case_details=[{"case_id": "CASE-1"}],
        unreviewed_findings=[],
        confirmed_fp_findings=[],
    )

    s2 = report.stage_2_adapter
    assert s2.count == 1
    assert s2.delta_from_previous == -1
    assert len(s2.lost_items) == 1
    assert s2.lost_items[0].reason_code == DeltaLossReason.PARSE_ERROR.value
    assert "ADAPTER_NORMALIZATION_LOSS" in report.warning_flags


# ══════════════════════════════════════════════════════════════════════════════
# 3. EXT-B Adapter Fault Injection Testing
# ══════════════════════════════════════════════════════════════════════════════

def test_fault_injection_truncated_json_fails_closed():
    """EXT-B: Verify truncated JSON output causes execution failure, never success."""
    truncated_stdout = '{"results": [{"test_id": "B602", "line_number": 28'

    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = subprocess.CompletedProcess(
            args=["bandit"],
            returncode=0,
            stdout=truncated_stdout,
            stderr="",
        )

        scorecard = run_lab_benchmark(
            target_id="fixture_sast_python",
            engine_id="bandit",
            user_id=1,
            username="admin",
        )

        assert scorecard.execution_status == ExecutionStatus.FAILED
        assert scorecard.benchmark_status == BenchmarkStatus.ERROR
        assert scorecard.coverage_telemetry.get("zero_coverage") is True
        assert any("Execution Failed" in r for r in scorecard.status_reasons)


def test_fault_injection_malformed_non_json_fails_closed():
    """EXT-B: Verify non-JSON output causes execution failure, never success."""
    non_json_stdout = "Fatal Python error: Segmentation fault in C extension"

    with patch("subprocess.run") as mock_sub:
        mock_sub.return_value = subprocess.CompletedProcess(
            args=["bandit"],
            returncode=139,
            stdout=non_json_stdout,
            stderr="Segmentation fault",
        )

        scorecard = run_lab_benchmark(
            target_id="fixture_sast_python",
            engine_id="bandit",
            user_id=1,
            username="admin",
        )

        assert scorecard.execution_status == ExecutionStatus.FAILED
        assert scorecard.benchmark_status == BenchmarkStatus.ERROR
        assert scorecard.coverage_telemetry.get("zero_coverage") is True


def test_fault_injection_timeout_fails_closed():
    """EXT-B: Verify hung process/timeout sets TIMED_OUT status, never success."""
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["bandit"], timeout=120)):
        scorecard = run_lab_benchmark(
            target_id="fixture_sast_python",
            engine_id="bandit",
            user_id=1,
            username="admin",
        )

        assert scorecard.execution_status == ExecutionStatus.TIMED_OUT
        assert scorecard.benchmark_status == BenchmarkStatus.ERROR
        assert scorecard.coverage_telemetry.get("zero_coverage") is True
        assert any("timed out" in r.lower() or "timeout" in r.lower() for r in scorecard.status_reasons)


# ══════════════════════════════════════════════════════════════════════════════
# 4. REST API & UI Scorecard Rendering
# ══════════════════════════════════════════════════════════════════════════════

def test_api_benchmark_json_exposes_phase4_fields(app, client):
    """Verify GET /api/lab/benchmarks/<id> exposes coverage_telemetry and wrapper_delta."""
    with client.session_transaction() as sess:
        sess["_user_id"] = "1"
        sess["_fresh"] = True

    response = client.post(
        "/api/lab/benchmarks/run",
        json={"target_id": "fixture_sast_python", "engine_id": "bandit", "sync": True},
    )
    assert response.status_code == 200
    sc = response.get_json()["scorecard"]
    bench_id = sc["benchmark_id"]

    get_res = client.get(f"/api/lab/benchmarks/{bench_id}")
    assert get_res.status_code == 200
    data = get_res.get_json()["scorecard"]
    assert "coverage_telemetry" in data
    assert "wrapper_delta" in data
    assert data["coverage_telemetry"]["empty_result_wording"] == EMPTY_RESULT_WORDING


def test_html_scorecard_renders_coverage_and_wrapper_delta(app, client):
    """Verify GET /api/lab/benchmarks/<id>/view renders Phase 4 Coverage and Wrapper Delta panels."""
    with client.session_transaction() as sess:
        sess["_user_id"] = "1"
        sess["_fresh"] = True

    response = client.post(
        "/api/lab/benchmarks/run",
        json={"target_id": "fixture_sast_python", "engine_id": "bandit", "sync": True},
    )
    sc = response.get_json()["scorecard"]
    bench_id = sc["benchmark_id"]

    view_res = client.get(f"/api/lab/benchmarks/{bench_id}/view")
    assert view_res.status_code == 200
    html = view_res.data.decode("utf-8")

    # Assert Coverage panel is rendered
    assert "Verified Scope &amp; Coverage Telemetry" in html or "Verified Scope & Coverage Telemetry" in html
    assert "Lines of Code Inspected" in html
    assert "Zero Coverage Guard" in html

    # Assert Wrapper Delta panel is rendered
    assert "Wrapper Delta (4-Stage Pipeline Analysis)" in html
    assert "Stage 1" in html
    assert "Raw Tool Output" in html
    assert "Stage 2" in html
    assert "Adapter Output" in html
    assert "Stage 3" in html
    assert "Persisted Findings" in html
    assert "Stage 4" in html
    assert "API &amp; UI Displayed Findings" in html or "API & UI Displayed Findings" in html
    assert "0 UNEXPLAINED LOSS (PASS)" in html
