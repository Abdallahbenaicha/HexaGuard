import pathlib
import pytest
from blueprints.phd import (
    _run_jobs_ac_uk_adapter,
    _run_academictransfer_adapter,
    _run_euraxess_adapter,
    _extract_institution,
    _extract_deadline,
    _extract_funding,
    _extract_language_req,
)

FIXTURES_DIR = pathlib.Path(__file__).parent / "fixtures" / "phd"


def _read_fixture(filename: str) -> str:
    path = FIXTURES_DIR / filename
    return path.read_text(encoding="utf-8")


# ── Jobs.ac.uk Tests ─────────────────────────────────────────────────────────

def test_jobs_ac_uk_normal(monkeypatch):
    html = _read_fixture("jobs_ac_uk_normal.html")
    monkeypatch.setattr("blueprints.phd._safe_fetch", lambda url, timeout=10: html)

    items, success, err, http_code, raw_count, rejected_count = _run_jobs_ac_uk_adapter("cybersecurity")
    assert success is True
    assert raw_count >= 1
    assert len(items) >= 1
    for it in items:
        assert it["source_id"] == "jobs_ac_uk"
        assert it["record_type"] == "vacancy_lead"
        assert it["verification_status"] == "unverified_lead"
        assert it["confidence"] == 0.5


def test_jobs_ac_uk_detail(monkeypatch):
    listing_html = _read_fixture("jobs_ac_uk_normal.html")
    detail_html = _read_fixture("jobs_ac_uk_detail.html")

    def mock_fetch(url, timeout=10):
        if "/search" in url or "keywords" in url:
            return listing_html
        return detail_html

    monkeypatch.setattr("blueprints.phd._safe_fetch", mock_fetch)

    items, success, err, http_code, raw_count, rejected_count = _run_jobs_ac_uk_adapter(
        "cybersecurity", fetch_details=True, max_details=1
    )
    assert success is True
    assert len(items) >= 1
    first = items[0]
    assert first["institution"] == "University of Oxford"
    assert first["deadline"] == "2026-05-30"
    assert first["record_type"] == "verified_vacancy"
    assert first["verification_status"] == "verified_vacancy"
    assert first["confidence"] == 0.85


def test_jobs_ac_uk_empty(monkeypatch):
    html = _read_fixture("jobs_ac_uk_empty.html")
    monkeypatch.setattr("blueprints.phd._safe_fetch", lambda url, timeout=10: html)

    items, success, err, http_code, raw_count, rejected_count = _run_jobs_ac_uk_adapter("cybersecurity")
    assert success is True
    assert raw_count == 0
    assert len(items) == 0


def test_jobs_ac_uk_drift(monkeypatch):
    html = _read_fixture("jobs_ac_uk_drift.html")
    monkeypatch.setattr("blueprints.phd._safe_fetch", lambda url, timeout=10: html)

    items, success, err, http_code, raw_count, rejected_count = _run_jobs_ac_uk_adapter("cybersecurity")
    assert success is True
    assert raw_count == 0 or len(items) == 0


# ── AcademicTransfer Tests ────────────────────────────────────────────────────

def test_academictransfer_normal(monkeypatch):
    html = _read_fixture("academictransfer_normal.html")
    monkeypatch.setattr("blueprints.phd._safe_fetch", lambda url, timeout=10: html)

    items, success, err, http_code, raw_count, rejected_count = _run_academictransfer_adapter("cybersecurity")
    assert success is True
    assert raw_count >= 1
    assert len(items) >= 1
    for it in items:
        assert it["source_id"] == "academictransfer"
        assert it["record_type"] == "vacancy_lead"
        assert it["verification_status"] == "unverified_lead"
        assert it["confidence"] == 0.5


def test_academictransfer_detail(monkeypatch):
    listing_html = _read_fixture("academictransfer_normal.html")
    detail_html = _read_fixture("academictransfer_detail.html")

    def mock_fetch(url, timeout=10):
        if "/jobs/?q=" in url:
            return listing_html
        return detail_html

    monkeypatch.setattr("blueprints.phd._safe_fetch", mock_fetch)

    items, success, err, http_code, raw_count, rejected_count = _run_academictransfer_adapter(
        "cybersecurity", fetch_details=True, max_details=1
    )
    assert success is True
    assert len(items) >= 1
    first = items[0]
    assert first["institution"] == "Delft University of Technology"
    assert first["deadline"] == "2026-06-15"
    assert first["record_type"] == "verified_vacancy"
    assert first["verification_status"] == "verified_vacancy"


def test_academictransfer_empty(monkeypatch):
    html = _read_fixture("academictransfer_empty.html")
    monkeypatch.setattr("blueprints.phd._safe_fetch", lambda url, timeout=10: html)

    items, success, err, http_code, raw_count, rejected_count = _run_academictransfer_adapter("cybersecurity")
    assert success is True
    assert len(items) == 0


def test_academictransfer_drift(monkeypatch):
    html = _read_fixture("academictransfer_drift.html")
    monkeypatch.setattr("blueprints.phd._safe_fetch", lambda url, timeout=10: html)

    items, success, err, http_code, raw_count, rejected_count = _run_academictransfer_adapter("cybersecurity")
    assert success is True
    assert len(items) == 0


# ── EURAXESS Tests ────────────────────────────────────────────────────────────

def test_euraxess_normal(monkeypatch):
    html = _read_fixture("euraxess_normal.html")
    monkeypatch.setattr("blueprints.phd._safe_fetch", lambda url, timeout=10: html)

    items, success, err, http_code, raw_count, rejected_count = _run_euraxess_adapter("cybersecurity")
    assert success is True
    assert raw_count >= 1
    assert len(items) >= 1
    for it in items:
        assert it["source_id"] == "euraxess"
        assert it["record_type"] == "vacancy_lead"
        assert it["verification_status"] == "unverified_lead"
        assert it["confidence"] == 0.5


def test_euraxess_detail(monkeypatch):
    listing_html = _read_fixture("euraxess_normal.html")
    detail_html = _read_fixture("euraxess_detail.html")

    def mock_fetch(url, timeout=10):
        if "/jobs/search" in url:
            return listing_html
        return detail_html

    monkeypatch.setattr("blueprints.phd._safe_fetch", mock_fetch)

    items, success, err, http_code, raw_count, rejected_count = _run_euraxess_adapter(
        "cybersecurity", fetch_details=True, max_details=1
    )
    assert success is True
    assert len(items) >= 1
    first = items[0]
    assert first["institution"] == "KU Leuven"
    assert first["deadline"] == "2026-07-01"
    assert first["record_type"] == "verified_vacancy"
    assert first["verification_status"] == "verified_vacancy"


def test_euraxess_empty(monkeypatch):
    html = _read_fixture("euraxess_empty.html")
    monkeypatch.setattr("blueprints.phd._safe_fetch", lambda url, timeout=10: html)

    items, success, err, http_code, raw_count, rejected_count = _run_euraxess_adapter("cybersecurity")
    assert success is True
    assert len(items) == 0


def test_euraxess_drift(monkeypatch):
    html = _read_fixture("euraxess_drift.html")
    monkeypatch.setattr("blueprints.phd._safe_fetch", lambda url, timeout=10: html)

    items, success, err, http_code, raw_count, rejected_count = _run_euraxess_adapter("cybersecurity")
    assert success is True
    assert len(items) == 0


def test_doctoral_filter_rejects_faculty_and_postdoc():
    from blueprints.phd import _is_doctoral_vacancy
    assert _is_doctoral_vacancy("Lecturer in Computer Science")[0] is False
    assert _is_doctoral_vacancy("Assistant Professor of Cybersecurity")[0] is False
    assert _is_doctoral_vacancy("Associate Professor in Information Security")[0] is False
    assert _is_doctoral_vacancy("Postdoctoral Researcher in Cryptography")[0] is False
    assert _is_doctoral_vacancy("Faculty Position in Computing")[0] is False
    assert _is_doctoral_vacancy("Senior Lecturer in Cloud Computing")[0] is False

    assert _is_doctoral_vacancy("PhD Studentship in Software Security")[0] is True
    assert _is_doctoral_vacancy("Doctoral Researcher — Vulnerability Analysis")[0] is True
    assert _is_doctoral_vacancy("PhD Candidate in Cryptography")[0] is True
    assert _is_doctoral_vacancy("Doctoral Fellow in Information Systems")[0] is True


def test_jobs_ac_uk_adapter_rejects_faculty_roles(monkeypatch):
    sample_html = """
    <div class="j-search-result__list">
      <div class="j-search-result__text">
        <a href="/job/JOB001/phd-studentship-cybersecurity">PhD Studentship in Cybersecurity</a>
        <div class="j-search-result__employer"><b>University of Oxford</b></div>
        <p>Cybersecurity doctoral studentship.</p>
      </div>
      <div class="j-search-result__text">
        <a href="/job/JOB002/lecturer-in-cybersecurity">Lecturer in Cybersecurity</a>
        <div class="j-search-result__employer"><b>University of Manchester</b></div>
        <p>Permanent faculty lecturer role.</p>
      </div>
      <div class="j-search-result__text">
        <a href="/job/JOB003/assistant-professor-in-cybersecurity">Assistant Professor of Cybersecurity</a>
        <div class="j-search-result__employer"><b>Imperial College London</b></div>
        <p>Tenure-track faculty position.</p>
      </div>
    </div>
    """
    monkeypatch.setattr("blueprints.phd._safe_fetch", lambda url, timeout=10: sample_html)
    items, success, err, http_code, raw_count, rejected_count = _run_jobs_ac_uk_adapter("cybersecurity")
    assert success is True
    assert raw_count == 3
    assert len(items) == 1
    assert items[0]["program"] == "PhD Studentship in Cybersecurity"
    assert rejected_count == 2

