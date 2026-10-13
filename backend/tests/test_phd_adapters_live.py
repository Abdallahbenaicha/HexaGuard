import pytest
from blueprints.phd import (
    _run_jobs_ac_uk_adapter,
    _run_academictransfer_adapter,
    _run_euraxess_adapter,
)


@pytest.mark.live
def test_jobs_ac_uk_live_structure():
    items, success, err, http_code, raw_count, rejected_count = _run_jobs_ac_uk_adapter("cybersecurity")
    # Live endpoints may be rate limited or succeed; we verify response schema contract
    assert isinstance(items, list)
    assert isinstance(success, bool)
    assert isinstance(http_code, int)
    if items:
        item = items[0]
        assert item["source_id"] == "jobs_ac_uk"
        assert item["record_type"] in ("vacancy_lead", "verified_vacancy")
        assert "id" in item
        assert "application_url" in item


@pytest.mark.live
def test_academictransfer_live_structure():
    items, success, err, http_code, raw_count, rejected_count = _run_academictransfer_adapter("cybersecurity")
    assert isinstance(items, list)
    assert isinstance(success, bool)
    assert isinstance(http_code, int)
    if items:
        item = items[0]
        assert item["source_id"] == "academictransfer"
        assert item["record_type"] in ("vacancy_lead", "verified_vacancy")


@pytest.mark.live
def test_euraxess_live_structure():
    items, success, err, http_code, raw_count, rejected_count = _run_euraxess_adapter("cybersecurity")
    assert isinstance(items, list)
    assert isinstance(success, bool)
    assert isinstance(http_code, int)
    if items:
        item = items[0]
        assert item["source_id"] == "euraxess"
        assert item["record_type"] in ("vacancy_lead", "verified_vacancy")
