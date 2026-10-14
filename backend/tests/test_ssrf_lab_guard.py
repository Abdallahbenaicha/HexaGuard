"""
test_ssrf_lab_guard.py
======================
Hermetic tests for the ALLOW_LOCAL_LAB_TARGETS env-flag behaviour in
check_ssrf() (backend/utils.py).

check_ssrf() reads os.environ at *call time* (not at import time), so
monkeypatch.setenv/delenv takes effect without reloading the module.

Task: MASTER_PLAN 2.0.2
Evidence: all 4 tests must pass (pytest -q).
"""

import pytest

from utils import check_ssrf  # noqa: E402 — tests/ runs from backend/


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_ssrf_blocks_localhost_by_default(monkeypatch):
    """Without the flag, 127.0.0.1 must be blocked."""
    monkeypatch.delenv("ALLOW_LOCAL_LAB_TARGETS", raising=False)
    safe, msg = check_ssrf("http://127.0.0.1:8080")
    assert not safe, f"Expected blocked, got: {msg}"


def test_ssrf_allows_localhost_with_lab_flag(monkeypatch):
    """With ALLOW_LOCAL_LAB_TARGETS=true, 127.0.0.1 must be permitted."""
    monkeypatch.setenv("ALLOW_LOCAL_LAB_TARGETS", "true")
    safe, msg = check_ssrf("http://127.0.0.1:8080")
    assert safe, f"Expected allowed, got: {msg}"


def test_ssrf_blocks_metadata_even_with_lab_flag(monkeypatch):
    """169.254.169.254 must always be blocked, lab flag notwithstanding."""
    monkeypatch.setenv("ALLOW_LOCAL_LAB_TARGETS", "true")
    safe, msg = check_ssrf("http://169.254.169.254/latest/meta-data/")
    assert not safe, f"Expected blocked, got: {msg}"


def test_ssrf_blocks_private_rfc1918_even_with_lab_flag(monkeypatch):
    """RFC-1918 (192.168.x.x) must be blocked even when lab flag is true.
    The lab flag allows ONLY loopback (127.0.0.0/8), not full RFC-1918.
    """
    monkeypatch.setenv("ALLOW_LOCAL_LAB_TARGETS", "true")
    safe, msg = check_ssrf("http://192.168.1.100")
    assert not safe, f"Expected blocked, got: {msg}"


def test_ssrf_fails_closed_on_dns_resolution_failure():
    """Fail-closed security: if DNS resolution fails, the request must be REJECTED."""
    safe, msg = check_ssrf("http://unresolvable-domain-dns-fail.invalid")
    assert not safe, "Expected SSRF guard to fail CLOSED on unresolvable target"
    assert "could not be resolved" in msg.lower()


def test_ssrf_allows_valid_public_domain():
    """Valid public target resolving to public IP is permitted."""
    safe, msg = check_ssrf("http://example.com")
    assert safe, f"Expected public target to be allowed, got: {msg}"


