import os
import pytest
from utils import is_env_truthy, check_ssrf
from scanners.dast_scanner import run_dast_scan, DASTConfig

def test_is_env_truthy_various_inputs(monkeypatch):
    """Verifies that is_env_truthy accepts 1/true/yes/on in any case and rejects others."""
    # Truthy values
    for val in ("1", "true", "True", "TRUE", "yes", "Yes", "YES", "on", "ON"):
        monkeypatch.setenv("TEST_FLAG", val)
        assert is_env_truthy("TEST_FLAG") is True
        
    # Falsy values
    for val in ("0", "false", "False", "no", "NO", "off", "", "random", "none"):
        monkeypatch.setenv("TEST_FLAG", val)
        assert is_env_truthy("TEST_FLAG") is False

    monkeypatch.delenv("TEST_FLAG", raising=False)
    assert is_env_truthy("TEST_FLAG") is False


def test_allow_local_lab_targets_unified_truthy_support(monkeypatch):
    """Verifies that ALLOW_LOCAL_LAB_TARGETS accepts 1, true, yes to permit loopback in SSRF guard."""
    for truthy_val in ("1", "true", "yes", "YES", "True"):
        monkeypatch.setenv("ALLOW_LOCAL_LAB_TARGETS", truthy_val)
        ok, err = check_ssrf("127.0.0.1")
        assert ok is True, f"Failed for value {truthy_val}: {err}"

    # Falsy values block loopback by default
    for falsy_val in ("0", "false", "no", ""):
        monkeypatch.setenv("ALLOW_LOCAL_LAB_TARGETS", falsy_val)
        ok, err = check_ssrf("127.0.0.1")
        assert ok is False


def test_dast_allow_internal_unified_truthy_support(monkeypatch):
    """Verifies that DAST_ALLOW_INTERNAL accepts 1, true, yes."""
    for truthy_val in ("1", "true", "yes", "YES", "True"):
        monkeypatch.setenv("DAST_ALLOW_INTERNAL", truthy_val)
        # Scan internal loopback URL; should not raise SSRF error before tool availability check
        result = run_dast_scan("http://127.0.0.1:8080")
        assert isinstance(result, dict)
        assert result.get("target") == "http://127.0.0.1:8080"
