import os
import sys
import tempfile
import socket
import pytest

# ── Hermetic Database Isolation ──────────────────────────────────────────────
# Ensure that all unit/integration tests running under pytest use an isolated
# temporary SQLite database, preventing any test from modifying production securax.db.
_TEST_TEMP_DIR = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
_TEST_TEMP_DB = os.path.join(_TEST_TEMP_DIR.name, "test_session_isolated.db")
os.environ["DB_PATH"] = _TEST_TEMP_DB

# Reset any thread-local connection and bootstrap schema on the isolated test database
try:
    from db.connection import init_db, _local
    if hasattr(_local, "conn") and _local.conn:
        try:
            _local.conn.close()
        except Exception:
            pass
        _local.conn = None
        _local.conn_path = None
    init_db()
except Exception:
    pass

import atexit
def _cleanup_test_db():
    try:
        from db.connection import _local
        if hasattr(_local, "conn") and _local.conn:
            _local.conn.close()
            _local.conn = None
            _local.conn_path = None
    except Exception:
        pass
atexit.register(_cleanup_test_db)


@pytest.fixture(scope="session", autouse=True)
def test_db_session():
    """Session-scoped fixture guaranteeing hermetic DB isolation."""
    os.environ["DB_PATH"] = _TEST_TEMP_DB
    yield _TEST_TEMP_DB


@pytest.fixture(autouse=True)
def mock_dns_resolution(monkeypatch):
    """Hermetic DNS resolution mock for tests.

    Ensures that socket-disabled hermetic tests can run safely without
    modifying production SSRF guard code.
    - Known test domains resolve to public IP literals.
    - Specific unresolvable test hostnames raise socket.gaierror to test fail-closed behavior.
    """
    _PUBLIC_TEST_MAP = {
        "example.com": "93.184.216.34",
        "scanme.nmap.org": "45.33.32.156",
        "google.com": "142.250.190.46",
        "securax-demo.target": "93.184.216.34",
        "target.example": "93.184.216.34",
    }

    def _mock_getaddrinfo(host, port, *args, **kwargs):
        h = str(host).lower().strip()
        # Fail-closed test hostnames
        if "unresolvable" in h or "nonexistent" in h or h == "invalid-host-dns-fail":
            raise socket.gaierror(-2, "Name or service not known")
        if h in ("localhost", "127.0.0.1", "::1"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', port or 0))]
        if h in ("169.254.169.254", "metadata.google.internal"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', port or 0))]
        if h in _PUBLIC_TEST_MAP:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (_PUBLIC_TEST_MAP[h], port or 0))]
        # Generic fallback for any other public domain tested in unit tests
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ("93.184.216.34", port or 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _mock_getaddrinfo)
