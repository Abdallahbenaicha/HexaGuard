"""Unit and integration tests for Bug Bounty Policy Enforcement Gate (P0)."""

import json
import os
import sys
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-tests")

import database as db
from blueprints.bounty import (
    _bounty_engine_params,
    _enforce_bounty_policy_gate,
    _extract_scan_domain,
    _passive_bounty_guard,
)


@pytest.fixture()
def app(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_bounty_gate.db")
    monkeypatch.setenv("DB_PATH", db_file)
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("ENABLE_LIVE_BOUNTY_SCANNING", "true")

    if hasattr(db._local, "conn"):
        del db._local.conn
    db.DB_PATH = db_file

    from app import create_app
    flask_app = create_app()
    flask_app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SESSION_COOKIE_SECURE=False,
    )
    with flask_app.app_context():
        db.init_db()
        yield flask_app

    if hasattr(db._local, "conn"):
        db._local.conn.close()
        del db._local.conn


@pytest.fixture()
def auth_client(app):
    client = app.test_client()
    client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "Admin@2024!"},
        content_type="application/json",
    )
    return client


class TestBountyEngineParams:
    """Tests for P0.2 enforced rate limits based on policy signals."""

    def test_rate_signals_throttle_engine(self):
        snapshot = {
            "signals": ["- automated tools strictly prohibited", "no brute force allowed"]
        }
        rate, threads = _bounty_engine_params(snapshot)
        assert rate == 5
        assert threads == 1

    def test_low_and_slow_signal_throttles(self):
        snapshot = {"signals": ["low and slow testing only"]}
        rate, threads = _bounty_engine_params(snapshot)
        assert rate == 5
        assert threads == 1

    def test_no_restrictions_allows_default(self):
        snapshot = {"signals": ["+ testing encouraged", "+ automated scanners welcome"]}
        rate, threads = _bounty_engine_params(snapshot)
        assert rate == 50
        assert threads == 3


class TestEnforceBountyPolicyGate:
    """Tests for P0.1 server-side policy enforcement gate logic."""

    def test_no_bounty_context_passes_through(self, app):
        with app.test_request_context():
            data = {"url": "https://example.com"}
            ok, res = _enforce_bounty_policy_gate(data, 1, "admin")
            assert ok is True
            assert res is None

    def test_restricted_target_unacknowledged_blocks(self, app):
        with app.test_request_context():
            data = {
                "bounty_context": {
                    "asset": "restricted.example.com",
                    "platform": "hackerone",
                    "program_handle": "restricted-corp",
                    "scan_policy": {
                        "status": "RESTRICTED",
                        "confidence": 85,
                        "signals": ["- automated scanning forbidden"],
                    },
                    "acknowledged": False,
                }
            }
            ok, res = _enforce_bounty_policy_gate(data, 1, "admin")
            assert ok is False
            response, status_code = res
            assert status_code == 403
            resp_data = json.loads(response.get_data(as_text=True))
            assert resp_data["code"] == "POLICY_GATE_BLOCKED"

            # Verify audit log recorded the block
            logs, total = db.get_audit_log(category="bounty", action="bounty_scan_blocked")
            assert total >= 1

    def test_restricted_target_acknowledged_allows(self, app):
        with app.test_request_context():
            data = {
                "bounty_context": {
                    "asset": "restricted.example.com",
                    "platform": "hackerone",
                    "program_handle": "restricted-corp",
                    "scan_policy": {
                        "status": "RESTRICTED",
                        "confidence": 85,
                        "signals": ["- automated scanning forbidden"],
                    },
                    "acknowledged": True,
                }
            }
            ok, meta = _enforce_bounty_policy_gate(data, 1, "admin")
            assert ok is True
            assert isinstance(meta, dict)
            assert meta["bounty_platform"] == "hackerone"
            assert meta["bounty_program_handle"] == "restricted-corp"
            assert meta["bounty_asset"] == "restricted.example.com"
            assert meta["bounty_acknowledged_by"] == "admin"
            assert "bounty_policy_snapshot" in meta

            # Verify audit log recorded the acknowledgment
            logs, total = db.get_audit_log(category="bounty", action="bounty_scan_acknowledged")
            assert total >= 1

    def test_allowed_target_passes_without_acknowledgment(self, app):
        with app.test_request_context():
            data = {
                "bounty_context": {
                    "asset": "allowed.example.com",
                    "platform": "bugcrowd",
                    "program_handle": "friendly-program",
                    "scan_policy": {
                        "status": "ALLOWED",
                        "confidence": 90,
                        "signals": ["+ automated scanning permitted"],
                    },
                    "acknowledged": False,
                }
            }
            ok, meta = _enforce_bounty_policy_gate(data, 1, "admin")
            assert ok is True
            assert isinstance(meta, dict)
            assert meta["bounty_asset"] == "allowed.example.com"


class TestBountyGateApiIntegration:
    """Integration tests via HTTP client for P0 gate."""

    def test_verify_policy_endpoint(self, auth_client):
        payload = {
            "bounty_context": {
                "asset": "target.com",
                "instruction": "Automated tools and scanners are completely forbidden.",
            }
        }
        res = auth_client.post("/api/bounty/verify-policy", json=payload)
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] in ("RESTRICTED", "UNKNOWN")
        assert data["blocked"] is True

    def test_scan_url_restricted_unacknowledged_returns_403(self, auth_client):
        payload = {
            "url": "https://restricted.example.com",
            "bounty_context": {
                "asset": "restricted.example.com",
                "platform": "hackerone",
                "program_handle": "test-prog",
                "scan_policy": {
                    "status": "RESTRICTED",
                    "confidence": 90,
                    "signals": ["- no scanning"],
                },
                "acknowledged": False,
            },
        }
        res = auth_client.post("/scan_url", json=payload)
        assert res.status_code == 403
        data = res.get_json()
        assert data["code"] == "POLICY_GATE_BLOCKED"

    def test_async_scan_web_restricted_unacknowledged_returns_403(self, auth_client):
        payload = {
            "url": "https://restricted.example.com",
            "bounty_context": {
                "asset": "restricted.example.com",
                "platform": "hackerone",
                "program_handle": "test-prog",
                "scan_policy": {
                    "status": "RESTRICTED",
                    "confidence": 90,
                    "signals": ["- no scanning"],
                },
                "acknowledged": False,
            },
        }
        res = auth_client.post("/api/scan/async/web", json=payload)
        assert res.status_code == 403
        data = res.get_json()
        assert data["code"] == "POLICY_GATE_BLOCKED"


class TestReportBountyAuditSnapshot:
    """Tests for P0.3 audit trail and frozen policy snapshot persistence."""

    def test_store_report_persists_bounty_metadata(self, app):
        with app.app_context():
            result = {
                "scan_type": "web",
                "target": "bounty.shopify.com",
                "vulnerabilities": [],
            }
            bounty_meta = {
                "bounty_platform": "hackerone",
                "bounty_program_handle": "shopify",
                "bounty_asset": "*.shopify.com",
                "bounty_policy_snapshot": {
                    "status": "ALLOWED",
                    "confidence": 95,
                    "signals": ["+ automated scanning permitted"],
                    "captured_at": "2026-09-06T12:00:00Z",
                },
                "bounty_acknowledged_by": "admin",
                "bounty_acknowledged_at": "2026-09-06T12:00:01Z",
            }
            token = db.store_report(
                result, risk_score=15.0, original_content=None,
                user_id=1, username="admin", bounty_meta=bounty_meta,
            )

            report = db.get_report(token)
            assert report is not None
            assert report.get("bounty_platform") == "hackerone"
            assert report.get("bounty_program_handle") == "shopify"
            assert report.get("bounty_asset") == "*.shopify.com"

            # Check result JSON preserves the full frozen snapshot
            bounty_data = report["result"]["bounty"]
            assert bounty_data["bounty_policy_snapshot"]["status"] == "ALLOWED"

class TestExtractScanDomain:
    """Unit tests for _extract_scan_domain helper."""

    def test_plain_domain(self):
        assert _extract_scan_domain("shopify.com") == "shopify.com"

    def test_https_url_with_path(self):
        assert _extract_scan_domain("https://admin.shopify.com/some/path?q=1") == "admin.shopify.com"

    def test_http_url(self):
        assert _extract_scan_domain("http://target.example.com") == "target.example.com"

    def test_url_with_port(self):
        assert _extract_scan_domain("https://example.com:8443/api") == "example.com"

    def test_ip_address(self):
        assert _extract_scan_domain("https://192.168.1.1:8080/path") == "192.168.1.1"

    def test_empty_string(self):
        assert _extract_scan_domain("") == ""

    def test_none_like_empty(self):
        assert _extract_scan_domain(None) == ""


class TestPassiveBountyGuard:
    """Unit tests for Layer-1 passive guard."""

    def _make_cache(self, monkeypatch, targets_by_platform: dict):
        """Inject synthetic cache entries and normaliser into bounty module."""
        import blueprints.bounty as bounty_mod

        fake_cache = {
            plat: {"data": targets, "ts": __import__('time').time()}
            for plat, targets in targets_by_platform.items()
        }

        # Identity normaliser: data IS already the normalised target list
        def _identity_norm(raw):
            return raw

        fake_normalisers = {plat: (None, _identity_norm) for plat in targets_by_platform}

        monkeypatch.setattr(bounty_mod, "_get_bb_cache",
                            lambda: (fake_cache, fake_normalisers))

    def test_exact_match_restricted_high_confidence_blocks(self, monkeypatch):
        self._make_cache(monkeypatch, {
            "hackerone": [{
                "asset": "restricted.example.com",
                "program_handle": "test-prog",
                "program_name": "Test Program",
                "scan_policy": {"status": "RESTRICTED", "confidence": 90, "signals": []},
            }]
        })
        ok, info = _passive_bounty_guard("restricted.example.com")
        assert ok is False
        assert info["match_type"] == "exact"
        assert info["status"] == "RESTRICTED"
        assert info["confidence"] == 90

    def test_wildcard_suffix_match_blocks(self, monkeypatch):
        self._make_cache(monkeypatch, {
            "bugcrowd": [{
                "asset": "*.shopify.com",
                "program_handle": "shopify",
                "program_name": "Shopify",
                "scan_policy": {"status": "RESTRICTED", "confidence": 85, "signals": []},
            }]
        })
        ok, info = _passive_bounty_guard("store.shopify.com")
        assert ok is False
        assert info["match_type"] == "wildcard_suffix"

    def test_wildcard_does_not_match_parent_domain(self, monkeypatch):
        """'*.shopify.com' must NOT block 'shopify.com' itself."""
        self._make_cache(monkeypatch, {
            "bugcrowd": [{
                "asset": "*.shopify.com",
                "program_handle": "shopify",
                "program_name": "Shopify",
                "scan_policy": {"status": "RESTRICTED", "confidence": 85, "signals": []},
            }]
        })
        ok, info = _passive_bounty_guard("shopify.com")
        assert ok is True
        assert info is None

    def test_low_confidence_does_not_block(self, monkeypatch):
        """Confidence < 80 must be ignored by passive guard."""
        self._make_cache(monkeypatch, {
            "hackerone": [{
                "asset": "target.com",
                "program_handle": "prog",
                "program_name": "Prog",
                "scan_policy": {"status": "RESTRICTED", "confidence": 40, "signals": []},
            }]
        })
        ok, info = _passive_bounty_guard("target.com")
        assert ok is True
        assert info is None

    def test_allowed_asset_never_blocks(self, monkeypatch):
        self._make_cache(monkeypatch, {
            "hackerone": [{
                "asset": "allowed.example.com",
                "program_handle": "prog",
                "program_name": "Prog",
                "scan_policy": {"status": "ALLOWED", "confidence": 95, "signals": []},
            }]
        })
        ok, info = _passive_bounty_guard("allowed.example.com")
        assert ok is True
        assert info is None

    def test_empty_cache_allows_all(self, monkeypatch):
        self._make_cache(monkeypatch, {})
        ok, info = _passive_bounty_guard("any-target.com")
        assert ok is True
        assert info is None

    def test_unrelated_domain_passes(self, monkeypatch):
        self._make_cache(monkeypatch, {
            "hackerone": [{
                "asset": "restricted.example.com",
                "program_handle": "prog",
                "program_name": "Prog",
                "scan_policy": {"status": "RESTRICTED", "confidence": 90, "signals": []},
            }]
        })
        ok, info = _passive_bounty_guard("my-own-server.internal.corp")
        assert ok is True
        assert info is None


class TestPassiveGuardViaEnforceGate:
    """Integration: _enforce_bounty_policy_gate Layer-1 passive guard path."""

    def test_no_bounty_context_no_cache_passes(self, app):
        """Without cache data, regular scans always pass through."""
        with app.test_request_context():
            data = {"url": "https://my-own-site.example.internal"}
            ok, res = _enforce_bounty_policy_gate(data, 1, "admin")
            assert ok is True
            assert res is None

    def test_no_bounty_context_restricted_cached_blocks(self, app, monkeypatch):
        import blueprints.bounty as bounty_mod

        fake_cache = {
            "hackerone": {
                "data": [{
                    "asset": "restricted-known.com",
                    "program_handle": "prog",
                    "program_name": "Prog",
                    "scan_policy": {"status": "RESTRICTED", "confidence": 90, "signals": []},
                }],
                "ts": __import__('time').time(),
            }
        }
        fake_normalisers = {"hackerone": (None, lambda raw: raw)}
        monkeypatch.setattr(bounty_mod, "_get_bb_cache",
                            lambda: (fake_cache, fake_normalisers))

        with app.test_request_context():
            data = {"url": "https://restricted-known.com/login"}
            ok, res = _enforce_bounty_policy_gate(data, 1, "admin")
            assert ok is False
            response, status_code = res
            assert status_code == 403
            resp_data = json.loads(response.get_data(as_text=True))
            assert resp_data["code"] == "PASSIVE_BOUNTY_BLOCK"
            assert resp_data["matched_asset"] == "restricted-known.com"
            assert resp_data["match_type"] == "exact"


class TestFeatureFlagDisabled:
    """Tests for Bug Bounty feature flag disabled state (public deploy mode)."""

    @pytest.fixture()
    def disabled_app(self, tmp_path, monkeypatch):
        db_file = str(tmp_path / "test_bounty_disabled.db")
        monkeypatch.setenv("DB_PATH", db_file)
        monkeypatch.setenv("FLASK_ENV", "testing")
        monkeypatch.setenv("ENABLE_LIVE_BOUNTY_SCANNING", "false")

        if hasattr(db._local, "conn"):
            del db._local.conn
        db.DB_PATH = db_file

        from app import create_app
        flask_app = create_app()
        flask_app.config.update(
            TESTING=True,
            WTF_CSRF_ENABLED=False,
            SESSION_COOKIE_SECURE=False,
        )
        with flask_app.app_context():
            db.init_db()
            yield flask_app

        if hasattr(db._local, "conn"):
            db._local.conn.close()
            del db._local.conn

    @pytest.fixture()
    def disabled_client(self, disabled_app):
        client = disabled_app.test_client()
        client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "Admin@2024!"},
            content_type="application/json",
        )
        return client

    def test_bounty_endpoints_return_404_when_disabled(self, disabled_client):
        """When feature flag is disabled, all bounty endpoints return 404."""
        res1 = disabled_client.get("/api/admin/bounty-targets")
        assert res1.status_code == 404

        res2 = disabled_client.get("/api/admin/bounty-targets/stats")
        assert res2.status_code == 404

        res3 = disabled_client.post("/api/admin/bounty-targets/refresh")
        assert res3.status_code == 404

        res4 = disabled_client.post("/api/bounty/verify-policy", json={})
        assert res4.status_code == 404

    def test_scan_with_bounty_context_blocked_when_disabled(self, disabled_app):
        """Direct scan request with bounty_context is rejected with 403."""
        with disabled_app.test_request_context():
            data = {
                "url": "https://example.com",
                "bounty_context": {"asset": "example.com"},
            }
            ok, res = _enforce_bounty_policy_gate(data, 1, "admin")
            assert ok is False
            response, status = res
            assert status == 403
            resp_data = json.loads(response.get_data(as_text=True))
            assert resp_data["code"] == "BOUNTY_SCANNING_DISABLED"

    def test_normal_scan_passes_when_disabled(self, disabled_app):
        """Regular scans without bounty_context pass through without interference."""
        with disabled_app.test_request_context():
            data = {"url": "https://normal-scan.com"}
            ok, res = _enforce_bounty_policy_gate(data, 1, "admin")
            assert ok is True
            assert res is None

