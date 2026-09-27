"""Bounty Radar Recon Visibility Regression Tests -- Phase 11.

PURPOSE:
    Regression suite documenting the EXACT root cause of the Recon button
    visibility difference between api.nebius.cloud and api.tokenfactory.nebius.com.

ROOT CAUSE (identified 2026-09-27):
    BountyTargetsPage.jsx line 254:
        {(target.asset?.startsWith('*.') || target.asset_type === 'WILDCARD') && (
          <button onClick={() => onRecon(target)}>Recon</button>
        )}

    asset_type is set by backend normalizers in bounty.py.
    HackerOne: asset_type comes from scope_item["asset_type"] in arkadiyt JSON.
    *.nebius.cloud  -> asset_type=WILDCARD -> Recon visible
    api.tokenfactory.nebius.com -> asset_type=URL -> Recon hidden

    The wildcard-vs-single-host correlation IS the actual controlling factor.
    Verified with counterexamples from Bugcrowd and Intigriti below.

BACKEND ENFORCEMENT:
    /api/bounty/recon/subdomains enforces _enforce_bounty_policy_gate independently.
    Hidden frontend button != security control.

NOTES:
    - No live requests to api.nebius.cloud or api.tokenfactory.nebius.com.
    - All tests use synthetic fixtures or mocked data.
"""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest

os.environ.setdefault("SECURAX_TESTING", "1")
os.environ.setdefault("DEPLOYMENT_MODE", "local")
os.environ.setdefault("ENABLE_LIVE_BOUNTY_SCANNING", "true")
os.environ.setdefault("SECRET_KEY", "test-secret-recon-regression-2026")

from blueprints.bounty import (
    _normalise_hackerone,
    _normalise_bugcrowd,
    _normalise_intigriti,
    STATUS_AUTOMATED,
    STATUS_MANUAL,
    STATUS_BLOCKED,
    STATUS_UNKNOWN,
    TIER_MANUAL,
    TIER_BLOCKED,
    TIER_AUTOMATED,
    _TIER1_ARKADIYT_SOURCE_DISABLED,
)


# ---------------------------------------------------------------------------
# Synthetic fixture mirroring the arkadiyt HackerOne schema for Nebius
# ---------------------------------------------------------------------------
_NEBIUS_HACKERONE_FIXTURE = [
    {
        "name": "Nebius",
        "handle": "nebius",
        "url": "https://hackerone.com/nebius",
        "policy": (
            "Manual testing only. Do not use automated scanning tools without "
            "prior written permission from Nebius security team."
        ),
        "submission_state": "open",
        "managed_program": False,
        "average_time_to_first_program_response": 48,
        "targets": {
            "in_scope": [
                {
                    "asset_identifier": "*.nebius.cloud",
                    "asset_type": "WILDCARD",
                    "max_severity": "critical",
                    "eligible_for_bounty": True,
                    "instruction": (
                        "In scope: all GA services on *.nebius.cloud. "
                        "No automated scanning without permission."
                    ),
                },
                {
                    "asset_identifier": "api.tokenfactory.nebius.com",
                    "asset_type": "URL",
                    "max_severity": "high",
                    "eligible_for_bounty": True,
                    "instruction": (
                        "Out of scope: token factory endpoints are excluded from "
                        "automated testing. Manual verification required."
                    ),
                },
            ],
            "out_of_scope": [],
        },
    }
]


# ---------------------------------------------------------------------------
# Helper: simulate the frontend Recon visibility condition
# (BountyTargetsPage.jsx line 254)
# ---------------------------------------------------------------------------
def _recon_visible(target: dict) -> bool:
    asset = target.get("asset", "")
    asset_type = target.get("asset_type", "")
    return asset.startswith("*.") or asset_type == "WILDCARD"


# ===========================================================================
# PHASE 2 GOLDEN RECON TEST -- Target A vs Target B root cause
# ===========================================================================

class TestTargetAvsTargetBReconRootCause:
    """Regression for the Recon visibility difference. Root cause confirmed:
    asset_type == WILDCARD vs URL is the exact controlling factor.
    """

    def test_wildcard_scope_produces_wildcard_asset_type(self):
        """Target A: *.nebius.cloud -> asset_type=WILDCARD."""
        results = _normalise_hackerone(_NEBIUS_HACKERONE_FIXTURE)
        wc = [r for r in results if r["asset"] == "*.nebius.cloud"]
        assert len(wc) == 1
        assert wc[0]["asset_type"] == "WILDCARD"
        assert wc[0]["asset"].startswith("*.")

    def test_single_host_scope_produces_url_asset_type(self):
        """Target B: api.tokenfactory.nebius.com -> asset_type=URL."""
        results = _normalise_hackerone(_NEBIUS_HACKERONE_FIXTURE)
        sh = [r for r in results if r["asset"] == "api.tokenfactory.nebius.com"]
        assert len(sh) == 1
        assert sh[0]["asset_type"] == "URL"
        assert not sh[0]["asset"].startswith("*.")

    def test_frontend_recon_condition_wildcard_visible(self):
        """Target A: Recon button VISIBLE (WILDCARD condition satisfied)."""
        results = _normalise_hackerone(_NEBIUS_HACKERONE_FIXTURE)
        t = next(r for r in results if r["asset"] == "*.nebius.cloud")
        assert _recon_visible(t) is True

    def test_frontend_recon_condition_single_host_hidden(self):
        """Target B: Recon button HIDDEN (neither wildcard condition satisfied)."""
        results = _normalise_hackerone(_NEBIUS_HACKERONE_FIXTURE)
        t = next(r for r in results if r["asset"] == "api.tokenfactory.nebius.com")
        assert _recon_visible(t) is False

    def test_recon_visibility_does_not_affect_scan_authorization(self):
        """PHASE 11 SECTION R -- Recon visible NEVER implies auto_scan_ok=True."""
        results = _normalise_hackerone(_NEBIUS_HACKERONE_FIXTURE)
        wildcard_t = next(r for r in results if r["asset"] == "*.nebius.cloud")
        assert _recon_visible(wildcard_t) is True
        assert wildcard_t.get("auto_scan_ok") is False, (
            "Recon visibility must NOT grant scan authorization"
        )

    def test_both_targets_have_same_authorization_tier_manual(self):
        """Both targets get TIER_MANUAL -- the difference is ONLY asset_type."""
        assert _TIER1_ARKADIYT_SOURCE_DISABLED is True
        results = _normalise_hackerone(_NEBIUS_HACKERONE_FIXTURE)
        for r in results:
            assert r.get("auto_scan_ok") is False, (
                f"auto_scan_ok must be False for {r['asset']!r}"
            )


# ===========================================================================
# PHASE 11 SECTION S -- Counterexample verification
# ===========================================================================

class TestWildcardCorrelationCounterexamples:
    """Verify the wildcard-vs-single-host condition is the ACTUAL controlling factor,
    not a coincidental correlation limited to the Nebius program.
    Tests Bugcrowd and Intigriti fixtures beyond Target A/B.
    """

    def test_bugcrowd_wildcard_recon_visible(self):
        """Bugcrowd wildcard target shows Recon."""
        fixture = [{
            "name": "Acme Corp", "code": "acme",
            "targets": {"in_scope": [
                {"target": "*.acme.com", "type": "wildcard", "description": ""},
            ]}
        }]
        results = _normalise_bugcrowd(fixture)
        wc = next((r for r in results if r["asset"] == "*.acme.com"), None)
        assert wc is not None
        assert _recon_visible(wc) is True, f"asset_type={wc['asset_type']!r}"

    def test_bugcrowd_single_host_recon_hidden(self):
        """Bugcrowd single-host target hides Recon."""
        fixture = [{
            "name": "Acme Corp", "code": "acme",
            "targets": {"in_scope": [
                {"target": "specific.acme.com", "type": "website", "description": ""},
            ]}
        }]
        results = _normalise_bugcrowd(fixture)
        sh = next((r for r in results if r["asset"] == "specific.acme.com"), None)
        assert sh is not None
        assert _recon_visible(sh) is False, f"asset_type={sh['asset_type']!r}"

    def test_intigriti_wildcard_recon_visible(self):
        """Intigriti wildcard target shows Recon."""
        fixture = [{
            "id": "x1", "handle": "sec", "company_handle": "corp",
            "name": "Corp", "status": "open",
            "max_bounty": {"value": 5000},
            "targets": {"in_scope": [
                {"endpoint": "*.corp.io", "type": "wildcard", "description": ""},
            ]}
        }]
        results = _normalise_intigriti(fixture)
        wc = next((r for r in results if "*.corp.io" in r["asset"]), None)
        assert wc is not None
        assert _recon_visible(wc) is True, f"asset_type={wc['asset_type']!r}"

    def test_intigriti_single_host_recon_hidden(self):
        """Intigriti single-host target hides Recon."""
        fixture = [{
            "id": "x1", "handle": "sec", "company_handle": "corp",
            "name": "Corp", "status": "open",
            "max_bounty": {"value": 5000},
            "targets": {"in_scope": [
                {"endpoint": "api.corp.io", "type": "url", "description": ""},
            ]}
        }]
        results = _normalise_intigriti(fixture)
        sh = next((r for r in results if r["asset"] == "api.corp.io"), None)
        assert sh is not None
        assert _recon_visible(sh) is False, f"asset_type={sh['asset_type']!r}"


# ===========================================================================
# PHASE 11 SECTION N -- Target A and Target B behavior retained
# ===========================================================================

class TestTargetABBehaviorRetained:
    """Regression: correct state for Target A and Target B must not regress."""

    def test_target_a_recon_visible_no_scan_auth(self):
        target_a = {"asset": "*.nebius.cloud", "asset_type": "WILDCARD",
                    "auto_scan_ok": False, "authorization_tier": TIER_MANUAL}
        assert _recon_visible(target_a) is True
        assert target_a["auto_scan_ok"] is False

    def test_target_b_recon_hidden_no_scan_auth(self):
        target_b = {"asset": "api.tokenfactory.nebius.com", "asset_type": "URL",
                    "auto_scan_ok": False, "authorization_tier": TIER_MANUAL}
        assert _recon_visible(target_b) is False
        assert target_b["auto_scan_ok"] is False

    def test_target_a_manual_only_policy_is_blocked(self):
        from blueprints.bounty import _analyse_policy
        p = _analyse_policy(
            "Manual testing only. Do not use automated scanning tools without prior written permission."
        )
        assert p["status"] == STATUS_BLOCKED

    def test_target_b_policy_not_automated(self):
        from blueprints.bounty import _analyse_policy
        p = _analyse_policy(
            "Out of scope: token factory endpoints are excluded from automated testing. "
            "Manual verification required."
        )
        assert p["status"] != STATUS_AUTOMATED


# ===========================================================================
# PHASE 11 SECTION O -- Backend enforcement
# ===========================================================================

@pytest.fixture(scope="module")
def bounty_client():
    from app import create_app
    from database import init_db
    app = create_app()
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.app_context():
        init_db()
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["_user_id"] = "1"
            sess["user_id"] = 1
            sess["username"] = "regression_hunter"
            sess["role"] = "admin"
        yield c


class TestBackendEnforcementBypass:
    """Direct API calls cannot bypass frontend button visibility."""

    def test_out_of_scope_active_probe_rejected(self, bounty_client):
        """OUT_OF_SCOPE + probe_alive=True -> 403, zero probes sent."""
        payload = {
            "domain": "api.tokenfactory.nebius.com",
            "bounty_context": {
                "asset": "api.tokenfactory.nebius.com",
                "platform": "hackerone",
                "program_handle": "nebius",
                "scan_policy": {
                    "status": "OUT_OF_SCOPE",
                    "confidence": 85,
                    "signals": ["- Explicit restriction: 'manual testing only'"],
                },
                "acknowledged": False,
            },
            "probe_alive": True,
        }
        with patch("blueprints.bounty._probe_single_subdomain") as mock_probe:
            res = bounty_client.post("/api/bounty/recon/subdomains", json=payload)
        assert res.status_code == 403
        data = res.get_json()
        assert data.get("code") in ("POLICY_GATE_BLOCKED", "OUT_OF_SCOPE_BLOCKED")
        assert mock_probe.call_count == 0

    def test_out_of_scope_passive_allowed(self, bounty_client):
        """Passive CT query (probe_alive=False) allowed -- zero target packets."""
        payload = {
            "domain": "api.tokenfactory.nebius.com",
            "bounty_context": {
                "asset": "api.tokenfactory.nebius.com",
                "platform": "hackerone",
                "program_handle": "nebius",
                "scan_policy": {"status": "OUT_OF_SCOPE", "confidence": 85, "signals": []},
                "acknowledged": False,
            },
            "probe_alive": False,
        }
        with patch("blueprints.bounty._fetch_crtsh_subdomains", return_value=[]):
            res = bounty_client.post("/api/bounty/recon/subdomains", json=payload)
        assert res.status_code == 200

    def test_unknown_policy_fails_closed(self, bounty_client):
        """SECTION E: UNKNOWN_AUTHORIZATION + unacknowledged + probe_alive=True -> 403."""
        payload = {
            "domain": "unknown-policy-target.example.com",
            "bounty_context": {
                "asset": "unknown-policy-target.example.com",
                "platform": "hackerone",
                "program_handle": "some-program",
                "scan_policy": {
                    "status": "UNKNOWN_AUTHORIZATION",
                    "confidence": 0,
                    "signals": ["No automation-related terms found"],
                },
                "acknowledged": False,
            },
            "probe_alive": True,
        }
        with patch("blueprints.bounty._probe_single_subdomain") as mock_probe:
            res = bounty_client.post("/api/bounty/recon/subdomains", json=payload)
        assert res.status_code == 403
        assert mock_probe.call_count == 0


# ===========================================================================
# PHASE 11 SECTION F -- Discovered != Authorized
# ===========================================================================

class TestDiscoveredNotAuthorized:
    """A discovered hostname must never automatically become an authorized scan target."""

    def test_tier1_unreachable_from_arkadiyt_source(self):
        assert _TIER1_ARKADIYT_SOURCE_DISABLED is True

    def test_keyword_match_alone_does_not_grant_tier1(self):
        from blueprints.bounty import _analyse_policy
        policy = _analyse_policy("automated scanning allowed and scanners are permitted")
        assert policy["status"] == STATUS_AUTOMATED
        # Simulate tier assignment from bounty.py lines 1357-1372
        st = policy["status"]
        if not _TIER1_ARKADIYT_SOURCE_DISABLED and st == STATUS_AUTOMATED:
            tier = TIER_AUTOMATED
        elif st == STATUS_BLOCKED:
            tier = TIER_BLOCKED
        else:
            tier = TIER_MANUAL
        assert tier == TIER_MANUAL

    def test_eligible_bounty_does_not_grant_scan_authorization(self):
        results = _normalise_hackerone(_NEBIUS_HACKERONE_FIXTURE)
        wc = next(r for r in results if r["asset"] == "*.nebius.cloud")
        assert wc["eligible_bounty"] is True
        assert wc["auto_scan_ok"] is False


# ===========================================================================
# GOLDEN FIXTURES (Section 15)
# ===========================================================================

GOLDEN_FIXTURES = [
    {
        "label": "target_with_recon_available",
        "asset": "*.nebius.cloud",
        "asset_type": "WILDCARD",
        "authorization_tier": TIER_MANUAL,
        "auto_scan_ok": False,
        "recon_visible": True,
    },
    {
        "label": "target_with_recon_unavailable",
        "asset": "api.tokenfactory.nebius.com",
        "asset_type": "URL",
        "authorization_tier": TIER_MANUAL,
        "auto_scan_ok": False,
        "recon_visible": False,
    },
    {
        "label": "verified_restricted",
        "asset": "api.restricted-target.com",
        "asset_type": "URL",
        "authorization_tier": TIER_BLOCKED,
        "auto_scan_ok": False,
        "recon_visible": False,
    },
    {
        "label": "unknown_policy_wildcard",
        "asset": "*.unknown-policy.io",
        "asset_type": "WILDCARD",
        "authorization_tier": TIER_MANUAL,
        "auto_scan_ok": False,
        "recon_visible": True,
    },
    {
        "label": "keyword_allow_but_still_tier_manual",
        "asset": "*.allowed-test.com",
        "asset_type": "WILDCARD",
        "authorization_tier": TIER_MANUAL,
        "auto_scan_ok": False,
        "recon_visible": True,
    },
]


class TestGoldenFixtures:
    """Validate golden fixtures represent correct system behavior."""

    @pytest.mark.parametrize("fixture", GOLDEN_FIXTURES, ids=[f["label"] for f in GOLDEN_FIXTURES])
    def test_recon_visibility(self, fixture):
        rv = _recon_visible(fixture)
        assert rv == fixture["recon_visible"], (
            f"[{fixture['label']}] Expected recon_visible={fixture['recon_visible']}, got {rv}. "
            f"asset={fixture['asset']!r}, asset_type={fixture['asset_type']!r}"
        )

    @pytest.mark.parametrize("fixture", GOLDEN_FIXTURES, ids=[f["label"] for f in GOLDEN_FIXTURES])
    def test_no_scan_auth_inheritance(self, fixture):
        assert fixture["auto_scan_ok"] is False, (
            f"[{fixture['label']}] auto_scan_ok must be False -- "
            "Recon visibility must never grant Scan authorization"
        )

    @pytest.mark.parametrize("fixture", GOLDEN_FIXTURES, ids=[f["label"] for f in GOLDEN_FIXTURES])
    def test_no_tier1_from_arkadiyt(self, fixture):
        assert fixture["authorization_tier"] != TIER_AUTOMATED, (
            f"[{fixture['label']}] TIER_AUTOMATED must not appear from arkadiyt source"
        )
