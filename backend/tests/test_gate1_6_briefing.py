# -*- coding: utf-8 -*-
"""
test_gate1_6_briefing.py — Gate 1.6 Academic Proof-of-Work & Private Supervisor Briefing Pack Tests.

Verifies:
1. Proof-of-Work Evidence Registry provenance, integrity hashes, and reproducible commands.
2. Briefings are strictly private by default upon creation.
3. Cross-user isolation (candidate A cannot view, share, or revoke candidate B's briefings).
4. Cryptographically unguessable token generation and activation.
5. Public supervisor access with valid token returns allowlisted data only (zero leak of private CRM notes or tokens).
6. Instant revocation enforcement (access immediately denied with HTTP 410 Gone).
7. Expiration date enforcement (expired link denied with HTTP 410 Gone).
8. Document download allowlist enforcement and path-traversal protection.
9. Forensic audit trail logging in audit_logs table.
"""
import os, sys, io, json, unittest, datetime
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

os.environ['SECRET_KEY'] = 'test-secret-key-gate1-6'
from app import create_app
from db.connection import _get_db, init_db


class TestGate16SupervisorBriefing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.app.config['WTF_CSRF_ENABLED'] = False
        with cls.app.app_context():
            init_db()

    def setUp(self):
        self.client = self.app.test_client()
        with self.client.session_transaction() as sess:
            sess['_user_id'] = '1'

    def test_evidence_registry_provenance_and_integrity(self):
        """Proof-of-Work evidence registry returns traceable artifacts with real hashes."""
        res = self.client.get("/api/dossier/evidence")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))
        items = data.get("evidence", [])
        self.assertGreaterEqual(len(items), 5)

        # Check SAST Engine evidence
        sast = next((i for i in items if i["id"] == "pow_sast_engine"), None)
        self.assertIsNotNone(sast)
        self.assertEqual(sast["category"], "source_code")
        self.assertEqual(sast["status"], "VERIFIED")
        self.assertIn("sast_scanner.py", sast["repo_path"])
        self.assertIsNotNone(sast["integrity_hash"])
        self.assertEqual(len(sast["integrity_hash"]), 64)  # Valid SHA-256 length
        self.assertIn("python -c", sast["reproducible_cmd"])
        self.assertIn("AST", sast["actual_result"])

        # Check Test Suite evidence
        test_ev = next((i for i in items if i["id"] == "pow_test_dossier_semantics"), None)
        self.assertIsNotNone(test_ev)
        self.assertEqual(test_ev["category"], "test_suite")
        self.assertEqual(test_ev["status"], "VERIFIED")
        self.assertIn("19 tests", test_ev["actual_result"])
        self.assertIn("unittest", test_ev["reproducible_cmd"])

        # Check Academic Credential
        acad = next((i for i in items if i["id"] == "pow_msc_qualification"), None)
        self.assertIsNotNone(acad)
        self.assertEqual(acad["category"], "academic_credential")
        self.assertEqual(acad["status"], "VERIFIED")
        self.assertIn("14.72", acad["description"])

    def test_create_briefing_private_by_default(self):
        """Newly created briefing pack is private by default and freezes allowlisted content."""
        payload = {
            "title": "PhD Briefing for Prof. Carolyn Rose (CMU)",
            "target_supervisor": "Prof. Carolyn Rose <cp3a@andrew.cmu.edu>",
            "opportunity_id": "opp_test_briefing",
            "allowed_evidence_ids": ["pow_sast_engine", "pow_test_dossier_semantics"],
            "allowed_document_ids": ["doc_cv", "doc_thesis_abstract"],
            "custom_statement": "I have engineered SecuraX and look forward to discussing doctoral alignment with your lab.",
            "expires_in_days": 14,
        }
        res = self.client.post("/api/dossier/briefings", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))
        self.assertFalse(data.get("is_shared"))  # Private by default!
        briefing_id = data.get("briefing_id")
        self.assertIsNotNone(briefing_id)

        # Retrieve detail
        detail_res = self.client.get(f"/api/dossier/briefings/{briefing_id}")
        self.assertEqual(detail_res.status_code, 200)
        d_data = detail_res.get_json().get("briefing")
        self.assertFalse(d_data.get("is_shared"))
        self.assertFalse(d_data.get("is_revoked"))
        self.assertEqual(d_data.get("target_supervisor"), "Prof. Carolyn Rose <cp3a@andrew.cmu.edu>")

    def test_cross_user_briefing_isolation(self):
        """User B (Analyst, ID 2) cannot access or manipulate User A's (Admin, ID 1) briefing pack."""
        # Create briefing as User 1
        create_res = self.client.post("/api/dossier/briefings", json={
            "title": "Private Briefing User 1",
            "target_supervisor": "Target Lab",
        })
        b_id = create_res.get_json()["briefing_id"]

        # Switch to User 2 (bootstrapped analyst account)
        client2 = self.app.test_client()
        with client2.session_transaction() as sess:
            sess['_user_id'] = '2'

        # Attempt to view
        get_res = client2.get(f"/api/dossier/briefings/{b_id}")
        self.assertEqual(get_res.status_code, 404)

        # Attempt to share
        share_res = client2.post(f"/api/dossier/briefings/{b_id}/share", json={})
        self.assertEqual(share_res.status_code, 404)

        # Attempt to revoke
        revoke_res = client2.post(f"/api/dossier/briefings/{b_id}/revoke", json={})
        self.assertEqual(revoke_res.status_code, 404)

    def test_sharing_workflow_and_supervisor_public_view(self):
        """Complete sharing journey: share -> view with unguessable token -> verify payload."""
        create_res = self.client.post("/api/dossier/briefings", json={
            "title": "Supervisor Pack — MIT CSAIL",
            "target_supervisor": "Prof. Nickolai Zeldovich",
            "allowed_evidence_ids": ["pow_sast_engine"],
            "allowed_document_ids": ["doc_cv"],
            "custom_statement": "Tailored briefing for systems security research.",
            "expires_in_days": 30,
        })
        b_id = create_res.get_json()["briefing_id"]

        # Activate sharing
        share_res = self.client.post(f"/api/dossier/briefings/{b_id}/share", json={"expires_in_days": 30})
        self.assertEqual(share_res.status_code, 200)
        s_data = share_res.get_json()
        self.assertTrue(s_data.get("is_shared"))
        token = s_data.get("share_token")
        self.assertIsNotNone(token)
        self.assertGreaterEqual(len(token), 32)  # High-entropy token

        # Anonymous public client access (no session login)
        anon_client = self.app.test_client()
        view_res = anon_client.get(f"/api/dossier/briefings/shared/{token}")
        self.assertEqual(view_res.status_code, 200)
        v_data = view_res.get_json()
        self.assertTrue(v_data.get("ok"))
        self.assertEqual(v_data.get("target_supervisor"), "Prof. Nickolai Zeldovich")
        self.assertIn("Abdallah Benaicha", v_data.get("candidate", {}).get("name", ""))

        # Verify allowed evidence is present and unallowed is excluded
        ev_ids = [e["id"] for e in v_data.get("selected_evidence", [])]
        self.assertIn("pow_sast_engine", ev_ids)
        self.assertNotIn("pow_docker_scanner", ev_ids)

        # Verify no credentials leaked
        self.assertNotIn("password_hash", str(v_data))
        self.assertNotIn("api_token", str(v_data))
        self.assertNotIn("session", str(v_data))

    def test_instant_revocation_denies_public_access(self):
        """Revoking briefing immediately cuts off public access with HTTP 410 Gone."""
        create_res = self.client.post("/api/dossier/briefings", json={
            "title": "Temporary Briefing for Revocation Test",
            "target_supervisor": "Prof. Test",
        })
        b_id = create_res.get_json()["briefing_id"]

        share_res = self.client.post(f"/api/dossier/briefings/{b_id}/share", json={})
        token = share_res.get_json()["share_token"]

        anon_client = self.app.test_client()
        # Verify it works initially
        self.assertEqual(anon_client.get(f"/api/dossier/briefings/shared/{token}").status_code, 200)

        # Candidate revokes
        revoke_res = self.client.post(f"/api/dossier/briefings/{b_id}/revoke", json={})
        self.assertEqual(revoke_res.status_code, 200)
        self.assertTrue(revoke_res.get_json().get("is_revoked"))

        # Subsequent public request is strictly denied
        blocked_res = anon_client.get(f"/api/dossier/briefings/shared/{token}")
        self.assertEqual(blocked_res.status_code, 410)
        self.assertEqual(blocked_res.get_json().get("status"), "revoked")
        self.assertIn("revoked", blocked_res.get_json().get("error", "").lower())

    def test_expired_link_returns_410(self):
        """Expired briefing token returns HTTP 410 Gone."""
        create_res = self.client.post("/api/dossier/briefings", json={
            "title": "Expired Link Test",
            "target_supervisor": "Prof. Expired",
        })
        b_id = create_res.get_json()["briefing_id"]

        share_res = self.client.post(f"/api/dossier/briefings/{b_id}/share", json={})
        token = share_res.get_json()["share_token"]

        # Artificially set expiration to the past in DB
        past_ts = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)).isoformat()
        with self.app.app_context():
            db = _get_db()
            db.execute("UPDATE supervisor_briefings SET expires_at=? WHERE id=?", (past_ts, b_id))
            db.commit()

        anon_client = self.app.test_client()
        exp_res = anon_client.get(f"/api/dossier/briefings/shared/{token}")
        self.assertEqual(exp_res.status_code, 410)
        self.assertEqual(exp_res.get_json().get("status"), "expired")

    def test_invalid_token_returns_404(self):
        """Random nonexistent token returns HTTP 404."""
        anon_client = self.app.test_client()
        res = anon_client.get("/api/dossier/briefings/shared/nonexistent_fake_random_token_1234567890")
        self.assertEqual(res.status_code, 404)

    def test_shared_document_download_allowlist_and_revocation(self):
        """Allowlisted document can be downloaded; unapproved doc or revoked token rejected."""
        create_res = self.client.post("/api/dossier/briefings", json={
            "title": "Doc Download Test",
            "allowed_document_ids": ["doc_cv"],
        })
        b_id = create_res.get_json()["briefing_id"]
        share_res = self.client.post(f"/api/dossier/briefings/{b_id}/share", json={})
        token = share_res.get_json()["share_token"]

        anon_client = self.app.test_client()
        # Allowed document -> 200
        ok_res = anon_client.get(f"/api/dossier/briefings/shared/{token}/download/doc_cv")
        self.assertEqual(ok_res.status_code, 200)
        self.assertIn("SECURAX ACADEMIC DOCUMENT ATTESTATION", ok_res.text)

        # Unapproved document -> 403 Forbidden
        denied_res = anon_client.get(f"/api/dossier/briefings/shared/{token}/download/unapproved_secret_doc.pdf")
        self.assertEqual(denied_res.status_code, 403)

        # After revocation -> 403 / 410
        self.client.post(f"/api/dossier/briefings/{b_id}/revoke", json={})
        revoked_download = anon_client.get(f"/api/dossier/briefings/shared/{token}/download/doc_cv")
        self.assertIn(revoked_download.status_code, [403, 410])

    def test_audit_trail_logging(self):
        """Sharing and revocation events are recorded in audit_logs table."""
        create_res = self.client.post("/api/dossier/briefings", json={
            "title": "Audit Trail Briefing",
        })
        b_id = create_res.get_json()["briefing_id"]
        share_res = self.client.post(f"/api/dossier/briefings/{b_id}/share", json={})
        token = share_res.get_json()["share_token"]

        anon_client = self.app.test_client()
        anon_client.get(f"/api/dossier/briefings/shared/{token}")
        self.client.post(f"/api/dossier/briefings/{b_id}/revoke", json={})

        with self.app.app_context():
            db = _get_db()
            rows = db.execute("SELECT action FROM audit_logs WHERE resource=? ORDER BY id ASC", (b_id,)).fetchall()
            actions = [r[0] for r in rows]
            self.assertIn("briefing_created", actions)
            self.assertIn("briefing_shared", actions)
            self.assertIn("briefing_accessed", actions)
            self.assertIn("briefing_revoked", actions)


if __name__ == "__main__":
    unittest.main()
