"""Audit Round 2: Offensive Security Attack Test Suite.

Verifies strict remediation of all critical attack vectors:
1. CORS rejection of arbitrary domains (e.g. hexaguard-attacker123.vercel.app).
2. Subscription quota reset attack prevention (downgrading preserves scans_used).
3. Invalid payment reference rejection (payment_ref validation).
4. Scheduled scans RBAC rejection for viewer role (403 Forbidden).
5. Scheduled scans SSRF rejection for loopback, cloud metadata, and RFC1918 IPs (400 Bad Request).
6. Arabic PDF F5 XML entity reversal fix (_safe preserves &lt; and avoids ;lt;).
"""

import os
import sys
import io
import fitz
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-offensive-suite")

import database as db
from db.subscriptions import set_subscription, get_subscription, increment_scan_count


@pytest.fixture()
def app(tmp_path, monkeypatch):
    db_file = str(tmp_path / "test_offensive_round2.db")
    monkeypatch.setenv("DB_PATH", db_file)
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("ENABLE_BACKGROUND_SCHEDULER", "false")

    if hasattr(db._local, "conn"):
        del db._local.conn
    db.DB_PATH = db_file

    from app import create_app
    flask_app = create_app()
    flask_app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
    )
    with flask_app.app_context():
        db.init_db()
        db.create_user("analyst_attacker", "Password123!", role="analyst", email="analyst@sec.corp")
        db.create_user("viewer_attacker", "Password123!", role="viewer", email="viewer@sec.corp")
        yield flask_app

    if hasattr(db._local, "conn"):
        db._local.conn.close()
        del db._local.conn


class TestOffensiveCORS:
    def test_cors_rejects_attacker_vercel_domain(self, app):
        """Attacker vercel subdomain hexaguard-attacker123.vercel.app MUST NOT be granted CORS access."""
        client = app.test_client()
        attacker_origin = "https://hexaguard-attacker123.vercel.app"

        res = client.get("/health", headers={"Origin": attacker_origin})
        allow_origin = res.headers.get("Access-Control-Allow-Origin")
        assert allow_origin != attacker_origin, f"CORS vulnerability: {attacker_origin} was reflected in headers!"
        assert allow_origin is None or allow_origin != "*"


class TestOffensiveSubscriptionQuota:
    def test_downgrade_preserves_scans_used_preventing_infinite_quota(self, app):
        """Downgrading to Free plan must NEVER reset scans_used to 0."""
        user = db.get_user_by_username("analyst_attacker")
        uid = user["id"]

        # Upgrade to pro and use 5 scans
        set_subscription(uid, "pro")
        for _ in range(5):
            increment_scan_count(uid)

        sub_pro = get_subscription(uid)
        assert sub_pro["scans_used"] == 5
        assert sub_pro["remaining"] == 15

        # Downgrade back to free
        set_subscription(uid, "free")
        sub_free = get_subscription(uid)

        # scans_used MUST NOT be reset to 0!
        assert sub_free["scans_used"] == 5, f"Expected scans_used=5 preserved, got {sub_free['scans_used']}"
        assert sub_free["remaining"] == 0, f"Remaining scans on free must be 0, got {sub_free['remaining']}"

    def test_upgrade_invalid_payment_ref_rejected(self, app):
        """Paid plan upgrade with invalid payment_ref must be rejected with 400."""
        client = app.test_client()
        client.post("/api/auth/login", json={"username": "analyst_attacker", "password": "Password123!"})

        # Temporarily enable payment verification by unsetting TESTING flag
        app.config["TESTING"] = False
        try:
            res = client.post("/api/subscription/upgrade", json={
                "plan": "pro",
                "payment_ref": "invalid_x",
            })
            assert res.status_code == 400
            data = res.get_json()
            assert "payment reference" in data.get("error", "").lower()
        finally:
            app.config["TESTING"] = True


class TestOffensiveScheduledScansRBACAndSSRF:
    def test_viewer_role_blocked_from_creating_scheduled_scan(self, app):
        """User with viewer role must receive 403 Forbidden when trying to create a scheduled scan."""
        client = app.test_client()
        client.post("/api/auth/login", json={"username": "viewer_attacker", "password": "Password123!"})

        res = client.post("/api/scheduled-scans", json={
            "scan_type": "web",
            "target": "example.com",
            "cron_expr": "daily",
        })
        assert res.status_code == 403

    def test_viewer_role_blocked_from_toggling_or_deleting(self, app):
        """User with viewer role must receive 403 Forbidden on PATCH and DELETE."""
        client = app.test_client()
        client.post("/api/auth/login", json={"username": "viewer_attacker", "password": "Password123!"})

        res_patch = client.patch("/api/scheduled-scans/1", json={"is_active": True})
        assert res_patch.status_code == 403

        res_del = client.delete("/api/scheduled-scans/1")
        assert res_del.status_code == 403

    @pytest.mark.parametrize("malicious_target", [
        "http://169.254.169.254",
        "169.254.169.254",
        "http://127.0.0.1:8080",
        "127.0.0.1:8080",
        "http://10.0.0.5",
        "10.0.0.5",
    ])
    def test_scheduled_scan_ssrf_payloads_rejected_with_400(self, app, malicious_target):
        """SSRF target payloads (AWS IMDS, localhost with port, private RFC1918) must return 400."""
        client = app.test_client()
        client.post("/api/auth/login", json={"username": "analyst_attacker", "password": "Password123!"})

        res = client.post("/api/scheduled-scans", json={
            "scan_type": "web",
            "target": malicious_target,
            "cron_expr": "daily",
        })
        assert res.status_code == 400, f"Expected 400 for {malicious_target}, got {res.status_code}"
        assert "blocked by security policy" in res.get_json().get("error", "").lower() or "invalid" in res.get_json().get("error", "").lower()


class TestOffensivePDFArabicF5:
    def test_f5_arabic_entity_reversal_fixed(self, app):
        """Arabic text with HTML entities must not reverse &lt; into ;lt;."""
        from blueprints.reports import _safe

        raw = "تقرير فحص: ثغرة <script>alert('XSS')</script> حرجة"
        safe_output = _safe(raw)

        # F5 fix verification
        assert ";lt;" not in safe_output, f"F5 Bug detected: ';lt;' found in output: {safe_output}"
        assert "&lt;" in safe_output, f"Entity '&lt;' expected in output: {safe_output}"

    def test_pdf_generation_renders_arabic_without_xml_syntax_error(self, app):
        """Generating a full PDF with Arabic and HTML entities must render cleanly with PyMuPDF verification."""
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from blueprints.reports import _safe

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4)
        styles = getSampleStyleSheet()
        style = ParagraphStyle("TestStyle", parent=styles["Normal"], fontSize=10)

        story = [
            Paragraph(_safe("عنوان التقرير الأمني"), style),
            Paragraph(_safe("وصف الثغرة: <script>console.log('safe')</script>"), style),
        ]
        # Must build without ReportLab XML syntax exception
        doc.build(story)

        pdf_bytes = buf.getvalue()
        assert pdf_bytes.startswith(b"%PDF-")

        # PyMuPDF verification: extract text from rendered document
        pdf_doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        assert len(pdf_doc) >= 1
        page_text = pdf_doc[0].get_text()
        assert ";lt;" not in page_text
