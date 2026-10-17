import os
import subprocess
import sys
import pytest

def test_app_boots_like_production():
    """Verify that backend/app.py boots without testing flags (no NameError for sys, etc.)."""
    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = os.environ.copy()
    env.pop("TESTING", None)
    env.pop("PYTEST_CURRENT_TEST", None)
    env["FLASK_ENV"] = "production"
    env["SECRET_KEY"] = "super-secret-key-for-testing-production-boot-check"
    env["SECURAX_ADMIN_PASSWORD"] = "AdminSecretPass123!"
    env["SECURAX_ANALYST_PASSWORD"] = "AnalystSecretPass123!"
    env["ENABLE_BACKGROUND_SCHEDULER"] = "false"

    code = """
import app
application = app.create_app()
client = application.test_client()

# 1. Health check
res_health = client.get('/health')
assert res_health.status_code == 200, f"Health check failed: {res_health.status_code}"
assert res_health.get_json().get("status") == "ok"

# 2. Upgrade endpoint check (should return 400 CSRF blocked or 401 Unauthorized, never 500)
res_up = client.post('/api/subscription/upgrade', json={'plan': 'pro'})
assert res_up.status_code in (400, 401), f"Expected 400 or 401 for upgrade, got: {res_up.status_code}"
assert res_up.status_code != 500

# 3. CSRF check
assert application.config['WTF_CSRF_ENABLED'] is True

print("BOOT_VERIFIED_SUCCESS")
"""

    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=backend_dir,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, f"Boot failed with stderr:\n{proc.stderr}\nstdout:\n{proc.stdout}"
    assert "BOOT_VERIFIED_SUCCESS" in proc.stdout
