"""Full functional audit of SecurAx — run from backend directory."""
import requests, json, sys, re, time

BASE = "http://127.0.0.1:5000"
PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"

findings = []

def log(phase, status, label, detail=""):
    mark = {"PASS":"[OK]", "FAIL":"[!!]", "WARN":"[??]"}.get(status, "[  ]")
    line = f"  {mark} {label}"
    if detail:
        line += f" | {detail}"
    print(line)
    findings.append({"phase": phase, "status": status, "label": label, "detail": detail})

def chk(phase, label, r, expected_codes=(200, 201, 302), detail_fn=None):
    ok = r.status_code in expected_codes
    status = PASS if ok else FAIL
    detail = ""
    if detail_fn:
        try:
            detail = detail_fn(r)
        except Exception:
            detail = f"status={r.status_code}"
    else:
        detail = f"HTTP {r.status_code}"
    log(phase, status, label, detail)
    return ok

# ── PHASE 1: Health ───────────────────────────────────────────────────────
print("\n=== PHASE 1: Health & Public Routes ===")
sess = requests.Session()

r = requests.get(f"{BASE}/health", timeout=5)
chk(1, "GET /health", r, (200,), lambda x: str(x.json()))

r = requests.get(f"{BASE}/", timeout=5, allow_redirects=True)
chk(1, "GET / (root)", r, (200,), lambda x: f"final={x.url}")

r = requests.get(f"{BASE}/login", timeout=5)
chk(1, "GET /login (HTML)", r, (200,), lambda x: f"{len(x.text)} bytes")

# ── PHASE 2: Login Flow ───────────────────────────────────────────────────
print("\n=== PHASE 2: Login Flow ===")

# Wrong credentials via JSON API (CSRF-exempt)
r = sess.post(f"{BASE}/api/auth/login",
              json={"username": "wrong", "password": "wrong"},
              headers={"Content-Type": "application/json"}, timeout=5)
chk(2, "POST /api/auth/login (wrong creds)", r, (401,), lambda x: str(x.json().get("error", ""))[:60])

# Correct credentials
r = sess.post(f"{BASE}/api/auth/login",
              json={"username": "admin", "password": "Admin@2024!"},
              headers={"Content-Type": "application/json"}, timeout=5)
chk(2, "POST /api/auth/login (admin)", r, (200,), lambda x: str(x.json()))

# Check session
r = sess.get(f"{BASE}/api/auth/me", timeout=5)
me = r.json()
u = me.get("user") or me
chk(2, "GET /api/auth/me (session check)", r, (200,), lambda x: f"user={u.get('username')} role={u.get('role')}")

# ── PHASE 3: Dashboard ────────────────────────────────────────────────────
print("\n=== PHASE 3: Dashboard ===")

r = sess.get(f"{BASE}/api/stats", timeout=5)
chk(3, "GET /api/stats", r, (200,), lambda x: str(x.json())[:80])

r = sess.get(f"{BASE}/api/dashboard", timeout=5)
chk(3, "GET /api/dashboard", r, (200,), lambda x: str(x.json())[:80])

r = sess.get(f"{BASE}/dashboard", timeout=5, allow_redirects=True)
chk(3, "GET /dashboard (HTML)", r, (200,), lambda x: f"{len(x.text)} bytes, url={x.url}")

r = sess.get(f"{BASE}/", timeout=5, allow_redirects=True)
chk(3, "GET / (home, logged in)", r, (200,), lambda x: f"url={x.url}")

# ── PHASE 4: Scanner Endpoints ────────────────────────────────────────────
print("\n=== PHASE 4: Scanner API Endpoints ===")

web_token = None
SCAN_TIMEOUT = 120  # real scans can take time

scan_tests = [
    ("/scan_url",         {"target": "127.0.0.1", "scan_type": "web"},         (200,)),
    ("/scan_network",     {"target": "127.0.0.1", "scan_type": "network_ext"}, (200,)),
    ("/analyze_code",     {"target": "test_code",  "scan_type": "sast"},        (200, 400)),
    ("/scan_dependencies",{"target": "test",       "scan_type": "dep"},         (200, 400)),
    ("/scan_dast",        {"target": "127.0.0.1",  "scan_type": "dast"},        (200,)),
    ("/fix_config",       {"target": "apache",     "scan_type": "apache"},      (200, 400)),
    ("/scan_server",      {"target": "127.0.0.1",  "scan_type": "server_ext"},  (200,)),
]

for ep, payload, expected in scan_tests:
    try:
        r = sess.post(f"{BASE}{ep}", json=payload,
                      headers={"Content-Type": "application/json"}, timeout=SCAN_TIMEOUT)
        detail = f"HTTP {r.status_code}"
        if r.status_code == 200:
            keys = list(r.json().keys())[:4]
            detail = f"keys={keys}"
            t = r.json().get("token")
            if t and not web_token:
                web_token = t
        chk(4, f"POST {ep}", r, expected, lambda x, d=detail: d)
    except Exception as ex:
        log(4, FAIL, f"POST {ep}", f"EXCEPTION: {type(ex).__name__}: {str(ex)[:60]}")

# ── PHASE 5: Reports & Downloads ─────────────────────────────────────────
print("\n=== PHASE 5: Reports & Downloads ===")

r = sess.get(f"{BASE}/api/reports", timeout=5)
reports = r.json()
chk(5, "GET /api/reports", r, (200,), lambda x: f"count={len(x.json().get('reports', x.json() if isinstance(x.json(), list) else []))}")

# Use web_token or first report from list
token = web_token
if not token:
    try:
        rlist = reports if isinstance(reports, list) else reports.get("reports", [])
        if rlist:
            token = rlist[0].get("token") or rlist[0].get("id")
    except Exception:
        pass

if token:
    r = sess.get(f"{BASE}/report/{token}", timeout=5, allow_redirects=True)
    chk(5, f"GET /report/{token[:8]}... (HTML)", r, (200,), lambda x: f"{len(x.text)} bytes")

    r = sess.get(f"{BASE}/api/reports/{token}", timeout=5)
    chk(5, f"GET /api/reports/{token[:8]}...", r, (200,), lambda x: f"keys={list(x.json().keys())[:5]}")

    r = sess.get(f"{BASE}/download_report?token={token}", timeout=10)
    chk(5, f"GET /download_report (PDF)", r, (200,),
        lambda x: f"content-type={x.headers.get('Content-Type','?')[:30]} size={len(x.content)}B")

    r = sess.get(f"{BASE}/download_report_csv?token={token}", timeout=5)
    chk(5, "GET /download_report_csv", r, (200,), lambda x: f"size={len(x.content)}B")

    r = sess.get(f"{BASE}/download_report_json?token={token}", timeout=5)
    chk(5, "GET /download_report_json", r, (200,), lambda x: f"size={len(x.content)}B")

    r = sess.get(f"{BASE}/download_report_md?token={token}", timeout=5)
    chk(5, "GET /download_report_md", r, (200,), lambda x: f"size={len(x.content)}B")
else:
    log(5, WARN, "No report token available — run a scan first")

# ── PHASE 6: AI Chat (ARIA) ───────────────────────────────────────────────
print("\n=== PHASE 6: AI Chat (ARIA) ===")

r = sess.get(f"{BASE}/api/ai/status", timeout=5)
chk(6, "GET /api/ai/status", r, (200,), lambda x: str(x.json())[:60])

r = sess.post(f"{BASE}/api/ai/chat",
              json={"message": "Bonjour ARIA, qu'est-ce que SecurAx?"},
              headers={"Content-Type": "application/json"}, timeout=15)
chk(6, "POST /api/ai/chat (test message)", r, (200,),
    lambda x: f"reply_len={len(str(x.json().get('reply','')))} chars")

r = sess.post(f"{BASE}/api/chat",
              json={"message": "test bridge"},
              headers={"Content-Type": "application/json"}, timeout=10)
chk(6, "POST /api/chat (compat bridge)", r, (200,), lambda x: f"status={x.status_code}")

# ── PHASE 7: Admin Panel ──────────────────────────────────────────────────
print("\n=== PHASE 7: Admin Panel ===")

r = sess.get(f"{BASE}/admin", timeout=5, allow_redirects=True)
chk(7, "GET /admin (HTML)", r, (200,), lambda x: f"url={x.url} size={len(x.text)}B")

r = sess.get(f"{BASE}/admin/users", timeout=5, allow_redirects=True)
chk(7, "GET /admin/users (HTML)", r, (200,), lambda x: f"size={len(x.text)}B")

r = sess.get(f"{BASE}/api/admin/stats", timeout=5)
chk(7, "GET /api/admin/stats", r, (200,), lambda x: str(x.json())[:70])

r = sess.get(f"{BASE}/api/admin/users", timeout=5)
users = r.json()
chk(7, "GET /api/admin/users", r, (200,),
    lambda x: f"count={len(x.json().get('users', x.json() if isinstance(x.json(),list) else []))}")

# Create test user
r = sess.post(f"{BASE}/api/admin/users",
              json={"username": "testuser99", "password": "Test@1234!", "role": "analyst"},
              headers={"Content-Type": "application/json"}, timeout=5)
chk(7, "POST /api/admin/users (create testuser99)", r, (200, 201), lambda x: str(x.json())[:60])

new_uid = None
try:
    new_uid = r.json().get("user", {}).get("id") or r.json().get("id")
except Exception:
    pass

r = sess.get(f"{BASE}/api/admin/scans", timeout=5)
chk(7, "GET /api/admin/scans", r, (200,), lambda x: f"count={len(x.json().get('scans', []))}")

r = sess.get(f"{BASE}/api/admin/audit", timeout=5)
chk(7, "GET /api/admin/audit", r, (200,), lambda x: f"count={len(x.json().get('entries', []))}")

r = sess.get(f"{BASE}/admin/scans", timeout=5, allow_redirects=True)
chk(7, "GET /admin/scans (HTML)", r, (200,), lambda x: f"size={len(x.text)}B")

r = sess.get(f"{BASE}/admin/audit", timeout=5, allow_redirects=True)
chk(7, "GET /admin/audit (HTML)", r, (200,), lambda x: f"size={len(x.text)}B")

# Clean up test user
if new_uid:
    r = sess.delete(f"{BASE}/api/admin/users/{new_uid}", timeout=5)
    chk(7, f"DELETE /api/admin/users/{new_uid} (cleanup testuser99)", r, (200,), lambda x: str(x.json())[:40])

# ── PHASE 8: Settings / Profile ───────────────────────────────────────────
print("\n=== PHASE 8: Settings / Profile ===")

r = sess.get(f"{BASE}/change-password", timeout=5, allow_redirects=True)
chk(8, "GET /change-password (HTML)", r, (200,), lambda x: f"size={len(x.text)}B")

r = sess.get(f"{BASE}/setup-totp", timeout=5, allow_redirects=True)
chk(8, "GET /setup-totp (HTML)", r, (200,), lambda x: f"size={len(x.text)}B")

r = sess.post(f"{BASE}/api/auth/change-password",
              json={"current_password": "wrong", "new_password": "NewPass@2024!"},
              headers={"Content-Type": "application/json"}, timeout=5)
chk(8, "POST /api/auth/change-password (wrong current)", r, (400, 401), lambda x: str(x.json())[:50])

# ── PHASE 9: Logout ───────────────────────────────────────────────────────
print("\n=== PHASE 9: Navigation & Logout ===")

r = sess.get(f"{BASE}/logout", timeout=5, allow_redirects=True)
chk(9, "GET /logout", r, (200,), lambda x: f"final={x.url}")

r = sess.get(f"{BASE}/api/auth/me", timeout=5)
chk(9, "GET /api/auth/me (after logout)", r, (401,), lambda x: str(x.json()))

# ─── SUMMARY ─────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("AUDIT SUMMARY")
print("="*60)
total = len(findings)
passed = sum(1 for f in findings if f["status"] == PASS)
warned = sum(1 for f in findings if f["status"] == WARN)
failed = sum(1 for f in findings if f["status"] == FAIL)
print(f"  TOTAL : {total}")
print(f"  PASS  : {passed}")
print(f"  WARN  : {warned}")
print(f"  FAIL  : {failed}")

if failed:
    print("\nFAILED ITEMS:")
    for f in findings:
        if f["status"] == FAIL:
            print(f"  Phase {f['phase']}: {f['label']} | {f['detail']}")

if warned:
    print("\nWARNINGS:")
    for f in findings:
        if f["status"] == WARN:
            print(f"  Phase {f['phase']}: {f['label']} | {f['detail']}")
