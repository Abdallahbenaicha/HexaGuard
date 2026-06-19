"""
seed_demo_db.py
===============
Creates a fresh demo database: securax_demo.db
populated with realistic security scan data that reflects
the SecurAX PFE project goals (network, web, SAST, server scans).

Usage:
    python seed_demo_db.py

To switch to this DB:
    1. Rename securax.db  ->  securax_backup.db
    2. Rename securax_demo.db  ->  securax.db
    3. Restart the backend
"""

import json
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt

DB_PATH = "securax_demo.db"

# ── Schema (identical to production) ─────────────────────────────────────────
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT    UNIQUE NOT NULL,
    email            TEXT,
    password_hash    TEXT    NOT NULL,
    role             TEXT    NOT NULL DEFAULT 'analyst',
    permissions      TEXT    NOT NULL DEFAULT '[]',
    is_active        INTEGER NOT NULL DEFAULT 1,
    totp_secret      TEXT,
    totp_enabled     INTEGER NOT NULL DEFAULT 0,
    failed_attempts  INTEGER NOT NULL DEFAULT 0,
    locked_until     TEXT,
    last_login       TEXT,
    login_count      INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT    NOT NULL,
    created_by       TEXT,
    locked_target    TEXT
);

CREATE TABLE IF NOT EXISTS scan_reports (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    token            TEXT    UNIQUE NOT NULL,
    user_id          INTEGER,
    username         TEXT,
    scan_type        TEXT,
    target           TEXT,
    risk_score       REAL    NOT NULL DEFAULT 0,
    vuln_count       INTEGER NOT NULL DEFAULT 0,
    critical_count   INTEGER NOT NULL DEFAULT 0,
    high_count       INTEGER NOT NULL DEFAULT 0,
    medium_count     INTEGER NOT NULL DEFAULT 0,
    low_count        INTEGER NOT NULL DEFAULT 0,
    result_json      TEXT    NOT NULL,
    original_content TEXT,
    stored_at        TEXT    NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id   INTEGER NOT NULL,
    check_name  TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    description TEXT,
    evidence    TEXT,
    remediation TEXT,
    line_number INTEGER NOT NULL DEFAULT 0,
    cve_ids     TEXT    NOT NULL DEFAULT '[]',
    is_fixed    INTEGER NOT NULL DEFAULT 0,
    fixed_at    TEXT,
    found_at    TEXT    NOT NULL,
    FOREIGN KEY (report_id) REFERENCES scan_reports(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    action       TEXT    NOT NULL,
    username     TEXT,
    user_id      INTEGER,
    category     TEXT    NOT NULL DEFAULT 'general',
    resource     TEXT,
    ip_address   TEXT,
    user_agent   TEXT,
    status       TEXT,
    details      TEXT,
    created_at   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_username        ON users (username);
CREATE INDEX IF NOT EXISTS idx_scan_reports_user     ON scan_reports (user_id, stored_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_reports_token    ON scan_reports (token);
CREATE INDEX IF NOT EXISTS idx_scan_reports_stored   ON scan_reports (stored_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_reports_type     ON scan_reports (scan_type);
CREATE INDEX IF NOT EXISTS idx_vulns_report          ON scan_vulnerabilities (report_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity        ON scan_vulnerabilities (severity, report_id);
CREATE INDEX IF NOT EXISTS idx_vulns_check           ON scan_vulnerabilities (check_name);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user       ON audit_logs (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action     ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_category   ON audit_logs (category);
CREATE INDEX IF NOT EXISTS idx_audit_logs_time       ON audit_logs (created_at DESC);
"""

# ── Helpers ───────────────────────────────────────────────────────────────────

def now_utc(delta_days=0, delta_hours=0, delta_minutes=0):
    dt = datetime.now(timezone.utc) - timedelta(
        days=delta_days, hours=delta_hours, minutes=delta_minutes
    )
    return dt.isoformat()

def make_token():
    return uuid.uuid4().hex

def hash_pw(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()

def insert_user(db, username, email, password, role, permissions, created_days_ago=30):
    ph = hash_pw(password)
    db.execute(
        "INSERT OR IGNORE INTO users "
        "(username,email,password_hash,role,permissions,is_active,created_at,created_by,login_count,last_login) "
        "VALUES (?,?,?,?,?,1,?,?,?,?)",
        (username, email, ph, role, json.dumps(permissions),
         now_utc(delta_days=created_days_ago), "seed_script",
         round(created_days_ago * 1.5),
         now_utc(delta_hours=1)),
    )

def insert_report(db, user_id, username, scan_type, target, risk_score, vulns, stored_days_ago=1, stored_hours_ago=0):
    token = make_token()
    stored_at = now_utc(delta_days=stored_days_ago, delta_hours=stored_hours_ago)
    critical = sum(1 for v in vulns if v["severity"] == "critical")
    high     = sum(1 for v in vulns if v["severity"] == "high")
    medium   = sum(1 for v in vulns if v["severity"] == "medium")
    low      = sum(1 for v in vulns if v["severity"] == "low")

    result = {
        "scan_type": scan_type,
        "target": target,
        "vulnerabilities": vulns,
        "summary": f"Found {len(vulns)} vulnerabilities ({critical} critical, {high} high)",
        "risk_breakdown": {
            "base_score": round(risk_score * 0.8, 1),
            "temporal_score": round(risk_score * 0.9, 1),
            "env_score": round(risk_score, 1),
            "final_score": risk_score,
            "risk_level": (
                "CRITICAL" if risk_score >= 9 else
                "HIGH" if risk_score >= 7 else
                "MEDIUM" if risk_score >= 4 else
                "LOW"
            ),
            "confidence": "high",
            "recommendations": [f"Fix {critical} critical issues immediately."],
        },
    }

    db.execute(
        "INSERT INTO scan_reports "
        "(token,user_id,username,scan_type,target,risk_score,vuln_count,"
        "critical_count,high_count,medium_count,low_count,result_json,stored_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (token, user_id, username, scan_type, target, risk_score,
         len(vulns), critical, high, medium, low, json.dumps(result), stored_at),
    )
    report_id = db.execute("SELECT id FROM scan_reports WHERE token=?", (token,)).fetchone()[0]

    for v in vulns:
        sev = v["severity"]
        cves = v.get("cve_ids", [])
        db.execute(
            "INSERT INTO scan_vulnerabilities "
            "(report_id,check_name,severity,title,description,evidence,remediation,"
            "line_number,cve_ids,is_fixed,fixed_at,found_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,0,NULL,?)",
            (report_id, v.get("check", "unknown"), sev,
             v.get("title", "Untitled"),
             v.get("description", ""),
             v.get("evidence", ""),
             v.get("remediation", ""),
             v.get("line_number", 0),
             json.dumps(cves),
             stored_at),
        )
    return report_id, token

def insert_audit(db, action, username, user_id, category, resource, ip, status, details, days_ago=0, hours_ago=0, minutes_ago=0):
    db.execute(
        "INSERT INTO audit_logs "
        "(action,username,user_id,category,resource,ip_address,status,details,created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (action, username, user_id, category, resource, ip, status, details,
         now_utc(delta_days=days_ago, delta_hours=hours_ago, delta_minutes=minutes_ago)),
    )


# ── Main seeder ───────────────────────────────────────────────────────────────

def seed():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)

    print("[1/5] Creating users...")

    # Admin
    insert_user(db, "admin",   "admin@securax.local",   "Admin@2024!",   "admin",
                ["run_scan","view_reports","delete_reports","manage_users","view_audit"])
    # Analysts
    insert_user(db, "yasser",  "yasser@securax.local",  "Analyst@2024!", "analyst",
                ["run_scan","view_reports"], created_days_ago=25)
    insert_user(db, "sara",    "sara@securax.local",    "Analyst@2024!", "analyst",
                ["run_scan","view_reports"], created_days_ago=20)
    insert_user(db, "hamza",   "hamza@securax.local",   "Analyst@2024!", "analyst",
                ["run_scan","view_reports"], created_days_ago=15)
    db.commit()

    uid_admin  = db.execute("SELECT id FROM users WHERE username='admin'").fetchone()[0]
    uid_yasser = db.execute("SELECT id FROM users WHERE username='yasser'").fetchone()[0]
    uid_sara   = db.execute("SELECT id FROM users WHERE username='sara'").fetchone()[0]
    uid_hamza  = db.execute("SELECT id FROM users WHERE username='hamza'").fetchone()[0]

    print("[2/5] Inserting scan reports...")

    # ── NETWORK EXTERNAL SCAN — high risk web server ──────────────────────────
    net_vulns_1 = [
        {
            "check": "open_port_22", "severity": "medium",
            "title": "SSH Port Exposed to Internet (Port 22)",
            "description": "Port 22 (SSH) is open and accessible from the public internet, allowing brute-force attacks.",
            "evidence": "PORT 22/tcp open ssh OpenSSH 7.4 (protocol 2.0)",
            "remediation": "Restrict SSH access to specific IPs via firewall rules or move to a non-standard port with key-based authentication only.",
            "line_number": 0, "cve_ids": ["CVE-2016-20012"],
        },
        {
            "check": "open_port_80", "severity": "low",
            "title": "HTTP Service Exposed (Port 80 — Unencrypted)",
            "description": "Plain HTTP traffic can be intercepted. All communication should be served over HTTPS.",
            "evidence": "PORT 80/tcp open http Apache httpd 2.4.29",
            "remediation": "Redirect all HTTP to HTTPS. Implement HSTS.",
            "line_number": 0, "cve_ids": [],
        },
        {
            "check": "open_port_3306", "severity": "critical",
            "title": "MySQL Database Port Exposed to Internet (Port 3306)",
            "description": "MySQL is accessible from the public internet. This is a critical misconfiguration that allows direct database attacks.",
            "evidence": "PORT 3306/tcp open mysql MySQL 5.7.38",
            "remediation": "Immediately restrict port 3306 to localhost or internal network only using firewall rules.",
            "line_number": 0, "cve_ids": ["CVE-2021-2022", "CVE-2022-21303"],
        },
        {
            "check": "os_detection", "severity": "info",
            "title": "OS Fingerprinting Successful",
            "description": "Operating system was identified remotely: Ubuntu 18.04. Exposing OS info aids attackers in targeting known vulnerabilities.",
            "evidence": "OS: Linux 4.15 (Ubuntu 18.04)",
            "remediation": "Configure the firewall to block OS fingerprinting probes.",
            "line_number": 0, "cve_ids": [],
        },
        {
            "check": "ftp_anonymous", "severity": "high",
            "title": "Anonymous FTP Login Enabled (Port 21)",
            "description": "The FTP server allows anonymous logins, potentially exposing sensitive files.",
            "evidence": "PORT 21/tcp open ftp vsftpd 3.0.3 — Anonymous login: allowed",
            "remediation": "Disable anonymous FTP access immediately. Use SFTP instead.",
            "line_number": 0, "cve_ids": [],
        },
    ]
    r1_id, r1_tok = insert_report(db, uid_admin, "admin", "network_ext",
                                  "192.168.1.100", 8.7, net_vulns_1,
                                  stored_days_ago=14)

    # ── WEB APPLICATION SCAN — XSS / SQLi ────────────────────────────────────
    web_vulns_1 = [
        {
            "check": "sql_injection", "severity": "critical",
            "title": "SQL Injection — Login Form",
            "description": "The login endpoint is vulnerable to SQL injection. An attacker can bypass authentication or dump the entire database.",
            "evidence": "Payload: ' OR '1'='1 — Response: Welcome admin",
            "remediation": "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
            "line_number": 0, "cve_ids": ["CWE-89"],
        },
        {
            "check": "xss_reflected", "severity": "high",
            "title": "Reflected Cross-Site Scripting (XSS) — Search Field",
            "description": "User input in the search parameter is reflected without sanitization, enabling script injection.",
            "evidence": "GET /search?q=<script>alert(1)</script> — Reflected in response body",
            "remediation": "Encode all user-controlled output using HTML entity encoding. Implement Content-Security-Policy headers.",
            "line_number": 0, "cve_ids": ["CWE-79"],
        },
        {
            "check": "missing_csp", "severity": "medium",
            "title": "Missing Content-Security-Policy Header",
            "description": "No CSP header found. This increases the risk of XSS and data injection attacks.",
            "evidence": "HTTP Response headers do not include Content-Security-Policy.",
            "remediation": "Add a strict CSP header: default-src 'self'; script-src 'self'",
            "line_number": 0, "cve_ids": [],
        },
        {
            "check": "insecure_cookie", "severity": "medium",
            "title": "Session Cookie Missing HttpOnly and Secure Flags",
            "description": "Session cookies are accessible via JavaScript and transmitted over HTTP, enabling session hijacking.",
            "evidence": "Set-Cookie: PHPSESSID=abc123 (no HttpOnly, no Secure)",
            "remediation": "Set HttpOnly and Secure flags on all session cookies. Set SameSite=Strict.",
            "line_number": 0, "cve_ids": [],
        },
        {
            "check": "open_redirect", "severity": "medium",
            "title": "Open Redirect Vulnerability",
            "description": "The application redirects users to URLs specified in query parameters without validation.",
            "evidence": "GET /redirect?url=https://evil.com — 302 redirect to evil.com",
            "remediation": "Validate and whitelist allowed redirect destinations. Never trust user-supplied URLs.",
            "line_number": 0, "cve_ids": ["CWE-601"],
        },
        {
            "check": "directory_listing", "severity": "low",
            "title": "Directory Listing Enabled",
            "description": "Web server returns directory contents when accessing /uploads/ directly.",
            "evidence": "GET /uploads/ — Response: Index of /uploads/ (directory listing shown)",
            "remediation": "Disable directory listing in the web server configuration (Options -Indexes in Apache).",
            "line_number": 0, "cve_ids": [],
        },
    ]
    r2_id, r2_tok = insert_report(db, uid_yasser, "yasser", "web",
                                  "http://testapp.securax.local", 9.1, web_vulns_1,
                                  stored_days_ago=10)

    # ── SAST SCAN — Python source code ───────────────────────────────────────
    sast_vulns_1 = [
        {
            "check": "hardcoded_secret", "severity": "critical",
            "title": "Hardcoded Database Password in Source Code",
            "description": "A plaintext database password was found hardcoded in the application source code.",
            "evidence": "db_password = 'SuperSecret123!'  # line 42 in config.py",
            "remediation": "Move all secrets to environment variables or a secrets manager. Never commit credentials to source control.",
            "line_number": 42, "cve_ids": ["CWE-798"],
        },
        {
            "check": "command_injection", "severity": "critical",
            "title": "Command Injection via os.system() with User Input",
            "description": "User-supplied data is passed directly to os.system(), allowing arbitrary command execution.",
            "evidence": "os.system('ping ' + user_input)  # line 87 in utils.py",
            "remediation": "Use subprocess with a list of arguments instead of shell=True. Validate and sanitize all user input.",
            "line_number": 87, "cve_ids": ["CWE-78"],
        },
        {
            "check": "insecure_random", "severity": "medium",
            "title": "Use of Insecure Random Number Generator for Token",
            "description": "random.random() is used for generating authentication tokens, making them predictable.",
            "evidence": "token = str(random.random())  # line 23 in auth.py",
            "remediation": "Use secrets.token_hex() or os.urandom() for cryptographically secure random values.",
            "line_number": 23, "cve_ids": ["CWE-330"],
        },
        {
            "check": "sql_string_concat", "severity": "high",
            "title": "SQL Query Built by String Concatenation",
            "description": "SQL queries are built by concatenating user input directly, leading to SQL injection risk.",
            "evidence": "query = 'SELECT * FROM users WHERE id=' + user_id  # line 15 in models.py",
            "remediation": "Use parameterized queries or an ORM. Never concatenate user data into SQL.",
            "line_number": 15, "cve_ids": ["CWE-89"],
        },
        {
            "check": "weak_hash", "severity": "high",
            "title": "Passwords Hashed with MD5 (Weak Algorithm)",
            "description": "MD5 is cryptographically broken and unsuitable for password hashing.",
            "evidence": "hashlib.md5(password.encode()).hexdigest()  # line 61 in auth.py",
            "remediation": "Replace MD5 with bcrypt, argon2, or scrypt for password hashing.",
            "line_number": 61, "cve_ids": ["CWE-327"],
        },
        {
            "check": "debug_mode", "severity": "medium",
            "title": "Flask Debug Mode Enabled in Production",
            "description": "Debug mode exposes an interactive debugger that allows remote code execution.",
            "evidence": "app.run(debug=True)  # line 112 in app.py",
            "remediation": "Set FLASK_ENV=production and debug=False for production deployments.",
            "line_number": 112, "cve_ids": [],
        },
        {
            "check": "path_traversal", "severity": "high",
            "title": "Path Traversal in File Download Endpoint",
            "description": "User-supplied filename is used directly to open files without path sanitization.",
            "evidence": "open('/uploads/' + request.args.get('file'))  # line 34 in views.py",
            "remediation": "Use os.path.basename() to strip directory components. Validate the resolved path stays within allowed directory.",
            "line_number": 34, "cve_ids": ["CWE-22"],
        },
        {
            "check": "insecure_deserialization", "severity": "critical",
            "title": "Insecure Deserialization using pickle",
            "description": "User-supplied data is deserialized using Python's pickle module, enabling arbitrary code execution.",
            "evidence": "obj = pickle.loads(user_data)  # line 99 in api.py",
            "remediation": "Never deserialize untrusted data with pickle. Use JSON or a safe serialization format.",
            "line_number": 99, "cve_ids": ["CWE-502"],
        },
    ]
    r3_id, r3_tok = insert_report(db, uid_sara, "sara", "sast",
                                  "vulnerable_webapp_v1.zip", 9.5, sast_vulns_1,
                                  stored_days_ago=7)

    # ── SERVER INTERNAL CONFIG SCAN — Apache ─────────────────────────────────
    server_vulns_1 = [
        {
            "check": "server_tokens_full", "severity": "medium",
            "title": "ServerTokens Set to Full — Version Disclosure",
            "description": "Apache is configured to expose full version information in HTTP response headers.",
            "evidence": "ServerTokens Full → Server: Apache/2.4.29 (Ubuntu)",
            "remediation": "Set ServerTokens Prod and ServerSignature Off in httpd.conf.",
            "line_number": 12, "cve_ids": [],
        },
        {
            "check": "directory_listing_enabled", "severity": "medium",
            "title": "Directory Listing Enabled (Options +Indexes)",
            "description": "Apache is configured to list directory contents if no index file is present.",
            "evidence": "Options +Indexes found in httpd.conf",
            "remediation": "Replace with Options -Indexes to prevent directory listing.",
            "line_number": 28, "cve_ids": [],
        },
        {
            "check": "ssl_protocols_weak", "severity": "critical",
            "title": "Deprecated SSL/TLS Protocols Enabled (SSLv3, TLSv1.0)",
            "description": "Old and vulnerable SSL/TLS versions are allowed, enabling POODLE, BEAST attacks.",
            "evidence": "SSLProtocol all -SSLv2  (TLSv1.0 and SSLv3 still enabled)",
            "remediation": "Set SSLProtocol TLSv1.2 TLSv1.3 and disable all older protocols.",
            "line_number": 45, "cve_ids": ["CVE-2014-3566", "CVE-2011-3389"],
        },
        {
            "check": "weak_ssl_ciphers", "severity": "high",
            "title": "Weak SSL Cipher Suites Allowed (RC4, DES, NULL)",
            "description": "Insecure cipher suites are enabled, allowing downgrade attacks.",
            "evidence": "SSLCipherSuite ALL:!aNULL (RC4 and DES ciphers still permitted)",
            "remediation": "Use a modern cipher suite: SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384",
            "line_number": 49, "cve_ids": ["CVE-2015-2808"],
        },
        {
            "check": "missing_security_headers", "severity": "medium",
            "title": "Security Headers Not Configured (HSTS, X-Frame-Options)",
            "description": "Key security headers are absent from the server configuration.",
            "evidence": "No Header always set Strict-Transport-Security found in config.",
            "remediation": "Add: Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains'",
            "line_number": 0, "cve_ids": [],
        },
        {
            "check": "admin_interface_exposed", "severity": "high",
            "title": "phpMyAdmin Accessible Without IP Restriction",
            "description": "The database management interface is accessible from any IP without additional authentication.",
            "evidence": "Alias /phpmyadmin /usr/share/phpmyadmin — no IP allow/deny rules",
            "remediation": "Restrict /phpmyadmin to trusted IPs only using Require ip directives.",
            "line_number": 67, "cve_ids": [],
        },
    ]
    r4_id, r4_tok = insert_report(db, uid_hamza, "hamza", "server_int",
                                  "apache_production.conf", 8.2, server_vulns_1,
                                  stored_days_ago=5)

    # ── NETWORK INTERNAL SCAN ─────────────────────────────────────────────────
    net_int_vulns = [
        {
            "check": "smb_vuln", "severity": "critical",
            "title": "EternalBlue (MS17-010) — SMB Vulnerability Detected",
            "description": "The target is vulnerable to EternalBlue, a critical SMB exploit used by WannaCry ransomware.",
            "evidence": "PORT 445/tcp open — smb-vuln-ms17-010: VULNERABLE",
            "remediation": "Apply Microsoft patch MS17-010 immediately. Disable SMBv1.",
            "line_number": 0, "cve_ids": ["CVE-2017-0144"],
        },
        {
            "check": "rdp_exposed", "severity": "high",
            "title": "RDP Service Exposed on Internal Network (Port 3389)",
            "description": "Remote Desktop is open and accessible without NLA, enabling brute-force attacks.",
            "evidence": "PORT 3389/tcp open — ms-wbt-server — NLA: not required",
            "remediation": "Enable Network Level Authentication (NLA). Restrict RDP access via VPN only.",
            "line_number": 0, "cve_ids": ["CVE-2019-0708"],
        },
        {
            "check": "telnet_open", "severity": "high",
            "title": "Telnet Service Active (Port 23) — Cleartext Protocol",
            "description": "Telnet transmits all data including credentials in plaintext.",
            "evidence": "PORT 23/tcp open telnet — Linux telnetd",
            "remediation": "Disable Telnet immediately. Replace with SSH.",
            "line_number": 0, "cve_ids": [],
        },
        {
            "check": "default_credentials", "severity": "critical",
            "title": "Default Credentials Accepted on Network Device",
            "description": "The router/switch accepts factory default username/password (admin/admin).",
            "evidence": "Login successful with admin:admin on 192.168.1.1",
            "remediation": "Change all default credentials immediately. Implement a strong password policy.",
            "line_number": 0, "cve_ids": [],
        },
    ]
    r5_id, _ = insert_report(db, uid_yasser, "yasser", "network_int",
                             "192.168.1.0/24", 9.3, net_int_vulns,
                             stored_days_ago=3)

    # ── DEPENDENCY SCAN ───────────────────────────────────────────────────────
    dep_vulns = [
        {
            "check": "outdated_django", "severity": "critical",
            "title": "Django 2.2.4 — SQL Injection Vulnerability",
            "description": "The installed Django version has a known SQL injection vulnerability.",
            "evidence": "django==2.2.4 (current: 4.2.x)",
            "remediation": "Upgrade Django to the latest stable version: pip install 'Django>=4.2'",
            "line_number": 3, "cve_ids": ["CVE-2019-14234"],
        },
        {
            "check": "outdated_requests", "severity": "medium",
            "title": "requests 2.18.0 — SSRF and Certificate Validation Bypass",
            "description": "Old version of requests library with known vulnerabilities.",
            "evidence": "requests==2.18.0 (current: 2.31.x)",
            "remediation": "Upgrade: pip install 'requests>=2.31.0'",
            "line_number": 7, "cve_ids": ["CVE-2018-18074"],
        },
        {
            "check": "outdated_pillow", "severity": "high",
            "title": "Pillow 6.2.0 — Remote Code Execution via Image Processing",
            "description": "Vulnerable version of Pillow/PIL with RCE vulnerability in TIFF parsing.",
            "evidence": "Pillow==6.2.0 (current: 10.x)",
            "remediation": "Upgrade: pip install 'Pillow>=10.0.0'",
            "line_number": 12, "cve_ids": ["CVE-2020-5313"],
        },
        {
            "check": "outdated_flask", "severity": "medium",
            "title": "Flask 0.12.2 — Multiple Vulnerabilities",
            "description": "Outdated Flask with known security issues including open redirect and debug mode exposure.",
            "evidence": "Flask==0.12.2 (current: 3.x)",
            "remediation": "Upgrade: pip install 'Flask>=3.0.0'",
            "line_number": 1, "cve_ids": ["CVE-2018-1000656"],
        },
    ]
    r6_id, _ = insert_report(db, uid_sara, "sara", "dependencies",
                              "requirements.txt", 7.8, dep_vulns,
                              stored_days_ago=2)

    # ── DAST SCAN ─────────────────────────────────────────────────────────────
    dast_vulns = [
        {
            "check": "xss_stored", "severity": "critical",
            "title": "Stored XSS in Comment Section",
            "description": "Malicious JavaScript stored in the database is executed for every visitor viewing the comments.",
            "evidence": "POST /comments — payload: <img src=x onerror=alert(document.cookie)> stored and reflected.",
            "remediation": "Sanitize all user input server-side before storing. Use a CSP and encode on output.",
            "line_number": 0, "cve_ids": ["CWE-79"],
        },
        {
            "check": "csrf", "severity": "high",
            "title": "Cross-Site Request Forgery (CSRF) on Password Change",
            "description": "The password change form lacks CSRF token, allowing attackers to change user passwords via forged requests.",
            "evidence": "POST /change-password with no CSRF token — action performed successfully.",
            "remediation": "Implement CSRF tokens on all state-changing forms. Use SameSite cookie attribute.",
            "line_number": 0, "cve_ids": ["CWE-352"],
        },
        {
            "check": "idor", "severity": "high",
            "title": "Insecure Direct Object Reference (IDOR) — User Profiles",
            "description": "Changing the user ID in the URL allows accessing other users' private data.",
            "evidence": "GET /profile?id=2 returns another user's profile without authorization check.",
            "remediation": "Implement proper authorization checks. Verify object ownership before returning data.",
            "line_number": 0, "cve_ids": ["CWE-639"],
        },
        {
            "check": "broken_auth", "severity": "high",
            "title": "No Account Lockout on Failed Login Attempts",
            "description": "The application does not lock accounts after repeated failed login attempts, allowing brute-force attacks.",
            "evidence": "1000 failed login attempts sent without any lockout triggered.",
            "remediation": "Implement account lockout after 5 failed attempts. Add CAPTCHA. Use rate limiting.",
            "line_number": 0, "cve_ids": ["CWE-307"],
        },
    ]
    r7_id, _ = insert_report(db, uid_admin, "admin", "dast",
                              "http://staging.securax.local", 8.9, dast_vulns,
                              stored_days_ago=1)

    # ── Additional older reports for chart variety ────────────────────────────
    # Week ago scans
    insert_report(db, uid_yasser, "yasser", "web", "http://blog.securax.local", 4.2,
                  [{"check":"missing_headers","severity":"medium","title":"Missing Security Headers",
                    "description":"X-Frame-Options and HSTS are missing.",
                    "evidence":"HTTP headers analyzed","remediation":"Add security headers","line_number":0,"cve_ids":[]}],
                  stored_days_ago=8)

    insert_report(db, uid_hamza, "hamza", "network_ext", "10.0.0.50", 3.1,
                  [{"check":"open_port_8080","severity":"low","title":"Development Port 8080 Open",
                    "description":"Port 8080 is open and may expose a development server.",
                    "evidence":"PORT 8080/tcp open http","remediation":"Close unused ports","line_number":0,"cve_ids":[]}],
                  stored_days_ago=12)

    insert_report(db, uid_sara, "sara", "sast", "api_service.zip", 6.5,
                  [{"check":"missing_input_validation","severity":"high","title":"Missing Input Validation",
                    "description":"API endpoints lack input validation allowing malformed data.",
                    "evidence":"No validation middleware found","remediation":"Add input validation","line_number":0,"cve_ids":["CWE-20"]},
                   {"check":"logging_sensitive_data","severity":"medium","title":"Sensitive Data Logged",
                    "description":"Passwords and tokens are written to log files.",
                    "evidence":"logger.info('Password: ' + password)","remediation":"Never log sensitive data","line_number":55,"cve_ids":["CWE-532"]}],
                  stored_days_ago=9)

    db.commit()

    print("[3/5] Inserting audit logs...")

    # Login events
    for i in range(20):
        insert_audit(db, "login_success", "admin", uid_admin, "auth",
                     "/api/auth/login", "127.0.0.1", "success",
                     "Admin login", days_ago=i // 3, hours_ago=i % 8)

    insert_audit(db, "login_success", "yasser", uid_yasser, "auth",
                 "/api/auth/login", "192.168.1.10", "success", "", days_ago=1)
    insert_audit(db, "login_success", "sara", uid_sara, "auth",
                 "/api/auth/login", "192.168.1.15", "success", "", days_ago=2)
    insert_audit(db, "login_success", "hamza", uid_hamza, "auth",
                 "/api/auth/login", "192.168.1.20", "success", "", days_ago=3)

    # Failed login attempts
    insert_audit(db, "login_failed", "unknown", None, "auth",
                 "/api/auth/login", "185.234.219.10", "failed",
                 "Invalid username or password.", days_ago=1, hours_ago=2)
    insert_audit(db, "login_failed", "admin", uid_admin, "auth",
                 "/api/auth/login", "185.234.219.10", "failed",
                 "Invalid username or password.", days_ago=1, hours_ago=1)
    insert_audit(db, "login_failed", "admin", uid_admin, "auth",
                 "/api/auth/login", "185.234.219.11", "failed",
                 "Invalid username or password.", days_ago=0, hours_ago=3)

    # Scan events
    insert_audit(db, "scan_started", "admin", uid_admin, "scan",
                 "192.168.1.100", "127.0.0.1", "success", "type=network_ext", days_ago=14)
    insert_audit(db, "scan_completed", "admin", uid_admin, "scan",
                 "192.168.1.100", "127.0.0.1", "success",
                 "type=network_ext risk=8.7 level=HIGH findings=5", days_ago=14)

    insert_audit(db, "scan_started", "yasser", uid_yasser, "scan",
                 "http://testapp.securax.local", "192.168.1.10", "success",
                 "type=web", days_ago=10)
    insert_audit(db, "scan_completed", "yasser", uid_yasser, "scan",
                 "http://testapp.securax.local", "192.168.1.10", "success",
                 "type=web risk=9.1 level=CRITICAL findings=6", days_ago=10)

    insert_audit(db, "scan_started", "sara", uid_sara, "scan",
                 "vulnerable_webapp_v1.zip", "192.168.1.15", "success",
                 "type=sast", days_ago=7)
    insert_audit(db, "scan_completed", "sara", uid_sara, "scan",
                 "vulnerable_webapp_v1.zip", "192.168.1.15", "success",
                 "type=sast risk=9.5 level=CRITICAL findings=8", days_ago=7)

    insert_audit(db, "scan_started", "hamza", uid_hamza, "scan",
                 "apache_production.conf", "192.168.1.20", "success",
                 "type=server_int", days_ago=5)
    insert_audit(db, "scan_completed", "hamza", uid_hamza, "scan",
                 "apache_production.conf", "192.168.1.20", "success",
                 "type=server_int risk=8.2 level=HIGH findings=6", days_ago=5)

    # User management
    insert_audit(db, "user_created", "admin", uid_admin, "admin",
                 "yasser", "127.0.0.1", "success", "Created analyst account", days_ago=25)
    insert_audit(db, "user_created", "admin", uid_admin, "admin",
                 "sara", "127.0.0.1", "success", "Created analyst account", days_ago=20)
    insert_audit(db, "user_created", "admin", uid_admin, "admin",
                 "hamza", "127.0.0.1", "success", "Created analyst account", days_ago=15)

    # Security events
    insert_audit(db, "access_denied", "yasser", uid_yasser, "security",
                 "/api/admin/users", "192.168.1.10", "denied",
                 "Missing permission: manage_users", days_ago=3)
    insert_audit(db, "target_violation", "hamza", uid_hamza, "security",
                 "8.8.8.8", "192.168.1.20", "denied",
                 "Blocked: tried 8.8.8.8, allowed target is 10.0.0.50", days_ago=2)

    db.commit()

    print("[4/5] Verifying data...")
    users_count   = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    reports_count = db.execute("SELECT COUNT(*) FROM scan_reports").fetchone()[0]
    vulns_count   = db.execute("SELECT COUNT(*) FROM scan_vulnerabilities").fetchone()[0]
    audit_count   = db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]

    print(f"  Users:           {users_count}")
    print(f"  Scan reports:    {reports_count}")
    print(f"  Vulnerabilities: {vulns_count}")
    print(f"  Audit events:    {audit_count}")

    db.close()

    print()
    print("=" * 58)
    print(f"  Demo DB created: {DB_PATH}")
    print()
    print("  Accounts:")
    print("    admin  / Admin@2024!   (admin role — full access)")
    print("    yasser / Analyst@2024! (analyst role)")
    print("    sara   / Analyst@2024! (analyst role)")
    print("    hamza  / Analyst@2024! (analyst role)")
    print()
    print("  To switch to this DB (when you're ready):")
    print("    1. Rename  securax.db       ->  securax_backup.db")
    print("    2. Rename  securax_demo.db  ->  securax.db")
    print("    3. Restart the backend server")
    print("=" * 58)


if __name__ == "__main__":
    seed()

