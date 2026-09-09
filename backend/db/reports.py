# Auto-generated modular DB component
import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
import bcrypt

logger = logging.getLogger(__name__)

try:
    from db.connection import (
        _get_db, _exec, _norm, _count_severities, _UNSET, _local, _resolve_db_path, DB_PATH
    )
except ImportError:
    from backend.db.connection import (
        _get_db, _exec, _norm, _count_severities, _UNSET, _local, _resolve_db_path, DB_PATH
    )

try:
    from vuln_taxonomy import normalize_check_to_vuln_type
except ImportError:
    from backend.vuln_taxonomy import normalize_check_to_vuln_type

def store_report(result: dict, risk_score: float, original_content: str | None,
                 user_id: int, username: str, bounty_meta: dict | None = None) -> str:
    token = uuid.uuid4().hex
    vulns = result.get("vulnerabilities", [])
    c, h, m, l = _count_severities(vulns)
    now = datetime.now(timezone.utc).isoformat()
    if bounty_meta:
        result.setdefault("bounty", {}).update(bounty_meta)
    b_meta = bounty_meta or result.get("bounty") or {}
    b_platform = b_meta.get("bounty_platform")
    b_program  = b_meta.get("bounty_program_handle")
    b_asset    = b_meta.get("bounty_asset")
    db = _get_db()
    try:
        cursor = db.execute(
            "INSERT INTO scan_reports"
            " (token,user_id,username,scan_type,target,risk_score,vuln_count,"
            "  critical_count,high_count,medium_count,low_count,result_json,original_content,stored_at,"
            "  bounty_platform,bounty_program_handle,bounty_asset)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (token, user_id, username,
             result.get("scan_type", ""), result.get("target", ""),
             risk_score, len(vulns), c, h, m, l,
             json.dumps(result), original_content, now,
             b_platform, b_program, b_asset),
        )
        report_id = cursor.lastrowid

        unique_vuln_types = set()
        scan_type = result.get("scan_type", "")
        for vuln in vulns:
            v_type = normalize_check_to_vuln_type(
                check=str(vuln.get("check") or vuln.get("check_name") or ""),
                title=str(vuln.get("title") or ""),
                scanner=scan_type,
            )
            vuln["vuln_type"] = v_type
            unique_vuln_types.add(v_type)

            sev = (str(vuln.get("severity", "low")).strip().lower() or "low")
            if sev not in {"critical", "high", "medium", "low", "info"}:
                sev = "low"
            raw_cves = vuln.get("cve_ids", [])
            if isinstance(raw_cves, str):
                cve_list = [c.strip() for c in raw_cves.split(",") if c.strip()]
            elif isinstance(raw_cves, list):
                cve_list = [str(c).strip() for c in raw_cves if str(c).strip()]
            else:
                cve_list = []

            tri_status = (str(vuln.get("triage_status") or "New")).strip() or "New"
            tri_notes = str(vuln.get("triage_notes") or "")

            # Prior triage inheritance on same target asset
            if tri_status == "New" and (b_asset or result.get("target")):
                target_match = b_asset or result.get("target")
                check_val = str(vuln.get("check") or vuln.get("check_name") or "")
                title_val = str(vuln.get("title") or "")
                try:
                    prior_vuln = db.execute(
                        "SELECT sv.triage_status, sv.triage_notes FROM scan_vulnerabilities sv "
                        "JOIN scan_reports sr ON sv.report_id = sr.id "
                        "WHERE (sr.bounty_asset = ? OR sr.target = ?) "
                        "AND (sv.title = ? OR (sv.check_name = ? AND sv.check_name != 'unknown_check')) "
                        "AND sv.triage_status != 'New' ORDER BY sv.id DESC LIMIT 1",
                        (target_match, target_match, title_val, check_val),
                    ).fetchone()
                    if prior_vuln:
                        tri_status = prior_vuln[0]
                        tri_notes = prior_vuln[1] or ""
                except Exception:
                    pass

            cur_v = db.execute(
                "INSERT INTO scan_vulnerabilities"
                " (report_id,check_name,severity,title,description,evidence,"
                "  remediation,line_number,cve_ids,is_fixed,fixed_at,found_at,triage_status,triage_notes)"
                " VALUES (?,?,?,?,?,?,?,?,?,0,NULL,?,?,?)",
                (
                    report_id,
                    str(vuln.get("check", "unknown_check")),
                    sev,
                    str(vuln.get("title", "Untitled finding")),
                    str(vuln.get("description", "")),
                    str(vuln.get("evidence", "")),
                    str(vuln.get("remediation", "")),
                    int(vuln.get("line_number", 0) or 0),
                    json.dumps(cve_list),
                    now,
                    tri_status,
                    tri_notes,
                ),
            )
            vuln["id"] = getattr(cur_v, "lastrowid", None)
            vuln["triage_status"] = tri_status
            vuln["triage_notes"] = tri_notes

        # Generate unique shadow manual tasks for this report
        for vt in sorted(list(unique_vuln_types)):
            try:
                db.execute(
                    "INSERT INTO shadow_manual_tasks (report_token, user_id, vuln_type, status, created_at) "
                    "VALUES (?, ?, ?, 'pending', ?)",
                    (token, user_id, vt, now),
                )
            except Exception:
                pass

        db.commit()
    except Exception:
        db.rollback()
        raise
    return token


def get_report(token: str) -> dict | None:
    db = _get_db()
    row = db.execute("SELECT * FROM scan_reports WHERE token=?", (token,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["result"] = json.loads(d["result_json"])
    try:
        vuln_rows = db.execute(
            "SELECT id, check_name, severity, title, triage_status, triage_notes, is_fixed, fixed_at "
            "FROM scan_vulnerabilities WHERE report_id=? ORDER BY id ASC",
            (d["id"],),
        ).fetchall()
        if vuln_rows and "vulnerabilities" in d["result"]:
            vulns = d["result"]["vulnerabilities"]
            for idx, v in enumerate(vulns):
                if idx < len(vuln_rows):
                    vr = dict(vuln_rows[idx])
                    v["id"] = vr["id"]
                    v["triage_status"] = vr.get("triage_status") or "New"
                    v["triage_notes"] = vr.get("triage_notes") or ""
                    v["is_fixed"] = bool(vr.get("is_fixed", 0))
    except Exception as exc:
        logger.warning("Error enriching report with DB vulnerabilities: %s", exc)
    return d


def update_vulnerability_triage(vuln_id: int, triage_status: str, triage_notes: str | None = None) -> bool:
    """Update finding triage status ('New', 'Reviewing', 'Reported', 'Duplicate', 'False Positive')."""
    valid_statuses = {"New", "Reviewing", "Reported", "Duplicate", "False Positive"}
    if triage_status not in valid_statuses:
        raise ValueError(f"Invalid triage status: {triage_status}. Must be one of {valid_statuses}")
    db = _get_db()
    cur = db.execute(
        "UPDATE scan_vulnerabilities SET triage_status=?, triage_notes=? WHERE id=?",
        (triage_status, triage_notes or "", vuln_id),
    )
    db.commit()
    return getattr(cur, "rowcount", 0) > 0


def get_target_scan_history(target_asset: str, platform: str | None = None, limit: int = 10) -> dict:
    """Retrieve historical scan reports for a given target asset and compute diffs."""
    db = _get_db()
    clean_target = target_asset.strip().lower().lstrip("*.")
    query = (
        "SELECT id, token, user_id, username, scan_type, target, risk_score, vuln_count, "
        "critical_count, high_count, medium_count, low_count, stored_at, "
        "bounty_platform, bounty_program_handle, bounty_asset, result_json "
        "FROM scan_reports "
        "WHERE bounty_asset = ? OR target = ? OR target LIKE ? "
    )
    params = [target_asset, target_asset, f"%{clean_target}%"]
    if platform and platform != "all":
        query += "AND bounty_platform = ? "
        params.append(platform)
    query += "ORDER BY stored_at DESC LIMIT ?"
    params.append(limit)

    rows = db.execute(query, tuple(params)).fetchall()
    if not rows:
        return {
            "target": target_asset,
            "total_scans": 0,
            "scans": [],
            "differential": {
                "new_count": 0,
                "resolved_count": 0,
                "recurrent_count": 0,
                "new_findings": [],
                "resolved_findings": [],
                "recurrent_findings": [],
            },
        }

    scans = []
    parsed_results = []
    for r in rows:
        d = dict(r)
        res_json = d.pop("result_json", "{}")
        try:
            res = json.loads(res_json)
        except Exception:
            res = {}
        parsed_results.append(res)
        scans.append({
            "token": d["token"],
            "stored_at": d["stored_at"],
            "scan_type": d["scan_type"],
            "target": d["target"],
            "risk_score": d["risk_score"],
            "vuln_count": d["vuln_count"],
            "critical_count": d["critical_count"],
            "high_count": d["high_count"],
            "medium_count": d["medium_count"],
            "low_count": d["low_count"],
            "bounty_platform": d.get("bounty_platform"),
            "bounty_program": d.get("bounty_program_handle"),
        })

    diff = {
        "new_count": 0,
        "resolved_count": 0,
        "recurrent_count": 0,
        "new_findings": [],
        "resolved_findings": [],
        "recurrent_findings": [],
    }

    if len(parsed_results) >= 2:
        latest_vulns = parsed_results[0].get("vulnerabilities", [])
        prev_vulns = parsed_results[1].get("vulnerabilities", [])

        def _finding_fp(v):
            return f"{v.get('check', '')}::{v.get('title', '')}::{v.get('severity', '')}"

        prev_fps = {_finding_fp(v): v for v in prev_vulns}
        latest_fps = {_finding_fp(v): v for v in latest_vulns}

        for fp, v in latest_fps.items():
            if fp not in prev_fps:
                diff["new_findings"].append({
                    "check": v.get("check"),
                    "title": v.get("title"),
                    "severity": v.get("severity"),
                })
            else:
                diff["recurrent_findings"].append({
                    "check": v.get("check"),
                    "title": v.get("title"),
                    "severity": v.get("severity"),
                })

        for fp, v in prev_fps.items():
            if fp not in latest_fps:
                diff["resolved_findings"].append({
                    "check": v.get("check"),
                    "title": v.get("title"),
                    "severity": v.get("severity"),
                })

        diff["new_count"] = len(diff["new_findings"])
        diff["resolved_count"] = len(diff["resolved_findings"])
        diff["recurrent_count"] = len(diff["recurrent_findings"])
    elif len(parsed_results) == 1:
        latest_vulns = parsed_results[0].get("vulnerabilities", [])
        diff["new_findings"] = [{
            "check": v.get("check"),
            "title": v.get("title"),
            "severity": v.get("severity"),
        } for v in latest_vulns]
        diff["new_count"] = len(diff["new_findings"])

    return {
        "target": target_asset,
        "target_asset": target_asset,
        "total_scans": len(scans),
        "last_scanned_at": scans[0]["stored_at"] if scans else None,
        "scans": scans,
        "differential": diff,
    }


def get_user_reports(user_id: int, limit: int = 100) -> list[dict]:
    return [dict(r) for r in _get_db().execute(
        "SELECT token,user_id,username,scan_type,target,risk_score,vuln_count,"
        "critical_count,high_count,medium_count,low_count,stored_at"
        " FROM scan_reports WHERE user_id=? ORDER BY stored_at DESC LIMIT ?",
        (user_id, limit),
    ).fetchall()]


def get_all_reports(limit: int = 200, date_from: str | None = None,
                    date_to: str | None = None, scan_type: str | None = None,
                    username: str | None = None) -> list[dict]:
    clauses, params = [], []
    if date_from: clauses.append("stored_at >= ?");  params.append(date_from)
    if date_to:   clauses.append("stored_at <= ?");  params.append(date_to)
    if scan_type: clauses.append("scan_type=?");     params.append(scan_type)
    if username:  clauses.append("username LIKE ?"); params.append(f"%{username}%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    return [dict(r) for r in _get_db().execute(
        f"SELECT * FROM scan_reports {where} ORDER BY stored_at DESC LIMIT ?", params  # nosec B608
    ).fetchall()]


def delete_report(token: str) -> tuple[bool, str]:
    _exec("DELETE FROM scan_reports WHERE token=?", (token,))
    return True, "Report deleted."


# ── Dashboard stats ───────────────────────────────────────────────────────────

def get_dashboard_stats(user_id: int) -> dict:
    db = _get_db()
    total       = db.execute("SELECT COUNT(*) FROM scan_reports WHERE user_id=?", (user_id,)).fetchone()[0]
    avg         = db.execute("SELECT AVG(risk_score) FROM scan_reports WHERE user_id=?", (user_id,)).fetchone()[0] or 0
    total_vulns = db.execute("SELECT SUM(vuln_count) FROM scan_reports WHERE user_id=?", (user_id,)).fetchone()[0] or 0
    critical    = db.execute("SELECT SUM(critical_count) FROM scan_reports WHERE user_id=?", (user_id,)).fetchone()[0] or 0
    high        = db.execute("SELECT SUM(high_count) FROM scan_reports WHERE user_id=?", (user_id,)).fetchone()[0] or 0
    rows        = db.execute(
        "SELECT scan_type, COUNT(*) as c FROM scan_reports WHERE user_id=? GROUP BY scan_type",
        (user_id,),
    ).fetchall()
    recent      = db.execute(
        "SELECT risk_score FROM scan_reports WHERE user_id=? ORDER BY stored_at DESC LIMIT 10",
        (user_id,),
    ).fetchall()
    return {
        "total_scans":    total,
        "total_vulns":    int(total_vulns),
        "critical_count": int(critical),
        "high_count":     int(high),
        "avg_risk_score": round(float(avg), 1),
        "by_type":        [{"type": r["scan_type"], "count": r["c"]} for r in rows],
        "recent_scores":  [r["risk_score"] for r in recent],
    }


def get_all_dashboard_stats() -> dict:
    db = _get_db()
    total       = db.execute("SELECT COUNT(*) FROM scan_reports").fetchone()[0]
    avg         = db.execute("SELECT AVG(risk_score) FROM scan_reports").fetchone()[0] or 0
    total_vulns = db.execute("SELECT SUM(vuln_count) FROM scan_reports").fetchone()[0] or 0
    critical    = db.execute("SELECT SUM(critical_count) FROM scan_reports").fetchone()[0] or 0
    high        = db.execute("SELECT SUM(high_count) FROM scan_reports").fetchone()[0] or 0
    rows        = db.execute(
        "SELECT scan_type, COUNT(*) as c FROM scan_reports GROUP BY scan_type"
    ).fetchall()
    recent      = db.execute(
        "SELECT risk_score FROM scan_reports ORDER BY stored_at DESC LIMIT 10"
    ).fetchall()
    return {
        "total_scans":    total,
        "total_vulns":    int(total_vulns),
        "critical_count": int(critical),
        "high_count":     int(high),
        "avg_risk_score": round(float(avg), 1),
        "by_type":        [{"type": r["scan_type"], "count": r["c"]} for r in rows],
        "recent_scores":  [r["risk_score"] for r in recent],
    }


def get_system_stats() -> dict:
    db   = _get_db()
    now  = datetime.now(timezone.utc)
    today = now.date().isoformat()

    # ── Basic counts ──────────────────────────────────────────────────────────
    total_users  = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active_users = db.execute("SELECT COUNT(*) FROM users WHERE is_active=1").fetchone()[0]
    total_scans  = db.execute("SELECT COUNT(*) FROM scan_reports").fetchone()[0]
    total_vulns  = db.execute("SELECT SUM(vuln_count) FROM scan_reports").fetchone()[0] or 0
    critical     = db.execute("SELECT SUM(critical_count) FROM scan_reports").fetchone()[0] or 0
    today_scans  = db.execute(
        "SELECT COUNT(*) FROM scan_reports WHERE stored_at LIKE ?", (f"{today}%",)
    ).fetchone()[0]

    # ── This week ─────────────────────────────────────────────────────────────
    week_scans = db.execute(
        "SELECT COUNT(*) FROM scan_reports WHERE stored_at >= date('now','-7 days')"
    ).fetchone()[0]

    # ── Failed logins today ───────────────────────────────────────────────────
    failed_logins = db.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE action='login_failed' AND created_at LIKE ?",
        (f"{today}%",),
    ).fetchone()[0]

    # ── Risk distribution ─────────────────────────────────────────────────────
    risk_row = db.execute(
        "SELECT "
        "  SUM(CASE WHEN risk_score >= 9.0 THEN 1 ELSE 0 END) as critical,"
        "  SUM(CASE WHEN risk_score >= 7.0 AND risk_score < 9.0 THEN 1 ELSE 0 END) as high,"
        "  SUM(CASE WHEN risk_score >= 4.0 AND risk_score < 7.0 THEN 1 ELSE 0 END) as medium,"
        "  SUM(CASE WHEN risk_score >= 1.0 AND risk_score < 4.0 THEN 1 ELSE 0 END) as low,"
        "  SUM(CASE WHEN risk_score < 1.0 THEN 1 ELSE 0 END) as minimal "
        "FROM scan_reports"
    ).fetchone()
    risk_distribution = {
        "critical": int(risk_row["critical"] or 0),
        "high":     int(risk_row["high"]     or 0),
        "medium":   int(risk_row["medium"]   or 0),
        "low":      int(risk_row["low"]      or 0),
        "minimal":  int(risk_row["minimal"]  or 0),
    }

    # ── Top scan types ────────────────────────────────────────────────────────
    top_scan_types = [
        {"type": r["scan_type"], "count": r["c"]}
        for r in db.execute(
            "SELECT scan_type, COUNT(*) as c FROM scan_reports "
            "GROUP BY scan_type ORDER BY c DESC"
        ).fetchall()
    ]

    # ── Recent scans (last 10) ────────────────────────────────────────────────
    recent_scans = [
        dict(r) for r in db.execute(
            "SELECT token,username,scan_type,target,risk_score,vuln_count,stored_at "
            "FROM scan_reports ORDER BY stored_at DESC LIMIT 10"
        ).fetchall()
    ]

    # ── Top scanners ──────────────────────────────────────────────────────────
    top_scanners = db.execute(
        "SELECT username, COUNT(*) as c FROM scan_reports "
        "GROUP BY username ORDER BY c DESC LIMIT 5"
    ).fetchall()

    # ── Recent events ─────────────────────────────────────────────────────────
    recent_events = db.execute(
        "SELECT action, username, created_at FROM audit_logs "
        "ORDER BY created_at DESC LIMIT 10"
    ).fetchall()

    # ── Users list (for admin user management) ────────────────────────────────
    users_list = [_norm(r) for r in db.execute("SELECT * FROM users ORDER BY id").fetchall()]

    return {
        "total_users":       total_users,
        "active_users":      active_users,
        "total_scans":       total_scans,
        "today_scans":       today_scans,
        "scans_this_week":   week_scans,
        "total_vulns":       int(total_vulns),
        "critical_vulns":    int(critical),
        "failed_logins":     failed_logins,
        "risk_distribution": risk_distribution,
        "top_scan_types":    top_scan_types,
        "recent_scans":      recent_scans,
        "recent_events":     [dict(r) for r in recent_events],
        "top_scanners":      [{"username": r["username"], "count": r["c"]} for r in top_scanners],
        "users_list":        users_list,
    }


def get_top_vulnerabilities(limit: int = 10) -> list[dict]:
    """Return the most frequent vulnerability check_names from the dedicated table."""
    rows = _get_db().execute(
        "SELECT check_name, severity, COUNT(*) AS count"
        " FROM scan_vulnerabilities"
        " GROUP BY check_name, severity"
        " ORDER BY count DESC"
        " LIMIT ?",
        (limit,),
    ).fetchall()
    if rows:
        return [{"title": r["check_name"], "severity": r["severity"], "count": r["count"]}
                for r in rows]
    # Fallback: parse result_json for databases that predate the scan_vulnerabilities table
    result_rows = _get_db().execute(
        "SELECT result_json FROM scan_reports ORDER BY stored_at DESC LIMIT 100"
    ).fetchall()
    counts: dict[str, dict] = {}
    for row in result_rows:
        try:
            vulns = json.loads(row["result_json"]).get("vulnerabilities", [])
        except (ValueError, TypeError):
            continue
        for v in vulns:
            title = (v.get("title") or v.get("check") or "Unknown")[:80]
            sev   = (v.get("severity") or "info").lower()
            if title not in counts:
                counts[title] = {"title": title, "severity": sev, "count": 0}
            counts[title]["count"] += 1
    ordered = sorted(counts.values(), key=lambda x: x["count"], reverse=True)
    return ordered[:limit]


# ── Scan Jobs (persistent background jobs) ────────────────────────────────────

def upsert_job(job: dict) -> None:
    """Insert or replace a background scan job record."""
    _exec(
        "INSERT OR REPLACE INTO scan_jobs"
        " (job_id,scan_type,target,user_id,username,status,progress,message,"
        "  result_json,error,report_token,started_at,completed_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            job["job_id"], job["scan_type"], job["target"],
            job["user_id"], job["username"], job["status"],
            job["progress"], job["message"],
            json.dumps(job.get("result")) if job.get("result") is not None else None,
            job.get("error"), job.get("report_token"),
            job["started_at"], job.get("completed_at"),
        ),
    )


def get_job_from_db(job_id: str) -> dict | None:
    row = _get_db().execute(
        "SELECT * FROM scan_jobs WHERE job_id=?", (job_id,)
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    if d.get("result_json"):
        try:
            d["result"] = json.loads(d["result_json"])
        except (ValueError, TypeError):
            d["result"] = None
    else:
        d["result"] = None
    return d


def get_user_jobs_from_db(user_id: int, limit: int = 20) -> list[dict]:
    rows = _get_db().execute(
        "SELECT job_id,scan_type,target,user_id,username,status,progress,"
        "message,error,report_token,started_at,completed_at"
        " FROM scan_jobs WHERE user_id=? ORDER BY started_at DESC LIMIT ?",
        (user_id, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def delete_job(job_id: str, user_id: int) -> None:
    """Delete a single job row (only if it belongs to user_id)."""
    _exec("DELETE FROM scan_jobs WHERE job_id=? AND user_id=?", (job_id, user_id))


def delete_user_error_jobs(user_id: int) -> None:
    """Delete all error-status jobs for a user."""
    _exec("DELETE FROM scan_jobs WHERE user_id=? AND status='error'", (user_id,))


def purge_old_jobs(ttl_minutes: int = 60) -> int:
    """Delete completed/errored jobs older than ttl_minutes. Returns count deleted."""
    cutoff = (datetime.now(timezone.utc) - __import__("datetime").timedelta(minutes=ttl_minutes)).isoformat()
    cur = _exec(
        "DELETE FROM scan_jobs WHERE status IN ('done','error') AND completed_at < ?",
        (cutoff,),
    )
    return cur.rowcount if hasattr(cur, "rowcount") else 0


# ── Scheduled Scans ───────────────────────────────────────────────────────────

def get_or_create_share_token(report_token: str, expires_in_days: int = 7) -> str | None:
    row = _get_db().execute(
        "SELECT share_token, share_expires_at FROM scan_reports WHERE token=?", (report_token,)
    ).fetchone()
    if not row:
        return None
    d = dict(row)
    existing = d.get("share_token")
    expires_at = d.get("share_expires_at")
    now_dt = datetime.now(timezone.utc)
    if existing:
        if expires_at:
            try:
                exp_dt = datetime.fromisoformat(expires_at)
                if exp_dt > now_dt:
                    return existing
            except (ValueError, TypeError):
                pass
        else:
            return existing
    share_token = uuid.uuid4().hex
    new_expires_at = (now_dt + timedelta(days=expires_in_days)).isoformat()
    try:
        _exec(
            "UPDATE scan_reports SET share_token=?, share_expires_at=? WHERE token=?",
            (share_token, new_expires_at, report_token),
        )
        return share_token
    except Exception:
        return None


def get_report_by_share_token(share_token: str) -> dict | None:
    try:
        row = _get_db().execute(
            "SELECT * FROM scan_reports WHERE share_token=?", (share_token,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        expires_at = d.get("share_expires_at")
        if expires_at:
            try:
                exp_dt = datetime.fromisoformat(expires_at)
                if datetime.now(timezone.utc) > exp_dt:
                    logger.warning("Access denied: share token expired: %s", share_token[:8])
                    return None
            except (ValueError, TypeError):
                pass
        d["result"] = json.loads(d["result_json"])
        return d
    except Exception:
        return None


# ── Domain Verification ───────────────────────────────────────────────────────

def request_domain_verification(user_id: int, domain: str) -> str:
    """Create or refresh a verification request. Returns the verification token."""
    token = uuid.uuid4().hex
    now   = datetime.now(timezone.utc).isoformat()
    domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    existing = _get_db().execute(
        "SELECT user_id FROM domain_verifications WHERE user_id=?", (user_id,)
    ).fetchone()
    if existing:
        _exec(
            "UPDATE domain_verifications"
            " SET domain=?, verify_token=?, verified=0, verified_at=NULL, verified_by=NULL"
            " WHERE user_id=?",
            (domain, token, user_id),
        )
    else:
        _exec(
            "INSERT INTO domain_verifications"
            " (user_id, domain, verify_token, verified, created_at)"
            " VALUES (?, ?, ?, 0, ?)",
            (user_id, domain, token, now),
        )
    return token


def get_domain_verification(user_id: int) -> dict | None:
    row = _get_db().execute(
        "SELECT * FROM domain_verifications WHERE user_id=?", (user_id,)
    ).fetchone()
    return dict(row) if row else None


def mark_domain_verified(user_id: int, method: str) -> bool:
    """Mark the user's domain as verified (called after DNS/meta check passes)."""
    now = datetime.now(timezone.utc).isoformat()
    cur = _exec(
        "UPDATE domain_verifications"
        " SET verified=1, verified_at=?, verified_by=?"
        " WHERE user_id=? AND verified=0",
        (now, method, user_id),
    )
    return (getattr(cur, "rowcount", 1) or 1) > 0


def admin_verify_domain(user_id: int, domain: str) -> None:
    """Admin bypass: directly set a domain as verified without any check."""
    domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    now   = datetime.now(timezone.utc).isoformat()
    token = uuid.uuid4().hex
    existing = _get_db().execute(
        "SELECT user_id FROM domain_verifications WHERE user_id=?", (user_id,)
    ).fetchone()
    if existing:
        _exec(
            "UPDATE domain_verifications"
            " SET domain=?, verify_token=?, verified=1, verified_at=?, verified_by='admin'"
            " WHERE user_id=?",
            (domain, token, now, user_id),
        )
    else:
        _exec(
            "INSERT INTO domain_verifications"
            " (user_id, domain, verify_token, verified, verified_at, verified_by, created_at)"
            " VALUES (?, ?, ?, 1, ?, 'admin', ?)",
            (user_id, domain, token, now, now),
        )


# ── Network Scan History ──────────────────────────────────────────────────────

def store_network_snapshot(target: str, user_id: int, hosts_summary: list[dict]) -> None:
    """Store a lightweight snapshot of discovered hosts for port-history comparison."""
    _exec(
        "INSERT INTO network_snapshots (target, user_id, scan_time, hosts_json) VALUES (?,?,?,?)",
        (target, user_id, datetime.now(timezone.utc).isoformat(),
         json.dumps(hosts_summary, separators=(",", ":"))),
    )
    # Keep only the last 5 snapshots per target per user to avoid unbounded growth
    db = _get_db()
    rows = db.execute(
        "SELECT id FROM network_snapshots WHERE target=? AND user_id=? ORDER BY scan_time DESC",
        (target, user_id),
    ).fetchall()
    if len(rows) > 5:
        old_ids = [r[0] if not hasattr(r, "keys") else r["id"] for r in rows[5:]]
        for old_id in old_ids:
            try:
                _exec("DELETE FROM network_snapshots WHERE id=?", (old_id,))
            except Exception:
                pass


def get_last_network_snapshot(target: str, user_id: int) -> list[dict] | None:
    """Return the most recent previous snapshot (before the current scan) for diff."""
    db = _get_db()
    cur = db.execute(
        "SELECT hosts_json FROM network_snapshots WHERE target=? AND user_id=?"
        " ORDER BY scan_time DESC LIMIT 1",
        (target, user_id),
    )
    row = cur.fetchone()
    if not row:
        return None
    try:
        raw = row[0] if not hasattr(row, "keys") else row["hosts_json"]
        return json.loads(raw)
    except Exception:
        return None
