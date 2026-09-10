"""
tracks.py -- Learning Tracks Blueprint (E-01)

GET /api/tracks          -> list of all tracks with live completion %
GET /api/tracks/<id>     -> single track detail with step-by-step progress

Architecture: tracks are defined as a static catalogue (no extra DB table).
Progress is computed live from existing data sources:
  - Skill Ledger  (db/skills.py -> get_user_skill_ledger)
  - Dojo streak   (dojo_completions table)
  - Shadow backlog (shadow_manual_tasks)

This implements the "integration layer, not new build" principle:
maximum value from existing data, minimum new schema.
"""
from __future__ import annotations

from typing import Any

from flask import Blueprint, jsonify
from flask_login import current_user, login_required

try:
    from database import get_user_skill_ledger, get_user_shadow_backlog
except ImportError:
    from backend.database import get_user_skill_ledger, get_user_shadow_backlog

try:
    from db.connection import _get_db
except ImportError:
    from backend.db.connection import _get_db

tracks_bp = Blueprint("tracks", __name__, url_prefix="/api/tracks")

# ---------------------------------------------------------------------------
# Track catalogue (static definition -- no DB table needed)
# Each track references vuln_types from vuln_taxonomy.py DATASET_VULN_TYPES
# ---------------------------------------------------------------------------

_TRACKS: list[dict[str, Any]] = [
    {
        "id": "bug-bounty-hunter",
        "name_ar": "صائد الثغرات (Bug Bounty Hunter)",
        "name_en": "Bug Bounty Hunter",
        "description_ar": (
            "مسار متكامل من اكتشاف الهدف إلى كتابة تقرير ثغرة احترافي. "
            "يجمع: الموسوعة + دليل الصيد + السانبوكس + دوجو + Bounty Radar + Learn & Earn."
        ),
        "description_en": (
            "End-to-end path: recon to report. "
            "Integrates Encyclopedia, Hunt Guide, Sandbox, Dojo, Bounty Radar."
        ),
        "icon": "target",
        "color": "#ff6b35",
        "tier": "Practitioner",
        "required_vuln_types": [
            "xss", "sqli", "rce", "broken_auth", "csrf",
            "open_redirect", "info_disclosure", "sensitive_data_exposure",
            "security_misconfig", "session_fixation",
        ],
        "shadow_weight": 0.15,
        "dojo_streak_bonus_threshold": 7,
        "dojo_streak_bonus_pct": 0.10,
    },
    {
        "id": "soc-analyst",
        "name_ar": "محلل SOC (Blue Team)",
        "name_en": "SOC Analyst",
        "description_ar": (
            "مسار الجانب الدفاعي: تحليل سجلات، تصنيف تنبيهات، خريطة MITRE ATT&CK، "
            "ملفات قضايا جاهزة (Case Files). "
            "مجال Blue Team مُضاف للمنصة في الجلسة الرابعة."
        ),
        "description_en": (
            "Defensive path: log analysis, alert triage, MITRE ATT&CK mapping, case files."
        ),
        "icon": "shield",
        "color": "#00b4d8",
        "tier": "Apprentice",
        "required_vuln_types": [
            "security_misconfig", "weak_crypto", "missing_security_headers",
            "missing_csp", "vulnerable_dependency",
        ],
        "shadow_weight": 0.20,
        "dojo_streak_bonus_threshold": 3,
        "dojo_streak_bonus_pct": 0.05,
    },
    {
        "id": "ejpt-oscp-readiness",
        "name_ar": "مسار الجاهزية لـ eJPT / OSCP",
        "name_en": "eJPT to OSCP Readiness",
        "description_ar": (
            "مسار شخصي مخصَّص نحو الشهادات المهنية. مؤشر الجاهزية يُحسَب "
            "من تغطية Skill Ledger عبر المجالات التي يتطلبها OSCP فعلياً. "
            "تنويه: مؤشر داخلي تقريبي لا ضمان اجتياز فعلي."
        ),
        "description_en": (
            "Personal cert-readiness track. Readiness % from Skill Ledger coverage "
            "across OSCP-required domains. Disclaimer: internal estimate only."
        ),
        "icon": "award",
        "color": "#7b2d8b",
        "tier": "Expert",
        "required_vuln_types": [
            "xss", "sqli", "rce", "broken_auth", "session_fixation",
            "open_redirect", "info_disclosure", "security_misconfig",
            "csrf", "sensitive_data_exposure",
            "missing_security_headers", "weak_crypto",
        ],
        "shadow_weight": 0.10,
        "dojo_streak_bonus_threshold": 14,
        "dojo_streak_bonus_pct": 0.15,
        "cert_disclaimer": True,
    },
]

_TRACK_INDEX: dict[str, dict] = {t["id"]: t for t in _TRACKS}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_dojo_streak(user_id: int) -> int:
    """Return current dojo streak for user (days)."""
    try:
        db = _get_db()
        row = db.execute(
            "SELECT streak FROM dojo_completions WHERE user_id=? ORDER BY completed_date DESC LIMIT 1",
            (user_id,)
        ).fetchone()
        return int(row[0]) if row else 0
    except Exception:
        return 0


def _get_shadow_cleared_ratio(user_id: int) -> float:
    """Return fraction of shadow tasks completed vs total for user."""
    try:
        backlog = get_user_shadow_backlog(user_id)
        if not backlog:
            return 1.0  # nothing pending = fully cleared
        done = sum(1 for t in backlog if t.get("completed"))
        return done / len(backlog)
    except Exception:
        return 0.0


def _get_casefiles_cleared_ratio(user_id: int) -> float:
    """Return fraction of SOC case files solved by user."""
    try:
        db = _get_db()
        row = db.execute(
            "SELECT count(DISTINCT case_id) FROM casefile_submissions WHERE user_id=? AND passed=1",
            (user_id,)
        ).fetchone()
        passed_count = int(row[0]) if row else 0
        return min(1.0, passed_count / 4.0)
    except Exception:
        return 0.0


def _compute_track_progress(track: dict, skill_ledger: list[dict], user_id: int) -> dict:
    """
    Compute completion percentage for a track given the user skill ledger.

    Formula:
        base_ratio  = (practiced types & required types) / len(required types)
        shadow      = shadow_cleared_ratio * shadow_weight
        dojo_bonus  = dojo_streak_bonus_pct  if streak >= threshold else 0
        base_weight = 1 - shadow_weight - dojo_streak_bonus_pct
        total       = min(1.0, base_ratio * base_weight + shadow + dojo_bonus)
    """
    required = set(track.get("required_vuln_types", []))
    if not required:
        return {"percent": 0, "practiced": [], "missing": []}

    practiced_types: set[str] = set()
    for entry in skill_ledger:
        vt = entry.get("vuln_type", "")
        if vt and entry.get("practiced_count", 0) > 0:
            practiced_types.add(vt)

    intersection  = required & practiced_types
    base_ratio    = len(intersection) / len(required)

    shadow_weight     = track.get("shadow_weight", 0.0)
    dojo_bonus_thr    = track.get("dojo_streak_bonus_threshold", 999)
    dojo_bonus_pct    = track.get("dojo_streak_bonus_pct", 0.0)

    shadow_cleared   = _get_shadow_cleared_ratio(user_id)
    casefile_cleared = _get_casefiles_cleared_ratio(user_id)
    streak           = _get_dojo_streak(user_id)

    # For SOC Analyst track, casefiles give an additional boost
    if track.get("id") == "soc-analyst":
        shadow_contrib = (shadow_cleared * 0.5 + casefile_cleared * 0.5) * shadow_weight
    else:
        shadow_contrib = shadow_cleared * shadow_weight

    dojo_contrib    = dojo_bonus_pct if streak >= dojo_bonus_thr else 0.0
    base_weight     = 1.0 - shadow_weight - dojo_bonus_pct
    total           = min(1.0, base_ratio * base_weight + shadow_contrib + dojo_contrib)
    pct             = round(total * 100, 1)

    return {
        "percent":               pct,
        "practiced":             sorted(intersection),
        "missing":               sorted(required - practiced_types),
        "dojo_streak":           streak,
        "shadow_cleared_pct":    round(shadow_cleared * 100, 1),
        "casefiles_cleared_pct": round(casefile_cleared * 100, 1),
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@tracks_bp.route("", methods=["GET"])
@login_required
def list_tracks():
    """GET /api/tracks -- return all tracks with live progress for current user."""
    user_id      = int(current_user.get_id())
    skill_ledger = get_user_skill_ledger(user_id)

    result = []
    for t in _TRACKS:
        progress = _compute_track_progress(t, skill_ledger, user_id)
        result.append({
            "id":              t["id"],
            "name_ar":         t["name_ar"],
            "name_en":         t["name_en"],
            "description_ar":  t["description_ar"],
            "description_en":  t["description_en"],
            "icon":            t["icon"],
            "color":           t["color"],
            "tier":            t["tier"],
            "cert_disclaimer": t.get("cert_disclaimer", False),
            "progress":        progress,
        })

    return jsonify({"ok": True, "tracks": result})


# ---------------------------------------------------------------------------
# External Certification Readiness (E-04)
# ---------------------------------------------------------------------------
_CERT_REQUIREMENTS: dict[str, dict[str, Any]] = {
    "ejpt": {
        "id": "ejpt",
        "name": "eJPT (eLearnSecurity Junior Penetration Tester)",
        "provider": "INE Security",
        "badge_color": "#ff6b35",
        "required_skills": [
            "open_ports", "info_disclosure", "broken_auth", "xss", "sqli", "weak_crypto", "security_misconfig"
        ],
        "disclaimer_en": "Internal estimate based on Skill Ledger coverage. Does not guarantee official exam passage.",
        "disclaimer_ar": "تقدير داخلي مبني على تغطية سجل المهارات. لا يعد ضماناً رسمياً لاجتياز الاختبار.",
    },
    "oscp": {
        "id": "oscp",
        "name": "OSCP (OffSec Certified Professional)",
        "provider": "OffSec",
        "badge_color": "#7b2d8b",
        "required_skills": [
            "rce", "sqli", "xss", "broken_auth", "deserialization", "sensitive_data_exposure",
            "security_misconfig", "session_fixation", "vulnerable_dependency", "weak_crypto", "missing_csp"
        ],
        "disclaimer_en": "Internal estimate based on Skill Ledger coverage. Note: Dedicated Active Directory labs are also required for the official exam.",
        "disclaimer_ar": "تقدير داخلي مبني على سجل المهارات. تنبيه: يتطلب الاختبار الرسمي تدريباً مكثفاً إضافياً على بيئات Active Directory.",
    },
    "secplus": {
        "id": "secplus",
        "name": "CompTIA Security+ (SY0-701)",
        "provider": "CompTIA",
        "badge_color": "#00b4d8",
        "required_skills": [
            "phishing", "brute_force", "missing_security_headers", "weak_crypto", "security_misconfig", "missing_spf_dkim_dmarc"
        ],
        "disclaimer_en": "Internal estimate based on defensive and foundational skills. Does not guarantee official exam passage.",
        "disclaimer_ar": "تقدير داخلي مبني على المهارات الدفاعية والأساسية. لا يعد ضماناً رسمياً للاختبار.",
    },
}


@tracks_bp.route("/cert-readiness", methods=["GET"])
@login_required
def get_cert_readiness():
    """GET /api/tracks/cert-readiness -- return external certification readiness index (E-04)."""
    user_id = int(current_user.get_id())
    skill_ledger = get_user_skill_ledger(user_id)

    practiced_types = {
        e["vuln_type"] for e in skill_ledger if e.get("practiced_count", 0) > 0
    }

    results = []
    for cert_id, cert in _CERT_REQUIREMENTS.items():
        req = set(cert["required_skills"])
        covered = req & practiced_types
        missing = req - practiced_types
        pct = round((len(covered) / len(req)) * 100, 1) if req else 0.0

        results.append({
            "id": cert["id"],
            "name": cert["name"],
            "provider": cert["provider"],
            "badge_color": cert["badge_color"],
            "readiness_pct": pct,
            "covered_skills": sorted(covered),
            "missing_skills": sorted(missing),
            "total_skills": len(req),
            "disclaimer_en": cert["disclaimer_en"],
            "disclaimer_ar": cert["disclaimer_ar"],
        })

    return jsonify({"ok": True, "certifications": results})


@tracks_bp.route("/<track_id>", methods=["GET"])
@login_required
def get_track(track_id: str):
    """GET /api/tracks/<id> -- single track with per-vuln-type step detail."""
    track = _TRACK_INDEX.get(track_id)
    if not track:
        return jsonify({"ok": False, "error": f"Track '{track_id}' not found."}), 404

    user_id      = int(current_user.get_id())
    skill_ledger = get_user_skill_ledger(user_id)
    progress     = _compute_track_progress(track, skill_ledger, user_id)

    ledger_map = {e["vuln_type"]: e for e in skill_ledger}
    steps = []
    for vt in sorted(track.get("required_vuln_types", [])):
        entry = ledger_map.get(vt, {})
        steps.append({
            "vuln_type":       vt,
            "practiced":       entry.get("practiced_count", 0) > 0,
            "practiced_count": entry.get("practiced_count", 0),
            "verified":        entry.get("practiced_verified", False),
            "last_practiced":  entry.get("last_practiced"),
        })

    return jsonify({
        "ok":      True,
        "track":   {**{k: v for k, v in track.items() if k != "required_vuln_types"},
                    "progress": progress},
        "steps":   steps,
    })
