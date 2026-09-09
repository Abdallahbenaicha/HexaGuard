"""SecuraX — Micro-Dojo Daily Challenge Blueprint (Part 3).

Provides a focused 15-minute daily training card:
  - Deterministic per-day challenge selection (seeded by user_id + YYYY-MM-DD).
  - Selection Priority:
      1. Oldest pending Shadow Manual Pass finding from live scan reports.
      2. Lowest coverage / unpracticed gap in user's Skill Ledger.
  - Linked to Encyclopedia (/learn) and Adversarial Twin Sandbox (Part 1).
  - Honest streak tracking: streak increments ONLY upon verified daily completion,
    never by merely opening the page.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from flask import Blueprint, jsonify, request
from flask_login import current_user, login_required

from database import (
    _get_db,
    _norm,
    get_user_shadow_backlog,
    get_user_skill_ledger,
    record_skill_progress,
)
from vuln_taxonomy import VULN_TAXONOMY
from blueprints.sandbox import SANDBOX_ALLOWLIST

logger = logging.getLogger(__name__)

dojo_bp = Blueprint("dojo", __name__, url_prefix="/api/dojo")

# ── Question Bank for Daily Challenges ───────────────────────────────────────────
QUESTION_BANK: dict[str, dict[str, Any]] = {
    "xss": {
        "id": "q_xss_01",
        "question_ar": "أي من آليات الدفاع التالية تعتبر الأكثر فاعلية لمنع ثغرات XSS المنعكسة في المتصفح؟",
        "question_en": "Which defense is most effective against Reflected XSS?",
        "choices_ar": [
            "تشفير قاعدة البيانات بـ AES-256",
            "ترميز مخرجات السياق (Contextual Output Encoding) وتفعيل CSP",
            "استخدام بروتوكول HTTPS فقط",
            "إخفاء كوكيز الجلسة بتشفير Base64",
        ],
        "choices_en": [
            "Encrypting database with AES-256",
            "Contextual output encoding and deploying a strict CSP",
            "Using HTTPS only",
            "Base64 encoding session cookies",
        ],
        "correct_index": 1,
        "explanation": "ترميز المخرجات بحسب السياق (HTML/JS/Attr) يمنع المتصفح من تفسير مدخلات المستخدم ككود قابل للتنفيذ، بينما تمنع سياسة CSP تنفيذ أي سكربتات محقونة.",
    },
    "sqli": {
        "id": "q_sqli_01",
        "question_ar": "ما هو الإجراء القياسي الأضمن لإلغاء خطر ثغرات SQL Injection جذرياً؟",
        "question_en": "What is the industry-standard remediation for SQL Injection?",
        "choices_ar": [
            "استبدال علامات الاقتباس الفردية بحذفها عبر Regex",
            "استخدام الاستعلامات المعلمة (Parameterized Queries / Prepared Statements)",
            "استخدام جدار ناري WAF فقط",
            "تقليل وقت جلسة المستخدم",
        ],
        "choices_en": [
            "Stripping single quotes with regular expressions",
            "Parameterized Queries / Prepared Statements",
            "Relying solely on a Web Application Firewall (WAF)",
            "Shortening user session timeouts",
        ],
        "correct_index": 1,
        "explanation": "الاستعلامات المعلمة تفصل بشكل قاطع بين بنية الأمر البرمجي وقيم البيانات، مما يجعل حقن الأوامر مستحيلاً حتى لو تضمنت المدخلات علامات اقتباس.",
    },
    "csrf": {
        "id": "q_csrf_01",
        "question_ar": "كيف تحمي سمة SameSite=Lax أو Strict في ملفات الكوكيز ضد هجمات CSRF؟",
        "question_en": "How does the SameSite cookie attribute protect against CSRF?",
        "choices_ar": [
            "تمنع المتصفح من إرسال الكوكي مع الطلبات المتقاطعة بين المواقع (Cross-Site Requests)",
            "تقوم بتشفير محتوى الكوكي بمفتاح خاص",
            "تمنع سحب الكوكي عبر الجافاسكريبت الداخلي",
            "تحذف الكوكي تلقائياً عند إغلاق التبويب",
        ],
        "choices_en": [
            "Restricts the browser from attaching cookies on cross-site requests",
            "Encrypts cookie contents with a private key",
            "Prevents client-side JavaScript from reading the cookie",
            "Deletes the cookie when the browser tab closes",
        ],
        "correct_index": 0,
        "explanation": "خاصية SameSite=Lax/Strict تمنع المتصفح من إرفاق كوكيز الجلسة التلقائية عندما يصدر الطلب من موقع خارجي، مما يحبط هجمات CSRF.",
    },
    "rce": {
        "id": "q_rce_01",
        "question_ar": "عند الحاجة لاستدعاء أوامر نظام التشغيل من بايثون، ما هو النمط الأكثر أماناً؟",
        "question_en": "In Python, which pattern is safest when executing OS commands?",
        "choices_ar": [
            "استخدام os.system(f'ping {host}')",
            "استخدام subprocess.run(['ping', '-c', '1', host], shell=False)",
            "استخدام subprocess.Popen(cmd, shell=True)",
            "تشفير المعامل بـ MD5 قبل تمريره لـ os.popen",
        ],
        "choices_en": [
            "Using os.system(f'ping {host}')",
            "Using subprocess.run(['ping', '-c', '1', host], shell=False)",
            "Using subprocess.Popen(cmd, shell=True)",
            "MD5 hashing the argument before passing to os.popen",
        ],
        "correct_index": 1,
        "explanation": "تمرير مصفوفة وسائط مع shell=False يتجاوز مفسر الأوامر (Shell) تماماً ويمنع عوامل السلسلة مثل الفواصل المنقوطة والأنابيب (| و ;) من تنفيذ أوامر إضافية.",
    },
    "ssrf": {
        "id": "q_ssrf_01",
        "question_ar": "ما العنوان السحابي الأكثر استهدافاً في هجمات SSRF على بيئات AWS للسطو على الرموز المؤقتة؟",
        "question_en": "Which cloud metadata IP is commonly targeted in AWS SSRF attacks?",
        "choices_ar": [
            "192.168.1.1",
            "169.254.169.254",
            "10.0.0.1",
            "127.0.0.1:8080",
        ],
        "choices_en": [
            "192.168.1.1",
            "169.254.169.254 (Instance Metadata Service)",
            "10.0.0.1",
            "127.0.0.1:8080",
        ],
        "correct_index": 1,
        "explanation": "عنوان 169.254.169.254 هو عنوان Link-Local الخاص بخدمة الـ Metadata (IMDS) في السحابة، وتستهدفه هجمات SSRF لسرقة أذونات IAM المؤقتة.",
    },
    "default": {
        "id": "q_default_01",
        "question_ar": "ما هو المبدأ الأمني القائم على تقييد الصلاحيات والمنافذ إلى الحد الأدنى المطلوب فقط للتشغيل؟",
        "question_en": "What security principle dictates limiting access rights to only what is strictly required?",
        "choices_ar": [
            "مبدأ الصلاحيات الأقل (Principle of Least Privilege)",
            "مبدأ الأمان عبر الغموض (Security by Obscurity)",
            "مبدأ التكرار الدفاعي (Fail-Open Redundancy)",
            "مبدأ الاعتماد الفردي (Single Factor Trust)",
        ],
        "choices_en": [
            "Principle of Least Privilege (PoLP)",
            "Security by Obscurity",
            "Fail-Open Redundancy",
            "Single Factor Trust",
        ],
        "correct_index": 0,
        "explanation": "مبدأ الامتيازات الأقل (PoLP) يضمن أن كل وحدة أو مستخدم يملك فقط الحد الأدنى من الصلاحيات والوصول اللازم لإتمام مهامه.",
    },
}


def _calculate_streak(user_id: int, today_str: str) -> int:
    """Calculate consecutive daily streak ending today or yesterday."""
    db = _get_db()
    rows = db.execute(
        "SELECT date_key FROM dojo_completions WHERE user_id = ? ORDER BY date_key DESC",
        (int(user_id),),
    ).fetchall()

    completed_dates = {r[0] if isinstance(r, (list, tuple)) else r["date_key"] for r in rows}

    try:
        cur_date = datetime.strptime(today_str, "%Y-%m-%d").date()
    except Exception:
        cur_date = datetime.now(timezone.utc).date()

    # Check if today is completed
    streak = 0
    test_date = cur_date

    # If today is not completed yet, streak might be active from yesterday
    if test_date.strftime("%Y-%m-%d") not in completed_dates:
        test_date = test_date - timedelta(days=1)

    while test_date.strftime("%Y-%m-%d") in completed_dates:
        streak += 1
        test_date = test_date - timedelta(days=1)

    return streak


@dojo_bp.route("/today", methods=["GET"])
@login_required
def get_daily_dojo():
    """Retrieve deterministic daily challenge for current user.

    Order of priority:
      (A) Oldest pending shadow manual task from scan reports.
      (B) Weakest / unpracticed gap in Skill Ledger.
    """
    user_id = current_user.id
    date_key = request.args.get("date", "").strip()
    if not date_key:
        date_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # 1. Deterministic Selection
    # (A) Check pending shadow backlog
    shadow_backlog = get_user_shadow_backlog(user_id)
    chosen_vuln_type = None
    source = "skill_ledger_gap"

    if shadow_backlog:
        # Priority A: Oldest pending shadow manual task
        chosen_vuln_type = shadow_backlog[0]["vuln_type"]
        source = "shadow_backlog"
    else:
        # Priority B: Skill Ledger gaps
        ledger = get_user_skill_ledger(user_id)
        theory_only = [item["vuln_type"] for item in ledger if item["status"] == "theory_only"]

        # Deterministic seed based on user_id + date_key
        seed_hash = hashlib.sha256(f"{user_id}:{date_key}".encode("utf-8")).hexdigest()
        seed_num = int(seed_hash[:8], 16)

        if theory_only:
            idx = seed_num % len(theory_only)
            chosen_vuln_type = theory_only[idx]
        else:
            # If everything is practiced, pick by oldest last_practiced_at
            sorted_by_age = sorted(
                ledger,
                key=lambda x: x.get("last_practiced_at") or "1970-01-01"
            )
            idx = seed_num % min(5, len(sorted_by_age))
            chosen_vuln_type = sorted_by_age[idx]["vuln_type"]

    meta = VULN_TAXONOMY.get(chosen_vuln_type, VULN_TAXONOMY["xss"])

    # 2. Check Sandbox Support
    sandbox_supported = chosen_vuln_type in SANDBOX_ALLOWLIST
    sandbox_info = SANDBOX_ALLOWLIST.get(chosen_vuln_type) if sandbox_supported else None

    # 3. Question Selection
    q_data = QUESTION_BANK.get(chosen_vuln_type, QUESTION_BANK.get("default", list(QUESTION_BANK.values())[0]))

    # 4. Check completion status and streak
    db = _get_db()
    completion_row = db.execute(
        "SELECT id, completed_at FROM dojo_completions WHERE user_id = ? AND date_key = ?",
        (user_id, date_key),
    ).fetchone()
    today_completed = bool(completion_row)

    streak_days = _calculate_streak(user_id, date_key)

    return jsonify({
        "ok": True,
        "date": date_key,
        "vuln_type": chosen_vuln_type,
        "meta": {
            "name_en": meta["name_en"],
            "name_ar": meta["name_ar"],
            "scanner": meta["scanner"],
            "difficulty": meta["difficulty"],
            "description_en": meta.get("description_en", ""),
            "description_ar": meta.get("description_ar", ""),
            "remediation_en": meta.get("remediation_en", ""),
            "remediation_ar": meta.get("remediation_ar", ""),
        },
        "source": source,
        "encyclopedia_link": f"/learn/vulnerabilities?search={chosen_vuln_type}",
        "sandbox_supported": sandbox_supported,
        "sandbox_name": sandbox_info["name"] if sandbox_info else None,
        "question": {
            "id": q_data["id"],
            "question_ar": q_data["question_ar"],
            "question_en": q_data["question_en"],
            "choices_ar": q_data["choices_ar"],
            "choices_en": q_data["choices_en"],
        },
        "today_completed": today_completed,
        "streak_days": streak_days,
    }), 200


@dojo_bp.route("/answer", methods=["POST"])
@login_required
def submit_dojo_answer():
    """Submit daily question answer and update streak upon correct verification."""
    data = request.get_json(silent=True) or {}
    q_id = str(data.get("question_id", "")).strip()
    vuln_type = str(data.get("vuln_type", "")).strip().lower()
    choice_idx = data.get("choice_index")
    date_key = str(data.get("date", "")).strip()
    if not date_key:
        date_key = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    if choice_idx is None:
        return jsonify({"ok": False, "error": "Missing choice_index"}), 400

    q_data = QUESTION_BANK.get(vuln_type, QUESTION_BANK.get("default"))
    is_correct = (int(choice_idx) == q_data["correct_index"])

    if not is_correct:
        return jsonify({
            "ok": True,
            "correct": False,
            "message": "إجابة غير صحيحة، حاول مجدداً بعد مراجعة المفهوم.",
            "explanation": q_data["explanation"],
        }), 200

    # Correct! Record completion for today
    db = _get_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    try:
        db.execute(
            "INSERT INTO dojo_completions (user_id, date_key, vuln_type, completed_at) "
            "VALUES (?, ?, ?, ?)",
            (current_user.id, date_key, vuln_type, now_iso),
        )
        db.commit()
    except Exception:
        # Already completed for today
        pass

    # Record progress in Skill Ledger if not verified yet
    try:
        record_skill_progress(
            user_id=current_user.id,
            vuln_type=vuln_type,
            status="practiced_self_reported",
            evidence_ref=f"dojo_challenge:{date_key}",
        )
    except Exception as exc:
        logger.warning("Dojo skill progress record warning: %s", exc)

    new_streak = _calculate_streak(current_user.id, date_key)

    return jsonify({
        "ok": True,
        "correct": True,
        "message": "إجابة ممتازة وصحيحة! تم توثيق إنجاز اليوم وزيادة سلسلة الأيام المتتالية.",
        "explanation": q_data["explanation"],
        "streak_days": new_streak,
        "today_completed": True,
    }), 200
