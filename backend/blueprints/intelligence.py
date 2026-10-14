"""
intelligence.py  --  Cyber Intelligence Center Blueprint

Provides structured intelligence feeds. Each feed has:
  - a static taxonomy (categories, types)
  - a /recent  endpoint that returns cached/simulated items (no ext. API keys needed)
  - a /search  endpoint for keyword filtering

Architecture: deterministic RULE ENGINE layer only.
ARIA AI synthesis is invoked client-side via /api/ai/chat (existing ai_routes.py).
No new DB tables; results are assembled from vuln_taxonomy data + static catalogue.
"""
from __future__ import annotations
import datetime
from flask import Blueprint, jsonify, request
from flask_login import login_required

intelligence_bp = Blueprint("intelligence", __name__, url_prefix="/api/intelligence")

# ── Feed categories taxonomy ──────────────────────────────────────────────────
FEED_CATEGORIES = [
    {"id": "cve",          "label_en": "CVE / Vulnerabilities", "label_ar": "CVE / الثغرات",           "icon": "bug",        "color": "#ef4444"},
    {"id": "kev",          "label_en": "CISA KEV",              "label_ar": "CISA KEV",                "icon": "alert",      "color": "#f97316"},
    {"id": "advisories",   "label_en": "Security Advisories",   "label_ar": "الإرشادات الأمنية",       "icon": "shield",     "color": "#f59e0b"},
    {"id": "research",     "label_en": "Research Papers",       "label_ar": "الأوراق البحثية",          "icon": "book",       "color": "#8b5cf6"},
    {"id": "tools",        "label_en": "Security Tools",        "label_ar": "أدوات الأمن",              "icon": "tool",       "color": "#10b981"},
    {"id": "regulations",  "label_en": "Regulations / Frameworks", "label_ar": "اللوائح والأطر",       "icon": "law",        "color": "#3b82f6"},
    {"id": "conferences",  "label_en": "Conferences & Events",  "label_ar": "المؤتمرات والفعاليات",     "icon": "calendar",   "color": "#06b6d4"},
    {"id": "incidents",    "label_en": "Incidents & Breaches",  "label_ar": "الحوادث والاختراقات",       "icon": "fire",       "color": "#dc2626"},
]

# ── Static intelligence items (representative, not live-scraped) ──────────────
_STATIC_ITEMS = [
    # CVEs
    {"id": "cve-2024-38812", "category": "cve", "severity": "critical",
     "title": "CVE-2024-38812 — VMware vCenter RCE (CVSS 9.8)",
     "title_ar": "CVE-2024-38812 — ثغرة تنفيذ كود عن بُعد في VMware vCenter (CVSS 9.8)",
     "source": "NVD", "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-38812",
     "epss": 0.94, "kev": True,
     "published": "2024-09-17", "tags": ["rce", "vmware", "vcenter"]},
    {"id": "cve-2024-21762", "category": "cve", "severity": "critical",
     "title": "CVE-2024-21762 — Fortinet FortiOS OOB Write RCE (CVSS 9.6)",
     "title_ar": "CVE-2024-21762 — ثغرة كتابة خارج الحدود في FortiOS",
     "source": "NVD", "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
     "epss": 0.97, "kev": True,
     "published": "2024-02-08", "tags": ["rce", "fortinet", "vpn"]},
    {"id": "cve-2024-3400", "category": "cve", "severity": "critical",
     "title": "CVE-2024-3400 — Palo Alto PAN-OS Command Injection (CVSS 10.0)",
     "title_ar": "CVE-2024-3400 — حقن أوامر في PAN-OS من Palo Alto",
     "source": "NVD", "source_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
     "epss": 0.97, "kev": True,
     "published": "2024-04-12", "tags": ["rce", "paloalto", "firewall"]},
    # KEV
    {"id": "kev-ivanti-2024", "category": "kev", "severity": "critical",
     "title": "CISA KEV: Ivanti Connect Secure Auth Bypass (CVE-2024-21887)",
     "title_ar": "CISA KEV: تجاوز المصادقة في Ivanti Connect Secure",
     "source": "CISA KEV", "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
     "epss": 0.97, "kev": True,
     "published": "2024-01-10", "tags": ["auth_bypass", "ivanti", "vpn"]},
    # Research
    {"id": "arxiv-llmsec-2024", "category": "research", "severity": "info",
     "title": "Prompt Injection Attacks Against LLM-Integrated Applications (arXiv 2024)",
     "title_ar": "هجمات حقن الموجهات ضد تطبيقات LLM (arXiv 2024)",
     "source": "arXiv", "source_url": "https://arxiv.org/abs/2402.00859",
     "epss": None, "kev": False,
     "published": "2024-02-01", "tags": ["ai", "llm", "prompt_injection"]},
    {"id": "arxiv-rag-2024", "category": "research", "severity": "info",
     "title": "RAG-Augmented Security Analysis: Surveying the Landscape (arXiv 2024)",
     "title_ar": "تحليل الأمن المعزز بـ RAG: مسح الأفق (arXiv 2024)",
     "source": "arXiv", "source_url": "https://arxiv.org",
     "epss": None, "kev": False,
     "published": "2024-06-15", "tags": ["ai", "rag", "survey"]},
    # Tools
    {"id": "tool-nuclei", "category": "tools", "severity": "info",
     "title": "Nuclei v3.2 — Fast Vulnerability Scanner (ProjectDiscovery)",
     "title_ar": "Nuclei v3.2 — فاحص ثغرات سريع",
     "source": "ProjectDiscovery", "source_url": "https://github.com/projectdiscovery/nuclei",
     "epss": None, "kev": False,
     "published": "2024-03-01", "tags": ["scanner", "nuclei", "open_source"]},
    {"id": "tool-semgrep", "category": "tools", "severity": "info",
     "title": "Semgrep 1.60 — Static Analysis for 30+ Languages",
     "title_ar": "Semgrep 1.60 — تحليل ثابت لـ 30+ لغة برمجية",
     "source": "Semgrep Inc", "source_url": "https://semgrep.dev",
     "epss": None, "kev": False,
     "published": "2024-04-20", "tags": ["sast", "semgrep", "open_source"]},
    # Regulations
    {"id": "reg-nist-csf2", "category": "regulations", "severity": "info",
     "title": "NIST Cybersecurity Framework 2.0 — Released Feb 2024",
     "title_ar": "إطار الأمن السيبراني NIST 2.0 — فبراير 2024",
     "source": "NIST", "source_url": "https://www.nist.gov/cyberframework",
     "epss": None, "kev": False,
     "published": "2024-02-26", "tags": ["nist", "framework", "csf"]},
    {"id": "reg-nis2", "category": "regulations", "severity": "info",
     "title": "EU NIS2 Directive — Effective October 2024",
     "title_ar": "توجيه NIS2 الأوروبي — نافذ أكتوبر 2024",
     "source": "EUR-Lex", "source_url": "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32022L2555",
     "epss": None, "kev": False,
     "published": "2024-10-01", "tags": ["eu", "nis2", "compliance"]},
    # Conferences
    {"id": "conf-defcon32", "category": "conferences", "severity": "info",
     "title": "DEF CON 32 — Las Vegas, Aug 8-11, 2024",
     "title_ar": "DEF CON 32 — لاس فيغاس، أغسطس 2024",
     "source": "DEF CON", "source_url": "https://defcon.org",
     "epss": None, "kev": False,
     "published": "2024-08-08", "tags": ["conference", "defcon", "hacking"]},
    {"id": "conf-blackhat24", "category": "conferences", "severity": "info",
     "title": "Black Hat USA 2024 — Las Vegas, Aug 3-8, 2024",
     "title_ar": "Black Hat USA 2024 — لاس فيغاس، أغسطس 2024",
     "source": "Black Hat", "source_url": "https://www.blackhat.com",
     "epss": None, "kev": False,
     "published": "2024-08-03", "tags": ["conference", "blackhat"]},
    # Incidents
    {"id": "inc-crowdstrike-2024", "category": "incidents", "severity": "critical",
     "title": "CrowdStrike Falcon Sensor Update BSOD Outage — July 2024",
     "title_ar": "انقطاع CrowdStrike العالمي بسبب تحديث خاطئ — يوليو 2024",
     "source": "CrowdStrike", "source_url": "https://www.crowdstrike.com",
     "epss": None, "kev": False,
     "published": "2024-07-19", "tags": ["incident", "crowdstrike", "outage"]},
    {"id": "inc-xz-utils-2024", "category": "incidents", "severity": "critical",
     "title": "XZ Utils Supply Chain Backdoor (CVE-2024-3094) — March 2024",
     "title_ar": "باب خلفي في سلسلة التوريد XZ Utils — مارس 2024",
     "source": "Red Hat", "source_url": "https://access.redhat.com/security/cve/CVE-2024-3094",
     "epss": 0.92, "kev": False,
     "published": "2024-03-29", "tags": ["supply_chain", "backdoor", "linux"]},
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@intelligence_bp.route("/feeds", methods=["GET"])
@login_required
def get_feeds():
    """GET /api/intelligence/feeds -- taxonomy of all feed categories."""
    return jsonify({"ok": True, "feeds": FEED_CATEGORIES})


@intelligence_bp.route("/recent", methods=["GET"])
@login_required
def get_recent():
    """GET /api/intelligence/recent?category=<id>&limit=<n> -- recent intelligence items."""
    category = request.args.get("category", "").strip()
    try:
        limit = min(int(request.args.get("limit", 50)), 100)
    except ValueError:
        limit = 50

    items = _STATIC_ITEMS
    if category:
        items = [i for i in items if i["category"] == category]

    items = sorted(items, key=lambda x: (SEVERITY_ORDER.get(x["severity"], 99), x["published"]))
    return jsonify({
        "ok": True,
        "count": len(items[:limit]),
        "items": items[:limit],
        "meta": {
            "source_note": "Static representative dataset. Live aggregation via NVD/CISA/arXiv requires API key configuration.",
            "last_updated": datetime.date.today().isoformat(),
        }
    })


@intelligence_bp.route("/search", methods=["GET"])
@login_required
def search_intel():
    """GET /api/intelligence/search?q=<query> -- keyword search across all items."""
    q = request.args.get("q", "").strip().lower()
    if not q or len(q) < 2:
        return jsonify({"ok": False, "error": "Query must be at least 2 characters."}), 400
    results = [
        i for i in _STATIC_ITEMS
        if q in i["title"].lower()
        or any(q in tag for tag in i.get("tags", []))
        or q in i.get("source", "").lower()
    ]
    return jsonify({"ok": True, "count": len(results), "query": q, "items": results})


@intelligence_bp.route("/stats", methods=["GET"])
@login_required
def intel_stats():
    """GET /api/intelligence/stats -- summary stats for the intelligence dashboard."""
    from collections import Counter
    cat_counts = Counter(i["category"] for i in _STATIC_ITEMS)
    sev_counts = Counter(i["severity"] for i in _STATIC_ITEMS)
    kev_count  = sum(1 for i in _STATIC_ITEMS if i.get("kev"))
    return jsonify({"ok": True, "stats": {
        "total_items": len(_STATIC_ITEMS),
        "by_category": dict(cat_counts),
        "by_severity": dict(sev_counts),
        "kev_items": kev_count,
        "categories": len(FEED_CATEGORIES),
    }})
