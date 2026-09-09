"""SecuraX — reports blueprint.

Handles:
  - HTML views: /, /dashboard, /report/<token>, /download-fixed/<token>
  - Report downloads: PDF, CSV, Markdown, JSON
  - JSON API: /api/dashboard, /api/reports, /api/reports/<token>
"""

import csv
import io
import json
import logging

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required

import hashlib

from database import (
    PLANS,
    delete_report,
    get_all_dashboard_stats,
    get_all_reports,
    get_dashboard_stats,
    get_or_create_share_token,
    get_report,
    get_report_by_share_token,
    get_subscription,
    get_user_reports,
    log_event,
    set_subscription,
    store_report,
    update_vulnerability_triage,
    get_shadow_tasks_for_report,
    complete_shadow_task,
    get_user_shadow_backlog,
)
from extensions import limiter
from forms import ScanForm
from report_generator import (
    build_network_recon,
    count_severities,
    executive_summary,
    generate_csv_rows,
    generate_markdown_report,
    normalize_api_report,
    risk_level_from_score,
    strip_md_for_pdf,
)
from scanners.server_int import generate_fixed_config
from utils import _UUID_RE

logger = logging.getLogger(__name__)

reports_bp = Blueprint("reports", __name__)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _rtl_text(text: str) -> str:
    """Apply Arabic reshaping + bidi reorder if libraries are available."""
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display
        return get_display(arabic_reshaper.reshape(text))
    except Exception:
        return text


def _get_report_for_download(token=None) -> dict:
    """Load report by token or fall back to user's most recent scan."""
    if token and _UUID_RE.match(token):
        return get_report(token)
    rows = get_user_reports(current_user.id, limit=1)
    if not rows:
        return None
    return get_report(rows[0]["token"])


def _authorize_report(data: dict) -> tuple:
    if not data:
        return False, (jsonify({"error": "No report found. Run a scan first."}), 404)
    if data.get("user_id") != current_user.id and current_user.role != "admin":
        return False, (jsonify({"error": "Access denied."}), 403)
    return True, None


# ════════════════════════════════════════════════════════════════════════════
#  HTML ROUTES
# ════════════════════════════════════════════════════════════════════════════

@reports_bp.route("/")
@login_required
def home():
    form = ScanForm()
    return render_template("index.html", form=form, user=current_user.username)


@reports_bp.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "admin":
        stats   = get_all_dashboard_stats()
        reps    = get_all_reports(limit=20)
    else:
        stats   = get_dashboard_stats(current_user.id)
        reps    = get_user_reports(current_user.id, limit=20)
    return render_template(
        "dashboard.html",
        stats=stats, reports=reps, user=current_user.username,
    )


@reports_bp.route("/report/<token>")
@login_required
@limiter.limit("30/minute")
def view_report(token: str):
    if not _UUID_RE.match(token):
        return jsonify({"error": "Invalid report token."}), 400

    data = get_report(token)
    if not data:
        return jsonify({"error": "Report not found or has expired."}), 404

    if data.get("user_id") != current_user.id and current_user.role != "admin":
        log_event("idor_attempt", current_user.username, current_user.id,
                  category="security", resource=f"/report/{token}",
                  ip_address=request.remote_addr, status="blocked")
        return jsonify({"error": "Access denied."}), 403

    return render_template(
        "report.html",
        result     = data["result"],
        risk_score = data["risk_score"],
        stored_at  = data["stored_at"],
        has_fix    = bool(data.get("original_content")),
        token      = token,
        user       = current_user.username,
        recon      = build_network_recon(data["result"])
            if str(data["result"].get("scan_type", "")).startswith("network") else None,
        executive  = executive_summary(data),
        risk_breakdown = (data["result"].get("risk_breakdown") or {}),
    )


@reports_bp.route("/download-fixed/<token>")
@login_required
@limiter.limit("10/minute")
def download_fixed(token: str):
    if not _UUID_RE.match(token):
        return jsonify({"error": "Invalid report token."}), 400

    data = get_report(token)
    if not data:
        return jsonify({"error": "Report not found."}), 404
    if data.get("user_id") != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Access denied."}), 403

    original = data.get("original_content")
    if not original:
        return jsonify({"error": "No configuration file stored for this scan."}), 400

    vulns         = data["result"].get("vulnerabilities", [])
    fixed_content, change_log = generate_fixed_config(original, vulns)

    return Response(
        fixed_content.encode("utf-8"),
        mimetype="text/plain; charset=utf-8",
        headers={
            "Content-Disposition": 'attachment; filename="httpd_securax_fixed.conf"',
            "X-Changes-Count":     str(len(change_log)),
        },
    )


# ════════════════════════════════════════════════════════════════════════════
#  REPORT DOWNLOAD ENDPOINTS (PDF / CSV / MD / JSON)
# ════════════════════════════════════════════════════════════════════════════

@reports_bp.route("/download_report")
@login_required
@limiter.limit("10/minute")
def download_report_pdf():
    """Download report as a professional PDF."""
    token = request.args.get("token", "").strip()
    lang  = request.args.get("lang", "en").strip().lower()
    data  = _get_report_for_download(token)
    ok, err = _authorize_report(data)
    if not ok:
        return err

    result = data.get("result") or {}
    if isinstance(result, str):
        result = json.loads(result)
    report_row = {**data, "result": result, "username": data.get("username", current_user.username)}
    vulns      = result.get("vulnerabilities", [])
    target     = result.get("target", "unknown")
    score      = float(data.get("risk_score") or 0)
    arabic     = lang == "ar"
    rb         = result.get("risk_breakdown") or {}
    stored_at  = str(data.get("stored_at", ""))
    username   = data.get("username", current_user.username)
    report_id  = data.get("token", "")
    scan_type  = str(result.get("scan_type", ""))
    sev_counts = count_severities(vulns)
    risk_level = rb.get("risk_level") or risk_level_from_score(score)

    _SCAN_LABELS = {
        "network_ext": "NETWORK EXT", "network_int": "NETWORK INT",
        "web": "WEB APP", "server_ext": "SERVER EXT",
        "server_int": "SERVER INT", "apache": "APACHE CONFIG",
        "sast": "SAST", "dast": "DAST", "dep": "DEPENDENCIES",
        "dependencies": "DEPENDENCIES",
    }
    scan_type_label = _SCAN_LABELS.get(scan_type, scan_type.upper().replace("_", " "))

    def _cve_ids(v: dict) -> list:
        raw = v.get("cve_ids") or v.get("cves") or []
        if isinstance(raw, str):
            return [c.strip() for c in raw.split(",") if c.strip()]
        return [str(c).strip() for c in raw if str(c).strip()]

    try:
        import os as _os

        from reportlab.lib import colors as rl_colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import (
            HRFlowable,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        _F  = "Helvetica"
        _FB = "Helvetica-Bold"
        _FONT_CANDIDATES = [
            ("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf", "_SecNorm", "_SecBold"),
            # FreeSans: installed via fonts-freefont-ttf — best Arabic glyph coverage on Debian
            ("/usr/share/fonts/truetype/freefont/FreeSans.ttf",
             "/usr/share/fonts/truetype/freefont/FreeSansBold.ttf", "_SecNorm", "_SecBold"),
            ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
             "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", "_SecNorm", "_SecBold"),
            ("/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
             "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf", "_SecNorm", "_SecBold"),
        ]
        for _fp, _fbp, _fn, _fbn in _FONT_CANDIDATES:
            if _os.path.exists(_fp):
                try:
                    pdfmetrics.registerFont(TTFont(_fn, _fp))
                    _F = _fn
                    if _os.path.exists(_fbp):
                        pdfmetrics.registerFont(TTFont(_fbn, _fbp))
                        pdfmetrics.registerFontFamily(_fn, normal=_fn, bold=_fbn)
                        _FB = _fbn
                    else:
                        _FB = _fn
                except Exception:
                    pass
                break

        PAGE_W, PAGE_H = A4
        L_MAR = R_MAR = 1.5 * cm
        CONTENT_W = PAGE_W - L_MAR - R_MAR

        C_NAVY   = rl_colors.HexColor("#1a2535")
        C_BORDER = rl_colors.HexColor("#dee2e6")
        C_LIGHT  = rl_colors.HexColor("#f8f9fa")
        C_MUTED  = rl_colors.HexColor("#888888")
        C_SEV = {
            "critical": rl_colors.HexColor("#c0392b"),
            "high":     rl_colors.HexColor("#6b7280"),
            "medium":   rl_colors.HexColor("#d4a017"),
            "low":      rl_colors.HexColor("#27ae60"),
            "info":     rl_colors.HexColor("#2980b9"),
        }
        risk_color = C_SEV.get(risk_level.lower(), C_SEV["critical"])

        def _page_chrome(canv, doc):
            canv.saveState()
            canv.setFillColor(C_NAVY)
            canv.rect(0, PAGE_H - 1.1 * cm, PAGE_W, 1.1 * cm, fill=True, stroke=False)
            canv.setFillColor(rl_colors.white)
            canv.setFont(_FB, 8)
            canv.drawString(L_MAR, PAGE_H - 0.72 * cm, "SECURAX Security Platform")
            canv.setFont(_F, 8)
            canv.drawRightString(PAGE_W - R_MAR, PAGE_H - 0.72 * cm,
                                 f"CONFIDENTIAL  ·  Target: {target}")
            canv.setFillColor(C_MUTED)
            canv.setFont(_F, 7)
            canv.drawString(L_MAR, 0.65 * cm, f"Generated: {stored_at}  ·  User: {username}")
            canv.drawRightString(PAGE_W - R_MAR, 0.65 * cm, f"Page {doc.page}")
            canv.line(L_MAR, 1.0 * cm, PAGE_W - R_MAR, 1.0 * cm)
            canv.restoreState()

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            leftMargin=L_MAR, rightMargin=R_MAR,
            topMargin=1.6 * cm, bottomMargin=1.6 * cm,
        )
        styles = getSampleStyleSheet()

        def _ps(name, **kw):
            kw.setdefault("fontName", _F)
            return ParagraphStyle(name, parent=styles["Normal"], **kw)

        def _needs_rtl(text: str) -> bool:
            import unicodedata
            return any(unicodedata.bidirectional(c) in ("R", "AL", "AN") for c in text)

        def _safe(text: str) -> str:
            s = strip_md_for_pdf(str(text))
            s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            if arabic or _needs_rtl(s):
                s = _rtl_text(s)
            return s

        def _p(text, style):
            return Paragraph(_safe(text), style)

        _ps("body",  fontSize=9,  leading=13)
        _ps("small", fontSize=7,  leading=10, textColor=C_MUTED)
        lbl   = _ps("lbl",   fontSize=8,  fontName=_FB, textColor=C_MUTED)
        val   = _ps("val",   fontSize=9,  fontName=_FB, textColor=C_NAVY)
        rval  = _ps("rval",  fontSize=9,  fontName=_FB, textColor=risk_color)
        row_v = _ps("rowv",  fontSize=8,  leading=12,   textColor=C_NAVY)
        row_l = _ps("rowl",  fontSize=8,  fontName=_FB, textColor=C_MUTED)

        story = []

        title_s = _ps("ts", fontSize=20, fontName=_FB, leading=26,
                      textColor=C_NAVY, alignment=TA_CENTER, spaceAfter=4)
        story.append(Spacer(1, 0.4 * cm))
        story.append(Paragraph(
            "تقرير تقييم الثغرات الأمنية" if arabic else "Vulnerability Assessment Report",
            title_s,
        ))
        story.append(Spacer(1, 0.3 * cm))

        CL = 2.8 * cm
        CV = CONTENT_W / 2 - CL

        def _lp(t): return Paragraph(t.upper(), lbl)
        def _vp(t): return Paragraph(str(t), val)
        def _rv(t): return Paragraph(str(t), rval)

        rid_display = (report_id[:32] + "\n" + report_id[32:]) if len(report_id) > 32 else report_id
        sum_data = [
            [_lp("Target"),        _vp(target),               _lp("Scan Type"), _vp(scan_type_label)],
            [_lp("Risk Score"),    _vp(f"{score:.1f} / 10"),  _lp("Risk Level"), _rv(risk_level.upper())],
            [_lp("Total Findings"), _vp(str(len(vulns))),     _lp("Generated"), _vp(stored_at[:19])],
            [_lp("Analyst"),       _vp(username),             _lp("Report ID"), _vp(rid_display)],
        ]
        sum_tbl = Table(sum_data, colWidths=[CL, CV, CL, CV])
        sum_tbl.setStyle(TableStyle([
            ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
            ("INNERGRID",     (0, 0), (-1, -1), 0.5, C_BORDER),
            ("BACKGROUND",    (0, 0), (-1, -1), rl_colors.white),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING",   (0, 0), (-1, -1), 7),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 7),
        ]))
        story.append(sum_tbl)
        story.append(Spacer(1, 0.3 * cm))

        rs_bar = Table(
            [[_p(f"Risk Score: {score:.1f}/10",
                 _ps("rsb", fontSize=11, fontName="Helvetica-Bold", textColor=C_NAVY)),
              _p(risk_level.upper(),
                 _ps("rlb", fontSize=11, fontName="Helvetica-Bold",
                     textColor=risk_color, alignment=TA_RIGHT))]],
            colWidths=[CONTENT_W * 0.65, CONTENT_W * 0.35],
        )
        rs_bar.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), C_LIGHT),
            ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
            ("LEFTPADDING",   (0, 0), (-1, -1), 8),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 8),
        ]))
        story.append(rs_bar)
        story.append(Spacer(1, 0.35 * cm))

        # ── Executive Summary ──────────────────────────────────────────────────
        exec_sum = executive_summary(report_row, lang="ar" if arabic else "en")
        if exec_sum:
            story.append(Paragraph(
                "ملخص تنفيذي" if arabic else "Executive Summary",
                _ps("exh", fontSize=11, fontName="Helvetica-Bold",
                    textColor=C_NAVY, spaceAfter=3),
            ))
            exec_tbl = Table(
                [[_p(exec_sum, _ps("exb", fontSize=8.5, leading=13, textColor=C_NAVY))]],
                colWidths=[CONTENT_W],
            )
            exec_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (-1, -1), rl_colors.HexColor("#eef4fb")),
                ("BOX",           (0, 0), (-1, -1), 0.5, rl_colors.HexColor("#b6cfe8")),
                ("LEFTPADDING",   (0, 0), (-1, -1), 10),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 10),
                ("TOPPADDING",    (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.append(exec_tbl)
            story.append(Spacer(1, 0.35 * cm))

        # ── Risk Breakdown ────────────────────────────────────────────────────
        if rb.get("base_score") is not None:
            rb_data = [
                [_lp("Base Score"),     _vp(f"{rb.get('base_score',0):.1f}"),
                 _lp("Temporal Score"), _vp(f"{rb.get('temporal_score',0):.1f}")],
                [_lp("Env Score"),      _vp(f"{rb.get('env_score',0):.1f}"),
                 _lp("Confidence"),     _vp(str(rb.get('confidence','—')))],
            ]
            rb_tbl = Table(rb_data, colWidths=[CL, CV, CL, CV])
            rb_tbl.setStyle(TableStyle([
                ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
                ("INNERGRID",     (0, 0), (-1, -1), 0.4, C_BORDER),
                ("BACKGROUND",    (0, 0), (-1, -1), C_LIGHT),
                ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 7),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 7),
            ]))
            story.append(Paragraph(
                "تحليل المخاطر التفصيلي" if arabic else "Risk Score Breakdown",
                _ps("rbh", fontSize=10, fontName="Helvetica-Bold", textColor=C_NAVY, spaceAfter=3),
            ))
            story.append(rb_tbl)
            story.append(Spacer(1, 0.35 * cm))

        story.append(HRFlowable(width="100%", thickness=0.4, color=C_BORDER))
        story.append(Spacer(1, 0.3 * cm))

        story.append(Paragraph(
            "ملخص الخطورة" if arabic else "Severity Summary",
            _ps("sevh", fontSize=12, fontName="Helvetica-Bold",
                textColor=C_NAVY, alignment=TA_RIGHT, spaceAfter=4),
        ))

        sev_order = ("critical", "high", "medium", "low", "info")
        num_row = []
        lab_row = []
        for sv in sev_order:
            num_row.append(Paragraph(
                str(sev_counts.get(sv, 0)),
                _ps(f"sn{sv}", fontSize=22, fontName="Helvetica-Bold",
                    textColor=rl_colors.white, alignment=TA_CENTER),
            ))
            lab_row.append(Paragraph(
                sv.upper(),
                _ps(f"sl{sv}", fontSize=9, fontName="Helvetica-Bold",
                    textColor=C_SEV[sv], alignment=TA_CENTER),
            ))

        sev_tbl = Table([num_row, lab_row], colWidths=[CONTENT_W / 5] * 5)
        sev_styles = [
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
            ("LINEAFTER",     (0, 0), (3, 1),   0.5, C_BORDER),
            ("TOPPADDING",    (0, 0), (-1, 0),  10),
            ("BOTTOMPADDING", (0, 0), (-1, 0),  10),
            ("TOPPADDING",    (0, 1), (-1, 1),  5),
            ("BOTTOMPADDING", (0, 1), (-1, 1),  8),
            ("BACKGROUND",    (0, 1), (-1, 1),  rl_colors.white),
        ]
        for idx, sv in enumerate(sev_order):
            sev_styles.append(("BACKGROUND", (idx, 0), (idx, 0), C_SEV[sv]))
        sev_tbl.setStyle(TableStyle(sev_styles))
        story.append(sev_tbl)
        story.append(Spacer(1, 0.5 * cm))

        # ── Network Recon Section ─────────────────────────────────────────────
        if scan_type.startswith("network"):
            recon = build_network_recon(result)
            story.append(Paragraph(
                "استطلاع الشبكة" if arabic else "Network Reconnaissance Summary",
                _ps("rech", fontSize=12, fontName="Helvetica-Bold", textColor=C_NAVY, spaceAfter=4),
            ))
            recon_meta = [
                [_lp("Target IP"),   _vp(recon.get("ip","—")),
                 _lp("OS"),          _vp(recon.get("os","—"))],
                [_lp("Hosts Up"),    _vp(f"{recon.get('hosts_up','?')} / {recon.get('total_hosts','?')}"),
                 _lp("Open Ports"),  _vp(str(recon.get("open_ports",0)))],
                [_lp("Subdomains"),  _vp(str(recon.get("subdomain_count",0))),
                 _lp("Tools Used"),  _vp(", ".join(recon.get("tools_used",[]) or ["—"]))],
            ]
            if recon.get("scan_time"):
                recon_meta.append([_lp("Scan Time"), _vp(str(recon["scan_time"])),
                                   _lp("Shodan CVEs"), _vp(str(recon.get("shodan_cve_count",0)))])
            rm_tbl = Table(recon_meta, colWidths=[CL, CV, CL, CV])
            rm_tbl.setStyle(TableStyle([
                ("BOX",           (0,0),(-1,-1), 0.5, C_BORDER),
                ("INNERGRID",     (0,0),(-1,-1), 0.4, C_BORDER),
                ("BACKGROUND",    (0,0),(-1,-1), C_LIGHT),
                ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
                ("TOPPADDING",    (0,0),(-1,-1), 5),
                ("BOTTOMPADDING", (0,0),(-1,-1), 5),
                ("LEFTPADDING",   (0,0),(-1,-1), 7),
                ("RIGHTPADDING",  (0,0),(-1,-1), 7),
            ]))
            story.append(rm_tbl)

            open_ports = recon.get("open_port_list", [])
            if open_ports:
                story.append(Spacer(1, 0.25 * cm))
                story.append(Paragraph(
                    "المنافذ المفتوحة" if arabic else "Open Ports",
                    _ps("oph", fontSize=10, fontName="Helvetica-Bold", textColor=C_NAVY, spaceAfter=3),
                ))
                pt_hdr = [
                    Paragraph("ENDPOINT", _ps("ph", fontSize=8, fontName="Helvetica-Bold", textColor=C_MUTED)),
                    Paragraph("SERVICE",  _ps("ph2", fontSize=8, fontName="Helvetica-Bold", textColor=C_MUTED)),
                    Paragraph("VERSION",  _ps("ph3", fontSize=8, fontName="Helvetica-Bold", textColor=C_MUTED)),
                    Paragraph("SEVERITY", _ps("ph4", fontSize=8, fontName="Helvetica-Bold", textColor=C_MUTED)),
                ]
                pt_rows = [pt_hdr]
                for p in open_ports[:30]:
                    sv = (p.get("severity") or "info").lower()
                    pt_rows.append([
                        Paragraph(f"{p.get('host','')}:{p.get('port','')}/{p.get('protocol','tcp')}", row_v),
                        Paragraph(p.get("service","—"), row_v),
                        Paragraph(p.get("version","—") or "—", row_v),
                        Paragraph(sv.upper(), _ps(f"ptl{sv}", fontSize=8, fontName="Helvetica-Bold",
                                                  textColor=C_SEV.get(sv, C_SEV["info"]))),
                    ])
                pt_tbl_styles = [
                    ("BACKGROUND",    (0,0),(-1,0),  C_NAVY),
                    ("TEXTCOLOR",     (0,0),(-1,0),  rl_colors.white),
                    ("BOX",           (0,0),(-1,-1), 0.5, C_BORDER),
                    ("INNERGRID",     (0,0),(-1,-1), 0.3, C_BORDER),
                    ("TOPPADDING",    (0,0),(-1,-1), 4),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 4),
                    ("LEFTPADDING",   (0,0),(-1,-1), 5),
                    ("RIGHTPADDING",  (0,0),(-1,-1), 5),
                ]
                for _ri in range(1, len(pt_rows)):
                    _bg = C_LIGHT if _ri % 2 == 0 else rl_colors.white
                    pt_tbl_styles.append(("BACKGROUND", (0,_ri),(-1,_ri), _bg))
                pt_tbl = Table(pt_rows, colWidths=[CONTENT_W*0.38, CONTENT_W*0.2, CONTENT_W*0.28, CONTENT_W*0.14])
                pt_tbl.setStyle(TableStyle(pt_tbl_styles))
                story.append(pt_tbl)

            if recon.get("subdomains"):
                story.append(Spacer(1, 0.2 * cm))
                story.append(Paragraph(
                    "نطاقات فرعية مكتشفة" if arabic else "Discovered Subdomains (sample)",
                    _ps("sdh", fontSize=10, fontName="Helvetica-Bold", textColor=C_NAVY, spaceAfter=2),
                ))
                sd_text = "  ·  ".join(recon["subdomains"][:20])
                story.append(Paragraph(_safe(sd_text), _ps("sdb", fontSize=7.5, textColor=C_MUTED, leading=11)))

            story.append(Spacer(1, 0.4 * cm))
            story.append(HRFlowable(width="100%", thickness=0.4, color=C_BORDER))
            story.append(Spacer(1, 0.3 * cm))

        # ── Attack Chains ────────────────────────────────────────────────────
        chains = rb.get("attack_chains") or []
        if chains:
            story.append(Paragraph(
                "سلاسل الهجوم المحتملة" if arabic else "Potential Attack Chains",
                _ps("ach", fontSize=11, fontName="Helvetica-Bold", textColor=C_NAVY, spaceAfter=4),
            ))
            for ci, ch in enumerate(chains, 1):
                ch_tbl = Table(
                    [[Paragraph(f"{ci}", _ps(f"cn{ci}", fontSize=10, fontName="Helvetica-Bold",
                                            textColor=rl_colors.white, alignment=TA_CENTER)),
                      Paragraph(_safe(str(ch)), _ps(f"cv{ci}", fontSize=8.5, leading=12))]],
                    colWidths=[0.65*cm, CONTENT_W - 0.65*cm],
                )
                ch_tbl.setStyle(TableStyle([
                    ("BACKGROUND",    (0,0),(0,0),  rl_colors.HexColor("#c0392b")),
                    ("BACKGROUND",    (1,0),(1,0),  rl_colors.HexColor("#fff5f5")),
                    ("BOX",           (0,0),(-1,-1), 0.5, C_BORDER),
                    ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
                    ("TOPPADDING",    (0,0),(-1,-1), 6),
                    ("BOTTOMPADDING", (0,0),(-1,-1), 6),
                    ("LEFTPADDING",   (0,0),(-1,-1), 6),
                    ("RIGHTPADDING",  (0,0),(-1,-1), 6),
                ]))
                story.append(ch_tbl)
                story.append(Spacer(1, 0.1 * cm))
            story.append(Spacer(1, 0.3 * cm))
            story.append(HRFlowable(width="100%", thickness=0.4, color=C_BORDER))
            story.append(Spacer(1, 0.3 * cm))

        story.append(Paragraph(
            "نتائج الثغرات" if arabic else "Vulnerability Findings",
            _ps("fndh", fontSize=12, fontName="Helvetica-Bold",
                textColor=C_NAVY, alignment=TA_RIGHT, spaceAfter=6),
        ))

        BADGE_W = 1.6 * cm
        DATA_W  = CONTENT_W - BADGE_W

        for i, v in enumerate(vulns, 1):
            sev      = (v.get("severity") or "info").lower()
            vtitle   = v.get("title") or v.get("check") or "Finding"
            desc     = v.get("description") or ""
            evidence = v.get("evidence") or ""
            rem      = v.get("remediation") or v.get("recommendation") or ""
            cves     = _cve_ids(v)
            host     = v.get("host", "")
            port     = v.get("port")
            service  = v.get("service", "")
            color    = C_SEV.get(sev, C_SEV["info"])

            cve_str   = ", ".join(cves)
            first_cve = cves[0] if cves else ""
            hdr_title = f"#{i}"
            if first_cve:
                hdr_title += f" CVE {first_cve}"
            hdr_title += f" — {vtitle}"

            net_parts = []
            if host:
                net_parts.append(f"Host: {host}")
            if port:
                net_parts.append(f"Port: {port}")
            if service:
                net_parts.append(f"Service: {service}")
            net_str = "  ".join(net_parts)

            badge_s = _ps("badge", fontSize=8, fontName="Helvetica-Bold",
                          textColor=rl_colors.white, alignment=TA_CENTER)
            hdr_s   = _ps("hdrs",  fontSize=9, fontName="Helvetica-Bold", textColor=C_NAVY)

            rows = [[Paragraph(sev.upper(), badge_s), Paragraph(_safe(hdr_title), hdr_s)]]
            if desc:
                rows.append([Paragraph("DESCRIPTION", row_l), Paragraph(_safe(desc), row_v)])
            if evidence:
                rows.append([Paragraph("EVIDENCE", row_l), Paragraph(_safe(evidence), row_v)])
            if net_str:
                rows.append([Paragraph("NETWORK", row_l), Paragraph(_safe(net_str), row_v)])
            if cves:
                rows.append([Paragraph("CVE IDs", row_l),
                              Paragraph(cve_str,
                                        ParagraphStyle("cv2", parent=styles["Normal"],
                                                       fontSize=8, fontName="Helvetica-Bold",
                                                       textColor=color))])
            if rem:
                rows.append([Paragraph("REMEDIATION", row_l), Paragraph(_safe(rem), row_v)])
            owasp = v.get("owasp") or ""
            cwe   = v.get("cwe")   or ""
            cvss  = v.get("cvss_score") or v.get("cvss") or ""
            if owasp:
                rows.append([Paragraph("OWASP", row_l), Paragraph(_safe(str(owasp)), row_v)])
            if cwe:
                rows.append([Paragraph("CWE", row_l), Paragraph(_safe(str(cwe)), row_v)])
            if cvss:
                rows.append([Paragraph("CVSS", row_l),
                              Paragraph(str(cvss),
                                        _ps("cvs", fontSize=8, fontName="Helvetica-Bold",
                                            textColor=color))])
            if cves:
                nvd_urls = "  |  ".join(
                    f"nvd.nist.gov/vuln/detail/{c}" for c in cves[:4]
                )
                rows.append([Paragraph("NVD REFS", row_l),
                              Paragraph(_safe(nvd_urls),
                                        _ps("nvd", fontSize=7.5, textColor=rl_colors.HexColor("#1a6db5"), leading=11))])

            ftbl = Table(rows, colWidths=[BADGE_W, DATA_W])
            ftbl.setStyle(TableStyle([
                ("BACKGROUND",    (0, 0), (0, 0),  color),
                ("BACKGROUND",    (1, 0), (1, 0),  C_LIGHT),
                ("BACKGROUND",    (0, 1), (-1, -1), rl_colors.white),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("ALIGN",         (0, 0), (0, 0),  "CENTER"),
                ("VALIGN",        (0, 0), (0, 0),  "MIDDLE"),
                ("BOX",           (0, 0), (-1, -1), 0.5, C_BORDER),
                ("INNERGRID",     (0, 1), (-1, -1), 0.3, C_BORDER),
                ("LINEBELOW",     (0, 0), (-1, 0),  0.8, C_BORDER),
                ("TOPPADDING",    (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING",   (0, 0), (-1, -1), 6),
                ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
            ]))
            story.append(ftbl)
            story.append(Spacer(1, 0.2 * cm))

        # ── Recommendations ───────────────────────────────────────────────────
        recs = rb.get("recommendations") or []
        if recs:
            story.append(Spacer(1, 0.4 * cm))
            story.append(HRFlowable(width="100%", thickness=0.4, color=C_BORDER))
            story.append(Spacer(1, 0.3 * cm))
            story.append(Paragraph(
                "التوصيات الأمنية" if arabic else "Security Recommendations",
                _ps("rech2", fontSize=12, fontName="Helvetica-Bold", textColor=C_NAVY, spaceAfter=6),
            ))
            rec_rows = []
            for ri, rec in enumerate(recs, 1):
                rec_rows.append([
                    Paragraph(str(ri),
                              _ps(f"ri{ri}", fontSize=9, fontName="Helvetica-Bold",
                                  textColor=C_NAVY, alignment=TA_CENTER)),
                    Paragraph(_safe(str(rec)),
                              _ps(f"rv{ri}", fontSize=8.5, leading=12)),
                ])
            rec_tbl_styles = [
                ("BACKGROUND",    (0,0),(0,-1), rl_colors.HexColor("#e8f4fd")),
                ("BOX",           (0,0),(-1,-1), 0.5, C_BORDER),
                ("INNERGRID",     (0,0),(-1,-1), 0.3, C_BORDER),
                ("VALIGN",        (0,0),(-1,-1), "TOP"),
                ("ALIGN",         (0,0),(0,-1),  "CENTER"),
                ("TOPPADDING",    (0,0),(-1,-1), 5),
                ("BOTTOMPADDING", (0,0),(-1,-1), 5),
                ("LEFTPADDING",   (0,0),(-1,-1), 6),
            ]
            for _ri in range(len(rec_rows)):
                _bg = C_LIGHT if _ri % 2 == 0 else rl_colors.white
                rec_tbl_styles.append(("BACKGROUND", (1,_ri),(1,_ri), _bg))
            rec_tbl = Table(rec_rows, colWidths=[0.7*cm, CONTENT_W - 0.7*cm])
            rec_tbl.setStyle(TableStyle(rec_tbl_styles))
            story.append(rec_tbl)

        # ── CISA KEV Findings ─────────────────────────────────────────────────
        kev = rb.get("cisa_kev_findings") or []
        if kev:
            story.append(Spacer(1, 0.35 * cm))
            story.append(Paragraph(
                "ثغرات CISA KEV المستغَلة فعلياً" if arabic else "CISA Known Exploited Vulnerabilities (KEV)",
                _ps("kevh", fontSize=11, fontName="Helvetica-Bold",
                    textColor=rl_colors.HexColor("#c0392b"), spaceAfter=4),
            ))
            kev_note = Table(
                [[Paragraph(
                    _safe("⚠  The following CVEs are listed in CISA's Known Exploited Vulnerabilities catalog "
                           "and MUST be prioritized for immediate patching."),
                    _ps("kevn", fontSize=8.5, leading=12, textColor=rl_colors.HexColor("#7b2200"))
                )]],
                colWidths=[CONTENT_W],
            )
            kev_note.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,-1), rl_colors.HexColor("#fff0ed")),
                ("BOX",           (0,0),(-1,-1), 0.8, rl_colors.HexColor("#c0392b")),
                ("LEFTPADDING",   (0,0),(-1,-1), 10),
                ("RIGHTPADDING",  (0,0),(-1,-1), 10),
                ("TOPPADDING",    (0,0),(-1,-1), 7),
                ("BOTTOMPADDING", (0,0),(-1,-1), 7),
            ]))
            story.append(kev_note)
            story.append(Spacer(1, 0.2 * cm))
            kev_rows = [[
                Paragraph("CVE ID",  _ps("kh1", fontSize=8, fontName="Helvetica-Bold", textColor=C_MUTED)),
                Paragraph("DETAILS", _ps("kh2", fontSize=8, fontName="Helvetica-Bold", textColor=C_MUTED)),
            ]]
            for k in kev[:20]:
                cve_id = k if isinstance(k, str) else k.get("cve_id","")
                detail = "" if isinstance(k, str) else k.get("description","")
                kev_rows.append([
                    Paragraph(cve_id, _ps("kci", fontSize=8, fontName="Helvetica-Bold",
                                          textColor=rl_colors.HexColor("#c0392b"))),
                    Paragraph(_safe(detail or f"nvd.nist.gov/vuln/detail/{cve_id}"),
                              _ps("kdt", fontSize=7.5, textColor=C_NAVY, leading=11)),
                ])
            kev_tbl = Table(kev_rows, colWidths=[CONTENT_W*0.28, CONTENT_W*0.72])
            kev_tbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0),(-1,0),  C_NAVY),
                ("BACKGROUND",    (0,1),(-1,-1), rl_colors.white),
                ("BOX",           (0,0),(-1,-1), 0.5, C_BORDER),
                ("INNERGRID",     (0,0),(-1,-1), 0.3, C_BORDER),
                ("TOPPADDING",    (0,0),(-1,-1), 4),
                ("BOTTOMPADDING", (0,0),(-1,-1), 4),
                ("LEFTPADDING",   (0,0),(-1,-1), 5),
                ("RIGHTPADDING",  (0,0),(-1,-1), 5),
            ]))
            story.append(kev_tbl)

        story.append(Spacer(1, 0.4 * cm))
        story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
        story.append(Spacer(1, 0.15 * cm))
        story.append(Paragraph(
            "This report is generated automatically by SECURAX Security Platform. "
            "All findings should be verified by a qualified security professional "
            "before remediation. Unauthorized disclosure is prohibited.",
            _ps("fn", fontSize=7, textColor=C_MUTED, alignment=TA_CENTER, leading=10),
        ))

        doc.build(story, onFirstPage=_page_chrome, onLaterPages=_page_chrome)
        pdf_bytes = buf.getvalue()
        fname = f"securax_report_{lang}.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    except ImportError:
        md = generate_markdown_report(report_row, lang=lang)
        return current_app.response_class(
            md,
            mimetype="text/markdown",
            headers={"Content-Disposition": "attachment; filename=vulnerability_report.md"},
        )


@reports_bp.route("/download_report_csv")
@login_required
@limiter.limit("10/minute")
def download_report_csv():
    token = request.args.get("token", "").strip()
    data  = _get_report_for_download(token)
    ok, err = _authorize_report(data)
    if not ok:
        return err
    buf = io.StringIO()
    w   = csv.writer(buf)
    for row in generate_csv_rows(data):
        w.writerow(row)
    return current_app.response_class(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings_summary.csv"},
    )


@reports_bp.route("/download_report_md")
@login_required
@limiter.limit("10/minute")
def download_report_md():
    token = request.args.get("token", "").strip()
    lang  = request.args.get("lang", "en").strip().lower()
    data  = _get_report_for_download(token)
    ok, err = _authorize_report(data)
    if not ok:
        return err
    md = generate_markdown_report(
        {**data, "username": data.get("username", current_user.username)},
        lang=lang,
    )
    return current_app.response_class(
        md,
        mimetype="text/markdown",
        headers={"Content-Disposition": "attachment; filename=vulnerability_report.md"},
    )


@reports_bp.route("/download_report_json")
@login_required
@limiter.limit("10/minute")
def download_report_json():
    token = request.args.get("token", "").strip()
    data  = _get_report_for_download(token)
    ok, err = _authorize_report(data)
    if not ok:
        return err
    payload = normalize_api_report({**data, "username": data.get("username", current_user.username)})
    return current_app.response_class(
        json.dumps(payload, indent=2, ensure_ascii=False),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=findings.json"},
    )


# ════════════════════════════════════════════════════════════════════════════
#  JSON API (consumed by React frontend)
# ════════════════════════════════════════════════════════════════════════════

@reports_bp.route("/api/dashboard")
@login_required
def api_dashboard():
    if current_user.role == "admin":
        stats   = get_all_dashboard_stats()
        reps    = get_all_reports(limit=20)
    else:
        stats   = get_dashboard_stats(current_user.id)
        reps    = get_user_reports(current_user.id, limit=20)

    reports_list = []
    for r in reps:
        reports_list.append({
            "token":          r.get("token"),
            "target":         r.get("target"),
            "scan_type":      r.get("scan_type"),
            "risk_score":     r.get("risk_score"),
            "vuln_count":     r.get("vuln_count", 0),
            "critical_count": r.get("critical_count", 0),
            "high_count":     r.get("high_count", 0),
            "medium_count":   r.get("medium_count", 0),
            "stored_at":      r.get("stored_at"),
            "username":       r.get("username"),
        })

    stats_dict = dict(stats) if stats else {}
    return jsonify({"stats": stats_dict, "reports": reports_list})


@reports_bp.route("/api/dashboard/shadow-backlog", methods=["GET"])
@login_required
def api_shadow_backlog():
    """Retrieve all pending shadow manual hunting tasks across all user reports."""
    backlog = get_user_shadow_backlog(current_user.id)
    return jsonify({"ok": True, "backlog": backlog, "count": len(backlog)})


@reports_bp.route("/api/reports/<token>/shadow", methods=["GET"])
@login_required
def api_report_shadow_tasks(token: str):
    """Retrieve pending/completed shadow manual tasks for a specific report."""
    if not _UUID_RE.match(token):
        return jsonify({"ok": False, "error": "Invalid report token format."}), 400
    report = get_report(token)
    if not report:
        return jsonify({"ok": False, "error": "Report not found."}), 404
    if current_user.role != "admin" and report.get("user_id") != current_user.id:
        return jsonify({"ok": False, "error": "Access denied."}), 403

    tasks = get_shadow_tasks_for_report(token)
    return jsonify({"ok": True, "token": token, "tasks": tasks})


@reports_bp.route("/api/reports/<token>/shadow/<vuln_type>/complete", methods=["POST"])
@login_required
def api_complete_shadow_task(token: str, vuln_type: str):
    """Mark a shadow manual task as completed (self-reported), updating the Skill Ledger."""
    if not _UUID_RE.match(token):
        return jsonify({"ok": False, "error": "Invalid report token format."}), 400
    report = get_report(token)
    if not report:
        return jsonify({"ok": False, "error": "Report not found."}), 404
    if current_user.role != "admin" and report.get("user_id") != current_user.id:
        return jsonify({"ok": False, "error": "Access denied."}), 403

    data = request.get_json(silent=True) or {}
    notes = str(data.get("notes", "")).strip()

    res = complete_shadow_task(
        report_token=token,
        vuln_type=vuln_type,
        user_id=current_user.id,
        notes=notes,
        verified=False,
    )
    return jsonify({
        "ok": True,
        "message": f"Successfully marked {vuln_type} as completed self-reported.",
        "task": res,
    })


@reports_bp.route("/api/reports/<token>/disagreement", methods=["POST"])
@login_required
def api_report_disagreement(token: str):
    """Log a human analyst disagreement (e.g. False Positive) into the E3 research dataset."""
    if not _UUID_RE.match(token):
        return jsonify({"ok": False, "error": "Invalid report token format."}), 400
    report = get_report(token)
    if not report:
        return jsonify({"ok": False, "error": "Report not found."}), 404
    if current_user.role != "admin" and report.get("user_id") != current_user.id:
        return jsonify({"ok": False, "error": "Access denied."}), 403

    data = request.get_json(silent=True) or {}
    vuln_type = str(data.get("vuln_type", "")).strip()
    disagreement_type = str(data.get("disagreement_type", "false_positive")).strip()
    scanner_id = str(data.get("scanner_id", "manual")).strip()
    rationale = str(data.get("rationale", "")).strip()
    evidence = str(data.get("evidence", "")).strip()
    target = str(report.get("result", {}).get("target") or report.get("target") or "")

    if not vuln_type:
        return jsonify({"ok": False, "error": "vuln_type is required."}), 400
    if not rationale:
        return jsonify({"ok": False, "error": "rationale is required explaining the disagreement."}), 400

    try:
        from research_loop import record_human_disagreement
        entry = record_human_disagreement(
            report_token=token,
            vuln_type=vuln_type,
            disagreement_type=disagreement_type,
            scanner_id=scanner_id,
            rationale=rationale,
            evidence=evidence,
            target=target,
            user_id=current_user.id,
        )
        log_event(
            "research_disagreement_logged",
            current_user.username,
            current_user.id,
            category="research",
            details=f"{disagreement_type} for {vuln_type} in {token}",
        )
        return jsonify({
            "ok": True,
            "message": "Disagreement successfully logged to E3 dataset.",
            "record": entry,
        })
    except Exception as exc:
        logger.exception("Failed to record research disagreement")
        return jsonify({"ok": False, "error": str(exc)}), 400


@reports_bp.route("/api/research/disagreements", methods=["GET"])
@login_required
def api_get_research_disagreements():
    """Return summary and recent human disagreements from the E3 dataset."""
    try:
        from research_loop import get_human_disagreements
        limit = min(200, max(1, request.args.get("limit", 50, type=int)))
        res = get_human_disagreements(limit=limit)
        return jsonify({"ok": True, **res})
    except Exception as exc:
        logger.exception("Failed to fetch research disagreements")
        return jsonify({"ok": False, "error": str(exc)}), 500


@reports_bp.route("/api/reports")
@login_required
def api_reports():
    try:
        page     = max(1, int(request.args.get("page", 1)))
        per_page = min(50, max(1, int(request.args.get("per_page", 20))))
    except (ValueError, TypeError):
        page, per_page = 1, 20

    if current_user.role == "admin":
        all_reps = get_all_reports(limit=1000)
    else:
        all_reps = get_user_reports(current_user.id, limit=1000)

    total     = len(all_reps)
    start     = (page - 1) * per_page
    page_reps = all_reps[start : start + per_page]
    return jsonify({
        "reports":  [dict(r) for r in page_reps],
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    max(1, (total + per_page - 1) // per_page),
    })


@reports_bp.route("/api/reports/<token>")
@login_required
@limiter.limit("30/minute")
def api_report(token: str):
    if not _UUID_RE.match(token):
        return jsonify({"error": "Invalid report token."}), 400
    data = get_report(token)
    if not data:
        return jsonify({"error": "Report not found."}), 404
    if data.get("user_id") != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Access denied."}), 403
    payload = normalize_api_report({**data, "token": token, "username": current_user.username})
    return jsonify(payload)


@reports_bp.route("/api/reports/<token>", methods=["DELETE"])
@login_required
def api_delete_report(token: str):
    if not _UUID_RE.match(token):
        return jsonify({"error": "Invalid report token."}), 400
    data = get_report(token)
    if not data:
        return jsonify({"error": "Report not found."}), 404
    if data.get("user_id") != current_user.id and current_user.role != "admin":
        log_event("idor_attempt", current_user.username, current_user.id,
                  category="security", resource=f"/api/reports/{token}",
                  ip_address=request.remote_addr, status="blocked")
        return jsonify({"error": "Access denied."}), 403
    ok, msg = delete_report(token)
    if ok:
        log_event("report_deleted", current_user.username, current_user.id,
                  category="scan", resource=token, status="success")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 500)


# ════════════════════════════════════════════════════════════════════════════
#  PUBLIC REPORT SHARING  (no authentication required)
# ════════════════════════════════════════════════════════════════════════════

@reports_bp.route("/api/reports/<token>/share", methods=["POST"])
@login_required
def api_generate_share_link(token):
    """Generate (or return existing) a public share token for a report."""
    if not _UUID_RE.match(token):
        return jsonify({"error": "Invalid token."}), 400
    data = get_report(token)
    if not data:
        return jsonify({"error": "Report not found."}), 404
    if data.get("user_id") != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Access denied."}), 403
    share_token = get_or_create_share_token(token)
    if not share_token:
        return jsonify({"error": "Could not generate share link."}), 500
    share_url = f"/public/report/{share_token}"
    return jsonify({"share_token": share_token, "share_url": share_url})


@reports_bp.route("/public/report/<share_token>")
@limiter.limit("20/minute")
def public_report(share_token):
    """Public read-only report view — no login required. Used for prospect demos."""
    logger.info("Public report access attempt: token=%s ip=%s", share_token[:8] if share_token else "none", request.remote_addr)
    data = get_report_by_share_token(share_token)
    if not data:
        logger.warning("Public report access denied or expired: token=%s ip=%s", share_token[:8] if share_token else "none", request.remote_addr)
        return jsonify({"error": "Report not found or link expired."}), 404
    logger.info("Public report access granted: token=%s target=%s scan_type=%s ip=%s", share_token[:8], data.get("target"), data.get("scan_type"), request.remote_addr)
    result = data.get("result", {})
    vulns  = result.get("vulnerabilities", [])
    return jsonify({
        "scan_type":   data.get("scan_type"),
        "target":      data.get("target"),
        "risk_score":  data.get("risk_score"),
        "vuln_count":  data.get("vuln_count"),
        "critical":    data.get("critical_count"),
        "high":        data.get("high_count"),
        "medium":      data.get("medium_count"),
        "low":         data.get("low_count"),
        "scanned_at":  data.get("stored_at"),
        "findings":    vulns[:50],
        "powered_by":  "SecuraX — securax.dz",
    })


# ════════════════════════════════════════════════════════════════════════════
#  SUBSCRIPTION STATUS  (user-facing — "my plan")
# ════════════════════════════════════════════════════════════════════════════

@reports_bp.route("/api/subscription")
@login_required
def api_my_subscription():
    """Return the current user's plan, usage and quota."""
    sub = get_subscription(current_user.id)
    return jsonify({
        "plan":            sub.get("plan"),
        "label":           sub.get("label"),
        "scans_used":      sub.get("scans_used"),
        "max_scans_month": sub.get("max_scans_month"),
        "remaining":       sub.get("remaining"),
        "cycle_start":     sub.get("cycle_start"),
        "expires_at":      sub.get("expires_at"),
        "price_dzd":       sub.get("price_dzd"),
    })


@reports_bp.route("/api/subscription/plans", methods=["GET"])
def api_list_plans():
    """Return list of all subscription tiers and details."""
    return jsonify({"ok": True, "plans": PLANS})


@reports_bp.route("/api/subscription/upgrade", methods=["POST"])
@login_required
@limiter.limit("10/minute")
def api_upgrade_subscription():
    """Self-service endpoint to upgrade/change subscription plan."""
    from datetime import datetime, timedelta, timezone

    data = request.get_json(silent=True) or {}
    raw_plan = (data.get("plan") or "").strip().lower()
    # Normalize aliases (e.g. enterprise -> enterprise or business)
    plan = raw_plan
    if plan not in PLANS:
        return jsonify({
            "ok": False,
            "error": f"Invalid plan '{raw_plan}'. Valid plans: {', '.join(PLANS.keys())}"
        }), 400

    expires_at = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    ok = set_subscription(
        current_user.id,
        plan=plan,
        notes="Upgraded via SecuraX pricing portal",
        expires_at=expires_at,
    )
    if not ok:
        return jsonify({"ok": False, "error": "Could not update subscription plan"}), 500

    log_event(
        "subscription_upgraded",
        current_user.username,
        current_user.id,
        category="subscription",
        resource=plan,
        details=f"User upgraded to {plan} (max_scans={PLANS[plan]['max_scans_month']})",
    )

    sub = get_subscription(current_user.id)
    return jsonify({
        "ok": True,
        "message": f"Successfully updated subscription to {PLANS[plan]['label']}!",
        "subscription": sub,
    })


# ════════════════════════════════════════════════════════════════════════════
#  FINDINGS TRIAGE & LEGAL CONSENT AUDIT (P2.2 & P3.2)
# ════════════════════════════════════════════════════════════════════════════

@reports_bp.route("/api/reports/vulnerabilities/<int:vuln_id>/triage", methods=["PATCH", "POST"])
@login_required
@limiter.limit("60/minute")
def api_update_vulnerability_triage(vuln_id: int):
    """Update finding triage status ('New', 'Reviewing', 'Reported', 'Duplicate', 'False Positive')."""
    data = request.get_json(silent=True) or {}
    status = (data.get("triage_status") or "").strip()
    notes = data.get("triage_notes", "")
    valid_statuses = {"New", "Reviewing", "Reported", "Duplicate", "False Positive"}
    if status not in valid_statuses:
        return jsonify({
            "error": f"Invalid triage_status '{status}'. Must be one of: {sorted(valid_statuses)}",
        }), 400

    try:
        ok = update_vulnerability_triage(vuln_id, status, notes)
        if not ok:
            return jsonify({"error": f"Vulnerability with ID {vuln_id} not found."}), 404
        log_event(
            "vulnerability_triage_updated",
            current_user.username,
            current_user.id,
            category="bounty",
            resource=f"vuln_{vuln_id}",
            status="success",
            details=json.dumps({"triage_status": status, "triage_notes": notes}),
        )
        return jsonify({
            "ok": True,
            "vuln_id": vuln_id,
            "triage_status": status,
            "triage_notes": notes,
        })
    except Exception as exc:
        logger.error("Failed to update triage status for vuln %s: %s", vuln_id, exc)
        return jsonify({"error": str(exc)}), 500


@reports_bp.route("/api/reports/<token>/consent-pdf")
@reports_bp.route("/api/bounty/consent-pdf/<token>")
@login_required
@limiter.limit("20/minute")
def api_download_consent_pdf(token: str):
    """Generate and download a formal Legal Consent Record PDF for a bounty scan (P3.2)."""
    if not _UUID_RE.match(token):
        return jsonify({"error": "Invalid report token."}), 400

    data = get_report(token)
    if not data:
        return jsonify({"error": "Report not found."}), 404

    if data.get("user_id") != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Access denied."}), 403

    result = data.get("result", {})
    bounty_meta = result.get("bounty") or {}
    platform = data.get("bounty_platform") or bounty_meta.get("bounty_platform")
    program = data.get("bounty_program_handle") or bounty_meta.get("bounty_program_handle")
    asset = data.get("bounty_asset") or bounty_meta.get("bounty_asset") or data.get("target")

    # If this is not a bounty scan with consent/acknowledgment metadata, return 404
    if not platform and not bounty_meta.get("acknowledged") and not bounty_meta.get("bounty_acknowledged_by"):
        return jsonify({"error": "No bug bounty legal consent record exists for this scan."}), 404

    raw_payload = f"{token}|{asset}|{platform}|{program}|{bounty_meta.get('bounty_acknowledged_by')}|{bounty_meta.get('bounty_acknowledged_at')}|{json.dumps(bounty_meta.get('policy_snapshot', {}), sort_keys=True)}"
    sha256_hash = hashlib.sha256(raw_payload.encode("utf-8")).hexdigest()

    try:
        from reportlab.lib import colors as rl_colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            leftMargin=1.5*cm, rightMargin=1.5*cm,
            topMargin=1.5*cm, bottomMargin=1.5*cm,
        )
        story = []
        styles = getSampleStyleSheet()

        C_NAVY = rl_colors.HexColor("#0f172a")
        C_CYAN = rl_colors.HexColor("#0ea5e9")
        C_BORDER = rl_colors.HexColor("#cbd5e1")
        C_LIGHT = rl_colors.HexColor("#f8fafc")

        title_style = ParagraphStyle(
            "ConsentTitle", parent=styles["Title"],
            fontSize=16, fontName="Helvetica-Bold",
            textColor=C_NAVY, leading=20, alignment=1, spaceAfter=8,
        )
        subtitle_style = ParagraphStyle(
            "ConsentSub", parent=styles["Normal"],
            fontSize=9, textColor=rl_colors.HexColor("#64748b"),
            alignment=1, spaceAfter=14,
        )
        cell_label = ParagraphStyle("CellLabel", parent=styles["Normal"], fontSize=8.5, fontName="Helvetica-Bold", textColor=C_NAVY)
        cell_val = ParagraphStyle("CellVal", parent=styles["Normal"], fontSize=8.5, fontName="Helvetica", textColor=C_NAVY)
        legal_text = ParagraphStyle("LegalText", parent=styles["Normal"], fontSize=8, leading=11, textColor=rl_colors.HexColor("#334155"))

        story.append(Paragraph("SECURAX CYBER DEFENSE PLATFORM", subtitle_style))
        story.append(Paragraph("LEGAL CONSENT & BUG BOUNTY AUDIT RECORD", title_style))
        story.append(Paragraph("Cryptographically verified authorization record for security assessment", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=C_CYAN, spaceAfter=12))

        table_data = [
            [Paragraph("Target Asset", cell_label), Paragraph(str(asset), cell_val)],
            [Paragraph("Program Handle", cell_label), Paragraph(str(program or 'N/A'), cell_val)],
            [Paragraph("Bounty Platform", cell_label), Paragraph(str(platform or 'Custom / Direct').upper(), cell_val)],
            [Paragraph("Scan Token", cell_label), Paragraph(str(token), cell_val)],
            [Paragraph("Policy Status", cell_label), Paragraph(str((bounty_meta.get('policy_snapshot') or {}).get('status', 'UNKNOWN')), cell_val)],
            [Paragraph("Acknowledged By", cell_label), Paragraph(str(bounty_meta.get('bounty_acknowledged_by') or current_user.username), cell_val)],
            [Paragraph("Acknowledged At", cell_label), Paragraph(str(bounty_meta.get('bounty_acknowledged_at') or data.get('stored_at')), cell_val)],
            [Paragraph("Operator Client IP", cell_label), Paragraph(str(request.remote_addr or '127.0.0.1'), cell_val)],
            [Paragraph("Attribution Header", cell_label), Paragraph(str(bounty_meta.get('attribution_header') or 'SecuraX-Bounty-Scanner/1.0'), cell_val)],
            [Paragraph("SHA-256 Anti-Tamper Hash", cell_label), Paragraph(f"<font name='Courier' size='7'>{sha256_hash}</font>", cell_val)],
        ]
        tbl = Table(table_data, colWidths=[5.0*cm, 12.0*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (0,-1), C_LIGHT),
            ("BOX", (0,0), (-1,-1), 1, C_BORDER),
            ("INNERGRID", (0,0), (-1,-1), 0.5, C_BORDER),
            ("TOPPADDING", (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
            ("RIGHTPADDING", (0,0), (-1,-1), 8),
        ]))
        story.append(tbl)
        story.append(Spacer(1, 14))

        story.append(Paragraph("<b>LEGAL SHIELD & SAFE HARBOR ACKNOWLEDGMENT</b>", cell_label))
        story.append(Spacer(1, 4))
        decl = (
            "This document establishes that the security researcher acknowledged the scope, terms, "
            "and restrictions of the targeted bug bounty program prior to initiating active automated scan operations. "
            "All testing was conducted in good faith within the declared scope, adhering to rate limits, "
            "researcher attribution headers, and non-destructive assessment guidelines under applicable "
            "Safe Harbor protections (including Gold Standard Safe Harbor and disclose.io best practices)."
        )
        story.append(Paragraph(decl, legal_text))
        story.append(Spacer(1, 14))

        signals = (bounty_meta.get("policy_snapshot") or {}).get("signals", [])
        if signals:
            story.append(Paragraph("<b>FROZEN POLICY SIGNALS DETECTED AT SCAN LAUNCH:</b>", cell_label))
            story.append(Spacer(1, 4))
            for s in signals:
                story.append(Paragraph(f"• {s}", legal_text))

        doc.build(story)
        pdf_bytes = buf.getvalue()
        fname = f"securax_consent_record_{token[:12]}.pdf"
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )
    except Exception as exc:
        logger.error("Failed to generate consent PDF: %s", exc)
        return jsonify({
            "sha256_fingerprint": sha256_hash,
            "target": asset,
            "platform": platform,
            "program": program,
            "acknowledged_at": bounty_meta.get("bounty_acknowledged_at"),
            "acknowledged_by": bounty_meta.get("bounty_acknowledged_by") or current_user.username,
        })

