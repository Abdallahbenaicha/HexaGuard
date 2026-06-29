# report_generator.py
"""
Professional report generation for HexaGuard Security scans.
Used by export endpoints, API responses, and scan bridges.
"""

from __future__ import annotations

import html
import re
from typing import Any, Optional

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

SEV_LABELS_AR = {
    "critical": "حرج",
    "high":     "عالٍ",
    "medium":   "متوسط",
    "low":      "منخفض",
    "info":     "معلومات",
}

SEV_LABELS_EN = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Info",
}

SCAN_TYPE_LABELS = {
    "network_ext":  "Network Scan (External Reconnaissance)",
    "network_int":  "Network Scan (Internal / LAN)",
    "web":          "Web Application Security Scan",
    "server_ext":   "External Server Assessment",
    "server_int":   "Server Configuration Audit",
    "apache":       "Apache Configuration Audit",
    "sast":         "Static Application Security Testing (SAST)",
    "dast":         "Dynamic Application Security Testing (DAST)",
    "dep":          "Dependency / Supply Chain Scan",
    "dependencies": "Dependency / Supply Chain Scan",
}


def _norm_sev(sev: Any) -> str:
    s = (str(sev or "info").strip().lower() or "info")
    return s if s in SEV_ORDER else "info"


def count_severities(vulns: list[dict]) -> dict[str, int]:
    counts = {k: 0 for k in SEV_ORDER}
    for v in vulns:
        counts[_norm_sev(v.get("severity"))] += 1
    return counts


def risk_level_from_score(score: float) -> str:
    if score >= 8:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def attach_risk_breakdown(result: dict, breakdown: Any) -> dict:
    """Persist risk engine output inside the scan result JSON."""
    result["risk_breakdown"] = {
        "base_score":        breakdown.base_score,
        "temporal_score":    breakdown.temporal_score,
        "env_score":         breakdown.env_score,
        "final_score":       breakdown.final_score,
        "risk_level":        breakdown.risk_level,
        "confidence":        breakdown.confidence,
        "recommendations":   breakdown.recommendations,
        "attack_chains":     breakdown.attack_chains,
        "cisa_kev_findings": breakdown.cisa_kev_findings,
    }
    return result


def _cve_list(v: dict) -> list[str]:
    raw = v.get("cve_ids") or v.get("cves") or []
    if isinstance(raw, str):
        return [c.strip() for c in raw.split(",") if c.strip()]
    return [str(c).strip() for c in raw if str(c).strip()]


def vuln_to_finding(v: dict, target: str = "") -> dict:
    """Convert backend vulnerability dict to rich frontend finding."""
    sev = _norm_sev(v.get("severity")).upper()
    cve_ids = _cve_list(v)
    host = v.get("host") or ""
    port = v.get("port")
    file_loc = v.get("file") or target or ""
    if host and port:
        file_loc = f"{host}:{port}"
    elif host:
        file_loc = host

    desc = (v.get("description") or "").strip()
    evidence = (v.get("evidence") or "").strip()
    remediation = (
        v.get("remediation") or v.get("recommendation") or v.get("fixed_directive") or ""
    ).strip()

    parts: list[str] = []
    if desc:
        parts.append(desc)
    if evidence and evidence not in desc:
        parts.append(f"\n\n**Evidence:** `{evidence}`")
    if remediation:
        parts.append(f"\n\n**Remediation:** {remediation}")
    if cve_ids:
        parts.append(f"\n\n**CVE:** {', '.join(cve_ids)}")

    return {
        "severity":    sev,
        "code":        v.get("title") or v.get("check") or "Finding",
        "title":       v.get("title") or v.get("check") or "Finding",
        "message":     "".join(parts) or desc,
        "description": desc,
        "evidence":    evidence,
        "remediation": remediation,
        "fix":         v.get("fixed_directive") or remediation,
        "file":        file_loc,
        "line":        v.get("line_number"),
        "cve":         ", ".join(cve_ids),
        "cve_id":      cve_ids[0] if cve_ids else "",
        "cve_ids":     cve_ids,
        "check":       v.get("check", ""),
        "host":        host,
        "port":        port,
        "service":     v.get("service", ""),
        "version":     v.get("version", ""),
    }


def vulns_to_findings(vulns: list[dict], target: str = "") -> list[dict]:
    return [vuln_to_finding(v, target) for v in vulns]


def build_network_recon(result: dict) -> dict:
    """Build accurate network recon summary from scanner output."""
    hosts = result.get("hosts") or []
    meta = result.get("meta") or {}
    subdomains = result.get("subdomains") or []

    open_ports = [
        v for v in result.get("vulnerabilities", [])
        if v.get("check") == "open_port"
    ]
    os_details = [
        f"{h.get('host', '?')}: {h.get('os')}"
        for h in hosts if h.get("os")
    ]
    primary_os = "Unknown"
    if os_details:
        primary_os = os_details[0].split(": ", 1)[-1]
    elif hosts:
        primary_os = f"{len(hosts)} host(s) detected — OS fingerprint pending"

    shodan_cves: list[str] = []
    for h in hosts:
        shodan_cves.extend(h.get("shodan_cves") or [])

    return {
        "ip":              result.get("target", ""),
        "os":              primary_os,
        "os_details":      os_details,
        "open_ports":      len(open_ports),
        "open_port_list":  [
            {
                "host":     v.get("host", ""),
                "port":     v.get("port"),
                "protocol": v.get("protocol", "tcp"),
                "service":  v.get("service", ""),
                "version":  v.get("version", ""),
                "severity": _norm_sev(v.get("severity")),
            }
            for v in open_ports
        ],
        "hosts_up":        meta.get("hosts_up", str(len(hosts))),
        "total_hosts":     meta.get("total_hosts", str(len(hosts))),
        "tools_used":      meta.get("tools_used", []),
        "subdomains":      subdomains[:50],
        "subdomain_count": len(subdomains),
        "scan_time":       meta.get("scan_time", ""),
        "deep_scan":       meta.get("deep", False),
        "nmap_args":       meta.get("nmap_args", ""),
        "shodan_cve_count": len(set(shodan_cves)),
        "hosts":           hosts,
    }


def scan_type_label(scan_type: str, lang: str = "en") -> str:
    key = (scan_type or "").strip().lower()
    label = SCAN_TYPE_LABELS.get(key, scan_type or "Security Scan")
    if lang == "ar":
        ar_map = {
            "network_ext":  "فحص الشبكة (استكشاف خارجي)",
            "network_int":  "فحص الشبكة (داخلي / LAN)",
            "web":          "فحص تطبيق ويب",
            "server_ext":   "تقييم الخادم الخارجي",
            "server_int":   "تدقيق إعدادات الخادم",
            "apache":       "تدقيق Apache",
            "sast":         "فحص SAST (تحليل ثابت)",
            "dast":         "فحص DAST (تحليل ديناميكي)",
            "dep":          "فحص التبعيات",
            "dependencies": "فحص التبعيات",
        }
        return ar_map.get(key, label)
    return label


def executive_summary(data: dict, lang: str = "en") -> str:
    """Generate executive summary paragraph."""
    result = data.get("result") or {}
    vulns = result.get("vulnerabilities") or []
    counts = count_severities(vulns)
    score = float(data.get("risk_score") or 0)
    rb = result.get("risk_breakdown") or {}
    level = rb.get("risk_level") or risk_level_from_score(score)
    target = result.get("target") or data.get("target") or "unknown"
    scan_type = result.get("scan_type") or data.get("scan_type") or ""
    st_label = scan_type_label(scan_type, lang)

    if lang == "ar":
        level_ar = SEV_LABELS_AR.get(level, level)
        lines = [
            f"تم إجراء {st_label} على الهدف `{target}`.",
            f"درجة المخاطر الإجمالية: **{score:.1f}/10** ({level_ar}).",
            f"إجمالي النتائج: **{len(vulns)}** "
            f"(حرج: {counts['critical']}, عالٍ: {counts['high']}, "
            f"متوسط: {counts['medium']}, منخفض: {counts['low']}, معلومات: {counts['info']}).",
        ]
        if counts["critical"] or counts["high"]:
            lines.append(
                "يُوصى بمعالجة الثغرات الحرجة والعالية فوراً قبل أي نشر أو توسيع للخدمة."
            )
        elif vulns:
            lines.append("لا توجد ثغرات حرجة — راجع التوصيات أدناه لتحسين الوضع الأمني.")
        else:
            lines.append("لم يُكتشف أي خطر أمني في نطاق هذا الفحص.")
        return " ".join(lines)

    lines = [
        f"A {st_label} was performed against `{target}`.",
        f"Overall risk score: **{score:.1f}/10** ({level.upper()}).",
        f"Total findings: **{len(vulns)}** "
        f"(Critical: {counts['critical']}, High: {counts['high']}, "
        f"Medium: {counts['medium']}, Low: {counts['low']}, Info: {counts['info']}).",
    ]
    if counts["critical"] or counts["high"]:
        lines.append(
            "Immediate remediation of critical and high-severity findings is recommended "
            "before production exposure."
        )
    elif vulns:
        lines.append("No critical findings — review recommendations below to harden posture.")
    else:
        lines.append("No security issues were identified within the scope of this assessment.")
    return " ".join(lines)


def _network_section_md(result: dict, lang: str) -> list[str]:
    if not str(result.get("scan_type", "")).startswith("network"):
        return []
    recon = build_network_recon(result)
    if lang == "ar":
        lines = [
            "## ملخص استكشاف الشبكة",
            "",
            f"| المقياس | القيمة |",
            f"|--------|--------|",
            f"| الهدف | `{recon['ip']}` |",
            f"| نظام التشغيل | {recon['os']} |",
            f"| المضيفين النشطين | {recon['hosts_up']} / {recon['total_hosts']} |",
            f"| المنافذ المفتوحة | {recon['open_ports']} |",
            f"| النطاقات الفرعية (crt.sh) | {recon['subdomain_count']} |",
            f"| أدوات الفحص | {', '.join(recon['tools_used']) or '—'} |",
            "",
        ]
        if recon["open_port_list"]:
            lines += ["### المنافذ المفتوحة", "", "| المنفذ | الخدمة | الإصدار | الخطورة |", "|--------|--------|---------|---------|"]
            for p in recon["open_port_list"][:40]:
                lines.append(
                    f"| {p['host']}:{p['port']}/{p['protocol']} | {p['service']} | "
                    f"{p['version'] or '—'} | {SEV_LABELS_AR.get(p['severity'], p['severity'])} |"
                )
            lines.append("")
        if recon["subdomains"]:
            lines += ["### نطاقات فرعية (عينة)", "", ", ".join(f"`{s}`" for s in recon["subdomains"][:15]), ""]
        return lines

    lines = [
        "## Network Reconnaissance Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Target | `{recon['ip']}` |",
        f"| Operating System | {recon['os']} |",
        f"| Hosts Up | {recon['hosts_up']} / {recon['total_hosts']} |",
        f"| Open Ports | {recon['open_ports']} |",
        f"| Subdomains (crt.sh) | {recon['subdomain_count']} |",
        f"| Scan Tools | {', '.join(recon['tools_used']) or '—'} |",
        "",
    ]
    if recon["open_port_list"]:
        lines += ["### Open Ports", "", "| Endpoint | Service | Version | Severity |", "|----------|---------|---------|----------|"]
        for p in recon["open_port_list"][:40]:
            lines.append(
                f"| {p['host']}:{p['port']}/{p['protocol']} | {p['service']} | "
                f"{p['version'] or '—'} | {p['severity'].upper()} |"
            )
        lines.append("")
    if recon["subdomains"]:
        lines += ["### Subdomains (sample)", "", ", ".join(f"`{s}`" for s in recon["subdomains"][:15]), ""]
    return lines


def generate_markdown_report(data: dict, lang: str = "en") -> str:
    """Full professional Markdown vulnerability report."""
    result = data.get("result") or {}
    vulns = sorted(
        result.get("vulnerabilities") or [],
        key=lambda v: SEV_ORDER.get(_norm_sev(v.get("severity")), 9),
    )
    counts = count_severities(vulns)
    score = float(data.get("risk_score") or 0)
    rb = result.get("risk_breakdown") or {}
    target = result.get("target") or data.get("target") or "unknown"
    scan_type = result.get("scan_type") or data.get("scan_type") or ""
    stored_at = data.get("stored_at") or ""
    token = (data.get("token") or "")[:16].upper()
    labels = SEV_LABELS_AR if lang == "ar" else SEV_LABELS_EN

    if lang == "ar":
        title = "# HexaGuard — تقرير الفحص الأمني"
        meta_hdr = "## بيانات الفحص"
        exec_hdr = "## الملخص التنفيذي"
        risk_hdr = "## تقييم المخاطر"
        sev_hdr = "## توزيع الخطورة"
        find_hdr = "## النتائج التفصيلية"
        rec_hdr = "## التوصيات"
        chain_hdr = "## سلاسل الهجوم المحتملة"
        footer = f"*تقرير سري — HexaGuard Security Platform — {token}*"
    else:
        title = "# HexaGuard — Security Assessment Report"
        meta_hdr = "## Scan Metadata"
        exec_hdr = "## Executive Summary"
        risk_hdr = "## Risk Assessment"
        sev_hdr = "## Severity Distribution"
        find_hdr = "## Detailed Findings"
        rec_hdr = "## Recommendations"
        chain_hdr = "## Potential Attack Chains"
        footer = f"*Confidential — HexaGuard Security Platform — {token}*"

    lines = [
        title,
        "",
        meta_hdr,
        "",
        f"- **{'الهدف' if lang == 'ar' else 'Target'}:** `{target}`",
        f"- **{'نوع الفحص' if lang == 'ar' else 'Scan Type'}:** {scan_type_label(scan_type, lang)}",
        f"- **{'تاريخ الفحص' if lang == 'ar' else 'Scan Date'}:** {stored_at}",
        f"- **{'مدة الفحص' if lang == 'ar' else 'Duration'}:** {result.get('scan_duration_seconds', '—')}s",
        f"- **{'المُنفّذ' if lang == 'ar' else 'Assessed By'}:** {data.get('username', '—')}",
        "",
        exec_hdr,
        "",
        executive_summary(data, lang),
        "",
        risk_hdr,
        "",
        f"- **{'درجة المخاطر' if lang == 'ar' else 'Risk Score'}:** {score:.1f} / 10",
        f"- **{'المستوى' if lang == 'ar' else 'Risk Level'}:** {rb.get('risk_level', risk_level_from_score(score)).upper()}",
        f"- **{'الثقة' if lang == 'ar' else 'Confidence'}:** {rb.get('confidence', '—')}",
        "",
        sev_hdr,
        "",
        "| Severity | Count |" if lang != "ar" else "| الخطورة | العدد |",
        "|----------|-------|" if lang != "ar" else "|---------|-------|",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts[sev]:
            lines.append(f"| {labels[sev]} | {counts[sev]} |")
    lines.append("")

    lines.extend(_network_section_md(result, lang))

    chains = rb.get("attack_chains") or []
    if chains:
        lines += [chain_hdr, ""]
        for i, c in enumerate(chains, 1):
            lines.append(f"{i}. {c}")
        lines.append("")

    lines += [find_hdr, ""]
    if not vulns:
        lines.append("✅ " + ("لم يتم اكتشاف ثغرات." if lang == "ar" else "No vulnerabilities identified."))
    else:
        for i, v in enumerate(vulns, 1):
            sev = _norm_sev(v.get("severity"))
            title_txt = v.get("title") or v.get("check") or "Finding"
            lines.append(f"### {i}. [{labels[sev].upper()}] {title_txt}")
            if v.get("description"):
                lines.append("")
                lines.append(v["description"])
            if v.get("evidence"):
                lines.append("")
                lines.append(f"**{'الدليل' if lang == 'ar' else 'Evidence'}:** `{v['evidence']}`")
            cves = _cve_list(v)
            if cves:
                lines.append("")
                lines.append(f"**CVE:** {', '.join(cves)}")
            rem = v.get("remediation") or v.get("recommendation") or v.get("fixed_directive")
            if rem:
                lines.append("")
                lines.append(f"**{'الإصلاح' if lang == 'ar' else 'Remediation'}:** {rem}")
            if v.get("line_number"):
                lines.append("")
                lines.append(f"**{'السطر' if lang == 'ar' else 'Line'}:** {v['line_number']}")
            lines.append("")

    recs = rb.get("recommendations") or []
    if recs:
        lines += [rec_hdr, ""]
        for r in recs:
            lines.append(f"- {r}")
        lines.append("")

    lines += ["---", "", footer]
    return "\n".join(lines)


def generate_csv_rows(data: dict) -> list[list[str]]:
    """CSV rows including header."""
    result = data.get("result") or {}
    vulns = result.get("vulnerabilities") or []
    rows = [[
        "Severity", "Check ID", "Title", "Description", "Evidence",
        "Remediation", "Host", "Port", "Service", "CVE IDs", "Line",
    ]]
    for v in vulns:
        cves = _cve_list(v)
        rows.append([
            _norm_sev(v.get("severity")).upper(),
            v.get("check") or "",
            v.get("title") or v.get("check") or "",
            v.get("description") or "",
            v.get("evidence") or "",
            v.get("remediation") or v.get("recommendation") or "",
            str(v.get("host") or ""),
            str(v.get("port") or ""),
            v.get("service") or "",
            ", ".join(cves),
            str(v.get("line_number") or ""),
        ])
    return rows


def normalize_api_report(data: dict) -> dict:
    """Normalize stored report for React API consumers."""
    result = data.get("result") or {}
    target = result.get("target") or data.get("target") or ""
    rb = result.get("risk_breakdown") or {}
    vulns = result.get("vulnerabilities") or []
    scan_type = result.get("scan_type") or data.get("scan_type") or ""

    payload: dict[str, Any] = {
        "token":             data.get("token", ""),
        "target":            target,
        "scan_type":         scan_type,
        "scan_type_label":   scan_type_label(scan_type),
        "stored_at":         data.get("stored_at", ""),
        "risk_score":        data.get("risk_score", 0),
        "risk_level":        rb.get("risk_level") or risk_level_from_score(float(data.get("risk_score") or 0)),
        "vuln_count":        data.get("vuln_count") or len(vulns),
        "severity_counts":   count_severities(vulns),
        "findings":          vulns_to_findings(vulns, target),
        "vulnerabilities":   vulns,
        "result":            result,
        "has_fix":           bool(data.get("original_content")),
        "user":              data.get("username", ""),
        "recommendations":   rb.get("recommendations") or [],
        "attack_chains":     rb.get("attack_chains") or [],
        "cisa_kev_findings": rb.get("cisa_kev_findings") or [],
        "executive_summary": executive_summary(data),
    }
    if str(scan_type).startswith("network"):
        payload["recon"] = build_network_recon(result)
    return payload


def strip_md_for_pdf(text: str) -> str:
    """Light markdown cleanup for PDF paragraphs."""
    t = re.sub(r"\*\*(.+?)\*\*", r"\1", text or "")
    t = re.sub(r"`(.+?)`", r"\1", t)
    return t


def escape_html(text: str) -> str:
    return html.escape(str(text or ""), quote=True)

