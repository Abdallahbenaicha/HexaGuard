"""SecuraX — Module 0: Universal Assessment Methodology & Decision Architecture.

Provides the canonical 7-phase methodology for conducting cybersecurity assessments:
  1. Define Scope & Goal (Authorization, Context, Rules of Engagement)
  2. Passive Recon (OSINT & Surface Mapping without target interference)
  3. Select the Right Engine(s) (Asset & Objective Driven Decision Matrix)
  4. Read & Triage Findings (CVSS vs EPSS vs Business Impact)
  5. Manual Verification & Deep Dive (Reproducing signals, PoC formulation)
  6. Report & Remediate (ARIA Remediation planning, Compliance mapping)
  7. Escalate & Close the Loop (Bug Bounty Learn+Earn / SOC Case Debrief)
"""

from __future__ import annotations

from typing import Any, Dict, List

# ── 7-Phase Universal Assessment Methodology ──────────────────────────────────
ASSESSMENT_METHODOLOGY: dict[str, Any] = {
    "title": "Module 0: How to Run an Assessment — The Universal Methodology",
    "subtitle": "A phased, disciplined framework taking you from ambiguous objective to verified remediation",
    "description": (
        "Security assessments fail when testers run tools randomly without understanding the scope, "
        "asset profile, or reporting objectives. HexaGuard's 7-Phase Assessment Methodology establishes "
        "a standardized operational lifecycle applicable across bug bounty hunting, internal penetration "
        "testing, SOC defense auditing, and regulatory compliance reviews."
    ),
    "phases": [
        {
            "id": "phase-1-scope-goal",
            "number": 1,
            "title": "Define Scope & Goal",
            "tagline": "Establish authorization boundaries, context, and legal safeguards before touching a packet",
            "summary": (
                "Before initiating any scan or probe, clearly define what is authorized, what is strictly out of scope, "
                "and what success looks like. Personal lab practice allows aggressive payload injection, whereas bug "
                "bounty targets enforce strict rate limits and forbid automated testing without prior approval."
            ),
            "key_steps": [
                {
                    "title": "Verify Authorization & Safe Harbor",
                    "detail": "Always confirm you possess written authorization, an active bug bounty policy, or ownership of the target. Check whether automated scanning is 'ALLOWED', 'RESTRICTED', or prohibited.",
                },
                {
                    "title": "Identify Asset Archetype",
                    "detail": "Categorize the target accurately: Web Application URL, Wildcard Root Domain, IPv4/CIDR subnet, Source Code Repository, Container Image, or Managed CMS (WordPress).",
                },
                {
                    "title": "Establish the Assessment Objective",
                    "detail": "Determine if the engagement is vulnerability hunting (seeking high-severity zero-day or configuration flaws), compliance auditing (PCI-DSS, ISO 27001), or defensive hygiene.",
                },
            ],
            "common_pitfalls": [
                "Scanning third-party SaaS dependencies or external login providers (e.g. Google OAuth, Stripe) out of scope.",
                "Using aggressive fuzzing on production databases during business peak hours.",
            ],
            "hexaguard_tooling": "Bounty Radar policy gating, Target Locking, and Safe Mode controls.",
            "route_cta": "/scan",
        },
        {
            "id": "phase-2-passive-recon",
            "number": 2,
            "title": "Passive Reconnaissance",
            "tagline": "Map the digital footprint using external intelligence without touching the target server",
            "summary": (
                "Passive reconnaissance queries public records and third-party databases to discover subdomains, "
                "exposed services, historical endpoints, and leaked credentials without generating log events on the target."
            ),
            "key_steps": [
                {
                    "title": "Certificate Transparency & Subdomains",
                    "detail": "Query crt.sh and Certificate Transparency logs to discover staging, developer, and admin hosts.",
                },
                {
                    "title": "Internet Census & Search Indexing",
                    "detail": "Query Shodan, Censys, and GreyNoise to identify open ports, TLS certificates, and unmanaged public IP blocks.",
                },
                {
                    "title": "DNS & Email Authentication Audit",
                    "detail": "Inspect DNS zone records (SPF, DMARC, DKIM, CAA, DNSSEC) to identify mail spoofing and subdomain takeover vectors.",
                },
            ],
            "common_pitfalls": [
                "Skipping passive recon and jumping straight into active port scanning, triggering rate-limits or firewall bans.",
                "Ignoring developer and staging subdomains, which frequently run with disabled security controls.",
            ],
            "hexaguard_tooling": "DNS & Email Scanner, Network Shodan/GreyNoise integration, and Subdomain Takeover engine.",
            "route_cta": "/scan/dns",
        },
        {
            "id": "phase-3-engine-selection",
            "number": 3,
            "title": "Select the Right Engine(s)",
            "tagline": "Execute the precise diagnostic scanner tailored to the target asset type and assessment goal",
            "summary": (
                "HexaGuard operates 11 distinct, specialized scanning engines. Running an unspecialized scanner wastes "
                "time and generates noise. Use the decision matrix below to dispatch the exact engine required."
            ),
            "key_steps": [
                {
                    "title": "Consult the Engine Decision Matrix",
                    "detail": "Match the asset type (URL, code, docker, IP) directly to the specialized scanning engine.",
                },
                {
                    "title": "Configure Scan Depth & Throttling",
                    "detail": "Select between Fast Recon (surface validation) and Deep Audit (exhaustive injection checks). Provide session cookies if authenticated testing is authorized.",
                },
                {
                    "title": "Queue Scans Responsibly",
                    "detail": "Utilize HexaGuard's background worker queue to monitor progress and maintain concurrency thresholds.",
                },
            ],
            "common_pitfalls": [
                "Running DAST on an API without providing authentication headers or Swagger schemas.",
                "Using network port scanners on serverless Cloudflare Workers where ports 80/443 are reverse-proxied.",
            ],
            "hexaguard_tooling": "Scanner Hub, ScanJobs Background Queue, and ScannerGuard permission engine.",
            "route_cta": "/scan",
        },
        {
            "id": "phase-4-read-triage",
            "number": 4,
            "title": "Read & Triage Findings",
            "tagline": "Separate actionable threats from informational noise using EPSS, CVSS, and Risk Engine analysis",
            "summary": (
                "A vulnerability report is not a simple checklist. Triage each finding by cross-referencing CVSS base severity "
                "with real-world exploitability (EPSS probability), known in-the-wild exploitation (CISA KEV), and asset business impact."
            ),
            "key_steps": [
                {
                    "title": "Evaluate EPSS & In-The-Wild Threat Signals",
                    "detail": "A CVSS 7.5 vulnerability with an EPSS score above 50% presents vastly greater urgency than a theoretical CVSS 9.8 flaw with zero public exploit vectors.",
                },
                {
                    "title": "Inspect Evidence Payloads & Raw Responses",
                    "detail": "Review the exact HTTP request/response, line number, or configuration directive surfaced by the engine. Distinguish true positives from scanner heuristics.",
                },
                {
                    "title": "Assess Exposure Context",
                    "detail": "Consider whether the vulnerable component is internet-facing or shielded behind an internal subnet, VPC, or WAF.",
                },
            ],
            "common_pitfalls": [
                "Treating every Informational finding as critical, causing alert fatigue.",
                "Ignoring missing security headers or version disclosures that act as stepping stones in multi-stage exploit chains.",
            ],
            "hexaguard_tooling": "Risk Engine (CVSS v3.1 + FIRST.org EPSS v3), Report Summary Dashboard, and Finding Filters.",
            "route_cta": "/reports",
        },
        {
            "id": "phase-5-manual-verification",
            "number": 5,
            "title": "Manual Verification & Deep Dive",
            "tagline": "Reproduce scanner signals manually, confirm real impact, and consult the Vulnerability Encyclopedia",
            "summary": (
                "Never report an automated scanner finding without independent manual verification. Replay the finding "
                "through Burp Suite or curl, confirm execution, and consult HexaGuard's 4-Level Vulnerability Encyclopedia."
            ),
            "key_steps": [
                {
                    "title": "Formulate a Clean Proof-of-Concept (PoC)",
                    "detail": "Construct an idempotent, non-destructive reproduction command (e.g. curl with -v, or Burp Repeater request) that clearly demonstrates the security boundary failure.",
                },
                {
                    "title": "Consult the Dedicated Encyclopedia Lesson",
                    "detail": "Navigate to the canonical lesson on /learn to study Level 1 (Foundations), Level 2 (Detection Indicators), and Level 4 (Defenses).",
                },
                {
                    "title": "Practice in Adversarial Twin Sandbox",
                    "detail": "If the concept is unfamiliar, launch the matching containerized sandbox target on 127.0.0.1 to practice exploitation safely before validating the real asset.",
                },
            ],
            "common_pitfalls": [
                "Submitting automated scanner screenshots instead of reproducible steps.",
                "Exfiltrating private customer records or dropping live shells during proof generation.",
            ],
            "hexaguard_tooling": "Vulnerability Encyclopedia (/learn), Adversarial Twin Sandbox (/sandbox), and Shadow Manual Pass.",
            "route_cta": "/learn/vulnerabilities",
        },
        {
            "id": "phase-6-report-remediate",
            "number": 6,
            "title": "Report & Remediate",
            "tagline": "Generate developer-ready remediation advice, configuration snippets, and compliance mappings",
            "summary": (
                "An assessment only delivers value when findings are remediated. Translate technical findings into "
                "concrete code patches, hardened configuration directives, and regulatory compliance mappings (GDPR, PCI-DSS, ISO 27001)."
            ),
            "key_steps": [
                {
                    "title": "Author Clear Remediation Guidance",
                    "detail": "Provide exact code snippets (e.g. parameterized SQL queries, CSP header syntax, or non-root Dockerfile directives) rather than vague recommendations.",
                },
                {
                    "title": "Map to Compliance Frameworks",
                    "detail": "Correlate each finding to regulatory requirements: PCI-DSS (Requirements 6.4 & 6.5), GDPR Article 32, and ISO/IEC 27001 Annex A.",
                },
                {
                    "title": "Deploy ARIA AI Remediation Planner",
                    "detail": "Utilize ARIA's automated remediation planner to generate unified fix scripts and executive executive summaries.",
                },
            ],
            "common_pitfalls": [
                "Recommending client-side only fixes (e.g. JavaScript validation) without server-side validation.",
                "Failing to conduct a re-test after the patch is deployed.",
            ],
            "hexaguard_tooling": "ARIA AI Remediation Planner, PDF/HTML Report Export, and Compliance Matrix.",
            "route_cta": "/chat",
        },
        {
            "id": "phase-7-escalate-loop",
            "number": 7,
            "title": "Escalate & Close the Loop",
            "tagline": "Earn verified Skill Ledger credentials, capture bounty payouts, or debrief SOC forensic case files",
            "summary": (
                "Feed every assessment back into your learning and professional progression. Convert manual testing "
                "milestones into verified Skill Ledger credentials, submit findings to Bug Bounty programs, or complete "
                "Blue Team SOC forensic case files."
            ),
            "key_steps": [
                {
                    "title": "Update the Skill Ledger",
                    "detail": "Record hands-on sandbox completions to upgrade your Skill Ledger status from 'theory_only' to 'practiced_verified'.",
                },
                {
                    "title": "Submit Bug Bounty Findings via Learn+Earn",
                    "detail": "If operating on Bug Bounty Radar targets, draft professional markdown reports tailored to HackerOne or Bugcrowd guidelines.",
                },
                {
                    "title": "Engage the Socratic Red-Team Mentor",
                    "detail": "Debrief tricky edge cases with ARIA Socratic Mentor to expand your offensive methodology and defensive mindset.",
                },
            ],
            "common_pitfalls": [
                "Not tracking recurring finding patterns to improve automated defenses.",
                "Failing to document false positives in research feedback loops.",
            ],
            "hexaguard_tooling": "Skill Ledger (/skills), Micro-Dojo (/dojo), SOC Case Files (/casefiles), and ARIA Socratic Mentor.",
            "route_cta": "/skills",
        },
    ],

    # ── Engine Selection Decision Matrix ──────────────────────────────────────────
    "decision_matrix": [
        {
            "asset_type": "Web Application (URL / Domain)",
            "goal": "Runtime injection, XSS, CSRF, auth bypass, business logic",
            "recommended_primary": "dast",
            "secondary": ["web", "ssl"],
            "scan_route": "/scan/dast",
            "rationale": "DAST actively crawls links, fuzzes inputs, and tests for XSS, SQLi, and runtime errors against live web targets.",
        },
        {
            "asset_type": "Web Core Server / Headers",
            "goal": "Security headers, cookies, HTTP methods, server leaks",
            "recommended_primary": "web",
            "secondary": ["ssl", "server_ext"],
            "scan_route": "/scan/web",
            "rationale": "Web Core analyzes HTTP response headers, cookie flags (HttpOnly/SameSite), CORS policies, and server banner disclosures.",
        },
        {
            "asset_type": "Source Code Repository (Python / JS / Go)",
            "goal": "Hardcoded secrets, unsafe functions, code-level flaws",
            "recommended_primary": "sast",
            "secondary": ["deps"],
            "scan_route": "/scan/code",
            "rationale": "SAST uses Bandit, Semgrep, and Gitleaks rules to inspect source files before deployment without needing running infrastructure.",
        },
        {
            "asset_type": "Package Manifest (requirements.txt / package.json)",
            "goal": "Known CVEs, supply chain flaws, unpinned dependencies",
            "recommended_primary": "deps",
            "secondary": ["sast"],
            "scan_route": "/scan/dependencies",
            "rationale": "Dependencies audit checks package manifests against OSV.dev, Snyk, and pip/npm audit databases to uncover known CVEs.",
        },
        {
            "asset_type": "Host IP Address / CIDR Subnet",
            "goal": "Open ports, exposed daemons, outdated OS, network exposure",
            "recommended_primary": "network",
            "secondary": ["server_ext", "ssl"],
            "scan_route": "/scan/network",
            "rationale": "Network Recon leverages Nmap and threat intelligence (Shodan, GreyNoise, AbuseIPDB) to identify exposed ports and network services.",
        },
        {
            "asset_type": "TLS Endpoint / HTTPS Service",
            "goal": "Deprecated ciphers, expired certs, Heartbleed, ROBOT",
            "recommended_primary": "ssl",
            "secondary": ["web"],
            "scan_route": "/scan/ssl",
            "rationale": "SSLyze examines certificate validity, cipher suite negotiation, TLS 1.0/1.1 deprecation, and cryptographic flaws.",
        },
        {
            "asset_type": "Internal Server (Apache / Nginx Host)",
            "goal": "White-box Apache/Nginx configuration hardening",
            "recommended_primary": "server",
            "secondary": ["server_ext"],
            "scan_route": "/scan/apache",
            "rationale": "Server Internal inspects httpd.conf, nginx.conf, mod_security, and virtual host security controls from an insider perspective.",
        },
        {
            "asset_type": "External Server Perimeter",
            "goal": "Black-box server fingerprinting, TLS, virtual hosts",
            "recommended_primary": "server_ext",
            "secondary": ["network", "ssl"],
            "scan_route": "/scan/server-ext",
            "rationale": "Server External fingerprints server daemons, default installation pages, and TLS negotiation from the public internet perspective.",
        },
        {
            "asset_type": "Dockerfile or docker-compose.yml",
            "goal": "Privileged containers, socket mounts, root execution, image CVEs",
            "recommended_primary": "docker",
            "secondary": ["sast", "deps"],
            "scan_route": "/scan/docker",
            "rationale": "Docker Security analyzes container specifications for dangerous host mounts, root execution, sensitive port exposure, and image CVEs.",
        },
        {
            "asset_type": "Domain Name / Email System",
            "goal": "SPF/DMARC/DKIM spoofing, CAA records, DNSSEC, takeover",
            "recommended_primary": "dns",
            "secondary": ["web"],
            "scan_route": "/scan/dns",
            "rationale": "DNS Scanner validates mail authentication records (SPF, DKIM, DMARC) and probes for subdomain takeover and unrestricted AXFR transfers.",
        },
        {
            "asset_type": "WordPress CMS Site",
            "goal": "Outdated plugins, user enumeration, xmlrpc.php, wp-config leak",
            "recommended_primary": "wordpress",
            "secondary": ["web", "dast"],
            "scan_route": "/scan/wordpress",
            "rationale": "WordPress Scanner performs specialized non-destructive probing of WordPress core version, active plugins, user APIs, and XML-RPC exposure.",
        },
    ],
}


# ── Specialized Recon Helper (Shared with bounty.py) ──────────────────────────
def get_base_recon_steps(is_wildcard: bool = False, asset: str = "") -> list[dict[str, str]]:
    """Return the canonical reconnaissance phases used for manual testing and hunt guides."""
    target_str = asset or "<target>"
    steps = [
        {
            "phase": "Passive Recon",
            "action": "OSINT & Surface Mapping",
            "guidance": f"Query crt.sh, Shodan, and Censys for {target_str} without initiating active port probes.",
        },
        {
            "phase": "Traffic Inspection",
            "action": "Burp Suite Manual Proxying",
            "guidance": "Walk normal business flows (registration, search, profile, checkout) through Burp Suite proxy.",
        },
        {
            "phase": "Client-side Audit",
            "action": "JavaScript Analysis",
            "guidance": "Extract endpoints and internal path patterns from app bundles and source maps.",
        },
    ]
    if is_wildcard:
        steps.insert(1, {
            "phase": "Subdomain Discovery",
            "action": "Passive CT Query",
            "guidance": f"Use HexaGuard Recon (crt.sh) to identify staging, test, and regional subdomains for {target_str}.",
        })
    return steps
