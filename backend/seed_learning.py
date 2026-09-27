"""Seed initial Phase 1 learning exercises into the learning_exercises table.

Creates 4 core exercises:
- XSS Knowledge (Assessment)
- XSS Lab Exploitation (Lab)
- SQLi Knowledge (Assessment)
- SQLi Lab Exploitation (Lab)
"""

import json
import logging
from database import init_db, _get_db, create_exercise

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("seed_learning")

SEED_EXERCISES = [
    # ── Reference Skill 1: http_fundamentals (Non-containerized) ────────────────
    {
        "vuln_type": "http_fundamentals",
        "capability": "knowledge",
        "exercise_type": "concept_assessment",
        "title_en": "HTTP Protocol Mechanics & Security Architecture",
        "description_en": "Explain HTTP request/response anatomy, idempotency of methods (GET, POST, PUT, DELETE, OPTIONS), status code classes (2xx, 3xx, 4xx, 5xx), statelessness, and cookie security flags.",
        "difficulty": "easy",
        "content_json": {
            "min_words": 30,
            "expected_concepts": ["verbs", "methods", "status codes", "headers", "stateless", "cookies"],
            "synonyms": {
                "methods": ["verbs", "http verbs", "actions"],
                "verbs": ["methods", "http methods"],
                "stateless": ["statelessness", "session management"],
            },
        },
        "cert_hint": "CompTIA Security+ / CEH Network Protocol Fundamentals.",
    },
    {
        "vuln_type": "http_fundamentals",
        "capability": "recognition",
        "exercise_type": "pattern_recognition",
        "title_en": "Identifying Cleartext Credentials & Verb Tampering in Traffic Logs",
        "description_en": "Analyze raw HTTP request logs to identify unencrypted Basic Authentication transmitted over cleartext HTTP and detect dangerous HTTP verb tampering bypasses.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 15,
            "target_indicators": ["Authorization: Basic", "http://", "HEAD", "OPTIONS", "line 4"],
            "pattern_keywords": ["cleartext", "unencrypted", "base64", "verb tampering", "credentials"],
        },
        "cert_hint": "eJPT / OSCP traffic analysis and authentication reconnaissance.",
    },
    {
        "vuln_type": "http_fundamentals",
        "capability": "manual_detection",
        "exercise_type": "cli_detection",
        "title_en": "Probing HTTP Headers and Methods via cURL",
        "description_en": "Demonstrate manual HTTP reconnaissance by crafting cURL requests with flags (-I, -X, -v) to retrieve response headers, identify server banners, and enumerate supported methods.",
        "difficulty": "easy",
        "content_json": {
            "required_commands": ["curl", "-I", "-X"],
            "expected_artifacts": ["200 OK", "Server:", "Allow:", "Content-Type:"],
        },
        "cert_hint": "Practical CLI reconnaissance standard for penetration testers.",
    },
    {
        "vuln_type": "http_fundamentals",
        "capability": "validation",
        "exercise_type": "payload_validation",
        "title_en": "Validating HTTP Method Tampering & Access Control Bypasses",
        "description_en": "Differentiate true access control bypasses via alternative HTTP methods (HEAD, OPTIONS, PUT) from standard 403 Forbidden or 405 Method Not Allowed responses using canary validation and response body analysis.",
        "difficulty": "medium",
        "content_json": {
            "expected_classification": "true_positive",
            "proof_indicators": ["method override", "verb bypass", "200 ok", "unauthorized access", "head bypass", "options disclosure"],
        },
        "cert_hint": "CompTIA Security+ / CEH HTTP Protocol and Access Control Triage.",
    },
    {
        "vuln_type": "http_fundamentals",
        "capability": "lab_exploitation",
        "exercise_type": "safe_lab",
        "title_en": "Safe Local HTTP Protocol & Header Manipulation Lab",
        "description_en": "Execute safe local protocol analysis probing header injection, method overrides, and status code behavior using cURL to extract the required protocol verification signature.",
        "difficulty": "medium",
        "content_json": {
            "required_commands": ["curl", "-X", "-H"],
            "expected_artifacts": ["HTTP/1.1", "200 OK", "Content-Type:", "Server:"],
            "min_words": 20,
        },
        "cert_hint": "Practical HTTP protocol manipulation for penetration testers.",
    },
    {
        "vuln_type": "http_fundamentals",
        "capability": "impact_analysis",
        "exercise_type": "impact_analysis",
        "title_en": "HTTP Protocol Desynchronization CVSS v3.1 Scoring & Risk Analysis",
        "description_en": "Assess technical and business blast radius of HTTP verb tampering, request smuggling, and header injection, and determine the CVSS v3.1 score vector.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 20,
            "expected_cvss_components": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
            "impact_keywords": ["request smuggling", "cache poisoning", "verb tampering", "authorization bypass", "confidentiality", "integrity"],
        },
        "cert_hint": "CVSS v3.1 Threat Modeling for Web Protocols.",
    },
    {
        "vuln_type": "http_fundamentals",
        "capability": "remediation",
        "exercise_type": "remediation_review",
        "title_en": "Reverse Proxy HTTP Method Whitelisting & Header Normalization",
        "description_en": "Review reverse proxy configurations (Nginx/Envoy) enforcing strict HTTP method whitelisting, header normalization, and stripping descriptive server banners.",
        "difficulty": "medium",
        "content_json": {
            "defense_concepts": ["whitelist", "limit_except", "servertokens off", "proxy_hide_header", "rfc 9110", "crlf"],
            "prohibited_patterns": ["allow all", "traceenable on", "proxy_pass http://"],
        },
        "cert_hint": "Web Server Hardening and Reverse Proxy Security Architecture.",
    },
    {
        "vuln_type": "http_fundamentals",
        "capability": "reporting",
        "exercise_type": "vulnerability_report",
        "title_en": "Authoring a Vulnerability Disclosure: Insecure HTTP Methods & Information Leakage",
        "description_en": "Draft a professional vulnerability report documenting insecure HTTP method enablement (TRACE/OPTIONS), verbose banner exposure, impact narrative, and remediation directives.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 40,
            "required_sections": ["summary", "steps to reproduce", "impact", "remediation"],
        },
        "cert_hint": "Professional Security Assessment Reporting Standard.",
    },

    # ── Reference Skill 2: xss (Adversarial / Containerized) ───────────────────
    {
        "vuln_type": "xss",
        "capability": "knowledge",
        "exercise_type": "concept_assessment",
        "title_en": "Cross-Site Scripting (XSS) Mechanics & Contexts",
        "description_en": "Explain Reflected, Stored, and DOM XSS attack vectors, execution sinks, and contextual output encoding defense.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 30,
            "expected_concepts": ["escaping", "sanitization", "csp", "dom", "context", "reflection"],
        },
        "cert_hint": "Covers PortSwigger BSCP and OffSec OSWE XSS curriculum.",
    },
    {
        "vuln_type": "xss",
        "capability": "recognition",
        "exercise_type": "pattern_recognition",
        "title_en": "Spotting Dangerous DOM Sinks & Unescaped Reflection",
        "description_en": "Analyze vulnerable JavaScript and template source code to locate DOM execution sinks (innerHTML, document.write) and unsanitized parameters.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 15,
            "target_indicators": ["innerHTML", "document.write", "eval", "line 12", "location.search"],
            "pattern_keywords": ["sink", "unescaped", "reflection", "execution", "sanitization"],
        },
        "cert_hint": "OSWE source code review and taint analysis.",
    },
    {
        "vuln_type": "xss",
        "capability": "validation",
        "exercise_type": "payload_validation",
        "title_en": "Context Breakout & Canary Payload Validation",
        "description_en": "Differentiate active script execution from safe text rendering using canary markers and context boundary analysis (HTML body vs attribute vs script context).",
        "difficulty": "medium",
        "content_json": {
            "expected_classification": "true_positive",
            "proof_indicators": ["canary", "breakout", "alert", "unescaped", "attribute breakout", "executable"],
        },
        "cert_hint": "Bug bounty triage and PoC validation methodology.",
    },
    {
        "vuln_type": "xss",
        "capability": "lab_exploitation",
        "exercise_type": "lab",
        "title_en": "Reflected & DOM XSS Sandbox Lab",
        "description_en": "Exploit reflected input vectors in the isolated Adversarial Twin Sandbox environment.",
        "difficulty": "medium",
        "content_json": {
            "sandbox_target": "xss",
            "proof_flag": "FLAG{xss_dom_reflection_conquered_2026}",
        },
        "cert_hint": "eWPTX / OSWE hands-on lab proof capture.",
    },
    {
        "vuln_type": "xss",
        "capability": "impact_analysis",
        "exercise_type": "impact_analysis",
        "title_en": "XSS CVSS v3.1 Scoring & Attack Surface Blast Radius",
        "description_en": "Formulate realistic business and technical blast radius for XSS (session theft, credential harvesting, DOM defacement) and determine CVSS v3.1 vector.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 20,
            "expected_cvss_components": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
            "impact_keywords": ["session hijacking", "cookie theft", "account takeover", "privilege escalation", "confidentiality", "integrity"],
        },
        "cert_hint": "CVSS v3.1 specification and threat modeling standard.",
    },
    {
        "vuln_type": "xss",
        "capability": "manual_detection",
        "exercise_type": "cli_detection",
        "title_en": "Probing Parameter Reflection & Content-Security-Policy via cURL",
        "description_en": "Use cURL to submit benign canary probe strings into target parameters and inspect response headers and reflection contexts for Content-Security-Policy directives.",
        "difficulty": "easy",
        "content_json": {
            "required_commands": ["curl", "-i", "-s"],
            "expected_artifacts": ["HTTP/1.1 200", "Content-Type: text/html", "content-security-policy"],
        },
        "cert_hint": "OSWE / eWPT CLI Canary Reflection Probing.",
    },
    {
        "vuln_type": "xss",
        "capability": "remediation",
        "exercise_type": "remediation_review",
        "title_en": "Context-Aware Output Encoding & Content Security Policy Defense",
        "description_en": "Formulate defensive controls incorporating contextual output encoding (DOMPurify, template auto-escaping) and strict Content Security Policy directives to mitigate XSS execution.",
        "difficulty": "medium",
        "content_json": {
            "defense_concepts": ["content-security-policy", "default-src 'self'", "dompurify", "contextual encoding", "httponly", "nonce"],
            "prohibited_patterns": ["unsafe-inline", "unsafe-eval", "document.write", "innerhtml"],
        },
        "cert_hint": "OWASP Cross-Site Scripting Prevention & PCI-DSS 6.4.3.",
    },
    {
        "vuln_type": "xss",
        "capability": "reporting",
        "exercise_type": "vulnerability_report",
        "title_en": "Professional Bug Bounty Report: Stored / Reflected Cross-Site Scripting",
        "description_en": "Draft a vulnerability report documenting XSS injection vectors, browser execution proof, session hijacking risk, and contextual defense implementation.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 40,
            "required_sections": ["summary", "steps to reproduce", "impact", "remediation"],
        },
        "cert_hint": "Bug Bounty Vulnerability Disclosure Reporting Standard.",
    },

    # ── Batch 1 Skill 1: dns_recon (Local / Non-containerized) ───────────────
    {
        "vuln_type": "dns_recon",
        "capability": "recognition",
        "exercise_type": "pattern_recognition",
        "title_en": "Identifying Dangling CNAME Records & Takeover Signatures",
        "description_en": "Analyze DNS zone configuration and HTTP error fingerprints to identify dangling CNAME pointers to decommissioned cloud assets.",
        "difficulty": "easy",
        "content_json": {
            "min_words": 15,
            "target_indicators": ["blog.example.com", "example-corp.github.io", "CNAME", "NoSuchBucket"],
            "pattern_keywords": ["dangling", "subdomain takeover", "unregistered", "cname", "cloud"],
        },
        "cert_hint": "OSCP / eJPT External Reconnaissance & Asset Discovery.",
    },
    {
        "vuln_type": "dns_recon",
        "capability": "manual_detection",
        "exercise_type": "cli_detection",
        "title_en": "DNS Zone Enumeration & SPF/DMARC Probing with Dig",
        "description_en": "Execute manual DNS queries using dig/nslookup to enumerate mail exchange records, identify zone transfer leaks (AXFR), and audit email authentication.",
        "difficulty": "easy",
        "content_json": {
            "required_commands": ["dig", "TXT", "CNAME"],
            "expected_artifacts": ["v=spf1", "CNAME", "NOERROR", "ANSWER SECTION"],
        },
        "cert_hint": "CompTIA Security+ / CEH Network Reconnaissance Standards.",
    },
    {
        "vuln_type": "dns_recon",
        "capability": "impact_analysis",
        "exercise_type": "impact_analysis",
        "title_en": "Subdomain Takeover CVSS Scoring & Attack Blast Radius",
        "description_en": "Formulate technical and business blast radius for an abandoned subdomain takeover, including session cookie harvesting, spear-phishing, and CVSS v3.1 calculation.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 20,
            "expected_cvss_components": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
            "impact_keywords": ["subdomain takeover", "cookie theft", "phishing", "reputation", "csp bypass"],
        },
        "cert_hint": "CVSS v3.1 Threat Modeling for Cloud Asset Management.",
    },

    # ── Batch 1 Skill 2: missing_security_headers (Local / Non-containerized) ──
    {
        "vuln_type": "missing_security_headers",
        "capability": "recognition",
        "exercise_type": "pattern_recognition",
        "title_en": "Auditing Missing Browser Defense Headers",
        "description_en": "Analyze raw HTTP server response headers to identify missing declarative controls (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).",
        "difficulty": "easy",
        "content_json": {
            "min_words": 15,
            "target_indicators": ["HTTP/1.1 200 OK", "Server:", "Content-Type:"],
            "pattern_keywords": ["content-security-policy", "strict-transport-security", "x-frame-options", "nosniff", "framing"],
        },
        "cert_hint": "OWASP Secure Headers Project Baseline Audit.",
    },
    {
        "vuln_type": "missing_security_headers",
        "capability": "manual_detection",
        "exercise_type": "cli_detection",
        "title_en": "Probing Declarative Headers via cURL",
        "description_en": "Demonstrate manual header validation using curl -I to extract and evaluate edge security controls.",
        "difficulty": "easy",
        "content_json": {
            "required_commands": ["curl", "-I", "-s"],
            "expected_artifacts": ["HTTP/1.1", "Content-Type:", "Server:"],
        },
        "cert_hint": "Practical CLI reconnaissance and header validation.",
    },
    {
        "vuln_type": "missing_security_headers",
        "capability": "remediation",
        "exercise_type": "remediation_review",
        "title_en": "Injecting Declarative Security Headers at Reverse Proxy",
        "description_en": "Design and review Nginx or web application middleware configurations to enforce baseline defense headers across all HTTP responses.",
        "difficulty": "medium",
        "content_json": {
            "defense_concepts": ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy"],
            "prohibited_patterns": ["unsafe-inline", "unsafe-eval", "http://"],
        },
        "cert_hint": "PCI-DSS 4.0 Requirement 6.4.3 & Browser Defense Hardening.",
    },

    # ── Batch 1 Skill 3: broken_auth (Container Lab: DVWA) ────────────────────
    {
        "vuln_type": "broken_auth",
        "capability": "recognition",
        "exercise_type": "pattern_recognition",
        "title_en": "Spotting Weak Session Identifiers & Missing Cookie Attributes",
        "description_en": "Review authentication controller logic and Set-Cookie directives to identify predictable session generation and missing HttpOnly/Secure flags.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 15,
            "target_indicators": ["Set-Cookie", "session_id", "md5", "time.time()", "line 15"],
            "pattern_keywords": ["predictable", "httponly", "secure", "entropy", "session hijacking"],
        },
        "cert_hint": "OWASP ASVS V2 & eWPT Session Management Analysis.",
    },
    {
        "vuln_type": "broken_auth",
        "capability": "validation",
        "exercise_type": "payload_validation",
        "title_en": "Post-Logout Session Invalidation Testing",
        "description_en": "Validate broken session termination by issuing requests with previously active session cookies following explicit user logout.",
        "difficulty": "medium",
        "content_json": {
            "expected_classification": "true_positive",
            "proof_indicators": ["session valid", "200 ok", "not invalidated", "post-logout", "retained state"],
        },
        "cert_hint": "Authentication Bypass & Session Lifecycle Triage.",
    },
    {
        "vuln_type": "broken_auth",
        "capability": "lab_exploitation",
        "exercise_type": "lab",
        "title_en": "DVWA Broken Authentication & Session Hijacking Lab",
        "description_en": "Exploit weak authentication mechanisms in the isolated DVWA container to capture the proof flag.",
        "difficulty": "hard",
        "content_json": {
            "sandbox_target": "broken_auth",
            "proof_flag": "FLAG{broken_auth_admin_session_forged}",
        },
        "cert_hint": "OSWE / eWPT Hands-on Authentication Exploitation.",
    },

    # ── Batch 1 Skill 4: idor (Container Lab: Juice Shop) ─────────────────────
    {
        "vuln_type": "idor",
        "capability": "knowledge",
        "exercise_type": "concept_assessment",
        "title_en": "Insecure Direct Object References (IDOR/BOLA) Core Mechanics",
        "description_en": "Explain Insecure Direct Object References (IDOR/BOLA), horizontal vs vertical privilege escalation, and why client-supplied object identifiers without server-side ownership checks cause critical authorization failures.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 30,
            "expected_concepts": ["authorization", "ownership", "horizontal", "vertical", "tenant", "access control", "bola"],
        },
        "cert_hint": "OWASP Top 10 A01 / CompTIA Security+ Broken Access Control.",
    },
    {
        "vuln_type": "idor",
        "capability": "recognition",
        "exercise_type": "pattern_recognition",
        "title_en": "Spotting Unchecked Direct Object References in API Endpoints",
        "description_en": "Audit REST API route handlers to identify direct primary key lookups that omit user ownership verification (`user_id = current_user.id`).",
        "difficulty": "medium",
        "content_json": {
            "min_words": 15,
            "target_indicators": ["/api/order/", "order_id", "SELECT * FROM orders WHERE id", "line 8"],
            "pattern_keywords": ["ownership", "authorization", "direct object reference", "cross-tenant", "missing check"],
        },
        "cert_hint": "OWASP ASVS V4 & PortSwigger BSCP Access Control.",
    },
    {
        "vuln_type": "idor",
        "capability": "manual_detection",
        "exercise_type": "cli_detection",
        "title_en": "Multi-Session IDOR Probing via cURL",
        "description_en": "Perform manual API probing using cURL with distinct session tokens across two accounts to identify object endpoints that return unauthorized records.",
        "difficulty": "medium",
        "content_json": {
            "required_commands": ["curl", "-H", "Authorization:"],
            "expected_artifacts": ["200 OK", "id", "user_id"],
        },
        "cert_hint": "eWPTX / OSCP Multi-Session API Authorization Testing.",
    },
    {
        "vuln_type": "idor",
        "capability": "validation",
        "exercise_type": "payload_validation",
        "title_en": "Horizontal Access Control Bypass Validation",
        "description_en": "Prove horizontal privilege escalation by manipulating numeric resource IDs across two authenticated test accounts.",
        "difficulty": "medium",
        "content_json": {
            "expected_classification": "true_positive",
            "proof_indicators": ["horizontal privilege", "cross-account", "unauthorized access", "record leaked", "object reference"],
        },
        "cert_hint": "Bug Bounty Access Control Validation Standard.",
    },
    {
        "vuln_type": "idor",
        "capability": "lab_exploitation",
        "exercise_type": "lab",
        "title_en": "Juice Shop IDOR / BOLA Laboratory",
        "description_en": "Exploit insecure direct object references in the isolated OWASP Juice Shop container to access foreign user data and capture the flag.",
        "difficulty": "medium",
        "content_json": {
            "sandbox_target": "idor",
            "proof_flag": "FLAG{idor_insecure_direct_object_reference_extracted}",
        },
        "cert_hint": "eWPTX / PortSwigger IDOR Proof Capture.",
    },
    {
        "vuln_type": "idor",
        "capability": "impact_analysis",
        "exercise_type": "impact_analysis",
        "title_en": "IDOR CVSS v3.1 Blast Radius & Data Breach Exposure",
        "description_en": "Formulate technical and business blast radius for mass customer data exfiltration via IDOR, including regulatory fines (GDPR), and compute CVSS v3.1 base score.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 20,
            "expected_cvss_components": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
            "impact_keywords": ["horizontal escalation", "cross-tenant", "pii breach", "data exfiltration", "gdpr", "privilege escalation"],
        },
        "cert_hint": "Enterprise Threat Modeling & Risk Scoring for Access Control.",
    },
    {
        "vuln_type": "idor",
        "capability": "remediation",
        "exercise_type": "remediation_review",
        "title_en": "Authoritative Server-Side Ownership Enforcement",
        "description_en": "Design and review database query access control patterns that bind record lookup to authenticated session context (`current_user.id`) and eliminate client-supplied identity parameters.",
        "difficulty": "medium",
        "content_json": {
            "defense_concepts": ["current_user.id", "where user_id", "row-level security", "ownership", "404 not found", "session context"],
            "prohibited_patterns": ["select * from orders where id = id", "trust client", "admin_override = true"],
        },
        "cert_hint": "OWASP ASVS V4 Access Control Verification Standard.",
    },
    {
        "vuln_type": "idor",
        "capability": "reporting",
        "exercise_type": "vulnerability_report",
        "title_en": "Professional Bug Bounty Report: Broken Object-Level Authorization (IDOR)",
        "description_en": "Draft an executive-ready vulnerability disclosure report detailing cross-tenant order/profile access, dual-account reproduction steps, business impact, and code-level remediation.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 40,
            "required_sections": ["summary", "steps to reproduce", "impact", "remediation"],
        },
        "cert_hint": "HackerOne / Bugcrowd Quality Triage Submission Standards.",
    },

    # ── Batch 1 Skill 5: sqli (Container Lab: DVWA) ───────────────────────────
    {
        "vuln_type": "sqli",
        "capability": "knowledge",
        "exercise_type": "assessment",
        "title_en": "SQL Injection Mechanics & Parameterized Defenses",
        "description_en": "Explain syntax breakout, tautologies, UNION queries, and parameterized query compilation.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 30,
            "expected_concepts": ["parameterization", "prepared statements", "union", "orm", "syntax"],
        },
        "cert_hint": "Maps to OWASP A05 and CompTIA PenTest+ SQLi modules.",
    },
    {
        "vuln_type": "sqli",
        "capability": "recognition",
        "exercise_type": "pattern_recognition",
        "title_en": "Spotting Raw SQL String Concatenation & Injection Sinks",
        "description_en": "Analyze backend database queries in code to locate vulnerable string formatting (f-strings, %, +) passing unsanitized input to SQL execute functions.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 15,
            "target_indicators": ["cursor.execute", "f\"SELECT", "WHERE user = '", "line 10"],
            "pattern_keywords": ["concatenation", "unparameterized", "interpolation", "injection sink", "taint"],
        },
        "cert_hint": "OSWE Source Code Review & Taint Analysis for SQLi.",
    },
    {
        "vuln_type": "sqli",
        "capability": "validation",
        "exercise_type": "payload_validation",
        "title_en": "UNION Select & Tautology Payload Breakout Validation",
        "description_en": "Differentiate syntax error artifacts and UNION-based column extraction proofs from benign database query failures.",
        "difficulty": "medium",
        "content_json": {
            "expected_classification": "true_positive",
            "proof_indicators": ["union select", "column count", "syntax error", "tautology", "database extract"],
        },
        "cert_hint": "OffSec OSCP / PortSwigger BSCP SQLi Validation.",
    },
    {
        "vuln_type": "sqli",
        "capability": "lab_exploitation",
        "exercise_type": "lab",
        "title_en": "UNION-Based SQLi Hash Extraction Lab",
        "description_en": "Exploit classic SQL injection in the isolated DVWA container to capture the proof flag.",
        "difficulty": "hard",
        "content_json": {
            "sandbox_target": "sqli",
            "proof_flag": "FLAG{sqli_union_select_admin_extracted}",
        },
        "cert_hint": "OSWE / eWPT Database Extraction Practical.",
    },
    {
        "vuln_type": "sqli",
        "capability": "impact_analysis",
        "exercise_type": "impact_analysis",
        "title_en": "SQL Injection CVSS v3.1 Blast Radius & Data Exfiltration Analysis",
        "description_en": "Assess technical and business impact of full database compromise via SQLi, including credential dumping, data integrity destruction, and CVSS vector calculation.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 20,
            "expected_cvss_components": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
            "impact_keywords": ["database exfiltration", "credential theft", "data breach", "integrity", "confidentiality", "compliance"],
        },
        "cert_hint": "Enterprise Threat Modeling & Risk Scoring Standard.",
    },

    # ── Batch 2 Skill 1: ssrf (Container Lab: Juice Shop) ─────────────────────
    {
        "vuln_type": "ssrf",
        "capability": "recognition",
        "exercise_type": "pattern_recognition",
        "title_en": "Spotting Unchecked Destination URL Fetchers & Metadata Sinks",
        "description_en": "Audit backend service fetcher and proxy endpoints to identify unvalidated destination URLs accepting loopback and cloud metadata ranges (169.254.169.254).",
        "difficulty": "medium",
        "content_json": {
            "min_words": 15,
            "target_indicators": ["requests.get(avatar_url)", "169.254.169.254", "/api/import-avatar", "line 11"],
            "pattern_keywords": ["unvalidated url", "metadata", "loopback", "internal service", "ssrf sink"],
        },
        "cert_hint": "OWASP A10 / PortSwigger SSRF Vulnerability Identification.",
    },
    {
        "vuln_type": "ssrf",
        "capability": "validation",
        "exercise_type": "payload_validation",
        "title_en": "Cloud Metadata Extraction & Out-of-Band SSRF Validation",
        "description_en": "Distinguish authentic out-of-band collaborator interactions and AWS IMDS metadata disclosures from blind unreachable destination timeouts.",
        "difficulty": "medium",
        "content_json": {
            "expected_classification": "true_positive",
            "proof_indicators": ["metadata extracted", "iam credentials", "out-of-band", "internal network", "loopback reflection"],
        },
        "cert_hint": "OffSec OSWE / AWS Cloud Security SSRF Triage.",
    },
    {
        "vuln_type": "ssrf",
        "capability": "lab_exploitation",
        "exercise_type": "lab",
        "title_en": "Juice Shop Server-Side Request Forgery Laboratory",
        "description_en": "Exploit server-side request forgery in the isolated Juice Shop container to reach internal services and capture the proof flag.",
        "difficulty": "medium",
        "content_json": {
            "sandbox_target": "ssrf",
            "proof_flag": "FLAG{ssrf_internal_metadata_captured}",
        },
        "cert_hint": "eWPTX / OSCP Hands-on SSRF Exploitation.",
    },

    # ── Batch 2 Skill 2: path_traversal (Container Lab: DVWA) ─────────────────
    {
        "vuln_type": "path_traversal",
        "capability": "recognition",
        "exercise_type": "pattern_recognition",
        "title_en": "Identifying Unsanitized Path Concatenation & Filesystem Sinks",
        "description_en": "Audit file download and view controllers to locate raw path concatenation (os.path.join) lacking canonical path boundary verification.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 15,
            "target_indicators": ["os.path.join(STORAGE_DIR, filename)", "send_file(file_path)", "/download", "line 10"],
            "pattern_keywords": ["concatenation", "directory traversal", "dot-dot-slash", "unvalidated path", "filesystem sink"],
        },
        "cert_hint": "CWE-22 / SANS Top 25 Source Code Audit.",
    },
    {
        "vuln_type": "path_traversal",
        "capability": "validation",
        "exercise_type": "payload_validation",
        "title_en": "Traversing Directory Roots & /etc/passwd Extraction Validation",
        "description_en": "Validate arbitrary file disclosure by analyzing server response artifacts for root system users (root:x:0:0) versus reflection errors.",
        "difficulty": "medium",
        "content_json": {
            "expected_classification": "true_positive",
            "proof_indicators": ["root:x:0:0", "passwd leaked", "arbitrary read", "traversal confirmed", "operating system file"],
        },
        "cert_hint": "PortSwigger BSCP / Bug Bounty Arbitrary File Read Proof.",
    },
    {
        "vuln_type": "path_traversal",
        "capability": "lab_exploitation",
        "exercise_type": "lab",
        "title_en": "DVWA Directory Traversal & Arbitrary File Read Lab",
        "description_en": "Exploit path traversal vulnerabilities in the isolated DVWA container to navigate directory trees and capture the proof flag.",
        "difficulty": "medium",
        "content_json": {
            "sandbox_target": "path_traversal",
            "proof_flag": "FLAG{path_traversal_etc_passwd_extracted}",
        },
        "cert_hint": "OSWE / eWPT Hands-on Directory Traversal Exploitation.",
    },

    # ── Batch 2 Skill 3: file_upload (Container Lab: DVWA) ───────────────────
    {
        "vuln_type": "file_upload",
        "capability": "recognition",
        "exercise_type": "pattern_recognition",
        "title_en": "Auditing Insecure Upload Handlers & Web-Executable Storage",
        "description_en": "Analyze file upload controllers to detect client-supplied filename preservation and storage inside web document roots without extension whitelist enforcement.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 15,
            "target_indicators": ["file.save(destination)", "UPLOAD_FOLDER", "file.filename", "line 12"],
            "pattern_keywords": ["unrestricted upload", "webroot", "extension bypass", "executable directory", "webshell sink"],
        },
        "cert_hint": "CWE-434 / OWASP ASVS V12 File Upload Review.",
    },
    {
        "vuln_type": "file_upload",
        "capability": "validation",
        "exercise_type": "payload_validation",
        "title_en": "Server-Side Script Execution & RCE Validation",
        "description_en": "Confirm true positive arbitrary code execution by verifying dynamic interpreter output (phpinfo / math evaluation) versus static plaintext rendering.",
        "difficulty": "hard",
        "content_json": {
            "expected_classification": "true_positive",
            "proof_indicators": ["code execution", "rce confirmed", "php executed", "webshell proof", "script execution"],
        },
        "cert_hint": "OffSec OSCP / OSWE Remote Code Execution Validation.",
    },
    {
        "vuln_type": "file_upload",
        "capability": "lab_exploitation",
        "exercise_type": "lab",
        "title_en": "DVWA Unrestricted File Upload & Execution Lab",
        "description_en": "Bypass extension and MIME filters in the isolated DVWA container to upload and execute a test payload and capture the proof flag.",
        "difficulty": "hard",
        "content_json": {
            "sandbox_target": "file_upload",
            "proof_flag": "FLAG{arbitrary_file_upload_shell_executed}",
        },
        "cert_hint": "OSWE / eWPTX Hands-on Web Shell Execution.",
    },

    # ── Batch 2 Skill 4: cve_cvss_epss (Local / Vulnerability Intelligence) ───
    {
        "vuln_type": "cve_cvss_epss",
        "capability": "knowledge",
        "exercise_type": "assessment",
        "title_en": "Vulnerability Intelligence Metrics: CVE, CVSS v3.1, and EPSS Probability",
        "description_en": "Explain the distinctions between static severity (CVSS Base Score), exploitation probability (EPSS), and real-world weaponization (CISA KEV).",
        "difficulty": "easy",
        "content_json": {
            "min_words": 30,
            "expected_concepts": ["cvss", "epss", "probability", "severity", "cisa kev"],
        },
        "cert_hint": "FIRST.org / SANS Risk-Based Vulnerability Management.",
    },
    {
        "vuln_type": "cve_cvss_epss",
        "capability": "reporting",
        "exercise_type": "vulnerability_report",
        "title_en": "Authoring a Vulnerability Intelligence Brief & Prioritization Notice",
        "description_en": "Draft an executive vulnerability intelligence notice for an identified CVE, articulating CVSS v3.1 base metrics, live EPSS exploit likelihood percentile, CISA KEV status, and recommended remediation SLA.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 40,
            "required_sections": ["summary", "cvss", "epss", "remediation"],
        },
        "cert_hint": "FIRST.org / CISA Vulnerability Disclosure & Advisory Standards.",
    },
    {
        "vuln_type": "cve_cvss_epss",
        "capability": "impact_analysis",
        "exercise_type": "impact_analysis",
        "title_en": "Composite Risk Calculation: CVSS Severity vs EPSS Probability",
        "description_en": "Formulate a risk-based triage decision balancing high-CVSS theoretical vulnerabilities against high-EPSS actively weaponized exploits in production.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 20,
            "expected_cvss_components": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
            "impact_keywords": ["composite risk", "epss probability", "cisa kev", "prioritization", "weaponization", "triage"],
        },
        "cert_hint": "Enterprise RBVM & Threat-Informed Defense Prioritization.",
    },

    # ── Batch 2 Skill 5: bug_bounty_reporting (Local / Reporting Practice) ────
    {
        "vuln_type": "bug_bounty_reporting",
        "capability": "impact_analysis",
        "exercise_type": "impact_analysis",
        "title_en": "Technical Blast Radius & Financial Risk Impact Justification",
        "description_en": "Formulate a technical blast radius analysis and quantify business and financial exposure (regulatory fines, reputational loss, customer churn) to justify a Critical severity bounty reward.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 20,
            "expected_cvss_components": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
            "impact_keywords": ["blast radius", "business impact", "privilege escalation", "financial risk", "bounty payout"],
        },
        "cert_hint": "Bugcrowd VRT / HackerOne Severity & Reward Valuation Standard.",
    },
    {
        "vuln_type": "bug_bounty_reporting",
        "capability": "reporting",
        "exercise_type": "vulnerability_report",
        "title_en": "Authoring a Professional HackerOne/Bugcrowd Vulnerability Report",
        "description_en": "Draft a comprehensive, professional vulnerability disclosure report with Summary, Steps to Reproduce, Technical/Business Impact, and Remediation.",
        "difficulty": "medium",
        "content_json": {
            "min_words": 40,
            "required_sections": ["summary", "steps to reproduce", "impact", "remediation"],
        },
        "cert_hint": "HackerOne / Bugcrowd Quality Triage Submission Standards.",
    },
    {
        "vuln_type": "bug_bounty_reporting",
        "capability": "remediation",
        "exercise_type": "remediation_review",
        "title_en": "Designing a Coordinated Vulnerability Disclosure Policy & security.txt",
        "description_en": "Formulate an enterprise Vulnerability Disclosure Policy (VDP) and RFC 9116 security.txt configuration establishing safe harbor terms and triage SLAs.",
        "difficulty": "easy",
        "content_json": {
            "defense_concepts": ["security.txt", "vdp", "safe harbor", "contact", "sla", "rfc 9116"],
            "prohibited_patterns": ["unauthorized access prohibited without exception", "immediate prosecution", "no bug bounty"],
        },
        "cert_hint": "RFC 9116 / ISO 29147 Vulnerability Disclosure Standard.",
    },
]


def seed():
    init_db()
    db = _get_db()

    for item in SEED_EXERCISES:
        existing = db.execute(
            "SELECT id FROM learning_exercises WHERE vuln_type = ? AND capability = ? AND exercise_type = ?",
            (item["vuln_type"], item["capability"], item["exercise_type"]),
        ).fetchone()

        if not existing:
            created = create_exercise(
                vuln_type=item["vuln_type"],
                capability=item["capability"],
                exercise_type=item["exercise_type"],
                title_en=item["title_en"],
                description_en=item["description_en"],
                difficulty=item["difficulty"],
                content_json=item["content_json"],
                cert_hint=item["cert_hint"],
            )
            logger.info("Created exercise: %s (%s - %s)", created["title_en"], created["vuln_type"], created["capability"])
        else:
            logger.info("Exercise already exists: %s (%s - %s)", item["title_en"], item["vuln_type"], item["capability"])


if __name__ == "__main__":
    seed()
