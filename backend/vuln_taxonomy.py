"""SecuraX — Unified Vulnerability Taxonomy and Normalization Engine.

Single Source of Truth (SSoT) for vulnerability taxonomy across the platform:
  - Ground truth benchmark datasets (`datasets/*/ground_truth.json`)
  - Vulnerability Encyclopedia & Learning Center (/learn)
  - Skill Ledger (/skills)
  - Shadow Manual Pass (Report triage & manual hunting)
  - Micro-Dojo daily challenges (/dojo)
  - Bug Bounty Learn & Earn composite scoring

All 15 canonical vuln_types from datasets/ are preserved verbatim:
  broken_auth, csrf, deserialization, info_disclosure, missing_csp,
  missing_security_headers, open_redirect, rce, security_misconfig,
  sensitive_data_exposure, session_fixation, sqli, vulnerable_dependency,
  weak_crypto, xss.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# ── Ground Truth 15 Dataset Types (Mandatory Invariant) ──────────────────────────
DATASET_VULN_TYPES = {
    "broken_auth",
    "csrf",
    "deserialization",
    "info_disclosure",
    "missing_csp",
    "missing_security_headers",
    "open_redirect",
    "rce",
    "security_misconfig",
    "sensitive_data_exposure",
    "session_fixation",
    "sqli",
    "vulnerable_dependency",
    "weak_crypto",
    "xss",
}

# ── 11 Scanner Identifiers ───────────────────────────────────────────────────────
SCANNERS = [
    {"id": "web",        "name_en": "Web Core",            "name_ar": "فاحص تطبيقات الويب الأساسي"},
    {"id": "dast",       "name_en": "DAST Engine",         "name_ar": "فاحص التطبيقات الديناميكي"},
    {"id": "sast",       "name_en": "SAST Engine",         "name_ar": "فاحص الشفرة الساكن"},
    {"id": "network",    "name_en": "Network Recon",       "name_ar": "استطلاع وفحص الشبكات"},
    {"id": "ssl",        "name_en": "SSL/TLS Audit",       "name_ar": "تدقيق بروتوكولات التشفير"},
    {"id": "deps",       "name_en": "Dependencies Audit", "name_ar": "تدقيق حزم البرمجيات والتبعيات"},
    {"id": "server",     "name_en": "Server Internal",     "name_ar": "فحص إعدادات الخادم الداخلي"},
    {"id": "server_ext", "name_en": "Server External",     "name_ar": "استكشاف الخادم الخارجي"},
    {"id": "docker",     "name_en": "Docker Security",     "name_ar": "أمان حاويات دوكر"},
    {"id": "dns",        "name_en": "DNS & Email",         "name_ar": "فحص نطاق DNS ومصادقة البريد"},
    {"id": "wordpress",  "name_en": "WordPress Audit",     "name_ar": "تدقيق نظام إدارة المحتوى ووردبريس"},
]

# ── Master Taxonomy Dictionary ──────────────────────────────────────────────────
VULN_TAXONOMY: dict[str, dict[str, Any]] = {
    # ── Core 15 Types (from datasets/) ──────────────────────────────────────────
    "xss": {
        "id": "xss",
        "name_en": "Cross-Site Scripting (XSS)",
        "name_ar": "البرمجة النصية عبر المواقع (XSS)",
        "scanner": "dast",
        "difficulty": "easy",
        "severity_default": "medium",
        "description_en": "Flaw allowing injection of malicious client-side JavaScript into trusted web applications.",
        "description_ar": "ثغرة تتيح للمهاجم حقن نصوص جافاسكريبت خبيثة تنفذ في متصفح الضحية لسرقة الجلسات أو تغيير الواجهة.",
        "remediation_en": "Implement contextual output encoding, robust Content Security Policy (CSP), and use modern frameworks with auto-escaping.",
        "remediation_ar": "تطبيق ترميز السياق للمخرجات واعتماد سياسة أمن محتوى (CSP) صارمة واستخدام أطر عمل حديثة تفلت المدخلات تلقائياً.",
        "owasp": "https://owasp.org/www-community/attacks/xss/",
        "portswigger": "https://portswigger.net/web-security/cross-site-scripting",
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting",
    },
    "sqli": {
        "id": "sqli",
        "name_en": "SQL Injection (SQLi)",
        "name_ar": "حقن قواعد البيانات (SQLi)",
        "scanner": "dast",
        "difficulty": "hard",
        "severity_default": "high",
        "description_en": "Untrusted user inputs interfere with backend database queries, allowing data exfiltration or authentication bypass.",
        "description_ar": "تداخل مدخلات غير موثوقة مع استعلامات قاعدة البيانات، مما يسمح بتسريب البيانات أو تجاوز المصادقة أو تلفها.",
        "remediation_en": "Use parameterized queries (prepared statements) and Object-Relational Mapping (ORM) frameworks.",
        "remediation_ar": "استخدام الاستعلامات المعلمة (Prepared Statements) أو أطر عمل الـ ORM الآمنة لربط المتغيرات.",
        "owasp": "https://owasp.org/www-community/attacks/SQL_Injection",
        "portswigger": "https://portswigger.net/web-security/sql-injection",
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/sql-injection",
    },
    "csrf": {
        "id": "csrf",
        "name_en": "Cross-Site Request Forgery (CSRF)",
        "name_ar": "تزوير الطلبات عبر المواقع (CSRF)",
        "scanner": "dast",
        "difficulty": "medium",
        "severity_default": "medium",
        "description_en": "Forces an authenticated user into executing unwanted state-changing actions on a trusted application.",
        "description_ar": "إجبار متصفح المستخدم المصادق على تنفيذ إجراءات غير مرغوب فيها دون علمه أو إذنه.",
        "remediation_en": "Enforce anti-CSRF tokens (SameSite=Lax/Strict cookies and custom X-CSRFToken headers).",
        "remediation_ar": "استخدام رموز CSRF الفريدة وتعيين سمة SameSite للكوكيز والتحقق من ترويسات Origin/Referer.",
        "owasp": "https://owasp.org/www-community/attacks/csrf",
        "portswigger": "https://portswigger.net/web-security/csrf",
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery",
    },
    "open_redirect": {
        "id": "open_redirect",
        "name_en": "Open URL Redirection",
        "name_ar": "إعادة التوجيه المفتوح (Open Redirect)",
        "scanner": "web",
        "difficulty": "easy",
        "severity_default": "medium",
        "description_en": "A parameter accepts a user-controlled URL without verifying that the destination domain is safe.",
        "description_ar": "قبول روابط تحويل يحددها المستخدم دون التحقق من نطاق الوجهة، مما يسهل حملات التصيد الاحتيالي.",
        "remediation_en": "Disallow external redirect targets or validate against a strict internal allowlist.",
        "remediation_ar": "تجنب إعادة التوجيه بناءً على معطيات المستخدم، أو استخدام قائمة بيضاء صارمة للنطاقات المسموحة.",
        "owasp": "https://owasp.org/www-community/attacks/Open_redirect",
        "portswigger": "https://portswigger.net/web-security/open-redirection",
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/open-redirect",
    },
    "broken_auth": {
        "id": "broken_auth",
        "name_en": "Broken Authentication",
        "name_ar": "خلل في آليات المصادقة وإدارة الجلسات",
        "scanner": "web",
        "difficulty": "hard",
        "severity_default": "high",
        "description_en": "Compromised credential validation, weak session tokens, or logic flaws in login and password reset flows.",
        "description_ar": "ضعف في معالجة الجلسات ورموز التوكن وتخزين كلمات المرور مما يسمح بانتحال شخصية المستخدمين.",
        "remediation_en": "Implement multi-factor authentication, robust session renewal post-login, and rate-limit authentication endpoints.",
        "remediation_ar": "تفعيل المصادقة متعددة العوامل، وتجديد معرف الجلسة بعد تسجيل الدخول، وتطبيق حدود المعدل ضد التخمين.",
        "owasp": "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
        "portswigger": "https://portswigger.net/web-security/authentication",
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/authentication-bypass",
    },
    "security_misconfig": {
        "id": "security_misconfig",
        "name_en": "Security Misconfiguration",
        "name_ar": "سوء التهيئة والإعدادات الأمنية",
        "scanner": "server",
        "difficulty": "easy",
        "severity_default": "medium",
        "description_en": "Default configuration settings, unneeded enabled features, missing security headers, or open cloud storage.",
        "description_ar": "استخدام الإعدادات الافتراضية غير الآمنة أو تفعيل خدمات غير ضرورية أو غياب الترويسات الدفاعية.",
        "remediation_en": "Follow automated hardening checklists, disable unnecessary HTTP verbs, and remove default test files.",
        "remediation_ar": "تطبيق أدلة التصليد القياسية (Hardening Guides)، وحذف الملفات الافتراضية، وإلغاء تنشيط الميزات غير المستخدمة.",
        "owasp": "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/security-misconfiguration",
    },
    "sensitive_data_exposure": {
        "id": "sensitive_data_exposure",
        "name_en": "Sensitive Data Exposure",
        "name_ar": "كشف وتسريب البيانات الحساسة",
        "scanner": "sast",
        "difficulty": "medium",
        "severity_default": "high",
        "description_en": "Inadequate protection of sensitive data such as PII, credit cards, credentials, or proprietary intellectual property.",
        "description_ar": "عدم حماية البيانات الحساسة بالشكل الكافي سواء أثناء النقل أو التخزين مما يعرضها للاعتراض والتسريب.",
        "remediation_en": "Encrypt sensitive data at rest and in transit, mask PII in responses, and classify data sensitivity.",
        "remediation_ar": "تشفير البيانات الحساسة أثناء النقل والتخزين، وحجب أرقام الهويات والبطاقات في الردود البرمجية.",
        "owasp": "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-methodology",
    },
    "info_disclosure": {
        "id": "info_disclosure",
        "name_en": "Information Disclosure",
        "name_ar": "إفشاء وتسريب المعلومات الفنية",
        "scanner": "server_ext",
        "difficulty": "easy",
        "severity_default": "low",
        "description_en": "Leaking verbose error messages, stack traces, environment variables, or internal host names.",
        "description_ar": "تسريب معلومات تقنية مثل تفاصيل الأخطاء (Stack Traces) والمسارات الداخلية وإصدارات الحزم للمهاجمين.",
        "remediation_en": "Disable verbose error pages in production, sanitize HTTP headers, and enforce generic error templates.",
        "remediation_ar": "إيقاف صفحات الخطأ التفصيلية في بيئة الإنتاج، وإزالة الترويسات الكاشفة للإصدارات وتطبيق صفحات خطأ عامة.",
        "owasp": "https://owasp.org/www-community/Improper_Error_Handling",
        "portswigger": "https://portswigger.net/web-security/information-disclosure",
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/information-disclosure",
    },
    "missing_security_headers": {
        "id": "missing_security_headers",
        "name_en": "Missing HTTP Security Headers",
        "name_ar": "غياب ترويسات الأمان HTTP الدفاعية",
        "scanner": "server",
        "difficulty": "easy",
        "severity_default": "low",
        "description_en": "Absence of defensive browser headers such as HSTS, X-Frame-Options, X-Content-Type-Options, and Referrer-Policy.",
        "description_ar": "عدم إرسال ترويسات الأمان الأساسية التي توجه متصفح العميل لتفعيل دفاعات مضمنة ضد الهجمات الشائعة.",
        "remediation_en": "Configure web servers to send Strict-Transport-Security, X-Frame-Options: DENY, and X-Content-Type-Options: nosniff.",
        "remediation_ar": "ضبط الخادم لإرسال ترويسات HSTS و X-Frame-Options و X-Content-Type-Options لحماية المتصفح.",
        "owasp": "https://owasp.org/www-project-secure-headers/",
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/special-http-headers",
    },
    "deserialization": {
        "id": "deserialization",
        "name_en": "Insecure Deserialization",
        "name_ar": "فك التسلسل غير الآمن للبيانات (Insecure Deserialization)",
        "scanner": "sast",
        "difficulty": "hard",
        "severity_default": "high",
        "description_en": "Deserializing untrusted data without verification, leading to remote code execution or arbitrary object injection.",
        "description_ar": "إعادة بناء الكائنات والبيانات من تدفقات غير موثوقة دون تدقيق، مما يؤدي لتنفيذ أوامر أو العبث بمنطق التطبيق.",
        "remediation_en": "Do not accept serialized objects from untrusted sources; use safe data formats like JSON or Protocol Buffers.",
        "remediation_ar": "تجنب تمرير كائنات مسلسلة عبر واجهات المستخدم، والاعتماد على تنسيقات بيانات مجردة مثل JSON.",
        "owasp": "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
        "portswigger": "https://portswigger.net/web-security/deserialization",
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/deserialization",
    },
    "vulnerable_dependency": {
        "id": "vulnerable_dependency",
        "name_en": "Vulnerable Software Dependency",
        "name_ar": "حزم وبرمجيات طرف ثالث مصابة بثغرات معروفة",
        "scanner": "deps",
        "difficulty": "easy",
        "severity_default": "medium",
        "description_en": "Using third-party libraries, modules, or packages with published CVE security advisories.",
        "description_ar": "الاعتماد على مكتبات أو حزم برمجية مفتوحة المصدر تحتوي على ثغرات أمنية معلنة في قواعد بيانات CVE.",
        "remediation_en": "Continuously scan dependencies using automated tools (e.g. OSV, Trivy) and upgrade vulnerable packages.",
        "remediation_ar": "الفحص المستمر لشجرة التبعيات عبر أدوات تدقيق الاعتماديات وترقية الحزم المصابة للإصدارات المعالجة.",
        "owasp": "https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities",
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-methodology",
    },
    "rce": {
        "id": "rce",
        "name_en": "Remote Code Execution (RCE) / Command Injection",
        "name_ar": "تنفيذ التعليمات البرمجية والأوامر عن بعد (RCE)",
        "scanner": "dast",
        "difficulty": "hard",
        "severity_default": "critical",
        "description_en": "Executing arbitrary operating system commands or malicious code on the host server via application input.",
        "description_ar": "حقن وتنفيذ أوامر نظام التشغيل أو تعليمات برمجية مباشرة على الخادم مما يمنح المهاجم سيطرة تامة.",
        "remediation_en": "Avoid invoking shell commands directly; use language built-in APIs with argument arrays, and apply strict input whitelisting.",
        "remediation_ar": "تجنب استدعاء مفسرات الأوامر مباشرة (shell=True)، واستخدام الواجهات البرمجية الآمنة وقوائم الإدخال البيضاء.",
        "owasp": "https://owasp.org/www-community/attacks/Command_Injection",
        "portswigger": "https://portswigger.net/web-security/os-command-injection",
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/command-injection",
    },
    "missing_csp": {
        "id": "missing_csp",
        "name_en": "Missing Content Security Policy (CSP)",
        "name_ar": "غياب سياسة أمان المحتوى (Content Security Policy)",
        "scanner": "server",
        "difficulty": "medium",
        "severity_default": "medium",
        "description_en": "Lack of Content-Security-Policy header leaves the application vulnerable to XSS and clickjacking attacks.",
        "description_ar": "غياب ترويسة CSP يحرم التطبيق من جدار ناري متقدم داخل المتصفح يقيد مصادر تحميل السكربتات والوسائط.",
        "remediation_en": "Deploy a strict Content-Security-Policy with script-src 'self' and cryptographic nonces.",
        "remediation_ar": "تفعيل ترويسة Content-Security-Policy مع تقييد مصادر السكربتات واستخدام Nonces تشفيرية.",
        "owasp": "https://owasp.org/www-project-secure-headers/#content-security-policy",
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass",
    },
    "session_fixation": {
        "id": "session_fixation",
        "name_en": "Session Fixation & Insecure Cookie Handling",
        "name_ar": "تثبيت الجلسة والتعامل غير الآمن مع ملفات تعريف الارتباط",
        "scanner": "web",
        "difficulty": "medium",
        "severity_default": "medium",
        "description_en": "Failing to reissue session identifiers upon authentication or omitting HttpOnly, Secure, and SameSite flags.",
        "description_ar": "عدم تجديد معرف الجلسة بعد تسجيل الدخول بنجاح أو إرسال كوكيز الجلسة دون ترويسات الحماية (HttpOnly و Secure).",
        "remediation_en": "Regenerate session IDs on privilege escalation; apply HttpOnly, Secure, and SameSite=Lax flags.",
        "remediation_ar": "إعادة توليد معرّف الجلسة فور المصادقة، وإلزام تعيين خصائص HttpOnly و Secure و SameSite لكافة الكوكيز الحساسة.",
        "owasp": "https://owasp.org/www-community/attacks/Session_fixation",
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/session-fixation",
    },
    "weak_crypto": {
        "id": "weak_crypto",
        "name_en": "Weak Cryptographic Algorithms & Ciphers",
        "name_ar": "استخدام خوارزميات ومفاتيح تشفير ضعيفة أو متقادمة",
        "scanner": "ssl",
        "difficulty": "medium",
        "severity_default": "medium",
        "description_en": "Using obsolete ciphers (RC4, 3DES, CBC mode), broken hashes (MD5, SHA1), or short cryptographic keys.",
        "description_ar": "الاعتماد على خوارزميات تشفير مجروحة أو غير آمنة تسهل فك تشفير البيانات أو هجمات وسيط الشبكة.",
        "remediation_en": "Migrate to AES-GCM, ChaCha20, SHA-256+, and disable deprecated ciphers in web and TLS servers.",
        "remediation_ar": "استخدام خوارزميات التشفير الموثوقة حديثاً (AES-256-GCM, SHA-256+) وإلغاء تفعيل بروتوكولات CBC و 3DES.",
        "owasp": "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssl-tls-protocols",
    },

    # ── Extended Types Covering All 11 Scanners ──────────────────────────────────
    "ssrf": {
        "id": "ssrf",
        "name_en": "Server-Side Request Forgery (SSRF)",
        "name_ar": "تزوير الطلبات من جانب الخادم (SSRF)",
        "scanner": "dast",
        "difficulty": "hard",
        "severity_default": "high",
        "description_en": "Backend web server coerced into sending HTTP requests to unexpected internal destinations or metadata services.",
        "description_ar": "إجبار الخادم على إرسال طلبات نحو شبكات داخلية أو خدمات سحابية خاصة (Cloud Metadata) والتجسس عليها.",
        "remediation_en": "Enforce strict IP/domain allowlisting, block private IP ranges (RFC 1918), and disable following HTTP redirects.",
        "remediation_ar": "تقييد الطلبات الخارجية بقوائم بيضاء معتمدة، وحظر العناوين الخاصة والمحلية وخدمات الـ Metadata السحابية.",
        "owasp": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        "portswigger": "https://portswigger.net/web-security/ssrf",
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery",
    },
    "idor": {
        "id": "idor",
        "name_en": "Insecure Direct Object Reference (IDOR)",
        "name_ar": "المرجع المباشر غير الآمن للكائنات (IDOR)",
        "scanner": "dast",
        "difficulty": "medium",
        "severity_default": "high",
        "description_en": "Direct access to internal objects (files, records, database keys) via user input without authorization checks.",
        "description_ar": "الوصول المباشر لسجلات أو ملفات مستخدمين آخرين بمجرد تعديل رقم المعرف (ID) في الرابط أو الطلب دون تفويض.",
        "remediation_en": "Implement granular server-side object-level access control checks for every record access.",
        "remediation_ar": "فرض التحقق من صلاحيات المستخدم على مستوى الكائن المطلوب في كل استدعاء من جانب الخادم.",
        "owasp": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
        "portswigger": "https://portswigger.net/web-security/access-control/idor",
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/idor",
    },
    "cors": {
        "id": "cors",
        "name_en": "CORS Misconfiguration",
        "name_ar": "سوء تهيئة مشاركة الموارد عبر الأصول (CORS)",
        "scanner": "web",
        "difficulty": "easy",
        "severity_default": "medium",
        "description_en": "Permissive Access-Control-Allow-Origin header combined with Allow-Credentials permits data theft across domains.",
        "description_ar": "السماح لأي نطاق خارجي بقراءة بيانات المستخدمين عبر ترويسات CORS المفتوحة مع تفعيل الكوكيز.",
        "remediation_en": "Explicitly whitelist trusted origins instead of reflecting the Origin header or using wildcards with credentials.",
        "remediation_ar": "تحديد قائمة بيضاء دقيقة للنطاقات المسموح لها، وتجنب استخدام النجمة (*) مع تفعيل الاعتماديات.",
        "owasp": "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
        "portswigger": "https://portswigger.net/web-security/cors",
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/cors-bypass",
    },
    "parameter_pollution": {
        "id": "parameter_pollution",
        "name_en": "HTTP Parameter Pollution (HPP)",
        "name_ar": "تلويث معاملات بروتوكول HTTP (HPP)",
        "scanner": "web",
        "difficulty": "medium",
        "severity_default": "medium",
        "description_en": "Supplying duplicate parameter keys to bypass Web Application Firewall filters or alter backend logic.",
        "description_ar": "إرسال نفس المعامل أكثر من مرة في الطلب لاستغلال الاختلاف في معالجة المدخلات بين جدار الحماية والخادم.",
        "remediation_en": "Ensure web server and application frameworks adhere to consistent parameter parsing rules.",
        "remediation_ar": "توحيد قواعد معالجة المعاملات عبر طبقات التطبيق ورفض الطلبات ذات المعاملات المتكررة المشبوهة.",
        "owasp": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution",
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/parameter-pollution",
    },
    "takeover": {
        "id": "takeover",
        "name_en": "Subdomain Takeover",
        "name_ar": "الاستيلاء على النطاقات الفرعية (Subdomain Takeover)",
        "scanner": "dns",
        "difficulty": "hard",
        "severity_default": "high",
        "description_en": "DNS CNAME or routing records pointing to deactivated third-party cloud services or hosting providers.",
        "description_ar": "توجيه سجلات DNS إلى خدمات سحابية محذوفة أو شاغرة مما يتيح للمهاجم حجزها وانتحال النطاق بالكامل.",
        "remediation_en": "Audit DNS records regularly and prune dangling CNAME/A entries pointing to inactive services.",
        "remediation_ar": "المراجعة الدورية لسجلات DNS وإزالة سجلات CNAME المعلقة نحو خدمات أو منصات ملغاة.",
        "owasp": "https://owasp.org/www-community/attacks/Subdomain_takeover",
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/subdomain-takeover",
    },
    "hardcoded_secrets": {
        "id": "hardcoded_secrets",
        "name_en": "Hardcoded Secrets & Credentials",
        "name_ar": "تضمين مفاتيح وكلمات سر سرية داخل الشفرة المصدرية",
        "scanner": "sast",
        "difficulty": "easy",
        "severity_default": "critical",
        "description_en": "Embedding API keys, cryptographic private keys, or passwords directly into application source code or Dockerfiles.",
        "description_ar": "تثبيت المفاتيح السرية وبيانات المرور ومفاتيح الـ API في الكود أو ملفات الحاويات دون عزلها كمتغيرات بيئة.",
        "remediation_en": "Extract secrets into environment variables, use dedicated secret managers (Vault), and revoke exposed keys.",
        "remediation_ar": "نقل الأسرار إلى متغيرات بيئة آمنة واستخدام مدراء الأسرار (Secret Managers) وتدوير المفاتيح المكشوفة.",
        "owasp": "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password",
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-methodology",
    },
    "open_ports": {
        "id": "open_ports",
        "name_en": "Unnecessary Exposed Network Ports",
        "name_ar": "منافذ شبكية مكشوفة وغير ضرورية",
        "scanner": "network",
        "difficulty": "easy",
        "severity_default": "medium",
        "description_en": "Publicly reachable administrative or database services (SSH, Telnet, MySQL, Redis, RDP).",
        "description_ar": "فتح منافذ خدمات إدارية أو قواعد بيانات على الشبكة العامة دون تقييد بجدران نارية أو شبكات خاصة.",
        "remediation_en": "Enforce firewall rules, close unused ports, and restrict access through VPNs and bastion hosts.",
        "remediation_ar": "إغلاق المنافذ غير الضرورية وتطبيق سياسات الجدار الناري وحصر الإدارة عبر شبكات VPN الخاصة.",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/network-services-pentesting",
    },
    "service_version_exposure": {
        "id": "service_version_exposure",
        "name_en": "Outdated Service Version Exposure",
        "name_ar": "كشف إصدارات خدمات وخوادم متقادمة ومصابة",
        "scanner": "network",
        "difficulty": "medium",
        "severity_default": "medium",
        "description_en": "Service banners revealing specific outdated software versions with public exploit availability.",
        "description_ar": "ظهور إصدارات برمجيات الخادم والخدمات المتقادمة في البنرات مما يساعد المهاجم على مطابقة ثغرات CVE الجاهزة.",
        "remediation_en": "Upgrade system services and daemon software to current stable releases; suppress version banners.",
        "remediation_ar": "ترقية الخدمات والأنظمة للإصدارات المستقرة الحديثة وإخفاء رقم الإصدار من لافتات الاستجابة.",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/network-services-pentesting",
    },
    "deprecated_protocols": {
        "id": "deprecated_protocols",
        "name_en": "Deprecated SSL/TLS Protocols (TLS 1.0/1.1 / SSLv3)",
        "name_ar": "دعم بروتوكولات تشفير متقادمة وغير آمنة",
        "scanner": "ssl",
        "difficulty": "easy",
        "severity_default": "medium",
        "description_en": "Supporting outdated cryptographic protocols vulnerable to POODLE, BEAST, or downgrade attacks.",
        "description_ar": "استمرار دعم بروتوكولات قديمة مثل SSLv3 أو TLS 1.0/1.1 مما يعرض الاتصال لهجمات التخفيض وفك التشفير.",
        "remediation_en": "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1; enforce TLS 1.2 and TLS 1.3 exclusively.",
        "remediation_ar": "تعطيل كافة البروتوكولات القديمة وحصر الاتصال على بروتوكولي TLS 1.2 و TLS 1.3 الحديثين.",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssl-tls-protocols",
    },
    "certificate_issues": {
        "id": "certificate_issues",
        "name_en": "SSL/TLS Certificate Validity & Trust Flaws",
        "name_ar": "خلل في صلاحية وموثوقية شهادات SSL/TLS",
        "scanner": "ssl",
        "difficulty": "medium",
        "severity_default": "medium",
        "description_en": "Expired, self-signed, untrusted CA, or hostname mismatch in server SSL certificates.",
        "description_ar": "استخدام شهادات تشفير منتهية الصلاحية أو ذاتية التوقيع أو غير متطابقة مع اسم النطاق.",
        "remediation_en": "Deploy valid certificates from trusted public Certificate Authorities and automate renewal.",
        "remediation_ar": "إصدار وتثبيت شهادات معتمدة من جهات موثوقة (CAs) وأتمتة التجديد الدوري قبل انتهاء الصلاحية.",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssl-tls-protocols",
    },
    "heartbleed_robot": {
        "id": "heartbleed_robot",
        "name_en": "Critical TLS Implementation Flaws (Heartbleed / ROBOT)",
        "name_ar": "ثغرات بروتوكول TLS الحرجة (Heartbleed و ROBOT)",
        "scanner": "ssl",
        "difficulty": "hard",
        "severity_default": "critical",
        "description_en": "Implementation bugs in TLS libraries leaking server private keys or process memory.",
        "description_ar": "أخطاء تنفيذية خطيرة في مكتبات التشفير تتيح قراءة الذاكرة الحية للخادم أو استخراج المفاتيح الخاصة.",
        "remediation_en": "Patch and update OpenSSL and crypto libraries; disable vulnerable RSA encryption key exchanges.",
        "remediation_ar": "تحديث حزم OpenSSL والمكتبات المشفرة لآخر إصدار وتعطيل تبادل المفاتيح عبر RSA القديم.",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssl-tls-protocols",
    },
    "directory_listing": {
        "id": "directory_listing",
        "name_en": "Enabled Directory Listing / Browsing",
        "name_ar": "تفعيل استعراض المجلدات والملفات (Directory Listing)",
        "scanner": "server",
        "difficulty": "easy",
        "severity_default": "low",
        "description_en": "Web server indexes directories automatically, exposing internal structure and hidden files.",
        "description_ar": "سماح خادم الويب بتصفح شجرة المجلدات عند غياب ملف الفهرس (index) مما يكشف ملفات حساسة.",
        "remediation_en": "Disable directory indexes in server configurations (Options -Indexes in Apache, autoindex off in Nginx).",
        "remediation_ar": "تعطيل فهرسة المجلدات في خادم الويب (مثل Options -Indexes في أباتشي و autoindex off في إنجن إكس).",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/information-disclosure",
    },
    "default_credentials": {
        "id": "default_credentials",
        "name_en": "Default Administrative Credentials",
        "name_ar": "بيانات تسجيل الدخول الإدارية الافتراضية",
        "scanner": "server",
        "difficulty": "medium",
        "severity_default": "high",
        "description_en": "Administrative panels, databases, or devices operating with manufacturer or default factory passwords.",
        "description_ar": "ترك لوحات التحكم الإدارية أو قواعد البيانات بكلمات المرور الافتراضية للمصنع (مثل admin/admin).",
        "remediation_en": "Force password change upon initial deployment, disable default accounts, and enforce complex passphrases.",
        "remediation_ar": "إلزام تغيير كلمات المرور عند التثبيت لأول مرة وتعطيل الحسابات التجريبية الافتراضية.",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force",
    },
    "dangerous_http_methods": {
        "id": "dangerous_http_methods",
        "name_en": "Dangerous HTTP Methods Enabled (TRACE / OPTIONS / PUT / DELETE)",
        "name_ar": "تفعيل دوال بروتوكول HTTP غير الآمنة (TRACE / PUT / DELETE)",
        "scanner": "server_ext",
        "difficulty": "easy",
        "severity_default": "low",
        "description_en": "Web server allows dangerous verbs like TRACE (enabling XST) or uncontrolled PUT/DELETE.",
        "description_ar": "تفعيل طرق استدعاء غير ضرورية تتيح التلاعب بالملفات أو تسهل هجمات سرقة الكوكيز عبر Cross-Site Tracing.",
        "remediation_en": "Disable TRACE, TRACK, and restrict PUT/DELETE to authenticated REST endpoints only.",
        "remediation_ar": "تعطيل طرق TRACE و TRACK وتقييد PUT و DELETE للواجهات الموثقة فقط.",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/special-http-headers",
    },
    "server_banner_disclosure": {
        "id": "server_banner_disclosure",
        "name_en": "Verbose Web Server & Technology Banner Disclosure",
        "name_ar": "إفشاء بنرات وبيانات تعريف خادم الويب وتقنياته",
        "scanner": "server_ext",
        "difficulty": "easy",
        "severity_default": "low",
        "description_en": "Server and X-Powered-By response headers advertise server OS, engine, and exact component builds.",
        "description_ar": "إرسال معلومات دقيقة عن نوع الخادم ونظام التشغيل في ترويسات الاستجابة مثل Server و X-Powered-By.",
        "remediation_en": "Suppress Server and X-Powered-By headers (ServerTokens Prod in Apache, server_tokens off in Nginx).",
        "remediation_ar": "إخفاء ترويسات الخادم وإيقاف إظهار تقنيات التشغيل عبر ضبط ServerTokens Prod و server_tokens off.",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/information-disclosure",
    },
    "exposed_status_page": {
        "id": "exposed_status_page",
        "name_en": "Exposed Server Status & Metric Endpoints",
        "name_ar": "كشف صفحات المراقبة وحالة الخادم (Server Status)",
        "scanner": "server_ext",
        "difficulty": "medium",
        "severity_default": "medium",
        "description_en": "Server status, Prometheus metrics, or health probes exposed publicly without access controls.",
        "description_ar": "ترك مسارات المراقبة مثل /server-status أو /metrics مفتوحة للعموم مما يفشي طلبات وبيانات المستخدمين.",
        "remediation_en": "Restrict server-status and diagnostic routes to local loopback or authenticated internal proxies.",
        "remediation_ar": "قصر الوصول لصفحات الحالة والتشخيص على العناوين المحلية والشبكات الإدارية المعتمدة.",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/pentesting-web/information-disclosure",
    },
    "slowloris_dos": {
        "id": "slowloris_dos",
        "name_en": "Slowloris Partial HTTP Denial of Service",
        "name_ar": "قابلية حجب الخدمة عبر هجوم الطلبات البطيئة (Slowloris)",
        "scanner": "server_ext",
        "difficulty": "hard",
        "severity_default": "medium",
        "description_en": "Web server keeps worker threads occupied indefinitely awaiting incomplete HTTP header streams.",
        "description_ar": "استنزاف موارد وخيوط معالجة الخادم عن طريق إرسال ترويسات HTTP مجزأة وبطيئة للغاية.",
        "remediation_en": "Deploy reverse proxies (Nginx/Cloudflare) with aggressive request header timeout and read limits.",
        "remediation_ar": "ضبط حدود مهلة قراءة الترويسات (RequestReadTimeout) واستخدام بروكسي عكسي ذكي لحماية خيوط العمل.",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-methodology",
    },
    "exposed_docker_api": {
        "id": "exposed_docker_api",
        "name_en": "Unauthenticated Exposed Docker Socket / API",
        "name_ar": "كشف منفذ وواجهة تحكم دوكر دون مصادقة (Docker API)",
        "scanner": "docker",
        "difficulty": "medium",
        "severity_default": "critical",
        "description_en": "Docker daemon socket (port 2375/2376) reachable without mutual TLS authentication, granting full host takeover.",
        "description_ar": "إتاحة مقبس ومنافذ إدارة حاويات دوكر على الشبكة دون تشفير أو مصادقة، مما يتيح السيطرة التامة على المضيف.",
        "remediation_en": "Never expose TCP port 2375 publicly; enforce mutual TLS on port 2376 or use Unix sockets with tight permissions.",
        "remediation_ar": "حظر إتاحة منفذ 2375 عبر الشبكة وتفعيل المصادقة التشفيرية المتبادلة (mTLS) لحماية واجهة دوكر.",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security",
    },
    "privileged_containers": {
        "id": "privileged_containers",
        "name_en": "Privileged Containers & Dangerous Host Mounts",
        "name_ar": "حاويات دوكر ذات صلاحيات فائقة وربط مسارات المضيف الخطرة",
        "scanner": "docker",
        "difficulty": "hard",
        "severity_default": "high",
        "description_en": "Running containers with --privileged or mounting host root (/), docker.sock, or sensitive device nodes.",
        "description_ar": "تشغيل الحاويات بوضع الامتيازات الكاملة أو ربط مقبس دوكر أو جذر نظام المضيف مما يسهل الهروب من الحاوية.",
        "remediation_en": "Drop all unnecessary capabilities (cap-drop=ALL), avoid --privileged, and do not mount the host docker.sock.",
        "remediation_ar": "إسقاط كافة الصلاحيات الزائدة واستبعاد خيار Privileged وتجنب ربط ملفات نظام المضيف داخل الحاويات.",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security",
    },
    "missing_spf_dkim_dmarc": {
        "id": "missing_spf_dkim_dmarc",
        "name_en": "Missing or Permissive SPF / DKIM / DMARC Records",
        "name_ar": "غياب أو تساهل سجلات مصادقة البريد الإلكتروني (SPF/DKIM/DMARC)",
        "scanner": "dns",
        "difficulty": "easy",
        "severity_default": "medium",
        "description_en": "Inadequate domain email authentication records allow malicious threat actors to spoof corporate emails.",
        "description_ar": "غياب سجلات مصادقة وتوقيع البريد في الـ DNS مما يتيح للمهاجمين تزوير رسائل باسم النطاق لتنفيذ هجمات التصيد.",
        "remediation_en": "Configure strict SPF records (-all), implement cryptographic DKIM signing, and deploy DMARC policy with p=reject.",
        "remediation_ar": "نشر سجلات SPF مقيدة وتفعيل توقيع DKIM وتطبيق سياسة DMARC بوضع الرفض (p=reject).",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns",
    },
    "dns_zone_transfer": {
        "id": "dns_zone_transfer",
        "name_en": "Unrestricted DNS Zone Transfer (AXFR Enabled)",
        "name_ar": "السماح بنقل منطقة DNS دون قيود (AXFR Zone Transfer)",
        "scanner": "dns",
        "difficulty": "medium",
        "severity_default": "medium",
        "description_en": "Authoritative nameserver permits unrestricted zone transfers, exposing internal hostnames and IP topology.",
        "description_ar": "سماح خوادم الأسماء بنسخ جدول النطاق كاملاً لأي جهة مما يكشف كافة النطاقات الفرعية والبنية الداخلية.",
        "remediation_en": "Restrict AXFR zone transfers to authorized secondary nameserver IP addresses only.",
        "remediation_ar": "تقييد استعلامات AXFR وحصرها حصرياً على عناوين خوادم الأسماء الثانوية المصرح بها.",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns",
    },
    "outdated_plugins": {
        "id": "outdated_plugins",
        "name_en": "Vulnerable Outdated WordPress Plugins & Themes",
        "name_ar": "إضافات وقوالب ووردبريس غير محدثة ومصابة بثغرات",
        "scanner": "wordpress",
        "difficulty": "easy",
        "severity_default": "high",
        "description_en": "Active plugins or themes containing known CVEs (SQLi, XSS, arbitrary file upload) in WordPress deployments.",
        "description_ar": "تشغيل إضافات أو قوالب قديمة في ووردبريس تحتوي على ثغرات معروفة يمكن استغلالها لاختراق الموقع.",
        "remediation_en": "Update WordPress core, themes, and plugins to their latest versions, and remove inactive components.",
        "remediation_ar": "تحديث نواة ووردبريس وكافة الإضافات والقوالب باستمرار وحذف الإضافات غير المستخدمة.",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress",
    },
    "xmlrpc_exposure": {
        "id": "xmlrpc_exposure",
        "name_en": "Exposed WordPress XML-RPC Interface",
        "name_ar": "كشف واجهة ووردبريس البرمجية القديمة (XML-RPC)",
        "scanner": "wordpress",
        "difficulty": "medium",
        "severity_default": "low",
        "description_en": "Unrestricted xmlrpc.php endpoint leveraged for brute-force password amplification and pingback DDoS reflection.",
        "description_ar": "بقاء مسار xmlrpc.php مفعلاً مما يتيح تضخيم هجمات تخمين كلمات المرور واستغلال الخادم في هجمات الحرمان من الخدمة.",
        "remediation_en": "Disable xmlrpc.php via web server rules or application security plugins if mobile API is not required.",
        "remediation_ar": "تعطيل الوصول إلى ملف xmlrpc.php من خلال خادم الويب أو إضافات الأمان عند عدم الحاجة له.",
        "owasp": None,
        "portswigger": None,
        "hacktricks": "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress",
    },
}

# ── Explicit Scanner Check Mapping ──────────────────────────────────────────────
# Maps scanner check tokens directly to canonical vuln_type keys
CHECK_MAP: dict[str, str] = {
    # Server External Checks
    "missing_hsts":                  "missing_security_headers",
    "missing_csp":                   "missing_csp",
    "missing_x_frame_options":        "missing_security_headers",
    "missing_x_content_type_options": "missing_security_headers",
    "missing_referrer_policy":        "missing_security_headers",
    "missing_permissions_policy":     "missing_security_headers",
    "header_server_disclosure":      "server_banner_disclosure",
    "header_x_powered_by":           "server_banner_disclosure",
    "weak_tls_version":              "deprecated_protocols",
    "expired_ssl_cert":              "certificate_issues",
    "ssl_cert_expiring_soon":        "certificate_issues",
    "ssl_error":                     "certificate_issues",
    "vulnerable_apache_version":     "service_version_exposure",
    "outdated_apache_major":         "service_version_exposure",
    "vulnerable_nginx_version":      "service_version_exposure",
    "outdated_nginx_major":          "service_version_exposure",
    "os_detection":                  "info_disclosure",
    "https_not_available":           "security_misconfig",
    "http_unreachable":              "info_disclosure",
    "netscan_failed":                "info_disclosure",
    "netscan_unavailable":           "info_disclosure",

    # SSL / SSLyze Checks
    "sslyze-heartbleed":             "heartbleed_robot",
    "sslyze-robot":                  "heartbleed_robot",
    "sslyze-openssl-ccs":            "weak_crypto",
    "sslyze-tls-compression":        "weak_crypto",
    "sslyze-renegotiation-dos":      "weak_crypto",
    "ssl_overall":                   "certificate_issues",

    # Dependency Checks
    "dep_vuln":                      "vulnerable_dependency",

    # Network Checks
    "open_port":                     "open_ports",
    "shodan_cve":                    "service_version_exposure",
    "nvd_cve":                       "service_version_exposure",
    "shodan_tag":                    "info_disclosure",
    "greynoise":                     "info_disclosure",
    "abuseipdb":                     "info_disclosure",
    "eol_os":                        "service_version_exposure",
    "attack_surface":                "info_disclosure",
    "nmap_unavailable":              "info_disclosure",

    # Web Scanner checks
    "ssl":                           "weak_crypto",
    "headers":                       "missing_security_headers",
    "cookies":                       "session_fixation",
    "https_redirect":                "security_misconfig",
    "http_methods":                  "dangerous_http_methods",
    "cors":                          "cors",
    "sensitive_paths":               "info_disclosure",
    "disclosure":                    "info_disclosure",
    "server_cve":                    "service_version_exposure",
    "tech_detection":                "info_disclosure",
    "waf_detection":                 "info_disclosure",
}


def get_taxonomy() -> dict[str, dict[str, Any]]:
    """Return the entire master taxonomy."""
    return VULN_TAXONOMY


def get_vuln_type(vuln_type: str) -> Optional[dict[str, Any]]:
    """Retrieve details for a single canonical vuln_type, or None if unknown."""
    if not vuln_type:
        return None
    canon = vuln_type.strip().lower()
    return VULN_TAXONOMY.get(canon)


def get_all_vuln_types() -> list[str]:
    """Return all valid canonical vuln_type keys."""
    return list(VULN_TAXONOMY.keys())


def get_types_by_scanner(scanner_id: str) -> list[dict[str, Any]]:
    """Return all taxonomy entries matching a specific scanner engine."""
    sid = (scanner_id or "").strip().lower()
    return [v for v in VULN_TAXONOMY.values() if v.get("scanner") == sid]


def normalize_check_to_vuln_type(
    check: str,
    title: str = "",
    scanner: str = "",
) -> str:
    """Normalize a free-form scanner check, title, or scanner context to a canonical vuln_type.

    Order of resolution:
      1. Direct match in canonical taxonomy keys.
      2. Exact match in CHECK_MAP.
      3. Prefix / pattern matching on check identifier (bandit, semgrep, zap, sslyze).
      4. Title-based semantic matching.
      5. Scanner-based fallback.
      6. Platform default ('security_misconfig').
    """
    check_str = (check or "").strip()
    title_str = (title or "").strip()
    scanner_str = (scanner or "").strip().lower()

    # 1. Direct canonical match
    lower_check = check_str.lower()
    if lower_check in VULN_TAXONOMY:
        return lower_check

    # 2. Exact match in CHECK_MAP
    if check_str in CHECK_MAP:
        return CHECK_MAP[check_str]
    if lower_check in CHECK_MAP:
        return CHECK_MAP[lower_check]

    # 3. Dynamic pattern matching on check_str
    # SSLyze versions
    if lower_check.startswith("sslyze-") and "-enabled" in lower_check:
        return "deprecated_protocols"
    if "heartbleed" in lower_check or "robot" in lower_check:
        return "heartbleed_robot"

    # SAST - Bandit
    if lower_check.startswith("bandit_"):
        b_code = lower_check.replace("bandit_", "").upper()
        if b_code in {"B301", "B302", "B403"}:
            return "deserialization"
        if b_code in {"B601", "B602", "B603", "B604", "B605", "B606", "B607", "B608"}:
            return "rce"
        if b_code in {"B105", "B106", "B107"}:
            return "hardcoded_secrets"
        if b_code in {"B501", "B502", "B503", "B504"}:
            return "weak_crypto"
        if b_code in {"B201"}:
            return "missing_csp"
        return "security_misconfig"

    # SAST - Semgrep / Gitleaks
    if lower_check.startswith("gitleaks_") or "secret" in lower_check:
        return "hardcoded_secrets"
    if lower_check.startswith("semgrep_"):
        if "sqli" in lower_check or "sql-injection" in lower_check:
            return "sqli"
        if "xss" in lower_check:
            return "xss"
        if "rce" in lower_check or "exec" in lower_check or "command" in lower_check:
            return "rce"
        if "deserialization" in lower_check:
            return "deserialization"
        if "auth" in lower_check or "jwt" in lower_check:
            return "broken_auth"
        if "crypto" in lower_check:
            return "weak_crypto"
        if "csrf" in lower_check:
            return "csrf"
        if "cors" in lower_check:
            return "cors"
        return "security_misconfig"

    # DAST - ZAP / Nuclei
    if "xss" in lower_check or "cross-site-scripting" in lower_check:
        return "xss"
    if "sqli" in lower_check or "sql-injection" in lower_check or "sql_injection" in lower_check or "sql injection" in lower_check:
        return "sqli"
    if "csrf" in lower_check:
        return "csrf"
    if "ssrf" in lower_check:
        return "ssrf"
    if "rce" in lower_check or "command-injection" in lower_check or "code-exec" in lower_check:
        return "rce"
    if "open-redirect" in lower_check or "redirect" in lower_check:
        return "open_redirect"
    if "takeover" in lower_check:
        return "takeover"
    if "cve-" in lower_check:
        return "service_version_exposure"

    # 4. Title-based semantic matching
    lower_title = title_str.lower()
    if lower_title:
        if "xss" in lower_title or "cross-site scripting" in lower_title:
            return "xss"
        if "sql injection" in lower_title or "sqli" in lower_title:
            return "sqli"
        if "csrf" in lower_title or "cross-site request forgery" in lower_title:
            return "csrf"
        if "ssrf" in lower_title or "server-side request forgery" in lower_title:
            return "ssrf"
        if "remote code" in lower_title or "command injection" in lower_title:
            return "rce"
        if "open redirect" in lower_title or "url redirection" in lower_title:
            return "open_redirect"
        if "heartbleed" in lower_title or "robot" in lower_title:
            return "heartbleed_robot"
        if "subdomain takeover" in lower_title:
            return "takeover"
        if "deserialization" in lower_title:
            return "deserialization"
        if "content security policy" in lower_title or "csp" in lower_title:
            return "missing_csp"
        if "security header" in lower_title or "hsts" in lower_title or "x-frame" in lower_title:
            return "missing_security_headers"
        if "secret" in lower_title or "api key" in lower_title or "private key" in lower_title or "password in env" in lower_title:
            return "hardcoded_secrets"
        if "docker" in lower_title and ("socket" in lower_title or "api" in lower_title):
            return "exposed_docker_api"
        if "privileged" in lower_title or "root user" in lower_title:
            return "privileged_containers"
        if "spf" in lower_title or "dkim" in lower_title or "dmarc" in lower_title:
            return "missing_spf_dkim_dmarc"
        if "zone transfer" in lower_title or "axfr" in lower_title:
            return "dns_zone_transfer"
        if "wordpress" in lower_title and ("plugin" in lower_title or "theme" in lower_title):
            return "outdated_plugins"
        if "xmlrpc" in lower_title or "xml-rpc" in lower_title:
            return "xmlrpc_exposure"
        if "open port" in lower_title or "port exposed" in lower_title:
            return "open_ports"

    # 5. Scanner-based defaults
    if scanner_str == "ssl":
        return "weak_crypto"
    if scanner_str == "deps":
        return "vulnerable_dependency"
    if scanner_str == "docker":
        return "privileged_containers"
    if scanner_str == "dns":
        return "missing_spf_dkim_dmarc"
    if scanner_str == "wordpress":
        return "outdated_plugins"
    if scanner_str == "network":
        return "open_ports"

    # 6. Fallback
    return "security_misconfig"
