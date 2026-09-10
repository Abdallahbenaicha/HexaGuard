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
VULN_TAXONOMY: dict[str, dict[str, Any]] = {   'abandoned_dependency': {   'description_ar': 'استخدام مكتبات برمجية تم أرشفتها أو التوقف عن تطويرها مما يحرم '
                                                  'المشروع من أي تصحيحات أمنية مستقبلية.',
                                'description_en': 'Use of third-party libraries whose repositories have been archived, '
                                                  'unmaintained for years, or marked deprecated.',
                                'difficulty': 'medium',
                                'hacktricks': 'https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-ci-cd',
                                'id': 'abandoned_dependency',
                                'lesson': {   'deep_dive_links': [   {   'label': 'OpenSSF Scorecards Project',
                                                                         'url': 'https://securityscorecards.dev/'},
                                                                     {   'label': 'GitHub Advisory Database',
                                                                         'url': 'https://github.com/advisories'}],
                                              'level_1_foundations_en': 'Abandoned packages represent dead code that '
                                                                        'will never receive security updates when new '
                                                                        'vulnerability classes emerge. Furthermore, '
                                                                        'abandoned packages on public registries (npm, '
                                                                        'PyPI) are prime targets for takeover attacks: '
                                                                        'malicious actors contact registry support or '
                                                                        'register expired maintainer domains to take '
                                                                        'ownership of the package namespace.',
                                              'level_2_detection_en': 'Cross-reference dependencies against PyPI/npm '
                                                                      'API metadata to check last publish timestamp, '
                                                                      'GitHub repository archival status, and '
                                                                      'deprecation notices. HexaGuard Dependency '
                                                                      'Scanner alerts when packages have not released '
                                                                      'an update in over 3 years or are flagged as '
                                                                      'deprecated.',
                                              'level_3_practice': {   'challenge_prompt_en': 'Audit an existing '
                                                                                             "project's dependencies "
                                                                                             'to detect unmaintained '
                                                                                             'packages and develop a '
                                                                                             'migration strategy to '
                                                                                             'modern equivalents.',
                                                                      'guided_prompt_en': 'Query the PyPI or npm '
                                                                                          'registry API for a '
                                                                                          'deprecated library and '
                                                                                          'observe the deprecation '
                                                                                          'notice and last upload '
                                                                                          'date.',
                                                                      'sandbox_target': None},
                                              'level_4_remediation_en': 'Identify and replace abandoned libraries with '
                                                                        'modern, maintained equivalents (e.g. migrate '
                                                                        'from `request` to `axios`/`node-fetch` in '
                                                                        'Node.js). Enforce policy rules in CI to fail '
                                                                        'builds if any package has been archived by '
                                                                        'its authors. Mapped to OWASP A06:2021.'},
                                'name_ar': 'حزم برمجية مهجورة وغير مدعومة',
                                'name_en': 'Abandoned & Unmaintained Dependency Package',
                                'owasp': 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
                                'portswigger': None,
                                'prerequisites': ['vulnerable_dependency'],
                                'remediation_ar': 'استبدال الحزم المهجورة ببدائل نشطة ومدعومة ومتابعة حالة مطوري '
                                                  'المكتبات بشكل دوري.',
                                'remediation_en': 'Replace deprecated packages with actively maintained alternatives; '
                                                  'audit package maintainer activity regularly.',
                                'scanner': 'deps',
                                'severity_default': 'medium'},
    'broken_auth': {   'description_ar': 'عيوب في التحقق من الهوية تتيح انتحال شخصيات المستخدمين أو كسر الجلسات أو '
                                         'تجاوز كلمات المرور.',
                       'description_en': 'Vulnerabilities in authentication mechanisms allowing attackers to '
                                         'compromise passwords, tokens, or assume user identities.',
                       'difficulty': 'medium',
                       'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/authentication-bypass',
                       'id': 'broken_auth',
                       'lesson': {   'deep_dive_links': [   {   'label': 'OWASP Authentication Cheat Sheet',
                                                                'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'},
                                                            {   'label': 'PortSwigger Authentication Academy',
                                                                'url': 'https://portswigger.net/web-security/authentication'}],
                                     'level_1_foundations_en': 'Broken Authentication encompasses failures in identity '
                                                               'verification and session life-cycle controls, '
                                                               'including credential stuffing, weak password reset '
                                                               'entropy, absence of rate limiting, and predictable '
                                                               'session tokens. When authentication breaks, attackers '
                                                               'gain full access to administrative or tenant data '
                                                               'without needing specialized exploit payloads.',
                                     'level_2_detection_en': 'Test authentication endpoints for missing rate limits by '
                                                             'submitting multiple rapid failed logins. Test password '
                                                             'reset functions for token predictability or user '
                                                             'enumeration in response messages. In HexaGuard, the Web '
                                                             'Core scanner inspects authentication forms, cookie '
                                                             'entropy, login responses, and flag indicators for '
                                                             'missing multi-factor defenses.',
                                     'level_3_practice': {   'challenge_prompt_en': 'Exploit weak credential hashing '
                                                                                    'or session prediction in the DVWA '
                                                                                    'sandbox challenge to recover '
                                                                                    'administrative credentials and '
                                                                                    'capture the challenge flag.',
                                                             'guided_prompt_en': 'Start DVWA in the Adversarial Twin '
                                                                                 'Sandbox. Navigate to Brute Force '
                                                                                 'challenge (Low/Medium), test brute '
                                                                                 'forcing with Hydra or Burp Intruder, '
                                                                                 'and observe how missing rate '
                                                                                 'limiting permits immediate '
                                                                                 'credential compromise.',
                                                             'sandbox_target': 'broken_auth'},
                                     'level_4_remediation_en': 'Enforce Multi-Factor Authentication (MFA/TOTP). Hash '
                                                               'passwords with Argon2id or bcrypt (cost factor >= 12). '
                                                               'Protect endpoints against credential stuffing with '
                                                               'IP/user rate limiting and CAPTCHAs. Rotate session IDs '
                                                               'upon authentication state change. Mapped to OWASP '
                                                               'A07:2021-Identification and Authentication Failures '
                                                               'and PCI-DSS v4.0 Req 8.3.'},
                       'name_ar': 'خلل في آليات المصادقة وإدارة الجلسات',
                       'name_en': 'Broken Authentication & Session Management',
                       'owasp': 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
                       'portswigger': 'https://portswigger.net/web-security/authentication',
                       'prerequisites': ['session_fixation'],
                       'remediation_ar': 'تطبيق المصادقة متعددة العوامل وإدارة الجلسات الآمنة وقفل الحسابات واستخدام '
                                         'خوارزميات تجزئة قوية.',
                       'remediation_en': 'Implement multi-factor authentication, secure session handling, account '
                                         'lockout policies, and strong password hashing.',
                       'scanner': 'web',
                       'severity_default': 'high'},
    'certificate_issues': {   'description_ar': 'شهادات تشفير منتهية أو موقعة ذاتياً أو غير موثوقة أو غير مطابقة لاسم '
                                                'النطاق.',
                              'description_en': 'Expired certificates, self-signed certificates, untrusted root '
                                                'issuers, or hostname mismatches.',
                              'difficulty': 'easy',
                              'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssl-tls',
                              'id': 'certificate_issues',
                              'lesson': {   'deep_dive_links': [   {   'label': "Let's Encrypt Documentation",
                                                                       'url': 'https://letsencrypt.org/docs/'},
                                                                   {   'label': 'Certbot Automated ACME Client',
                                                                       'url': 'https://certbot.eff.org/'}],
                                            'level_1_foundations_en': 'Digital certificates establish trust between '
                                                                      'client browsers and server destinations. An '
                                                                      'expired, self-signed, or untrusted certificate '
                                                                      'triggers full-screen browser interstitial '
                                                                      'warnings. If users bypass these warnings, '
                                                                      'attackers can easily stage Man-in-the-Middle '
                                                                      '(MitM) proxies, spoof the server identity, and '
                                                                      'intercept credentials and tokens.',
                                            'level_2_detection_en': 'Inspect certificates with curl: `curl -v '
                                                                    'https://target.com`. Observe SSL verify return '
                                                                    'codes (e.g. `certificate has expired`, `self '
                                                                    'signed certificate`). HexaGuard SSL Audit '
                                                                    'verifies the certificate chain of trust, '
                                                                    'expiration timestamp, and Subject Alternative '
                                                                    'Names (SANs), flagging any certificate expiring '
                                                                    'within 30 days.',
                                            'level_3_practice': {   'challenge_prompt_en': 'Configure automated '
                                                                                           'certificate issuance and '
                                                                                           'renewal via Certbot / ACME '
                                                                                           'protocol for a web server '
                                                                                           'domain, ensuring renewal '
                                                                                           'occurs 30 days prior to '
                                                                                           'expiration.',
                                                                    'guided_prompt_en': 'Inspect an SSL certificate '
                                                                                        'chain using `openssl s_client '
                                                                                        '-showcerts -connect '
                                                                                        'target.com:443` and identify '
                                                                                        'the intermediate and root CA '
                                                                                        'certificates.',
                                                                    'sandbox_target': None},
                                            'level_4_remediation_en': "Deploy trusted certificates using Let's Encrypt "
                                                                      'with Certbot auto-renewal (`certbot renew '
                                                                      '--dry-run`). Ensure the web server serves the '
                                                                      'full certificate chain (`fullchain.pem`), '
                                                                      'including intermediate CA certificates. Mapped '
                                                                      'to PCI-DSS v4.0 Req 4.1.'},
                              'name_ar': 'عيوب صلاحية وشهادات التشفير SSL/TLS',
                              'name_en': 'SSL/TLS Certificate Validity & Trust Flaws',
                              'owasp': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
                              'portswigger': None,
                              'prerequisites': [],
                              'remediation_ar': 'إصدار شهادات معتمدة وموثوقة من جهة إصدار رسمية وتفعيل التجديد '
                                                'التلقائي ومراقبة التواريخ.',
                              'remediation_en': "Deploy valid, trusted X.509 certificates from an automated CA (Let's "
                                                'Encrypt); monitor expiration dates via automated alerts.',
                              'scanner': 'ssl',
                              'severity_default': 'medium'},
    'cors': {   'description_ar': 'إعدادات متساهلة في سياسة CORS تسمح لمواقع خارجية بقراءة بيانات حساسة وتبادل الجلسات '
                                  'دون تصريح.',
                'description_en': 'Excessively permissive Cross-Origin Resource Sharing headers permit unauthorized '
                                  'origins to read sensitive data.',
                'difficulty': 'medium',
                'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/cors-bypass',
                'id': 'cors',
                'lesson': {   'deep_dive_links': [   {   'label': 'PortSwigger CORS Vulnerabilities',
                                                         'url': 'https://portswigger.net/web-security/cors'},
                                                     {   'label': 'OWASP HTML5 Security Cheat Sheet',
                                                         'url': 'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html'}],
                              'level_1_foundations_en': 'Cross-Origin Resource Sharing (CORS) is an HTTP header '
                                                        'mechanism allowing servers to declare which origins can read '
                                                        'its resources in a browser. A catastrophic misconfiguration '
                                                        "occurs when a server dynamically reflects the client's "
                                                        '`Origin` header while returning '
                                                        '`Access-Control-Allow-Credentials: true`. This allows '
                                                        'malicious third-party websites to make cross-origin requests '
                                                        "with the victim's cookies and read confidential API "
                                                        'responses.',
                              'level_2_detection_en': 'Send an HTTP request with a custom origin header: `curl -H '
                                                      "'Origin: https://evil.com' -I https://target.com/api/user`. "
                                                      'Check if response contains `Access-Control-Allow-Origin: '
                                                      'https://evil.com` and `Access-Control-Allow-Credentials: true`. '
                                                      'In HexaGuard, Web Core tests API endpoints with arbitrary and '
                                                      'null origins to detect dangerous reflections.',
                              'level_3_practice': {   'challenge_prompt_en': 'Construct a client-side JavaScript PoC '
                                                                             'using '
                                                                             "`fetch('https://target.com/api/profile', "
                                                                             "{credentials: 'include'})` to exfiltrate "
                                                                             'private API data under a permissive CORS '
                                                                             'configuration.',
                                                      'guided_prompt_en': 'Execute a curl request against an API '
                                                                          'endpoint with `Origin: '
                                                                          'https://attacker.com` and inspect whether '
                                                                          'the origin is mirrored in '
                                                                          '`Access-Control-Allow-Origin`.',
                                                      'sandbox_target': None},
                              'level_4_remediation_en': 'Avoid reflecting incoming `Origin` headers. Enforce an '
                                                        'explicit allowlist of trusted domains. Never return '
                                                        '`Access-Control-Allow-Origin: *` when '
                                                        '`Access-Control-Allow-Credentials: true` is enabled. In '
                                                        "Express.js: `cors({ origin: ['https://trusted.domain.com'], "
                                                        'credentials: true })`. Mapped to OWASP A05:2021-Security '
                                                        'Misconfiguration.'},
                'name_ar': 'خلل في سياسة مشاركة الموارد عبر النطاقات (CORS)',
                'name_en': 'CORS Misconfiguration',
                'owasp': 'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny',
                'portswigger': 'https://portswigger.net/web-security/cors',
                'prerequisites': ['missing_security_headers'],
                'remediation_ar': 'عدم عكس ترويسة Origin تلقائياً مع تفعيل الاعتماديات، واستخدام قائمة بيضاء صارمة '
                                  'ومحددة للنطاقات.',
                'remediation_en': 'Never reflect Origin header dynamically with credentials; use an explicit, '
                                  'validated origin allowlist.',
                'scanner': 'web',
                'severity_default': 'medium'},
    'csrf': {   'description_ar': 'إجبار متصفح المستخدم المصادق على تنفيذ إجراءات غير مرغوب فيها دون علمه أو إذنه.',
                'description_en': 'Forces an authenticated user into executing unwanted state-changing actions on a '
                                  'trusted application.',
                'difficulty': 'medium',
                'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery',
                'id': 'csrf',
                'lesson': {   'deep_dive_links': [   {   'label': 'OWASP CSRF Prevention Cheat Sheet',
                                                         'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'},
                                                     {   'label': 'PortSwigger CSRF Guide',
                                                         'url': 'https://portswigger.net/web-security/csrf'}],
                              'level_1_foundations_en': 'Cross-Site Request Forgery (CSRF) tricks an authenticated '
                                                        'browser into submitting unauthorized commands to a vulnerable '
                                                        'web application. Because browsers automatically attach '
                                                        'session cookies to cross-origin requests, the target '
                                                        'application cannot distinguish legitimate user interactions '
                                                        'from forged attacker requests. In 2010, YouTube had a CSRF '
                                                        "vulnerability allowing attackers to add videos to users' "
                                                        'favorites, add contacts, or send friend requests without user '
                                                        'awareness.',
                              'level_2_detection_en': 'Inspect state-changing requests (POST, PUT, DELETE, sensitive '
                                                      'GETs) to see if anti-CSRF tokens or custom headers are '
                                                      'required. Test by creating a standalone HTML form on '
                                                      '`localhost:8080` submitting to the target while logged in. In '
                                                      'HexaGuard, DAST tests state-changing endpoints for missing CSRF '
                                                      'token validation and missing SameSite attributes on session '
                                                      'cookies.',
                              'level_3_practice': {   'challenge_prompt_en': 'Craft a working CSRF exploit '
                                                                             'proof-of-concept that successfully '
                                                                             'alters the administrator account profile '
                                                                             'or email within the local sandbox '
                                                                             'without user intervention.',
                                                      'guided_prompt_en': 'Launch DVWA in the Adversarial Twin '
                                                                          'Sandbox. Navigate to the CSRF module, '
                                                                          'inspect the password change form, and '
                                                                          'create a cross-origin HTML page with an '
                                                                          'image tag `<img '
                                                                          "src='http://127.0.0.1:.../vulnerabilities/csrf/?password_new=admin&password_conf=admin&Change=Change'>` "
                                                                          'to trigger automatic password reset.',
                                                      'sandbox_target': 'csrf'},
                              'level_4_remediation_en': 'Implement unpredictable, cryptographically random Anti-CSRF '
                                                        'tokens validated on every state-changing request '
                                                        '(Synchronizer Token Pattern). Mark session cookies with '
                                                        '`SameSite=Lax` or `SameSite=Strict` and verify `Origin` / '
                                                        '`Referer` headers. Mapped to OWASP A01:2021-Broken Access '
                                                        'Control and PCI-DSS v4.0 Req 6.4.1.'},
                'name_ar': 'تزوير الطلبات عبر المواقع (CSRF)',
                'name_en': 'Cross-Site Request Forgery (CSRF)',
                'owasp': 'https://owasp.org/www-community/attacks/csrf',
                'portswigger': 'https://portswigger.net/web-security/csrf',
                'prerequisites': ['session_fixation'],
                'remediation_ar': 'استخدام رموز CSRF الفريدة وتعيين سمة SameSite للكوكيز والتحقق من ترويسات '
                                  'Origin/Referer.',
                'remediation_en': 'Enforce anti-CSRF tokens (SameSite=Lax/Strict cookies and custom X-CSRFToken '
                                  'headers).',
                'scanner': 'dast',
                'severity_default': 'medium'},
    'dangerous_http_methods': {   'description_ar': 'سماح الخادم بطرق استدعاء غير آمنة تتيح رفع وتعديل الملفات أو '
                                                    'استرجاع الكوكيز عبر هجمات XST.',
                                  'description_en': 'Web server permits arbitrary file uploads via PUT, file deletion '
                                                    'via DELETE, or XST attacks via TRACE.',
                                  'difficulty': 'medium',
                                  'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/put-method-webdav',
                                  'id': 'dangerous_http_methods',
                                  'lesson': {   'deep_dive_links': [   {   'label': 'Apache TraceEnable Directive',
                                                                           'url': 'https://httpd.apache.org/docs/2.4/mod/core.html#traceenable'},
                                                                       {   'label': 'OWASP Testing for HTTP Methods',
                                                                           'url': 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods'}],
                                                'level_1_foundations_en': 'HTTP defines methods beyond GET and POST. '
                                                                          'Methods like `PUT` allow clients to create '
                                                                          'new files on the server; `DELETE` permits '
                                                                          'file removal; and `TRACE` mirrors the '
                                                                          "client's request back in the response body. "
                                                                          'If TRACE is enabled, attackers can exploit '
                                                                          'Cross-Site Tracing (XST) to steal '
                                                                          '`HttpOnly` cookies via XSS.',
                                                'level_2_detection_en': 'Send an OPTIONS request to the server: `curl '
                                                                        '-X OPTIONS -v https://target.com`. Inspect '
                                                                        'the `Allow` header. Send a test `TRACE` '
                                                                        'request: `curl -X TRACE https://target.com`. '
                                                                        "HexaGuard's Server scanner inspects allowed "
                                                                        'HTTP verbs and alerts when TRACE, PUT, or '
                                                                        'DELETE are enabled on unauthenticated '
                                                                        'endpoints.',
                                                'level_3_practice': {   'challenge_prompt_en': 'Configure an Apache '
                                                                                               'server with '
                                                                                               '`TraceEnable Off` and '
                                                                                               'a `<LimitExcept>` '
                                                                                               'block that restricts '
                                                                                               'HTTP methods to GET, '
                                                                                               'POST, and HEAD.',
                                                                        'guided_prompt_en': 'Send an `OPTIONS` and a '
                                                                                            '`TRACE` request using '
                                                                                            'curl to a test server and '
                                                                                            'observe the `Allow` '
                                                                                            'header response.',
                                                                        'sandbox_target': None},
                                                'level_4_remediation_en': 'In Apache: add `TraceEnable Off` and '
                                                                          '`<LimitExcept GET POST HEAD OPTIONS> '
                                                                          'Require all denied </LimitExcept>`. In '
                                                                          'Nginx: `if ($request_method !~ '
                                                                          '^(GET|HEAD|POST|OPTIONS)$ ) { return 405; '
                                                                          '}`. Mapped to OWASP A05:2021-Security '
                                                                          'Misconfiguration.'},
                                  'name_ar': 'تفعيل طرق HTTP الخطرة (PUT, DELETE, TRACE)',
                                  'name_en': 'Dangerous HTTP Methods Enabled (PUT / DELETE / TRACE)',
                                  'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                                  'portswigger': None,
                                  'prerequisites': [],
                                  'remediation_ar': 'قصر طرق HTTP على GET و POST و HEAD و OPTIONS وتعطيل طريقتي TRACE '
                                                    'و PUT بالكامل.',
                                  'remediation_en': 'Restrict HTTP methods on web server to GET, POST, HEAD, and '
                                                    'OPTIONS; disable TRACE and PUT globally.',
                                  'scanner': 'server',
                                  'severity_default': 'medium'},
    'default_credentials': {   'description_ar': 'بقاء كلمات السر الافتراضية لبرمجيات الخادم ولوحات التحكم دون تغيير '
                                                 'مما يسمح بالدخول الفوري للمهاجمين.',
                               'description_en': 'Factory default or well-known credentials active on external '
                                                 'administrative interfaces (e.g. admin/admin).',
                               'difficulty': 'easy',
                               'hacktricks': 'https://book.hacktricks.xyz/generic-methodologies-and-resources/brute-force',
                               'id': 'default_credentials',
                               'lesson': {   'deep_dive_links': [   {   'label': 'CISA Default Credentials Guidance',
                                                                        'url': 'https://www.cisa.gov/uscert/ncas/tips/ST04-003'},
                                                                    {   'label': 'OWASP Authentication Cheat Sheet',
                                                                        'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'}],
                                             'level_1_foundations_en': 'Many hardware appliances, server control '
                                                                       'panels (cPanel, Webmin), CMS installations, '
                                                                       'and network devices ship from the factory with '
                                                                       'well-known default usernames and passwords '
                                                                       '(e.g. `admin:admin`, `root:toor`, '
                                                                       '`tomcat:s3cret`). When deployed publicly '
                                                                       'without immediate password rotation, automated '
                                                                       'botnets compromise these systems within '
                                                                       'minutes.',
                                             'level_2_detection_en': 'Identify administrative portals and test '
                                                                     'standard default credential combinations from '
                                                                     'curated dictionaries. HexaGuard Server External '
                                                                     'non-destructively probes administrative '
                                                                     'endpoints against common default credential '
                                                                     'pairs and flags interfaces accepting default '
                                                                     'logins.',
                                             'level_3_practice': {   'challenge_prompt_en': 'Audit an infrastructure '
                                                                                            'inventory for exposed '
                                                                                            'management portals and '
                                                                                            'enforce an automated '
                                                                                            'credential rotation '
                                                                                            'script.',
                                                                     'guided_prompt_en': 'Identify an administrative '
                                                                                         'panel login on a local test '
                                                                                         'appliance and test default '
                                                                                         'username and password '
                                                                                         'combinations.',
                                                                     'sandbox_target': None},
                                             'level_4_remediation_en': 'Enforce mandatory password resets on first '
                                                                       'login. Never deploy software with hardcoded '
                                                                       'default passwords; generate cryptographically '
                                                                       'random passwords during deployment. Enforce '
                                                                       'MFA across all administrative logins. Mapped '
                                                                       'to OWASP A07:2021 and CIS Controls 5.2.'},
                               'name_ar': 'استخدام كلمات السر الافتراضية للأنظمة',
                               'name_en': 'Default Administrative Credentials',
                               'owasp': 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
                               'portswigger': 'https://portswigger.net/web-security/authentication',
                               'prerequisites': [],
                               'remediation_ar': 'فرض تغيير كلمة السر عند أول تسجيل دخول وتطبيق قفل الحسابات والمصادقة '
                                                 'الثنائية على لوحات التحكم.',
                               'remediation_en': 'Force mandatory password changes on initial setup; implement account '
                                                 'lockout and MFA on admin panels.',
                               'scanner': 'server_ext',
                               'severity_default': 'critical'},
    'default_page_exposed': {   'description_ar': 'بقاء صفحات الترحيب الافتراضية لخوادم الويب متاحة للعامة، مما يكشف '
                                                  'عن بيئة التشغيل دون تقديم وظيفة فعلية.',
                                'description_en': 'Default installation landing pages (Apache It Works!, Nginx '
                                                  'Welcome, IIS Welcome) remain accessible.',
                                'difficulty': 'easy',
                                'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/information-disclosure',
                                'id': 'default_page_exposed',
                                'lesson': {   'deep_dive_links': [   {   'label': 'Nginx Catch-All Server Block',
                                                                         'url': 'https://nginx.org/en/docs/http/request_processing.html'},
                                                                     {   'label': 'CIS Web Server Hardening Guide',
                                                                         'url': 'https://www.cisecurity.org/benchmark/apache_http_server'}],
                                              'level_1_foundations_en': 'Leaving default web server installation pages '
                                                                        "('Apache2 Ubuntu Default Page: It works!', "
                                                                        "'Welcome to nginx!') accessible informs "
                                                                        'adversaries that the server was newly '
                                                                        'installed and likely unhardened. These pages '
                                                                        'also reveal file system paths (e.g. '
                                                                        '`/var/www/html`), operating system versions, '
                                                                        'and package maintainers.',
                                              'level_2_detection_en': 'Navigate to the root URL or IP address of the '
                                                                      'target. Check whether the response body '
                                                                      'contains default welcome signatures. HexaGuard '
                                                                      'Server External inspects root responses and '
                                                                      'flags uncustomized welcome templates.',
                                              'level_3_practice': {   'challenge_prompt_en': 'Configure a default '
                                                                                             'catch-all virtual host '
                                                                                             'in Nginx that returns '
                                                                                             'HTTP 444 (connection '
                                                                                             'closed) for requests '
                                                                                             'made directly to the '
                                                                                             'server IP address.',
                                                                      'guided_prompt_en': 'Connect to a fresh web '
                                                                                          'server installation and '
                                                                                          'examine the default HTML '
                                                                                          'page to note the file paths '
                                                                                          'and OS information '
                                                                                          'disclosed.',
                                                                      'sandbox_target': None},
                                              'level_4_remediation_en': 'Remove default welcome files (`rm '
                                                                        '/var/www/html/index.html`). In Nginx, '
                                                                        'configure a default server block that drops '
                                                                        'unrecognized host requests: `server { listen '
                                                                        '80 default_server; return 444; }`. Mapped to '
                                                                        'OWASP A05:2021-Security Misconfiguration.'},
                                'name_ar': 'كشف صفحات الترحيب الافتراضية للخادم',
                                'name_en': 'Default Server Welcome Page Exposed',
                                'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                                'portswigger': None,
                                'prerequisites': ['server_banner_disclosure'],
                                'remediation_ar': 'حذف أو استبدال صفحات الترحيب الافتراضية بصفحات مخصصة أو إعادة '
                                                  'التوجيه للصفحة الرئيسية للمشروع.',
                                'remediation_en': 'Replace or delete default index pages; configure a custom document '
                                                  'root or catch-all 404 handler.',
                                'scanner': 'server_ext',
                                'severity_default': 'low'},
    'dependency_confusion_typosquatting': {   'description_ar': 'مخاطر سحب حزم خبيثة من المستودعات العامة تحمل أسماء '
                                                                'مشابهة لحزم داخلية خاصة بالمؤسسة.',
                                              'description_en': 'Application risks pulling malicious public packages '
                                                                'whose names mimic internal or common popular '
                                                                'packages.',
                                              'difficulty': 'hard',
                                              'hacktricks': 'https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-ci-cd',
                                              'id': 'dependency_confusion_typosquatting',
                                              'lesson': {   'deep_dive_links': [   {   'label': 'Alex Birsan: '
                                                                                                'Dependency Confusion '
                                                                                                'Research',
                                                                                       'url': 'https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610'},
                                                                                   {   'label': 'Microsoft Guidance on '
                                                                                                'Dependency Confusion',
                                                                                       'url': 'https://www.microsoft.com/en-us/security/blog/2021/03/25/3-ways-to-mitigate-risk-using-private-package-feeds/'}],
                                                            'level_1_foundations_en': 'Dependency Confusion occurs '
                                                                                      'when package managers (npm, '
                                                                                      'pip) configured with both '
                                                                                      'internal corporate registries '
                                                                                      'and public registries '
                                                                                      'prioritize public versions with '
                                                                                      'higher semver numbers. Security '
                                                                                      'researcher Alex Birsan '
                                                                                      'demonstrated this by '
                                                                                      'registering internal package '
                                                                                      'names on public npm and PyPI, '
                                                                                      'achieving code execution inside '
                                                                                      'Apple, Microsoft, and Tesla.',
                                                            'level_2_detection_en': 'Audit manifests for non-scoped '
                                                                                    'package names that match internal '
                                                                                    'naming conventions but are '
                                                                                    'missing from public registries. '
                                                                                    'HexaGuard Dependency Scanner '
                                                                                    'flags unscoped internal package '
                                                                                    'names that lack public '
                                                                                    'registration or private registry '
                                                                                    'pinning.',
                                                            'level_3_practice': {   'challenge_prompt_en': 'Configure '
                                                                                                           'an '
                                                                                                           'enterprise '
                                                                                                           '`.npmrc` '
                                                                                                           'file with '
                                                                                                           'scoped '
                                                                                                           'registry '
                                                                                                           'routing '
                                                                                                           'ensuring '
                                                                                                           '`@company/*` '
                                                                                                           'packages '
                                                                                                           'are '
                                                                                                           'exclusively '
                                                                                                           'resolved '
                                                                                                           'from '
                                                                                                           'private '
                                                                                                           'Artifactory/Nexus '
                                                                                                           'servers.',
                                                                                    'guided_prompt_en': 'Review npm or '
                                                                                                        'pip '
                                                                                                        'configuration '
                                                                                                        'files '
                                                                                                        '(`.npmrc`, '
                                                                                                        '`pip.conf`) '
                                                                                                        'to understand '
                                                                                                        'how package '
                                                                                                        'resolution '
                                                                                                        'order between '
                                                                                                        'internal and '
                                                                                                        'public feeds '
                                                                                                        'is handled.',
                                                                                    'sandbox_target': None},
                                                            'level_4_remediation_en': 'Adopt scoped namespaces for all '
                                                                                      'internal packages (e.g. '
                                                                                      '`@mycompany/auth-utils`). In '
                                                                                      '`.npmrc`, specify: '
                                                                                      '`@mycompany:registry=https://private.registry.internal/`. '
                                                                                      'In pip, use `--index-url` '
                                                                                      'rather than `--extra-index-url` '
                                                                                      'to prevent public fallback. '
                                                                                      'Mapped to OWASP A08:2021.'},
                                              'name_ar': 'هجمات خلط التبعيات والتسميات الخادعة (Dependency Confusion)',
                                              'name_en': 'Dependency Confusion & Typosquatting Risk',
                                              'owasp': 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
                                              'portswigger': None,
                                              'prerequisites': ['unpinned_dependency'],
                                              'remediation_ar': 'استخدام نطاقات محددة للحزم (@org) وضبط أولوية '
                                                                'المستودعات الخاصة وحجز الأسماء الداخلية.',
                                              'remediation_en': 'Use scoped package namespaces (@org/pkg), configure '
                                                                'private registry priority, and claim internal names '
                                                                'on public registries.',
                                              'scanner': 'deps',
                                              'severity_default': 'high'},
    'deprecated_protocols': {   'description_ar': 'دعم الخادم لبروتوكولات تشفير ملغاة رسمياً ومعرضة لهجمات فك التشفير '
                                                  'والتراجع.',
                                'description_en': 'Server supports legacy protocols vulnerable to POODLE, BEAST, and '
                                                  'cryptographic downgrade attacks.',
                                'difficulty': 'easy',
                                'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssl-tls',
                                'id': 'deprecated_protocols',
                                'lesson': {   'deep_dive_links': [   {   'label': 'RFC 8996: Deprecating TLS 1.0 and '
                                                                                  'TLS 1.1',
                                                                         'url': 'https://datatracker.ietf.org/doc/html/rfc8996'},
                                                                     {   'label': 'Mozilla TLS Guidelines',
                                                                         'url': 'https://infosec.mozilla.org/guidelines/web_security#transport-layer-security'}],
                                              'level_1_foundations_en': 'SSLv2, SSLv3, TLS 1.0, and TLS 1.1 have been '
                                                                        'deprecated by the IETF (RFC 8996) due to '
                                                                        'inherent architectural flaws. TLS 1.0 is '
                                                                        'susceptible to the BEAST attack and lacks '
                                                                        'modern authenticated encryption (AEAD), '
                                                                        'enabling Man-in-the-Middle (MitM) adversaries '
                                                                        'to execute protocol downgrade attacks and '
                                                                        'intercept sessions.',
                                              'level_2_detection_en': 'Test for protocol support using OpenSSL: '
                                                                      '`openssl s_client -tls1_1 -connect '
                                                                      'target.com:443`. If the connection succeeds and '
                                                                      'completes a handshake, deprecated protocols are '
                                                                      'active. HexaGuard SSL Audit enumerates protocol '
                                                                      'handshakes via SSLyze, flagging any server '
                                                                      'accepting connections below TLS 1.2.',
                                              'level_3_practice': {   'challenge_prompt_en': 'Audit an Apache or Nginx '
                                                                                             'configuration and modify '
                                                                                             'the `SSLProtocol` '
                                                                                             'directive to disable all '
                                                                                             'protocols below TLS 1.2, '
                                                                                             'verifying compliance '
                                                                                             'with testssl.sh.',
                                                                      'guided_prompt_en': 'Execute `openssl s_client '
                                                                                          '-tls1 -connect '
                                                                                          'target.com:443` and observe '
                                                                                          'whether the server '
                                                                                          'terminates the handshake or '
                                                                                          'negotiates an obsolete TLS '
                                                                                          '1.0 session.',
                                                                      'sandbox_target': None},
                                              'level_4_remediation_en': 'In Nginx configure: `ssl_protocols TLSv1.2 '
                                                                        'TLSv1.3;`. In Apache configure: `SSLProtocol '
                                                                        'all -SSLv3 -TLSv1 -TLSv1.1`. Both settings '
                                                                        'permanently block obsolete protocol '
                                                                        'negotiations. Mapped to PCI-DSS v4.0 Req 4.1 '
                                                                        'and NIST SP 800-52.'},
                                'name_ar': 'بروتوكولات تشفير قديمة (TLS 1.0, 1.1, SSLv3)',
                                'name_en': 'Deprecated SSL/TLS Protocols (TLS 1.0 / 1.1 / SSLv3)',
                                'owasp': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
                                'portswigger': None,
                                'prerequisites': ['weak_crypto'],
                                'remediation_ar': 'تعطيل بروتوكولات SSLv3 و TLS 1.0 و TLS 1.1 وفرض بروتوكولي TLS 1.2 و '
                                                  'TLS 1.3 حصراً.',
                                'remediation_en': 'Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1; enforce TLS 1.2 and TLS '
                                                  '1.3 exclusively.',
                                'scanner': 'ssl',
                                'severity_default': 'high'},
    'deserialization': {   'description_ar': 'معالجة كائنات مجزأة غير موثوقة تسمح بتنفيذ شفرات برمجية خبيثة والسيطرة '
                                             'على الخادم.',
                           'description_en': 'Untrusted serialized objects processed by application, leading to '
                                             'arbitrary code execution or privilege escalation.',
                           'difficulty': 'hard',
                           'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/deserialization',
                           'id': 'deserialization',
                           'lesson': {   'deep_dive_links': [   {   'label': 'OWASP Deserialization Cheat Sheet',
                                                                    'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html'},
                                                                {   'label': 'PortSwigger Insecure Deserialization',
                                                                    'url': 'https://portswigger.net/web-security/deserialization'}],
                                         'level_1_foundations_en': 'Insecure Deserialization occurs when an '
                                                                   'application unpacks untrusted serialized objects '
                                                                   "(such as Python's `pickle`, Java serialized "
                                                                   'streams, or PHP objects). Because object '
                                                                   'serialization preserves method dispatch tables and '
                                                                   'magic methods (`__reduce__`, `readObject`), '
                                                                   'attackers can construct gadget chains that trigger '
                                                                   'arbitrary remote code execution during object '
                                                                   'instantiation.',
                                         'level_2_detection_en': 'In static analysis, search for dangerous '
                                                                 'deserialization calls: `pickle.loads()`, '
                                                                 '`yaml.load(..., Loader=Loader)`, `unserialize()`, or '
                                                                 '`ObjectInputStream.readObject()`. In HexaGuard, SAST '
                                                                 'leverages Bandit (B301, B506) and Semgrep rules to '
                                                                 'detect unsafe deserialization invocations on '
                                                                 'untrusted network streams.',
                                         'level_3_practice': {   'challenge_prompt_en': 'Construct a Python pickle '
                                                                                        'payload using `__reduce__` to '
                                                                                        'execute an echo command and '
                                                                                        'demonstrate how '
                                                                                        'deserialization leads to '
                                                                                        'remote code execution.',
                                                                 'guided_prompt_en': 'Inspect Python source code for '
                                                                                     '`pickle.loads()` receiving HTTP '
                                                                                     'request data, and understand how '
                                                                                     'the `__reduce__` method triggers '
                                                                                     'execution.',
                                                                 'sandbox_target': None},
                                         'level_4_remediation_en': 'Never deserialize untrusted input using '
                                                                   'language-specific native serialization. Adopt '
                                                                   'safe, data-only formats such as standard JSON '
                                                                   '(`json.loads()`), Protocol Buffers, or '
                                                                   'MessagePack. In PyYAML, always use '
                                                                   '`yaml.safe_load()`. Mapped to OWASP '
                                                                   'A08:2021-Software & Data Integrity Failures.'},
                           'name_ar': 'معالجة البيانات غير الآمنة (Insecure Deserialization)',
                           'name_en': 'Insecure Deserialization',
                           'owasp': 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
                           'portswigger': 'https://portswigger.net/web-security/deserialization',
                           'prerequisites': [],
                           'remediation_ar': 'تجنب تنسيقات التسلسل الثنائية الخطرة واعتماد تنسيقات آمنة مثل JSON مع '
                                             'تدقيق المخطط.',
                           'remediation_en': 'Avoid native serialization formats (e.g. Python pickle, Java '
                                             'serialization); use pure JSON/protobuf with schema validation.',
                           'scanner': 'sast',
                           'severity_default': 'critical'},
    'directory_listing': {   'description_ar': 'عرض خادم الويب لقوائم الملفات عند غياب صفحة الفهرس، كاشفاً عن ملفات '
                                               'النسخ الاحتياطي والمجلدات الداخلية.',
                             'description_en': 'Web server displays raw file listings for directories lacking default '
                                               'index files, disclosing internal assets.',
                             'difficulty': 'easy',
                             'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/information-disclosure',
                             'id': 'directory_listing',
                             'lesson': {   'deep_dive_links': [   {   'label': 'Apache Directory Indexing '
                                                                               'Documentation',
                                                                      'url': 'https://httpd.apache.org/docs/2.4/mod/mod_autoindex.html'},
                                                                  {   'label': 'Nginx Autoindex Module',
                                                                      'url': 'https://nginx.org/en/docs/http/ngx_http_autoindex_module.html'}],
                                           'level_1_foundations_en': 'When a web server receives a request for a '
                                                                     'directory that does not contain an index file '
                                                                     '(e.g. `index.html`), default configurations in '
                                                                     'some servers generate an automated HTML listing '
                                                                     'of all files in that folder. This exposes backup '
                                                                     'archives, development scripts, test fixtures, '
                                                                     'and hidden endpoints directly to search engines '
                                                                     'and attackers.',
                                           'level_2_detection_en': 'Request directory paths directly (e.g. `/images/`, '
                                                                   '`/static/`, `/uploads/`) and check if the server '
                                                                   "returns an 'Index of /' page. In HexaGuard, Server "
                                                                   'Internal and Web Core test known static directory '
                                                                   'paths to verify whether directory listing is '
                                                                   'disabled.',
                                           'level_3_practice': {   'challenge_prompt_en': 'Configure an Apache virtual '
                                                                                          'host configuration file to '
                                                                                          'globally disable directory '
                                                                                          'browsing using `Options '
                                                                                          '-Indexes` and verify with '
                                                                                          'curl.',
                                                                   'guided_prompt_en': 'Browse to a directory on a '
                                                                                       'test Apache server with '
                                                                                       '`Options +Indexes` enabled and '
                                                                                       'observe how the file browser '
                                                                                       'reveals all directory '
                                                                                       'contents.',
                                                                   'sandbox_target': None},
                                           'level_4_remediation_en': 'In Apache httpd.conf: `Options -Indexes`. In '
                                                                     'Nginx: `autoindex off;`. In IIS: uncheck '
                                                                     "'Directory Browsing' in IIS Manager. Mapped to "
                                                                     'OWASP A05:2021-Security Misconfiguration.'},
                             'name_ar': 'تفعيل سرد محتويات المجلدات (Directory Listing)',
                             'name_en': 'Directory Listing & Indexing Enabled',
                             'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                             'portswigger': 'https://portswigger.net/web-security/information-disclosure',
                             'prerequisites': [],
                             'remediation_ar': 'تعطيل فهرسة المجلدات بإزالة خيار Indexes في أباتشي وضبط autoindex off '
                                               'في خوادم إنجن إكس.',
                             'remediation_en': 'Disable directory indexing: remove Options Indexes in Apache; ensure '
                                               'autoindex off in Nginx.',
                             'scanner': 'server',
                             'severity_default': 'low'},
    'dns_zone_transfer': {   'description_ar': 'سماح خادم الأسماء بنقل ملفات المنطقة بالكامل لأي طرف خارجي مما يكشف '
                                               'كافة أسماء الأجهزة والسيرفرات الفرعية.',
                             'description_en': 'Name server permits unrestricted zone transfers (AXFR) to untrusted '
                                               'clients, disclosing all internal DNS records.',
                             'difficulty': 'medium',
                             'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns#zone-transfer',
                             'id': 'dns_zone_transfer',
                             'lesson': {   'deep_dive_links': [   {   'label': 'DNS Zone Transfer Vulnerability '
                                                                               'Details',
                                                                      'url': 'https://digi.ninja/projects/zonetransferme.php'},
                                                                  {   'label': 'BIND 9 Administrator Reference Manual',
                                                                      'url': 'https://bind9.readthedocs.io/en/latest/'}],
                                           'level_1_foundations_en': 'DNS Zone Transfer (using the AXFR query type) is '
                                                                     'designed for replicating DNS records between '
                                                                     'primary and secondary name servers. When '
                                                                     'misconfigured to respond to public queries, an '
                                                                     'attacker can download the entire DNS zone file '
                                                                     'in a single request. This discloses all internal '
                                                                     'hosts, VPN gateways, developer portals, and '
                                                                     'staging environments.',
                                           'level_2_detection_en': "Query the target's authoritative name servers for "
                                                                   'a zone transfer: `dig AXFR @ns1.target.com '
                                                                   'target.com`. If the server returns all DNS '
                                                                   "records, the vulnerability exists. HexaGuard's DNS "
                                                                   'Scanner attempts a non-intrusive AXFR probe '
                                                                   'against each authoritative name server.',
                                           'level_3_practice': {   'challenge_prompt_en': 'Configure BIND9 '
                                                                                          '(`named.conf`) or PowerDNS '
                                                                                          'to restrict zone transfers '
                                                                                          'using an explicit '
                                                                                          '`allow-transfer` directive '
                                                                                          'containing only trusted '
                                                                                          'secondary IP addresses.',
                                                                   'guided_prompt_en': 'Test `dig AXFR '
                                                                                       '@nsztm1.digi.ninja '
                                                                                       'zonetransfer.me` against the '
                                                                                       'authorized educational testing '
                                                                                       'zone and observe the full list '
                                                                                       'of exposed DNS records.',
                                                                   'sandbox_target': None},
                                           'level_4_remediation_en': 'In BIND9 configuration (`named.conf.options`), '
                                                                     'restrict transfers: `allow-transfer { '
                                                                     '192.168.1.5; 192.168.1.6; };` or disable '
                                                                     'globally: `allow-transfer { none; };`. Mapped to '
                                                                     'CIS BIND Benchmark 2.2 and OWASP A05:2021.'},
                             'name_ar': 'السماح بنقل منطقة DNS بالكامل (AXFR)',
                             'name_en': 'Unrestricted DNS Zone Transfer (AXFR Enabled)',
                             'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                             'portswigger': None,
                             'prerequisites': [],
                             'remediation_ar': 'قصر نقل منطقة DNS على عناوين خوادم الأسماء الثانوية المصرح بها وحظرها '
                                               'تماماً عن الاستعلامات العامة.',
                             'remediation_en': 'Restrict AXFR zone transfers to authorized secondary name server IPs; '
                                               'disable AXFR globally for public queries.',
                             'scanner': 'dns',
                             'severity_default': 'medium'},
    'docker_root_user': {   'description_ar': 'غياب توجيه USER داخل ملف Dockerfile مما يجعل التطبيق يعمل بصلاحيات '
                                              'المستخدم الجذر (root).',
                            'description_en': 'Dockerfile lacks a USER directive, causing the application process to '
                                              'run with UID 0 (root) inside the container.',
                            'difficulty': 'medium',
                            'hacktricks': 'https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security',
                            'id': 'docker_root_user',
                            'lesson': {   'deep_dive_links': [   {   'label': 'Docker Best Practices: Non-Root Users',
                                                                     'url': 'https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user'},
                                                                 {   'label': 'CIS Docker Benchmark',
                                                                     'url': 'https://www.cisecurity.org/benchmark/docker'}],
                                          'level_1_foundations_en': 'By default, Docker containers execute processes '
                                                                    'with user ID 0 (root) unless specified otherwise. '
                                                                    'While container namespaces provide some '
                                                                    'containment, if an attacker achieves Remote Code '
                                                                    'Execution inside a container running as root, any '
                                                                    'container breakout flaw or misconfigured volume '
                                                                    'mount immediately grants them root privileges on '
                                                                    'the underlying host.',
                                          'level_2_detection_en': 'Inspect Dockerfile for the presence of a `USER` '
                                                                  'directive. In running containers, execute `docker '
                                                                  'top <container>` and verify the process UID. '
                                                                  'HexaGuard Docker Scanner parses Dockerfiles, '
                                                                  'raising a medium finding if no non-root `USER` '
                                                                  'directive is declared.',
                                          'level_3_practice': {   'challenge_prompt_en': 'Modify a Node.js or Python '
                                                                                         'Dockerfile to create a '
                                                                                         'dedicated unprivileged user, '
                                                                                         'configure proper ownership '
                                                                                         'of the app directory, and '
                                                                                         'run as that user.',
                                                                  'guided_prompt_en': 'Build a basic Dockerfile '
                                                                                      'without a USER directive, run '
                                                                                      'it, and execute `id` inside the '
                                                                                      'container to observe '
                                                                                      'uid=0(root) execution.',
                                                                  'sandbox_target': None},
                                          'level_4_remediation_en': 'In Dockerfile, add: `RUN groupadd -r appgroup && '
                                                                    'useradd -r -g appgroup -s /sbin/nologin appuser; '
                                                                    'USER appuser`. Alternatively, enable user '
                                                                    'namespace remapping (`userns-remap`) in the '
                                                                    'Docker daemon. Mapped to CIS Docker Benchmark '
                                                                    '4.1.'},
                            'name_ar': 'تشغيل تطبيق الحاوية بصلاحيات المستخدم الجذر (Root UID 0)',
                            'name_en': 'Container Application Executing as Root UID 0',
                            'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                            'portswigger': None,
                            'prerequisites': [],
                            'remediation_ar': 'إنشاء مستخدم غير جذري والتحويل إليه داخل ملف Dockerfile قبل تشغيل '
                                              'التطبيق.',
                            'remediation_en': 'Create and switch to a non-root user in Dockerfile: RUN useradd -r '
                                              'appuser && USER appuser.',
                            'scanner': 'docker',
                            'severity_default': 'medium'},
    'docker_secret_leak': {   'description_ar': 'تضمين كلمات السر ومفاتيح API الخاصة داخل تعليمات ENV أو ARG في ملف '
                                                'Dockerfile.',
                              'description_en': 'Sensitive credentials, API tokens, or private keys baked directly '
                                                'into Dockerfile ENV or ARG directives.',
                              'difficulty': 'medium',
                              'hacktricks': 'https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets',
                              'id': 'docker_secret_leak',
                              'lesson': {   'deep_dive_links': [   {   'label': 'Docker Build Secrets Guide',
                                                                       'url': 'https://docs.docker.com/build/building/secrets/'},
                                                                   {   'label': 'OWASP Docker Security Cheat Sheet',
                                                                       'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html'}],
                                            'level_1_foundations_en': 'Declaring passwords or API tokens in Dockerfile '
                                                                      '`ENV` or `ARG` directives bakes those '
                                                                      "credentials permanently into the image's "
                                                                      'filesystem metadata layers. Anyone with access '
                                                                      'to the container image (even without root '
                                                                      'access) can run `docker history <image>` or '
                                                                      '`docker inspect` to extract the plaintext '
                                                                      'secrets.',
                                            'level_2_detection_en': 'Inspect Dockerfile for `ENV` and `ARG` directives '
                                                                    'containing strings matching password, secret, '
                                                                    'token, or api_key patterns. HexaGuard Docker '
                                                                    'Scanner runs regex analysis over Dockerfile lines '
                                                                    'and flags credential declarations.',
                                            'level_3_practice': {   'challenge_prompt_en': 'Refactor a container build '
                                                                                           'workflow using Docker '
                                                                                           'BuildKit (`RUN '
                                                                                           '--mount=type=secret,id=mysecret '
                                                                                           '...`) to pass private '
                                                                                           'tokens during build '
                                                                                           'without baking them into '
                                                                                           'image layers.',
                                                                    'guided_prompt_en': 'Inspect an image layer '
                                                                                        'history using `docker history '
                                                                                        '<image>` and observe how '
                                                                                        'environment variable '
                                                                                        'declarations are visible to '
                                                                                        'all users.',
                                                                    'sandbox_target': None},
                                            'level_4_remediation_en': 'Remove secrets from Dockerfiles. Use Docker '
                                                                      'BuildKit secret mounts: `RUN '
                                                                      '--mount=type=secret,id=npmrc,target=/root/.npmrc '
                                                                      'npm install`. Pass runtime secrets via '
                                                                      'orchestration tools (Docker Swarm Secrets, '
                                                                      'Kubernetes Secrets, or AWS ECS Task '
                                                                      'Definitions). Mapped to CIS Docker Benchmark '
                                                                      '4.6.'},
                              'name_ar': 'تسريب المفاتيح وكلمات السر داخل Dockerfile',
                              'name_en': 'Secrets & Credentials in Dockerfile ENV Directives',
                              'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                              'portswigger': None,
                              'prerequisites': ['hardcoded_secrets'],
                              'remediation_ar': 'تجنب تضمين الأسرار في طبقات الصور واعتماد BuildKit secret mounts أو '
                                                'متغيرات التشغيل.',
                              'remediation_en': 'Never store secrets in image layers; use Docker BuildKit secret '
                                                'mounts (--mount=type=secret) or runtime environment files.',
                              'scanner': 'docker',
                              'severity_default': 'high'},
    'eol_os_exposure': {   'description_ar': 'الخادم يعمل بنظام تشغيل غير مدعوم رسمياً يفتقر للتحديثات الأمنية ويحتوي '
                                             'على ثغرات نواة معروفة.',
                           'description_en': 'Target host runs an unsupported operating system release that no longer '
                                             'receives vendor security patches.',
                           'difficulty': 'hard',
                           'hacktricks': 'https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network',
                           'id': 'eol_os_exposure',
                           'lesson': {   'deep_dive_links': [   {   'label': 'Endoflife.date Lifecycle Tracker',
                                                                    'url': 'https://endoflife.date/'},
                                                                {   'label': 'CIS Controls: Inventory & Control of '
                                                                             'Software Assets',
                                                                    'url': 'https://www.cisecurity.org/controls/'}],
                                         'level_1_foundations_en': 'Operating systems that have passed their '
                                                                   'End-of-Life (EOL) date (e.g. Windows Server 2008, '
                                                                   'Ubuntu 14.04, CentOS 7) cease receiving vendor '
                                                                   'security updates. When kernel or core library '
                                                                   'vulnerabilities (such as Dirty COW or EternalBlue) '
                                                                   'are discovered, EOL hosts remain permanently '
                                                                   'vulnerable, providing adversaries with reliable '
                                                                   'privilege escalation and lateral movement vectors.',
                                         'level_2_detection_en': 'Perform TCP/IP stack fingerprinting with `nmap -O '
                                                                 'target` to determine OS family and kernel build '
                                                                 "version. HexaGuard's Network Recon matches TCP "
                                                                 'window size, IP ID sequencing, and service banners '
                                                                 'against a curated EOL OS database to identify '
                                                                 'unsupported operating systems.',
                                         'level_3_practice': {   'challenge_prompt_en': 'Perform network '
                                                                                        'reconnaissance across a '
                                                                                        'multi-host network to detect '
                                                                                        'legacy EOL operating systems '
                                                                                        'and formulate an isolation '
                                                                                        'VLAN segmentation policy.',
                                                                 'guided_prompt_en': 'Run `nmap -O` against a test '
                                                                                     'virtual machine and inspect how '
                                                                                     'TCP sequence generation and IP '
                                                                                     'TTL headers reveal operating '
                                                                                     'system identity.',
                                                                 'sandbox_target': None},
                                         'level_4_remediation_en': 'Migrate legacy workloads to modern Long-Term '
                                                                   'Support (LTS) distributions (e.g. Ubuntu '
                                                                   '22.04/24.04, Debian 12, RHEL 9). If immediate '
                                                                   'migration is impossible, isolate the host on an '
                                                                   'isolated VLAN with no direct internet ingress and '
                                                                   'enforce strict EDR monitoring. Mapped to CIS '
                                                                   'Controls 2.2 and PCI-DSS v4.0 Req 6.2.'},
                           'name_ar': 'نظام تشغيل منتهي الصلاحية والدعم (EOL OS)',
                           'name_en': 'End-of-Life Operating System Detected',
                           'owasp': 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
                           'portswigger': None,
                           'prerequisites': ['service_version_exposure'],
                           'remediation_ar': 'ترقية نظام التشغيل لإصدار مدعوم (LTS) وعزل الأنظمة القديمة في شبكات '
                                             'افتراضية معزولة.',
                           'remediation_en': 'Upgrade the host operating system to a supported LTS distribution; '
                                             'isolate un-upgradable legacy hosts on dedicated VLANs.',
                           'scanner': 'network',
                           'severity_default': 'critical'},
    'exposed_docker_api': {   'description_ar': 'كشف منفذ التحكم في دوكر بدون تشفير أو مصادقة، مما يمنح المهاجم '
                                                'صلاحيات الروت الكاملة على المضيف.',
                              'description_en': 'Docker daemon TCP socket (port 2375) exposed without TLS '
                                                'authentication, granting root host access.',
                              'difficulty': 'hard',
                              'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker',
                              'id': 'exposed_docker_api',
                              'lesson': {   'deep_dive_links': [   {   'label': 'Docker Daemon Attack Surface',
                                                                       'url': 'https://docs.docker.com/engine/security/protect-access/'},
                                                                   {   'label': 'CIS Docker Benchmark',
                                                                       'url': 'https://www.cisecurity.org/benchmark/docker'}],
                                            'level_1_foundations_en': 'The Docker daemon API permits full management '
                                                                      'of containers, images, and host volume mounts. '
                                                                      'Exposing port 2375 (unencrypted HTTP) without '
                                                                      'authentication is equivalent to granting root '
                                                                      'access to the entire host. An attacker can '
                                                                      'instruct the daemon to launch a new container '
                                                                      'with the host root filesystem mounted (`-v '
                                                                      '/:/host`), edit `/etc/shadow`, and gain root '
                                                                      'shell access.',
                                            'level_2_detection_en': 'Probe port 2375 using curl: `curl '
                                                                    'http://target:2375/version` or `curl '
                                                                    'http://target:2375/containers/json`. If a JSON '
                                                                    'response detailing Docker versions or containers '
                                                                    'is returned, the API is exposed. HexaGuard Docker '
                                                                    'Scanner and Network Recon identify exposed daemon '
                                                                    'sockets and report critical findings.',
                                            'level_3_practice': {   'challenge_prompt_en': 'Audit an infrastructure '
                                                                                           'environment for exposed '
                                                                                           'Docker ports and '
                                                                                           'reconfigure '
                                                                                           '`/etc/docker/daemon.json` '
                                                                                           'to bind strictly to the '
                                                                                           'local Unix socket '
                                                                                           '`/var/run/docker.sock`.',
                                                                    'guided_prompt_en': 'Query an unauthenticated '
                                                                                        'Docker daemon API endpoint '
                                                                                        '(`curl '
                                                                                        'http://127.0.0.1:2375/version`) '
                                                                                        'and observe the full '
                                                                                        'diagnostic information '
                                                                                        'returned.',
                                                                    'sandbox_target': None},
                                            'level_4_remediation_en': 'In `/etc/docker/daemon.json`, set `"hosts": '
                                                                      '["unix:///var/run/docker.sock"]`. If remote '
                                                                      'management is necessary, enforce TLS mutual '
                                                                      'authentication on port 2376: `"tlsverify": '
                                                                      'true`, specifying CA, server certificate, and '
                                                                      'private key files. Mapped to CIS Docker '
                                                                      'Benchmark 2.1.'},
                              'name_ar': 'كشف واجهة دوكر البرمجية بدون مصادقة (Port 2375)',
                              'name_en': 'Unauthenticated Exposed Docker Socket / API',
                              'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                              'portswigger': None,
                              'prerequisites': ['open_ports'],
                              'remediation_ar': 'حظر ربط دوكر بالعناوين العامة واعتماد Unix socket محلياً أو تفعيل '
                                                'المصادقة الثنائية بشهادات TLS على منفذ 2376.',
                              'remediation_en': 'Never bind Docker daemon to 0.0.0.0; use Unix socket exclusively, or '
                                                'enable mandatory TLS mutual authentication on port 2376.',
                              'scanner': 'docker',
                              'severity_default': 'critical'},
    'hardcoded_secrets': {   'description_ar': 'وجود مفاتيح تشفير أو كلمات سر أو رموز واجهات برمجية مضمنة داخل الشفرة '
                                               'المصدرية للمشروع.',
                             'description_en': 'Cryptographic keys, database passwords, or third-party API tokens '
                                               'embedded in source code or repositories.',
                             'difficulty': 'easy',
                             'hacktricks': 'https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets',
                             'id': 'hardcoded_secrets',
                             'lesson': {   'deep_dive_links': [   {   'label': 'Gitleaks Secret Detection',
                                                                      'url': 'https://github.com/gitleaks/gitleaks'},
                                                                  {   'label': 'OWASP Secrets Management Cheat Sheet',
                                                                      'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'}],
                                           'level_1_foundations_en': 'Hardcoded secrets occur when developers commit '
                                                                     'API tokens, database credentials, AWS access '
                                                                     'keys, or private certificates directly into '
                                                                     'source code repositories. Even if repositories '
                                                                     'are private, leaked commit history or '
                                                                     'unauthorized developer access provides instant '
                                                                     'entry into production infrastructure without '
                                                                     'triggering firewall alarms.',
                                           'level_2_detection_en': 'Search source code using high-entropy scanners '
                                                                   '(Gitleaks, Trufflehog) and regex patterns '
                                                                   'targeting provider prefixes (e.g. '
                                                                   '`AKIA[0-9A-Z]{16}` for AWS, `ghp_` for GitHub). '
                                                                   'HexaGuard SAST integrates Gitleaks and Bandit '
                                                                   'rules (B105, B106) to identify hardcoded passwords '
                                                                   'and API tokens across all committed files.',
                                           'level_3_practice': {   'challenge_prompt_en': 'Audit git commit history '
                                                                                          'using `git log -p` to '
                                                                                          'uncover and invalidate '
                                                                                          'credentials mistakenly '
                                                                                          'committed and subsequently '
                                                                                          'removed in a later commit.',
                                                                   'guided_prompt_en': 'Run HexaGuard SAST or Gitleaks '
                                                                                       'against a test repository and '
                                                                                       'observe how high-entropy API '
                                                                                       'key strings are detected and '
                                                                                       'reported.',
                                                                   'sandbox_target': None},
                                           'level_4_remediation_en': 'Remove all credentials from source code. Load '
                                                                     'credentials via environment variables '
                                                                     "(`os.environ['SECRET_KEY']`) or enterprise "
                                                                     'secret management services (HashiCorp Vault, AWS '
                                                                     'Secrets Manager). Enforce pre-commit hooks '
                                                                     '(`gitleaks protect --staged`) to prevent secrets '
                                                                     'from entering version control. Mapped to OWASP '
                                                                     'A05:2021-Security Misconfiguration.'},
                             'name_ar': 'تسريب المفاتيح وكلمات السر المضمنة برمجياً',
                             'name_en': 'Hardcoded Secrets & API Keys',
                             'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                             'portswigger': 'https://portswigger.net/web-security/information-disclosure',
                             'prerequisites': [],
                             'remediation_ar': 'تخزين المفاتيح في متغيرات البيئة أو مدراء الأسرار واستخدام أدوات فحص '
                                               'تلقائية قبل إيداع الشفرة.',
                             'remediation_en': 'Store secrets in environment variables or dedicated secret managers '
                                               '(Vault, AWS Secrets Manager); use pre-commit secret scanners.',
                             'scanner': 'sast',
                             'severity_default': 'critical'},
    'heartbleed_robot': {   'description_ar': 'ثغرات خطيرة في مكتبات التشفير تتيح قراءة ذاكرة الخادم واستخراج المفاتيح '
                                              'الخاصة للجلسات.',
                            'description_en': 'Vulnerabilities in TLS implementations allowing memory disclosure or '
                                              'Bleichenbacher RSA padding oracle attacks.',
                            'difficulty': 'hard',
                            'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssl-tls',
                            'id': 'heartbleed_robot',
                            'lesson': {   'deep_dive_links': [   {   'label': 'The Heartbleed Bug Overview',
                                                                     'url': 'https://heartbleed.com/'},
                                                                 {   'label': 'ROBOT Attack Analysis',
                                                                     'url': 'https://robotattack.org/'}],
                                          'level_1_foundations_en': 'Implementation bugs in cryptographic software can '
                                                                    'completely bypass mathematical encryption '
                                                                    'guarantees. The Heartbleed bug (CVE-2014-0160 in '
                                                                    'OpenSSL) allowed attackers to read 64KB of server '
                                                                    'memory per request, leaking private keys, '
                                                                    'passwords, and sessions. The ROBOT attack revived '
                                                                    "Bleichenbacher's 1998 padding oracle attack "
                                                                    'against RSA encryption key exchange, enabling '
                                                                    'decryption of recorded TLS traffic.',
                                          'level_2_detection_en': 'Probe target with dedicated test tools: `sslyze '
                                                                  '--heartbleed --robot target.com`. In HexaGuard SSL '
                                                                  'Audit, active checks send crafted TLS heartbeat '
                                                                  'requests and modified Bleichenbacher padding probes '
                                                                  'to verify vulnerability without crashing the server '
                                                                  'daemon.',
                                          'level_3_practice': {   'challenge_prompt_en': 'Audit an infrastructure '
                                                                                         'environment to detect '
                                                                                         'services supporting RSA key '
                                                                                         'exchange and reconfigure the '
                                                                                         'server to use ECDHE key '
                                                                                         'exchange exclusively.',
                                                                  'guided_prompt_en': 'Analyze the Heartbleed '
                                                                                      'vulnerability mechanism by '
                                                                                      'reviewing the missing buffer '
                                                                                      "bounds check in OpenSSL's "
                                                                                      '`tls1_process_heartbeat()` '
                                                                                      'function.',
                                                                  'sandbox_target': None},
                                          'level_4_remediation_en': 'Update OpenSSL to the latest patched release. In '
                                                                    'server TLS configurations, eliminate static RSA '
                                                                    'key exchange by selecting cipher suites starting '
                                                                    'with `ECDHE-` exclusively. Mapped to OWASP '
                                                                    'A06:2021-Vulnerable & Outdated Components.'},
                            'name_ar': 'ثغرات تنفيذ بروتوكول TLS الحرجة (Heartbleed, ROBOT)',
                            'name_en': 'Critical TLS Implementation Flaws (Heartbleed / ROBOT)',
                            'owasp': 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
                            'portswigger': None,
                            'prerequisites': ['weak_crypto'],
                            'remediation_ar': 'ترقية وتحديث مكتبات OpenSSL فورا وتعطيل تبادل مفاتيح RSA لصالح ECDHE.',
                            'remediation_en': 'Patch OpenSSL and web server software; disable RSA key exchange in '
                                              'favor of ECDHE ciphers.',
                            'scanner': 'ssl',
                            'severity_default': 'critical'},
    'info_disclosure': {   'description_ar': 'ظهور رسائل أخطاء تفصيلية ومسارات الشفرة البرمجية وتعليقات المطورين في '
                                             'بيئة الإنتاج.',
                           'description_en': 'Detailed system errors, stack traces, or developer comments exposed in '
                                             'production responses.',
                           'difficulty': 'easy',
                           'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/information-disclosure',
                           'id': 'info_disclosure',
                           'lesson': {   'deep_dive_links': [   {   'label': 'OWASP Information Leak Prevention',
                                                                    'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Information_Leak_Prevention_Cheat_Sheet.html'},
                                                                {   'label': 'PortSwigger Information Disclosure',
                                                                    'url': 'https://portswigger.net/web-security/information-disclosure'}],
                                         'level_1_foundations_en': 'Information Disclosure happens when an application '
                                                                   'reveals sensitive technical details to users that '
                                                                   'should remain internal. Examples include raw '
                                                                   'database stack traces (disclosing table names and '
                                                                   'SQL queries), framework debug screens (e.g. Django '
                                                                   'debug page leaking environment variables), or '
                                                                   'internal IP addresses in HTTP response headers. '
                                                                   'Attackers use this data to map out targeted '
                                                                   'exploit chains.',
                                         'level_2_detection_en': 'Trigger application errors by supplying malformed '
                                                                 'input (e.g. non-numeric IDs where integers are '
                                                                 'expected or oversized payloads) and inspect the '
                                                                 'returned page for stack traces, file paths, and '
                                                                 'environment settings. HexaGuard Server External and '
                                                                 'Web Core test error handling behaviors across '
                                                                 'endpoints.',
                                         'level_3_practice': {   'challenge_prompt_en': 'Audit an application '
                                                                                        'framework configuration to '
                                                                                        'ensure all uncaught '
                                                                                        'exceptions trigger a '
                                                                                        'hardened, generic 500 error '
                                                                                        'page that logs details '
                                                                                        'internally without leaking '
                                                                                        'them to the client.',
                                                                 'guided_prompt_en': 'Send a malformed request to a '
                                                                                     'web endpoint and observe whether '
                                                                                     'the response contains a raw '
                                                                                     'stack trace or a hardened '
                                                                                     'generic error page.',
                                                                 'sandbox_target': None},
                                         'level_4_remediation_en': 'Set `DEBUG = False` in Django/Flask. In Express: '
                                                                   'implement an error handler middleware returning a '
                                                                   'generic JSON object: `{ "error": "Internal server '
                                                                   'error", "code": 500 }`. In Nginx: `error_page 500 '
                                                                   '502 503 504 /50x.html;`. Mapped to OWASP '
                                                                   'A05:2021-Security Misconfiguration.'},
                           'name_ar': 'كشف وتسريب المعلومات ورسائل الأخطاء',
                           'name_en': 'Information & Error Message Disclosure',
                           'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                           'portswigger': 'https://portswigger.net/web-security/information-disclosure',
                           'prerequisites': [],
                           'remediation_ar': 'تفعيل صفحات أخطاء مخصصة وعامة في بيئة الإنتاج وتعطيل أوضاع التصحيح '
                                             '(Debug Mode).',
                           'remediation_en': 'Configure generic error pages in production (e.g. custom 500 pages); '
                                             'disable debug modes in web frameworks.',
                           'scanner': 'server_ext',
                           'severity_default': 'low'},
    'insecure_command_execution': {   'description_ar': 'استخدام دوال تنفيذ العمليات الخارجية مع تفعيل مفسر الأوامر '
                                                        'shell=True دون عزل المدخلات.',
                                      'description_en': 'Use of dangerous process execution functions like subprocess '
                                                        'with shell=True or popen with dynamic inputs.',
                                      'difficulty': 'medium',
                                      'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/command-injection',
                                      'id': 'insecure_command_execution',
                                      'lesson': {   'deep_dive_links': [   {   'label': 'Bandit B602 Subprocess '
                                                                                        'Warning',
                                                                               'url': 'https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html'},
                                                                           {   'label': 'Python Security: Subprocess '
                                                                                        'Guidelines',
                                                                               'url': 'https://docs.python.org/3/library/subprocess.html#security-considerations'}],
                                                    'level_1_foundations_en': 'In source code, invoking system '
                                                                              'commands through functions like '
                                                                              "Python's `subprocess.call(..., "
                                                                              'shell=True)` or `os.system()` creates '
                                                                              'direct vulnerabilities to command '
                                                                              'injection. When `shell=True` is '
                                                                              'enabled, the system shell (bash/sh/cmd) '
                                                                              'parses the entire command string, '
                                                                              'interpreting metacharacters like `;`, '
                                                                              '`&`, and `|` to execute arbitrary '
                                                                              'secondary commands.',
                                                    'level_2_detection_en': 'Static analysis scans code for '
                                                                            '`shell=True` keyword arguments, '
                                                                            '`os.popen()`, `eval()`, or `exec()`. '
                                                                            'HexaGuard SAST utilizes Bandit rules '
                                                                            '(B601 through B608) and Semgrep rules to '
                                                                            'detect process spawns where shell '
                                                                            'interpretation is active or where input '
                                                                            'arguments are constructed with dynamic '
                                                                            'strings.',
                                                    'level_3_practice': {   'challenge_prompt_en': 'Refactor a '
                                                                                                   'vulnerable Python '
                                                                                                   'utility utilizing '
                                                                                                   '`os.system` into a '
                                                                                                   'secure '
                                                                                                   'implementation '
                                                                                                   'utilizing '
                                                                                                   '`subprocess.run` '
                                                                                                   'with an argument '
                                                                                                   'list and strict '
                                                                                                   'type checking.',
                                                                            'guided_prompt_en': 'Examine a Python '
                                                                                                'script calling '
                                                                                                "`subprocess.run(f'ping "
                                                                                                "{host}', shell=True)` "
                                                                                                'and observe how '
                                                                                                'passing `127.0.0.1; '
                                                                                                'whoami` leads to '
                                                                                                'arbitrary command '
                                                                                                'execution.',
                                                                            'sandbox_target': None},
                                                    'level_4_remediation_en': "Always use `subprocess.run(['command', "
                                                                              'arg1, arg2], shell=False, check=True)`. '
                                                                              'With `shell=False`, the OS treats each '
                                                                              'item in the list as an exact argument, '
                                                                              'rendering shell metacharacters inert. '
                                                                              'Validate all input arguments against a '
                                                                              'strict whitelist. Mapped to OWASP '
                                                                              'A03:2021-Injection.'},
                                      'name_ar': 'استدعاءات غير آمنة لأوامر النظام في الشفرة',
                                      'name_en': 'Unsafe Subprocess Execution in Source Code',
                                      'owasp': 'https://owasp.org/www-community/attacks/Command_Injection',
                                      'portswigger': 'https://portswigger.net/web-security/os-command-injection',
                                      'prerequisites': ['rce'],
                                      'remediation_ar': 'تمرير معاملات البرامج كمصفوفة عناصر منفصلة مع تعيين '
                                                        'shell=False وتجنب استدعاء مفسر الأوامر.',
                                      'remediation_en': 'Pass executable arguments as distinct array elements with '
                                                        'shell=False; avoid invoking system shells directly.',
                                      'scanner': 'sast',
                                      'severity_default': 'high'},
    'legacy_insecure_protocol': {   'description_ar': 'استخدام بروتوكولات قديمة تنقل كلمات السر والبيانات بنص صريح '
                                                      'عرضة للتنصت والاعتراض.',
                                    'description_en': 'Unencrypted legacy protocols transmit usernames, passwords, and '
                                                      'commands in plaintext across the network.',
                                    'difficulty': 'easy',
                                    'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-telnet',
                                    'id': 'legacy_insecure_protocol',
                                    'lesson': {   'deep_dive_links': [   {   'label': 'NIST SP 800-52 Rev 2: TLS '
                                                                                      'Guidelines',
                                                                             'url': 'https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final'},
                                                                         {   'label': 'OpenSSH Hardening Guide',
                                                                             'url': 'https://infosec.mozilla.org/guidelines/openssh'}],
                                                  'level_1_foundations_en': 'Protocols like Telnet (port 23), FTP '
                                                                            '(port 21), and rlogin (port 513) were '
                                                                            'created before internet-wide encryption '
                                                                            'was standard. They transmit all '
                                                                            'credentials, session tokens, and data '
                                                                            'streams in cleartext. Any passive network '
                                                                            'sniffer or compromised transit router can '
                                                                            'intercept administrative credentials in '
                                                                            'transit.',
                                                  'level_2_detection_en': 'Inspect open ports for port 21 (FTP), port '
                                                                          '23 (Telnet), or port 80 without SSL. In '
                                                                          'HexaGuard Network Recon, services returning '
                                                                          'Telnet or unencrypted FTP banners trigger '
                                                                          'high-severity alerts recommending immediate '
                                                                          'decommissioning.',
                                                  'level_3_practice': {   'challenge_prompt_en': 'Audit an '
                                                                                                 'infrastructure host, '
                                                                                                 'locate active legacy '
                                                                                                 'daemons in systemd, '
                                                                                                 'disable them, and '
                                                                                                 'migrate '
                                                                                                 'administrative '
                                                                                                 'workflows to SSH '
                                                                                                 'key-based access.',
                                                                          'guided_prompt_en': 'Capture network packets '
                                                                                              'using Wireshark while '
                                                                                              'connecting to a local '
                                                                                              'FTP or Telnet server, '
                                                                                              'and observe how '
                                                                                              'credentials appear in '
                                                                                              'plain text in the '
                                                                                              'packet payload.',
                                                                          'sandbox_target': None},
                                                  'level_4_remediation_en': 'Decommission Telnet and cleartext FTP '
                                                                            'services: `systemctl disable --now '
                                                                            'telnet.socket vsftpd`. Enforce SSH '
                                                                            'version 2 with public key authentication '
                                                                            '(`PasswordAuthentication no` in '
                                                                            '`sshd_config`). Mapped to PCI-DSS v4.0 '
                                                                            'Req 4.1 and NIST SP 800-52.'},
                                    'name_ar': 'بروتوكولات قديمة غير مشفرة (Telnet, FTP)',
                                    'name_en': 'Cleartext Legacy Protocol Active (Telnet/FTP)',
                                    'owasp': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
                                    'portswigger': None,
                                    'prerequisites': ['open_ports'],
                                    'remediation_ar': 'إلغاء تفعيل خدمات Telnet و FTP القديمة واعتماد بروتوكولات مشفرة '
                                                      'مثل SSH و SFTP حصراً.',
                                    'remediation_en': 'Disable Telnet, rlogin, and FTP daemons immediately in favor of '
                                                      'SSH, SFTP, and TLS-encrypted channels.',
                                    'scanner': 'network',
                                    'severity_default': 'high'},
    'missing_caa_record': {   'description_ar': 'غياب سجلات CAA يتيح لأي جهة إصدار شهادات عامة إصدار شهادات تشفير '
                                                'للنطاق دون تقييد.',
                              'description_en': 'Absence of DNS CAA records allows any public Certificate Authority to '
                                                'issue SSL certificates for the domain.',
                              'difficulty': 'easy',
                              'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns',
                              'id': 'missing_caa_record',
                              'lesson': {   'deep_dive_links': [   {   'label': 'Qualys SSL Labs: CAA Records',
                                                                       'url': 'https://blog.qualys.com/product-tech/2017/03/13/caa-mandated-by-cab-forum'},
                                                                   {   'label': 'CAA Record Helper',
                                                                       'url': 'https://ssl-mate.com/caa/'}],
                                            'level_1_foundations_en': 'Certificate Authority Authorization (CAA, RFC '
                                                                      '8659) is a DNS record that allows domain owners '
                                                                      'to specify which Certificate Authorities (CAs) '
                                                                      'are authorized to issue certificates for their '
                                                                      'domain. If an attacker compromises a minor or '
                                                                      'untrusted CA, or bypasses domain validation on '
                                                                      'an unlisted CA, the CA is legally required to '
                                                                      'check CAA before issuance. Without CAA, any CA '
                                                                      'can issue valid certificates for your domain.',
                                            'level_2_detection_en': 'Query DNS for CAA records: `dig CAA target.com`. '
                                                                    'If no records are returned, any public CA can '
                                                                    "issue certificates. HexaGuard's DNS Scanner "
                                                                    'queries CAA records via DoH and alerts when CAA '
                                                                    'records are missing.',
                                            'level_3_practice': {   'challenge_prompt_en': 'Construct a CAA record '
                                                                                           'that restricts issuance '
                                                                                           "exclusively to Let's "
                                                                                           'Encrypt and configures an '
                                                                                           'alert email for '
                                                                                           'unauthorized issuance '
                                                                                           'attempts.',
                                                                    'guided_prompt_en': 'Query DNS CAA records using '
                                                                                        '`dig CAA google.com` and '
                                                                                        'observe how authorized '
                                                                                        'issuers (pki.goog) are '
                                                                                        'restricted.',
                                                                    'sandbox_target': None},
                                            'level_4_remediation_en': 'Add CAA records in DNS: `example.com. IN CAA 0 '
                                                                      'issue "letsencrypt.org"` and `example.com. IN '
                                                                      'CAA 0 iodef '
                                                                      '"mailto:security-alerts@example.com"`. Mapped '
                                                                      'to RFC 8659 and CA/Browser Forum Baseline '
                                                                      'Requirements.'},
                              'name_ar': 'غياب سجلات تصريح جهات إصدار الشهادات (CAA Records)',
                              'name_en': 'Missing Certificate Authority Authorization (CAA) Records',
                              'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                              'portswigger': None,
                              'prerequisites': ['missing_spf_dkim_dmarc'],
                              'remediation_ar': 'نشر سجلات CAA تحدد حصراً جهات الإصدار المعتمدة للنطاق مثل '
                                                'letsencrypt.org.',
                              'remediation_en': 'Publish CAA DNS records specifying explicitly authorized Certificate '
                                                'Authorities (e.g. letsencrypt.org).',
                              'scanner': 'dns',
                              'severity_default': 'low'},
    'missing_csp': {   'description_ar': 'غياب ترويسة سياسة أمن المحتوى يسمح بتنفيذ سكربتات خبيثة وتضمين موارد غير '
                                         'موثوقة.',
                       'description_en': 'Lack of Content Security Policy allows execution of untrusted scripts and '
                                         'resources.',
                       'difficulty': 'medium',
                       'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/content-security-policy-csp-bypass',
                       'id': 'missing_csp',
                       'lesson': {   'deep_dive_links': [   {   'label': 'Google CSP Evaluator',
                                                                'url': 'https://csp-evaluator.withgoogle.com/'},
                                                            {   'label': 'MDN CSP Guide',
                                                                'url': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'}],
                                     'level_1_foundations_en': 'Content Security Policy (CSP) is an HTTP response '
                                                               'header that restricts the sources from which browsers '
                                                               'can load and execute scripts, stylesheets, images, and '
                                                               'fonts. Missing or overly permissive policies (such as '
                                                               "`script-src * 'unsafe-inline'`) leave web applications "
                                                               'vulnerable to client-side code injection, data '
                                                               'exfiltration, and clickjacking.',
                                     'level_2_detection_en': 'Inspect response headers of the target using `curl -I '
                                                             'https://target.com` and search for '
                                                             '`Content-Security-Policy`. Verify whether directives '
                                                             'contain wildcards (`*`) or dangerous keywords '
                                                             "(`'unsafe-inline'`, `'unsafe-eval'`). In HexaGuard, the "
                                                             'Web Core scanner evaluates the CSP header against strict '
                                                             'criteria, checking for missing directives and unsafe '
                                                             'fallbacks.',
                                     'level_3_practice': {   'challenge_prompt_en': 'Analyze a web server HTTP '
                                                                                    'response header output to '
                                                                                    'construct a hardened, zero-trust '
                                                                                    'CSP header policy that blocks '
                                                                                    'inline script execution and '
                                                                                    'disallows frame embedding.',
                                                             'guided_prompt_en': 'Use browser developer tools on any '
                                                                                 'target web application to inspect '
                                                                                 'the Network tab response headers for '
                                                                                 'Content-Security-Policy. Identify if '
                                                                                 'inline script execution is '
                                                                                 'permitted.',
                                                             'sandbox_target': None},
                                     'level_4_remediation_en': 'Configure a restrictive CSP header: '
                                                               "`Content-Security-Policy: default-src 'self'; "
                                                               "script-src 'self' 'nonce-{RANDOM}'; object-src 'none'; "
                                                               "frame-ancestors 'none'; base-uri 'self'`. Validate "
                                                               'policies using Google CSP Evaluator. Mapped to OWASP '
                                                               'A05:2021-Security Misconfiguration.'},
                       'name_ar': 'غياب أو ضعف سياسة أمن المحتوى (CSP)',
                       'name_en': 'Missing or Permissive Content Security Policy',
                       'owasp': 'https://owasp.org/www-community/controls/Content_Security_Policy',
                       'portswigger': 'https://portswigger.net/web-security/cross-site-scripting/content-security-policy',
                       'prerequisites': ['missing_security_headers'],
                       'remediation_ar': 'إضافة ترويسة CSP صارمة تحدد مصادر السكربتات الموثوقة وتمنع التضمين داخل '
                                         'إطارات خارجية.',
                       'remediation_en': 'Deploy a strict Content-Security-Policy header restricting script-src, '
                                         'object-src, and frame-ancestors.',
                       'scanner': 'web',
                       'severity_default': 'medium'},
    'missing_dnssec_validation': {   'description_ar': 'غياب التوقيع الرقمي لسجلات DNS مما يجعلها عرضة لهجمات التسميم '
                                                       'والتلاعب بالمسارات (Cache Poisoning).',
                                     'description_en': 'Domain lacks DNSSEC cryptographic signatures (DS and DNSKEY '
                                                       'records), leaving DNS responses susceptible to cache '
                                                       'poisoning.',
                                     'difficulty': 'hard',
                                     'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns',
                                     'id': 'missing_dnssec_validation',
                                     'lesson': {   'deep_dive_links': [   {   'label': 'Cloudflare DNSSEC Guide',
                                                                              'url': 'https://www.cloudflare.com/learning/dns/dnssec/how-dnssec-works/'},
                                                                          {   'label': 'ICANN DNSSEC Overview',
                                                                              'url': 'https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en'}],
                                                   'level_1_foundations_en': 'Standard DNS protocol queries and '
                                                                             'responses are unauthenticated UDP '
                                                                             'packets. Attackers on the network path '
                                                                             'can forge DNS responses (Kaminsky-style '
                                                                             'DNS cache poisoning) and redirect users '
                                                                             'to rogue servers. DNSSEC adds '
                                                                             'cryptographic signatures to DNS records '
                                                                             'using public-key cryptography, ensuring '
                                                                             'answers cannot be forged or tampered '
                                                                             'with.',
                                                   'level_2_detection_en': 'Query for DS records: `dig DS target.com` '
                                                                           'or verify with `delv target.com`. If the '
                                                                           'domain lacks a DS record at the parent TLD '
                                                                           'registrar, DNSSEC is inactive. HexaGuard '
                                                                           'DNS Scanner evaluates DS and DNSKEY '
                                                                           'records to determine validation status.',
                                                   'level_3_practice': {   'challenge_prompt_en': 'Configure DNSSEC on '
                                                                                                  'an authoritative '
                                                                                                  'DNS provider '
                                                                                                  '(Cloudflare or '
                                                                                                  'Route 53) and copy '
                                                                                                  'the DS record to '
                                                                                                  'the domain '
                                                                                                  'registrar to '
                                                                                                  'achieve full '
                                                                                                  'cryptographic '
                                                                                                  'validation.',
                                                                           'guided_prompt_en': 'Use `delv target.com` '
                                                                                               'to inspect '
                                                                                               'cryptographic chain '
                                                                                               'validation from the '
                                                                                               'root zone down to the '
                                                                                               'target domain.',
                                                                           'sandbox_target': None},
                                                   'level_4_remediation_en': 'Enable DNSSEC on your authoritative DNS '
                                                                             'provider. Retrieve the generated '
                                                                             'Delegation Signer (DS) record and add it '
                                                                             'to your domain registrar settings. '
                                                                             'Mapped to NIST SP 800-81-2: Secure '
                                                                             'Domain Name System Deployment Guide.'},
                                     'name_ar': 'غياب حماية وتوقيع نطاقات DNSSEC',
                                     'name_en': 'Missing DNSSEC Integrity Validation',
                                     'owasp': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
                                     'portswigger': None,
                                     'prerequisites': [],
                                     'remediation_ar': 'تفعيل ميزة توقيع DNSSEC لدى مسجل النطاق وخادم الأسماء ونشر '
                                                       'سجلات DS الرقمية.',
                                     'remediation_en': 'Enable DNSSEC signing with registrar and authoritative DNS '
                                                       'provider; publish Delegation Signer (DS) records.',
                                     'scanner': 'dns',
                                     'severity_default': 'medium'},
    'missing_security_headers': {   'description_ar': 'غياب ترويسات الحماية القياسية التي توجه المتصفح لتفعيل دفاعات '
                                                      'مدمجة ضد هجمات الويب.',
                                    'description_en': 'Absence of standard browser defensive headers like HSTS, '
                                                      'X-Frame-Options, and X-Content-Type-Options.',
                                    'difficulty': 'easy',
                                    'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/clickjacking',
                                    'id': 'missing_security_headers',
                                    'lesson': {   'deep_dive_links': [   {   'label': 'OWASP Secure Headers Project',
                                                                             'url': 'https://owasp.org/www-project-secure-headers/'},
                                                                         {   'label': 'SecurityHeaders.com Analyzer',
                                                                             'url': 'https://securityheaders.com/'}],
                                                  'level_1_foundations_en': 'Modern web browsers include robust '
                                                                            'built-in defensive primitives activated '
                                                                            'via standard HTTP response headers. '
                                                                            'Missing HSTS allows SSL stripping '
                                                                            'attacks; missing X-Frame-Options enables '
                                                                            'clickjacking; and missing '
                                                                            'X-Content-Type-Options: nosniff allows '
                                                                            'MIME-sniffing attacks where images are '
                                                                            'executed as scripts.',
                                                  'level_2_detection_en': 'Execute `curl -sI https://target.com` and '
                                                                          'inspect the headers list for '
                                                                          '`Strict-Transport-Security`, '
                                                                          '`X-Frame-Options`, and '
                                                                          "`X-Content-Type-Options`. HexaGuard's Web "
                                                                          'Core scanner inspects all root and subpage '
                                                                          'responses, flagging every omitted security '
                                                                          'header along with its severity and '
                                                                          'remediation directive.',
                                                  'level_3_practice': {   'challenge_prompt_en': 'Configure Nginx or '
                                                                                                 'Apache virtual host '
                                                                                                 'directives to return '
                                                                                                 'an A+ score on '
                                                                                                 'securityheaders.com '
                                                                                                 'with HSTS preload, '
                                                                                                 'DENY frame options, '
                                                                                                 'and strict-origin '
                                                                                                 'referrer policy.',
                                                                          'guided_prompt_en': 'Inspect your local '
                                                                                              'development server HTTP '
                                                                                              'response headers using '
                                                                                              'curl: `curl -I '
                                                                                              'http://127.0.0.1:5000`. '
                                                                                              'Note the complete '
                                                                                              'absence of defensive '
                                                                                              'headers.',
                                                                          'sandbox_target': None},
                                                  'level_4_remediation_en': 'Add to Nginx: `add_header '
                                                                            'Strict-Transport-Security '
                                                                            "'max-age=31536000; includeSubDomains; "
                                                                            "preload' always; add_header "
                                                                            "X-Frame-Options 'DENY' always; add_header "
                                                                            "X-Content-Type-Options 'nosniff' always; "
                                                                            'add_header Referrer-Policy '
                                                                            "'strict-origin-when-cross-origin' "
                                                                            'always;`. Mapped to OWASP '
                                                                            'A05:2021-Security Misconfiguration and '
                                                                            'PCI-DSS v4.0 Req 6.4.1.'},
                                    'name_ar': 'غياب ترويسات الأمان الأساسية (HSTS, X-Frame, Nosniff)',
                                    'name_en': 'Missing Core HTTP Security Headers',
                                    'owasp': 'https://owasp.org/www-project-secure-headers/',
                                    'portswigger': 'https://portswigger.net/web-security/clickjacking',
                                    'prerequisites': [],
                                    'remediation_ar': 'تفعيل ترويسات HSTS و X-Frame-Options و X-Content-Type-Options '
                                                      'على خادم الويب أو البروكسي العكسي.',
                                    'remediation_en': 'Configure HSTS, X-Frame-Options, X-Content-Type-Options, and '
                                                      'Referrer-Policy on reverse proxy/web server.',
                                    'scanner': 'web',
                                    'severity_default': 'low'},
    'missing_spf_dkim_dmarc': {   'description_ar': 'غياب سجلات مصادقة البريد الإلكتروني يتيح للمهاجمين انتحال هوية '
                                                    'النطاق وإرسال رسائل تصيد احتيالي باسم المؤسسة.',
                                  'description_en': 'Lack of email authentication records allows threat actors to '
                                                    "forge emails spoofing the organization's domain.",
                                  'difficulty': 'easy',
                                  'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp/spf-dkim-dmarc',
                                  'id': 'missing_spf_dkim_dmarc',
                                  'lesson': {   'deep_dive_links': [   {   'label': 'DMARC.org Deployment Guide',
                                                                           'url': 'https://dmarc.org/overview/'},
                                                                       {   'label': 'CISA Binding Operational '
                                                                                    'Directive 18-01',
                                                                           'url': 'https://www.cisa.gov/news-events/directives/bod-18-01-enhance-email-and-web-security'}],
                                                'level_1_foundations_en': 'The Simple Mail Transfer Protocol (SMTP) '
                                                                          'lacks inherent sender authentication; by '
                                                                          'default, any mail server can send messages '
                                                                          'claiming to originate from '
                                                                          '`ceo@company.com`. SPF (Sender Policy '
                                                                          'Framework), DKIM (DomainKeys Identified '
                                                                          'Mail), and DMARC establish a cryptographic '
                                                                          'and policy-based trust triangle that '
                                                                          'prevents spoofing. When DMARC is missing or '
                                                                          'set to `p=none`, attackers can easily spoof '
                                                                          'your domain in phishing campaigns.',
                                                'level_2_detection_en': 'Query TXT records for the domain: `dig TXT '
                                                                        'domain.com` (for SPF) and `dig TXT '
                                                                        '_dmarc.domain.com` (for DMARC). Inspect the '
                                                                        'DMARC policy parameter: `p=none` is '
                                                                        "ineffective for enforcement. HexaGuard's DNS "
                                                                        'Scanner queries Cloudflare DoH, parses '
                                                                        'SPF/DMARC policies, and alerts if policy '
                                                                        'strength is weak.',
                                                'level_3_practice': {   'challenge_prompt_en': 'Author an SPF record '
                                                                                               'with strict hard-fail '
                                                                                               '`-all` and a DMARC '
                                                                                               'record configured for '
                                                                                               'quarantine/reject with '
                                                                                               'forensic reporting '
                                                                                               'tags '
                                                                                               '(`mailto:dmarc-reports@domain.com`).',
                                                                        'guided_prompt_en': 'Query DNS for your '
                                                                                            "domain's SPF and DMARC "
                                                                                            'records using `dig TXT '
                                                                                            '_dmarc.domain.com` and '
                                                                                            'observe the policy '
                                                                                            'enforcement flag.',
                                                                        'sandbox_target': None},
                                                'level_4_remediation_en': 'Publish DNS records: SPF: `v=spf1 '
                                                                          'include:_spf.google.com -all`. DMARC: '
                                                                          '`v=DMARC1; p=reject; '
                                                                          'rua=mailto:dmarc-reports@example.com; '
                                                                          'pct=100; adkim=s; aspf=s;`. Enable DKIM on '
                                                                          'your email provider and publish matching '
                                                                          'selector records. Mapped to NIST SP 800-177 '
                                                                          'and CISA BOD 18-01.'},
                                  'name_ar': 'غياب أو ضعف سجلات حماية البريد (SPF, DKIM, DMARC)',
                                  'name_en': 'Missing or Ineffective SPF / DKIM / DMARC Records',
                                  'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                                  'portswigger': None,
                                  'prerequisites': [],
                                  'remediation_ar': 'إضافة سجل SPF صارم وتفعيل توقيع DKIM ونشر سياسة DMARC بوضع الرفض '
                                                    'p=reject وتفعيل التقارير.',
                                  'remediation_en': 'Publish a strict SPF record (-all), configure DKIM signing, and '
                                                    'deploy a DMARC policy with p=reject and aggregate reporting.',
                                  'scanner': 'dns',
                                  'severity_default': 'medium'},
    'modsecurity_disabled': {   'description_ar': 'عدم تفعيل جدار حماية تطبيقات الويب (WAF) أو تركه في وضع التسجيل فقط '
                                                  'بدلاً من الحظر الفعلي.',
                                'description_en': 'Web Application Firewall module is not active or is set to '
                                                  'DetectionOnly mode instead of On.',
                                'difficulty': 'medium',
                                'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/waf-evasion',
                                'id': 'modsecurity_disabled',
                                'lesson': {   'deep_dive_links': [   {   'label': 'OWASP ModSecurity Core Rule Set',
                                                                         'url': 'https://coreruleset.org/'},
                                                                     {   'label': 'ModSecurity Reference Manual',
                                                                         'url': 'https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual'}],
                                              'level_1_foundations_en': 'A Web Application Firewall (WAF) such as '
                                                                        'ModSecurity acts as an inline defensive layer '
                                                                        'inspecting incoming HTTP traffic against '
                                                                        'attack signatures. If ModSecurity is missing '
                                                                        'or configured in `DetectionOnly` mode, '
                                                                        'malicious payloads (SQLi, XSS, RCE) reach '
                                                                        'backend application handlers directly without '
                                                                        'inspection.',
                                              'level_2_detection_en': 'In white-box server scanning, inspect '
                                                                      '`modsecurity.conf` for the `SecRuleEngine` '
                                                                      'parameter. In HexaGuard Server Internal, the '
                                                                      'engine inspects active Apache modules and '
                                                                      'configuration files, flagging servers where '
                                                                      'ModSecurity is either not installed or '
                                                                      'disabled.',
                                              'level_3_practice': {   'challenge_prompt_en': 'Install and configure '
                                                                                             'ModSecurity on an Apache '
                                                                                             'or Nginx server, import '
                                                                                             'the OWASP Core Rule Set '
                                                                                             '(CRS), and verify it '
                                                                                             'blocks test SQL '
                                                                                             'injection payloads with '
                                                                                             'HTTP 403.',
                                                                      'guided_prompt_en': 'Inspect an Apache '
                                                                                          'configuration file to check '
                                                                                          'if `LoadModule '
                                                                                          'security2_module` is '
                                                                                          'enabled and verify the '
                                                                                          'state of `SecRuleEngine`.',
                                                                      'sandbox_target': None},
                                              'level_4_remediation_en': 'In `modsecurity.conf`, set `SecRuleEngine '
                                                                        'On`. Include the OWASP ModSecurity Core Rule '
                                                                        'Set (CRS v3.3+): `Include '
                                                                        'modsecurity.d/owasp-crs/rules/*.conf`. '
                                                                        'Periodically review audit logs in '
                                                                        '`/var/log/modsec_audit.log`. Mapped to '
                                                                        'PCI-DSS v4.0 Req 6.4.2.'},
                                'name_ar': 'تعطيل جدار حماية تطبيقات الويب (ModSecurity)',
                                'name_en': 'Web Application Firewall (ModSecurity) Disabled',
                                'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                                'portswigger': None,
                                'prerequisites': ['security_misconfig'],
                                'remediation_ar': 'تفعيل وحدة ModSecurity بضبط SecRuleEngine On وتفعيل حزمة قواعد '
                                                  'OWASP CRS القياسية.',
                                'remediation_en': 'Enable ModSecurity with SecRuleEngine On and configure the OWASP '
                                                  'Core Rule Set (CRS).',
                                'scanner': 'server',
                                'severity_default': 'medium'},
    'open_ports': {   'description_ar': 'منافذ اتصال مفتوحة على الإنترنت العام دون حاجة تشغيلية مما يوسع مساحة الهجوم.',
                      'description_en': 'Extraneous listening TCP/UDP ports exposed to the public internet, broadening '
                                        'the attack surface.',
                      'difficulty': 'easy',
                      'hacktricks': 'https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network',
                      'id': 'open_ports',
                      'lesson': {   'deep_dive_links': [   {   'label': 'Nmap Network Scanning Guide',
                                                               'url': 'https://nmap.org/book/man.html'},
                                                           {   'label': 'CIS Controls: Network Infrastructure '
                                                                        'Management',
                                                               'url': 'https://www.cisecurity.org/controls/'}],
                                    'level_1_foundations_en': 'Every open network port represents a running daemon and '
                                                              'a potential entry point for attackers. Exposing '
                                                              'management or debugging ports (e.g. 22 SSH, 3389 RDP, '
                                                              '2375 Docker, 5000 Dev servers) directly to the public '
                                                              'internet exposes systems to automated brute-force '
                                                              'attacks, port scanning recon, and unauthenticated '
                                                              'remote exploits.',
                                    'level_2_detection_en': 'Perform TCP SYN port scans using Nmap: `nmap -sS -p- -T4 '
                                                            'target.com` to enumerate listening daemons. HexaGuard '
                                                            'Network Recon orchestrates Nmap scans across the top '
                                                            '1,000 ports, cross-referencing results against Shodan and '
                                                            'GreyNoise to highlight unexpected listening daemons.',
                                    'level_3_practice': {   'challenge_prompt_en': 'Conduct a port audit on a target '
                                                                                   'subnet to identify non-standard '
                                                                                   'management ports and formulate an '
                                                                                   'iptables firewall rule set to drop '
                                                                                   'unauthorized ingress packets.',
                                                            'guided_prompt_en': 'Run Nmap against your local machine '
                                                                                '(`nmap -sT 127.0.0.1`) and observe '
                                                                                'how local development services '
                                                                                '(databases, dev servers) listen on '
                                                                                'ports.',
                                                            'sandbox_target': None},
                                    'level_4_remediation_en': 'Apply the principle of least privilege to network '
                                                              'exposure. Use `ufw default deny incoming`, opening only '
                                                              'required ports (80/443 for web). Bind internal '
                                                              'management services to `127.0.0.1` or private VPC '
                                                              'interfaces. Mapped to CIS Controls 9.2 and PCI-DSS v4.0 '
                                                              'Req 1.3.'},
                      'name_ar': 'منافذ شبكة مكشوفة وغير ضرورية',
                      'name_en': 'Unnecessary Exposed Network Ports',
                      'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                      'portswigger': None,
                      'prerequisites': [],
                      'remediation_ar': 'إغلاق الخدمات غير المطلوبة وتفعيل جدران الحماية وقصر منافذ الإدارة على شبكات '
                                        'VPN.',
                      'remediation_en': 'Close unneeded services, implement host-level firewalls (iptables/ufw), and '
                                        'restrict management ports to VPN/bastion.',
                      'scanner': 'network',
                      'severity_default': 'medium'},
    'open_redirect': {   'description_ar': 'إعادة توجيه متصفح المستخدم إلى مواقع خارجية غير موثوقة دون التحقق من وجهة '
                                           'الرابط.',
                         'description_en': 'Application redirects users to arbitrary external URLs supplied in '
                                           'untrusted parameters.',
                         'difficulty': 'easy',
                         'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/open-redirect',
                         'id': 'open_redirect',
                         'lesson': {   'deep_dive_links': [   {   'label': 'OWASP Unvalidated Redirects Cheat Sheet',
                                                                  'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'},
                                                              {   'label': 'PortSwigger Open Redirect Advisory',
                                                                  'url': 'https://portswigger.net/kb/issues/00500100_open-redirection-reflected'}],
                                       'level_1_foundations_en': 'An Open Redirect flaw occurs when an application '
                                                                 'accepts a target URL via user parameters (e.g. '
                                                                 '`?return_to=https://evil.com`) and issues an HTTP '
                                                                 '301/302 redirect without validating the destination '
                                                                 'host. Attackers leverage trusted organizational '
                                                                 'domains in phishing campaigns, convincing victims to '
                                                                 'click a genuine link that automatically forwards '
                                                                 'them to a malicious spoofed credential harvester.',
                                       'level_2_detection_en': 'Inspect login, logout, and language-switching '
                                                               'parameters (`redirect=`, `next=`, `return_to=`, '
                                                               '`url=`). Test with external targets like '
                                                               '`https://attacker.com`, protocol-relative URLs '
                                                               '(`//attacker.com`), and URL-encoded bypasses '
                                                               '(`%2F%2Fattacker.com`). In HexaGuard, DAST tests all '
                                                               'redirect parameters and flags responses returning 3xx '
                                                               'status codes whose `Location` header points to an '
                                                               'untrusted external origin.',
                                       'level_3_practice': {   'challenge_prompt_en': 'Bypass domain whitelist filters '
                                                                                      'using relative path or '
                                                                                      'subdomain confusion to execute '
                                                                                      'an unauthorized redirect and '
                                                                                      'retrieve the proof flag in the '
                                                                                      'local sandbox.',
                                                               'guided_prompt_en': 'Start OWASP Juice Shop in the '
                                                                                   'Adversarial Twin Sandbox. Navigate '
                                                                                   'to '
                                                                                   '`/redirect?to=https://example.com` '
                                                                                   'and observe how the application '
                                                                                   'redirects the browser to the '
                                                                                   'external site.',
                                                               'sandbox_target': 'open_redirect'},
                                       'level_4_remediation_en': 'Eliminate dynamic user-controlled redirect '
                                                                 'destinations where possible. If redirects are '
                                                                 'necessary, enforce relative paths starting with a '
                                                                 'single forward slash (`/`), verifying the second '
                                                                 'character is not `/` or `\\`. Alternatively, match '
                                                                 'destination hosts against an immutable allowlist. '
                                                                 'Mapped to OWASP A01:2021-Broken Access Control.'},
                         'name_ar': 'إعادة التوجيه غير الآمنة (Open Redirect)',
                         'name_en': 'Unvalidated Redirects and Forwards',
                         'owasp': 'https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet',
                         'portswigger': 'https://portswigger.net/kb/issues/00500100_open-redirection-reflected',
                         'prerequisites': [],
                         'remediation_ar': 'تجنب روابط التوجيه المعتمدة على المستخدم وفرض مسارات نسبية أو قائمة بيضاء '
                                           'للنطاقات المصرح بها.',
                         'remediation_en': 'Avoid user-controlled redirects; enforce relative path redirects or a '
                                           'strict allowlist of authorized domains.',
                         'scanner': 'dast',
                         'severity_default': 'low'},
    'outdated_plugins': {   'description_ar': 'احتواء إضافات أو قوالب ووردبريس المنصبة على ثغرات أمنية غير مرقعة تتيح '
                                              'اختراق الموقع.',
                            'description_en': 'Third-party WordPress plugins or themes contain unpatched '
                                              'vulnerabilities allowing SQLi, XSS, or arbitrary file upload.',
                            'difficulty': 'medium',
                            'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress',
                            'id': 'outdated_plugins',
                            'lesson': {   'deep_dive_links': [   {   'label': 'WPScan WordPress Vulnerability Database',
                                                                     'url': 'https://wpscan.com/vulnerabilities'},
                                                                 {   'label': 'WordPress Hardening Guide',
                                                                     'url': 'https://wordpress.org/documentation/article/hardening-wordpress/'}],
                                          'level_1_foundations_en': 'Over 90% of WordPress security breaches originate '
                                                                    'from third-party plugins and themes rather than '
                                                                    'WordPress core. Unmaintained plugins frequently '
                                                                    'introduce arbitrary file upload vulnerabilities, '
                                                                    'unauthenticated SQL injections, and stored XSS '
                                                                    'that grant full administrator access.',
                                          'level_2_detection_en': 'Enumerate active plugins by inspecting HTML source '
                                                                  'code for `/wp-content/plugins/<plugin-name>/` paths '
                                                                  'and checking readme.txt files for version numbers '
                                                                  '(`/wp-content/plugins/<name>/readme.txt`). '
                                                                  'HexaGuard WordPress Scanner probes common plugin '
                                                                  'endpoints and cross-references versions with public '
                                                                  'WPScan vulnerability databases.',
                                          'level_3_practice': {   'challenge_prompt_en': 'Perform a black-box plugin '
                                                                                         'audit on a target WordPress '
                                                                                         'site, enumerate installed '
                                                                                         'plugins, and correlate '
                                                                                         'findings against the WPScan '
                                                                                         'database.',
                                                                  'guided_prompt_en': 'Inspect the source code of a '
                                                                                      'WordPress site to locate plugin '
                                                                                      'asset URLs and deduce plugin '
                                                                                      'versions from readme.txt files.',
                                                                  'sandbox_target': None},
                                          'level_4_remediation_en': 'Enable automatic background security updates for '
                                                                    'plugins. Remove all inactive or decommissioned '
                                                                    'plugins. Deploy a WordPress-aware WAF (Wordfence '
                                                                    'or Cloudflare WAF). Mapped to OWASP '
                                                                    'A06:2021-Vulnerable & Outdated Components.'},
                            'name_ar': 'إضافات وقوالب ووردبريس قديمة ومصابة بثغرات',
                            'name_en': 'Vulnerable or Outdated WordPress Plugins',
                            'owasp': 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
                            'portswigger': None,
                            'prerequisites': [],
                            'remediation_ar': 'تفعيل التحديث التلقائي للإضافات وحذف الإضافات غير النشطة وتدقيق '
                                              'الإضافات دورياً عبر WPScan.',
                            'remediation_en': 'Enable automatic plugin updates, audit installed plugins with WPScan, '
                                              'and remove inactive themes and plugins.',
                            'scanner': 'wordpress',
                            'severity_default': 'high'},
    'path_traversal': {   'description_ar': 'قراءة أو كتابة ملفات الخادم استناداً لمسارات يحددها المستخدم دون إزالة '
                                            'تسلسلات التراجع (../).',
                          'description_en': 'Application reads or writes files based on user-supplied paths without '
                                            'stripping directory traversal sequences (../).',
                          'difficulty': 'medium',
                          'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/file-inclusion',
                          'id': 'path_traversal',
                          'lesson': {   'deep_dive_links': [   {   'label': 'OWASP Path Traversal Overview',
                                                                   'url': 'https://owasp.org/www-community/attacks/Path_Traversal'},
                                                               {   'label': 'PortSwigger File Path Traversal',
                                                                   'url': 'https://portswigger.net/web-security/file-path-traversal'}],
                                        'level_1_foundations_en': 'Path Traversal (or Directory Traversal) allows '
                                                                  'adversaries to access arbitrary files on the server '
                                                                  'file system by injecting dot-dot-slash (`../` or '
                                                                  '`..\\`) sequences into parameters passed to file '
                                                                  'system APIs. Attackers can read sensitive '
                                                                  'configuration files, source code, or system '
                                                                  'credentials (e.g. `/etc/shadow`, `web.config`), or '
                                                                  'overwrite system executables.',
                                        'level_2_detection_en': 'In static analysis, look for file sinks (`open()`, '
                                                                '`fs.readFile()`, `send_file()`) receiving untrusted '
                                                                'path parameters without canonicalization. HexaGuard '
                                                                'SAST scans for unsafe file path construction and '
                                                                'flags instances where inputs are concatenated into '
                                                                'path operations without directory boundary '
                                                                'verification.',
                                        'level_3_practice': {   'challenge_prompt_en': 'Write a Python secure path '
                                                                                       'validation wrapper that uses '
                                                                                       '`os.path.realpath` and '
                                                                                       '`os.path.commonpath` to safely '
                                                                                       'restrict file access to a '
                                                                                       'designated sandbox directory.',
                                                                'guided_prompt_en': 'Review a file download endpoint '
                                                                                    'implementation taking `filename` '
                                                                                    'parameter and observe how '
                                                                                    'requesting '
                                                                                    '`../../../../etc/passwd` reads '
                                                                                    'system files.',
                                                                'sandbox_target': None},
                                        'level_4_remediation_en': 'Resolve paths completely using `os.path.realpath()` '
                                                                  'and verify the resolved path starts with the base '
                                                                  'directory and a path separator: `resolved = '
                                                                  'os.path.realpath(path); if not '
                                                                  'resolved.startswith(base_dir + os.sep): raise '
                                                                  'AccessDenied()`. Prefer using indirect identifiers '
                                                                  '(e.g. numeric IDs or UUIDs) rather than raw '
                                                                  'filenames. Mapped to OWASP A01:2021-Broken Access '
                                                                  'Control.'},
                          'name_ar': 'اجتياز المسارات والوصول غير المصرح للملفات',
                          'name_en': 'Path Traversal & Unsafe File Access',
                          'owasp': 'https://owasp.org/www-community/attacks/Path_Traversal',
                          'portswigger': 'https://portswigger.net/web-security/file-path-traversal',
                          'prerequisites': [],
                          'remediation_ar': 'التحقق من المسار النهائي ومطابقته للمجلد المصرح به ورفض تسلسلات التراجع '
                                            'عبر path.resolve.',
                          'remediation_en': 'Use path.resolve() and verify the canonical path starts with the intended '
                                            'base directory; reject dot-dot sequences.',
                          'scanner': 'sast',
                          'severity_default': 'high'},
    'privileged_containers': {   'description_ar': 'تشغيل الحاويات بامتيازات مفرطة أو ربط مقبس دوكر مما يتيح الهروب من '
                                                   'الحاوية إلى نظام التشغيل المضيف.',
                                 'description_en': 'Containers running with privileged: true or mounting sensitive '
                                                   'host directories (/var/run/docker.sock, /etc, /proc).',
                                 'difficulty': 'hard',
                                 'hacktricks': 'https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation',
                                 'id': 'privileged_containers',
                                 'lesson': {   'deep_dive_links': [   {   'label': 'Docker Security: Capabilities & '
                                                                                   'Privileges',
                                                                          'url': 'https://docs.docker.com/engine/security/'},
                                                                      {   'label': 'Container Breakout Techniques & '
                                                                                   'Prevention',
                                                                          'url': 'https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation'}],
                                               'level_1_foundations_en': 'Running a container with `--privileged` '
                                                                         'disables all Linux kernel namespace and '
                                                                         'capability isolation mechanisms. A '
                                                                         'privileged container possesses raw device '
                                                                         "access (`/dev`) and can mount the host's "
                                                                         'physical hard drives or load kernel modules, '
                                                                         'making container breakout trivial. '
                                                                         'Similarly, mounting `/var/run/docker.sock` '
                                                                         'allows any code inside the container to '
                                                                         'communicate with the host daemon.',
                                               'level_2_detection_en': 'In static analysis of `docker-compose.yml` or '
                                                                       'Docker run commands, search for `privileged: '
                                                                       'true`, `cap_add: ["ALL"]`, or volume mounts '
                                                                       'pointing to `/var/run/docker.sock`. HexaGuard '
                                                                       'Docker Scanner inspects compose files and '
                                                                       'Dockerfiles, flagging dangerous capabilities '
                                                                       'and host mounts.',
                                               'level_3_practice': {   'challenge_prompt_en': 'Refactor a '
                                                                                              'docker-compose '
                                                                                              'configuration running '
                                                                                              'an application '
                                                                                              'container to remove '
                                                                                              '`privileged: true` and '
                                                                                              'replace it with minimal '
                                                                                              'specific Linux '
                                                                                              'capabilities (`cap_add: '
                                                                                              '["NET_BIND_SERVICE"]`).',
                                                                       'guided_prompt_en': 'Inspect a '
                                                                                           'docker-compose.yml file '
                                                                                           'containing `privileged: '
                                                                                           'true` and observe how all '
                                                                                           'Linux capabilities are '
                                                                                           'enabled for that service.',
                                                                       'sandbox_target': None},
                                               'level_4_remediation_en': 'Remove `privileged: true`. In '
                                                                         '`docker-compose.yml`, drop all default '
                                                                         'capabilities and add only what is required: '
                                                                         '`cap_drop: [ALL]`, `cap_add: '
                                                                         '[NET_BIND_SERVICE]`, and enforce '
                                                                         '`security_opt: ["no-new-privileges:true"]`. '
                                                                         'Never mount `docker.sock` into '
                                                                         'customer-facing containers. Mapped to CIS '
                                                                         'Docker Benchmark 5.4.'},
                                 'name_ar': 'حاويات بصلاحيات ممتازة وربط مسارات المضيف الخطرة',
                                 'name_en': 'Privileged Containers & Dangerous Host Mounts',
                                 'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                                 'portswigger': None,
                                 'prerequisites': ['exposed_docker_api'],
                                 'remediation_ar': 'إلغاء وضع الامتيازات الكاملة وحظر ربط مقبس دوكر داخل الحاويات '
                                                   'وإسقاط الصلاحيات غير الضرورية.',
                                 'remediation_en': 'Remove privileged: true; avoid mounting docker.sock into '
                                                   'containers; drop unnecessary Linux capabilities (cap_drop: ALL).',
                                 'scanner': 'docker',
                                 'severity_default': 'critical'},
    'rce': {   'description_ar': 'تتيح للمهاجم تنفيذ أوامر نظام التشغيل على الخادم المستضيف والسيطرة الكاملة عليه.',
               'description_en': 'Allows an adversary to execute arbitrary operating system commands on the hosting '
                                 'server.',
               'difficulty': 'hard',
               'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/command-injection',
               'id': 'rce',
               'lesson': {   'deep_dive_links': [   {   'label': 'OWASP OS Command Injection Defense',
                                                        'url': 'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'},
                                                    {   'label': 'PortSwigger Command Injection Academy',
                                                        'url': 'https://portswigger.net/web-security/os-command-injection'}],
                             'level_1_foundations_en': 'Remote Code Execution (RCE) represents one of the most '
                                                       'devastating web vulnerabilities. It allows an attacker to '
                                                       'execute arbitrary OS shell commands on the server through '
                                                       'unvalidated inputs passed to functions like `system()`, '
                                                       '`exec()`, or `subprocess.Popen(..., shell=True)`. The Equifax '
                                                       'breach in 2017 occurred through an Apache Struts RCE '
                                                       '(CVE-2017-5638), resulting in the exposure of personal data of '
                                                       '147 million consumers and $1.4 billion in remediation costs.',
                             'level_2_detection_en': 'Manually test inputs with command separator tokens: `;`, `|`, '
                                                     '`&&`, or backticks (e.g. `127.0.0.1; whoami` or `127.0.0.1 && '
                                                     'id`). Check responses for output of command execution or measure '
                                                     'response delay using `sleep 5`. In HexaGuard, DAST tests '
                                                     'ping/lookup utilities by injecting command chaining sequences '
                                                     'and verifying diagnostic command output in HTTP responses.',
                             'level_3_practice': {   'challenge_prompt_en': 'Exploit the command injection '
                                                                            'vulnerability in the sandbox container to '
                                                                            'read the `/etc/passwd` file and locate '
                                                                            'the hidden flag inside the `/tmp` '
                                                                            'directory.',
                                                     'guided_prompt_en': 'Start DVWA in the Adversarial Twin Sandbox. '
                                                                         'Navigate to Command Injection. Enter '
                                                                         '`127.0.0.1; id` in the IP address input form '
                                                                         'and examine the output showing '
                                                                         'uid=33(www-data) execution.',
                                                     'sandbox_target': 'rce'},
                             'level_4_remediation_en': 'Never concatenate untrusted input into system shell strings. '
                                                       'Use native APIs instead of shell commands. If system execution '
                                                       'is unavoidable, pass argument lists to '
                                                       "`subprocess.run(['ping', '-c', '1', validated_ip], "
                                                       'shell=False)` with strict regex validation (e.g. '
                                                       '`^[a-zA-Z0-9.-]+$`). Mapped to OWASP A03:2021-Injection, '
                                                       'PCI-DSS Req 6.4.1, and ISO/IEC 27001 A.14.2.1.'},
               'name_ar': 'تنفيذ التعليمات البرمجية عن بعد (RCE)',
               'name_en': 'Remote Code Execution (RCE)',
               'owasp': 'https://owasp.org/www-community/attacks/Command_Injection',
               'portswigger': 'https://portswigger.net/web-security/os-command-injection',
               'prerequisites': [],
               'remediation_ar': 'تجنب تمرير مدخلات المستخدم لدوال النظام واستخدام قوائم بيضاء صارمة وبيئات تشغيل '
                                 'معزولة.',
               'remediation_en': 'Avoid passing user inputs to system execution functions; use strict whitelists and '
                                 'isolated execution environments.',
               'scanner': 'dast',
               'severity_default': 'critical'},
    'security_misconfig': {   'description_ar': 'إعدادات افتراضية غير آمنة وغياب معايير التهيئة الدفاعية عبر مكونات '
                                                'النظام المختلفة.',
                              'description_en': 'Insecure default settings, unhardened server parameters, or missing '
                                                'defensive configurations across the stack.',
                              'difficulty': 'easy',
                              'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/information-disclosure',
                              'id': 'security_misconfig',
                              'lesson': {   'deep_dive_links': [   {   'label': 'CIS Apache HTTP Server Benchmark',
                                                                       'url': 'https://www.cisecurity.org/benchmark/apache_http_server'},
                                                                   {   'label': 'OWASP Security Misconfiguration '
                                                                                'Overview',
                                                                       'url': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'}],
                                            'level_1_foundations_en': 'Security Misconfiguration is the most common '
                                                                      'vulnerability category across enterprise '
                                                                      'networks. It includes leaving default '
                                                                      'credentials intact, enabling debugging '
                                                                      'endpoints in production, improper CORS headers, '
                                                                      'sample apps left online, and unhardened web '
                                                                      'servers. In 2020, Twitter suffered an admin '
                                                                      'account compromise due to internal tool '
                                                                      'misconfigurations and social engineering.',
                                            'level_2_detection_en': 'Inspect HTTP response headers, error messages, '
                                                                    "and server behavior. HexaGuard's Server Internal "
                                                                    'engine audits Apache and Nginx configuration '
                                                                    'files directly, verifying over 50 individual '
                                                                    'security settings against CIS Benchmarks.',
                                            'level_3_practice': {   'challenge_prompt_en': 'Harden an Apache or Nginx '
                                                                                           'web server configuration '
                                                                                           'file to eliminate default '
                                                                                           'welcome pages, disable '
                                                                                           'server signatures, and '
                                                                                           'restrict directory '
                                                                                           'indexing.',
                                                                    'guided_prompt_en': 'Run HexaGuard Server Internal '
                                                                                        'scan on an Apache test '
                                                                                        'configuration and review the '
                                                                                        'score breakdown across '
                                                                                        'modules.',
                                                                    'sandbox_target': None},
                                            'level_4_remediation_en': 'Adopt CIS Benchmark hardening guides for Apache '
                                                                      'and Nginx. Disable directory browsing (`Options '
                                                                      '-Indexes`), hide server signatures '
                                                                      '(`ServerSignature Off`), and enforce automated '
                                                                      'configuration drift detection via Ansible or '
                                                                      'Chef. Mapped to OWASP A05:2021-Security '
                                                                      'Misconfiguration.'},
                              'name_ar': 'أخطاء التكوين والإعدادات الأمنية العامة',
                              'name_en': 'General Security Misconfiguration',
                              'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                              'portswigger': 'https://portswigger.net/web-security/information-disclosure',
                              'prerequisites': [],
                              'remediation_ar': 'اعتماد معايير تهيئة قياسية موحدة وأتمتة التدقيق وتعطيل الميزات '
                                                'والحسابات غير المستخدمة.',
                              'remediation_en': 'Establish hardened baseline configurations, automate configuration '
                                                'audits, and disable unused features and accounts.',
                              'scanner': 'server',
                              'severity_default': 'medium'},
    'sensitive_data_exposure': {   'description_ar': 'ضعف حماية البيانات الحساسة مثل أرقام البطاقات وكلمات المرور '
                                                     'أثناء النقل أو في قواعد البيانات.',
                                   'description_en': 'Inadequate protection of sensitive data such as PII, encryption '
                                                     'keys, or credentials in transit and storage.',
                                   'difficulty': 'medium',
                                   'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/information-disclosure',
                                   'id': 'sensitive_data_exposure',
                                   'lesson': {   'deep_dive_links': [   {   'label': 'OWASP Cryptographic Storage '
                                                                                     'Cheat Sheet',
                                                                            'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'},
                                                                        {   'label': 'NIST Special Publication 800-111',
                                                                            'url': 'https://csrc.nist.gov/publications/detail/sp/800-111/final'}],
                                                 'level_1_foundations_en': 'Sensitive Data Exposure occurs when '
                                                                           'applications fail to properly safeguard '
                                                                           'sensitive personal identifiable '
                                                                           'information (PII), health records, '
                                                                           'financial credentials, or private '
                                                                           'cryptographic keys. In 2019, First '
                                                                           'American Financial exposed 885 million '
                                                                           'sensitive customer documents including '
                                                                           'bank records and tax forms due to lack of '
                                                                           'object-level authorization and unencrypted '
                                                                           'storage.',
                                                 'level_2_detection_en': 'Static code analysis inspects source files '
                                                                         'for unmasked credit card regexes, cleartext '
                                                                         'SSN storage, unencrypted database columns, '
                                                                         'and logging statements outputting passwords. '
                                                                         'HexaGuard SAST utilizes Semgrep and Bandit '
                                                                         'rules to flag instances where sensitive '
                                                                         'model fields are written to logs or '
                                                                         'transmitted via unencrypted channels.',
                                                 'level_3_practice': {   'challenge_prompt_en': 'Audit an application '
                                                                                                'codebase to identify '
                                                                                                'instances where '
                                                                                                'sensitive '
                                                                                                'authentication tokens '
                                                                                                'or plaintext PII are '
                                                                                                'logged into '
                                                                                                'application telemetry '
                                                                                                'streams.',
                                                                         'guided_prompt_en': 'Run HexaGuard SAST '
                                                                                             'against a local '
                                                                                             'repository containing '
                                                                                             'model definitions and '
                                                                                             'verify how unencrypted '
                                                                                             'sensitive fields are '
                                                                                             'flagged.',
                                                                         'sandbox_target': None},
                                                 'level_4_remediation_en': 'Encrypt sensitive data at rest using '
                                                                           'AES-256-GCM with hardware-backed key '
                                                                           'management (AWS KMS, HashiCorp Vault). '
                                                                           'Never log credentials or tokens. Mask '
                                                                           'credit card and identity numbers in user '
                                                                           'interfaces and APIs. Mapped to OWASP '
                                                                           'A02:2021-Cryptographic Failures, GDPR '
                                                                           'Article 32, and PCI-DSS v4.0 Req 3.4.'},
                                   'name_ar': 'كشف وتسريب البيانات الحساسة',
                                   'name_en': 'Sensitive Data Exposure',
                                   'owasp': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
                                   'portswigger': 'https://portswigger.net/web-security/information-disclosure',
                                   'prerequisites': [],
                                   'remediation_ar': 'تشفير البيانات الحساسة أثناء النقل والتخزين، وتطبيق مبدأ تقليل '
                                                     'البيانات وعزل المفاتيح.',
                                   'remediation_en': 'Encrypt sensitive data at rest and in transit; apply data '
                                                     'minimization, tokenization, and strict access controls.',
                                   'scanner': 'sast',
                                   'severity_default': 'high'},
    'sensitive_file_leak': {   'description_ar': 'إتاحة ملفات حساسة للعامة مثل مستودع git أو ملفات البيئة .env أو نسخ '
                                                 'قواعد البيانات الاحتياطية.',
                               'description_en': 'Hidden version control directories (.git), environment files (.env), '
                                                 'or database backup dumps accessible via web root.',
                               'difficulty': 'medium',
                               'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/information-disclosure',
                               'id': 'sensitive_file_leak',
                               'lesson': {   'deep_dive_links': [   {   'label': 'OWASP Testing for Sensitive Files',
                                                                        'url': 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces'},
                                                                    {   'label': 'GitTools: Git Repository Dumper',
                                                                        'url': 'https://github.com/internetwache/GitTools'}],
                                             'level_1_foundations_en': 'Developers frequently unpack files directly '
                                                                       'into production web roots or create temporary '
                                                                       'editor backups (e.g. `config.php.bak`, `.env`, '
                                                                       '`.git/`). Attackers use automated fuzzers to '
                                                                       'check for these files. Downloading a `.git` '
                                                                       'folder allows attackers to reconstruct the '
                                                                       'entire source code and commit history locally; '
                                                                       'downloading `.env` exposes database passwords '
                                                                       'and API keys.',
                                             'level_2_detection_en': 'Fuzz web roots using tools like ffuf or curl for '
                                                                     'known sensitive paths: `/.env`, `/.git/HEAD`, '
                                                                     '`/dump.sql`, `/backup.zip`. If `/.git/HEAD` '
                                                                     'returns `ref: refs/heads/master`, the git '
                                                                     'repository is exposed. HexaGuard Server External '
                                                                     'probes for over 40 standard sensitive path '
                                                                     'signatures.',
                                             'level_3_practice': {   'challenge_prompt_en': 'Write a server block rule '
                                                                                            'in Nginx that globally '
                                                                                            'returns HTTP 403 '
                                                                                            'Forbidden for any request '
                                                                                            'attempting to access '
                                                                                            'hidden files or dotfile '
                                                                                            'directories (`/.*`).',
                                                                     'guided_prompt_en': 'Test `curl -sI '
                                                                                         'https://target.com/.git/HEAD` '
                                                                                         'to check whether version '
                                                                                         'control internals are '
                                                                                         'accessible.',
                                                                     'sandbox_target': None},
                                             'level_4_remediation_en': 'In Nginx add: `location ~ /\\.(?!well-known).* '
                                                                       '{ deny all; access_log off; log_not_found off; '
                                                                       '}`. Never store environment files or backup '
                                                                       'archives in web root directories. Mapped to '
                                                                       'OWASP A05:2021-Security Misconfiguration.'},
                               'name_ar': 'تسريب ملفات النسخ الاحتياطي والتهيئة (.git, .env, .bak)',
                               'name_en': 'Public Exposure of Sensitive Files (.git / .env / backups)',
                               'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                               'portswigger': 'https://portswigger.net/web-security/information-disclosure',
                               'prerequisites': ['directory_listing'],
                               'remediation_ar': 'حظر الوصول للملفات المخفية وملفات النسخ (.git, .env, .sql) في '
                                                 'إعدادات الخادم وعزل ملفات البيئة.',
                               'remediation_en': 'Block access to dotfiles and backup extensions (.bak, .sql, .env) in '
                                                 'web server configurations; keep web roots clean.',
                               'scanner': 'server_ext',
                               'severity_default': 'high'},
    'server_banner_disclosure': {   'description_ar': 'كشف خادم الويب عن نوعه وإصداره ونظام التشغيل عبر ترويسات Server '
                                                      'و X-Powered-By.',
                                    'description_en': 'Web server leaks exact version, operating system, and installed '
                                                      'modules via Server and X-Powered-By headers.',
                                    'difficulty': 'easy',
                                    'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/information-disclosure',
                                    'id': 'server_banner_disclosure',
                                    'lesson': {   'deep_dive_links': [   {   'label': 'Apache ServerTokens Directive',
                                                                             'url': 'https://httpd.apache.org/docs/2.4/mod/core.html#servertokens'},
                                                                         {   'label': 'OWASP Information Disclosure '
                                                                                      'Prevention',
                                                                             'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Information_Leak_Prevention_Cheat_Sheet.html'}],
                                                  'level_1_foundations_en': 'By default, web servers and application '
                                                                            'runtimes announce their precise version '
                                                                            'numbers in response headers (e.g. '
                                                                            '`Server: Apache/2.4.41 (Ubuntu) '
                                                                            'mod_perl/2.0.11`, `X-Powered-By: '
                                                                            'PHP/7.4.3`). This intelligence enables '
                                                                            'adversaries to look up published exploits '
                                                                            'and tailor targeted payload attacks.',
                                                  'level_2_detection_en': 'Execute `curl -I https://target.com` and '
                                                                          'inspect the `Server` and `X-Powered-By` '
                                                                          'headers. In HexaGuard, Server Internal and '
                                                                          'Web Core scanners parse these banners, '
                                                                          'flagging detailed version leaks.',
                                                  'level_3_practice': {   'challenge_prompt_en': 'Configure an '
                                                                                                 'Express.js app '
                                                                                                 "(`app.disable('x-powered-by')`) "
                                                                                                 'and an Nginx reverse '
                                                                                                 'proxy to completely '
                                                                                                 'suppress server '
                                                                                                 'banner information.',
                                                                          'guided_prompt_en': 'Inspect the HTTP '
                                                                                              'response headers of an '
                                                                                              'unhardened web '
                                                                                              'application using curl '
                                                                                              'and observe the '
                                                                                              'detailed software '
                                                                                              'version strings.',
                                                                          'sandbox_target': None},
                                                  'level_4_remediation_en': 'In Apache: `ServerTokens Prod` and '
                                                                            '`ServerSignature Off`. In Nginx: '
                                                                            '`server_tokens off;`. In Express: '
                                                                            "`app.disable('x-powered-by')`. In PHP: "
                                                                            '`expose_php = Off` in `php.ini`. Mapped '
                                                                            'to OWASP A05:2021-Security '
                                                                            'Misconfiguration.'},
                                    'name_ar': 'كشف تفاصيل وتوقيع خادم الويب (Server Banner)',
                                    'name_en': 'Server Banner & Component Version Disclosure',
                                    'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                                    'portswigger': 'https://portswigger.net/web-security/information-disclosure',
                                    'prerequisites': [],
                                    'remediation_ar': 'ضبط ServerTokens Prod في أباتشي وتعطيل server_tokens في إنجن '
                                                      'إكس وإزالة ترويسة X-Powered-By.',
                                    'remediation_en': 'Set ServerTokens Prod in Apache, server_tokens off in Nginx, '
                                                      'and disable X-Powered-By in backend frameworks.',
                                    'scanner': 'server',
                                    'severity_default': 'low'},
    'service_version_exposure': {   'description_ar': 'إعلان الخدمات الشبكية عن إصدارات قديمة أو منتهية الصلاحية تحتوي '
                                                      'على ثغرات أمنية معروفة.',
                                    'description_en': 'Network services advertise outdated or end-of-life version '
                                                      'banners with known public CVE exploits.',
                                    'difficulty': 'medium',
                                    'hacktricks': 'https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network',
                                    'id': 'service_version_exposure',
                                    'lesson': {   'deep_dive_links': [   {   'label': 'NIST National Vulnerability '
                                                                                      'Database',
                                                                             'url': 'https://nvd.nist.gov/'},
                                                                         {   'label': 'CISA Known Exploited '
                                                                                      'Vulnerabilities Catalog',
                                                                             'url': 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'}],
                                                  'level_1_foundations_en': 'When network services broadcast their '
                                                                            'exact daemon names and version numbers in '
                                                                            'connection banners (e.g. OpenSSH 7.2p2, '
                                                                            'Apache 2.4.7), adversaries '
                                                                            'cross-reference these versions with '
                                                                            'national vulnerability databases (NVD) to '
                                                                            'select weaponized exploits without '
                                                                            'needing to guess or brute-force.',
                                                  'level_2_detection_en': 'Connect to services via netcat (`nc -v '
                                                                          'target 22`) or run `nmap -sV target` to '
                                                                          "probe banner responses. HexaGuard's Network "
                                                                          'Recon engine fingerprints service banners '
                                                                          'and queries the NVD and Shodan CVE '
                                                                          'databases to highlight critical public '
                                                                          'exploits.',
                                                  'level_3_practice': {   'challenge_prompt_en': 'Analyze service '
                                                                                                 'version banners from '
                                                                                                 'an Nmap scan output '
                                                                                                 'to identify '
                                                                                                 'unpatched daemons '
                                                                                                 'with active '
                                                                                                 'Metasploit modules '
                                                                                                 'and map them to CVE '
                                                                                                 'identifiers.',
                                                                          'guided_prompt_en': 'Use netcat to connect '
                                                                                              'to port 22 or 80 on a '
                                                                                              'target machine and '
                                                                                              'inspect the plain text '
                                                                                              'banner returned before '
                                                                                              'authentication.',
                                                                          'sandbox_target': None},
                                                  'level_4_remediation_en': 'Keep operating system packages upgraded '
                                                                            'via automated patch management '
                                                                            '(`unattended-upgrades` or yum-cron). '
                                                                            'Suppress banner details in service '
                                                                            'configs (e.g. `ServerTokens Prod` in '
                                                                            'Apache, `server_tokens off;` in Nginx). '
                                                                            'Mapped to OWASP A06:2021-Vulnerable & '
                                                                            'Outdated Components.'},
                                    'name_ar': 'كشف وإتاحة إصدارات خدمات قديمة',
                                    'name_en': 'Outdated Service Version Exposure',
                                    'owasp': 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
                                    'portswigger': None,
                                    'prerequisites': ['open_ports'],
                                    'remediation_ar': 'ترقية البرمجيات للإصدارات المدعومة وتعتيم ترويسات الإصدارات في '
                                                      'إعدادات الخادم.',
                                    'remediation_en': 'Upgrade daemons to actively maintained releases; suppress '
                                                      'version banners in server configurations.',
                                    'scanner': 'network',
                                    'severity_default': 'high'},
    'session_fixation': {   'description_ar': 'بقاء معرف الجلسة ثابتاً بعد تسجيل الدخول، أو غياب سمات الأمان '
                                              '(HttpOnly, Secure, SameSite).',
                            'description_en': 'Session identifier remains unchanged after authentication, or cookies '
                                              'lack HttpOnly/Secure/SameSite flags.',
                            'difficulty': 'medium',
                            'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/session-fixation',
                            'id': 'session_fixation',
                            'lesson': {   'deep_dive_links': [   {   'label': 'OWASP Session Management Cheat Sheet',
                                                                     'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'},
                                                                 {   'label': 'PortSwigger Cookies Deep Dive',
                                                                     'url': 'https://portswigger.net/web-security/essential-skills/cookies'}],
                                          'level_1_foundations_en': 'Session Fixation occurs when an application '
                                                                    'preserves the same session ID across '
                                                                    'authentication state transitions. An attacker can '
                                                                    "set a victim's session cookie (via XSS or "
                                                                    'subdomain injection) and wait for the victim to '
                                                                    'log in, gaining authenticated access with the '
                                                                    'fixed ID. Insecure cookie flags (`HttpOnly` '
                                                                    'missing allows XSS token theft; `Secure` missing '
                                                                    'allows cleartext transmission).',
                                          'level_2_detection_en': 'Inspect `Set-Cookie` headers across pre-login and '
                                                                  'post-login requests. If the session cookie value '
                                                                  'does not change after authenticating, session '
                                                                  'fixation is present. Verify that all sensitive '
                                                                  'cookies include `; Secure; HttpOnly; SameSite=Lax`. '
                                                                  "HexaGuard's Web Core engine automates cookie flag "
                                                                  'analysis and alerts on missing protection '
                                                                  'attributes.',
                                          'level_3_practice': {   'challenge_prompt_en': "Audit an application's "
                                                                                         'cookie configuration to '
                                                                                         'ensure session IDs are '
                                                                                         'regenerated upon login and '
                                                                                         'all session tokens include '
                                                                                         'Secure, HttpOnly, and '
                                                                                         'SameSite attributes.',
                                                                  'guided_prompt_en': 'Open browser DevTools '
                                                                                      'Application tab -> Cookies. Log '
                                                                                      'in to an application and verify '
                                                                                      'whether the session ID cookie '
                                                                                      'changes post-authentication.',
                                                                  'sandbox_target': None},
                                          'level_4_remediation_en': 'In Flask/Django/Express, configure: '
                                                                    '`SESSION_COOKIE_SECURE = True`, '
                                                                    '`SESSION_COOKIE_HTTPONLY = True`, '
                                                                    "`SESSION_COOKIE_SAMESITE = 'Lax'`. On successful "
                                                                    'authentication, explicitly call '
                                                                    '`session.regenerate()` or `session.cycle_key()`. '
                                                                    'Mapped to OWASP A07:2021-Identification & '
                                                                    'Authentication Failures.'},
                            'name_ar': 'تثبيت الجلسة وغياب سمات الكوكيز الآمنة',
                            'name_en': 'Session Fixation & Insecure Cookie Flags',
                            'owasp': 'https://owasp.org/www-community/attacks/Session_fixation',
                            'portswigger': 'https://portswigger.net/web-security/essential-skills/cookies',
                            'prerequisites': [],
                            'remediation_ar': 'إعادة توليد معرف الجلسة فور المصادقة، وتعيين سمات Secure و HttpOnly و '
                                              'SameSite لكافة الكوكيز.',
                            'remediation_en': 'Regenerate session tokens upon login, and mark all authentication '
                                              'cookies with Secure, HttpOnly, and SameSite=Lax/Strict.',
                            'scanner': 'web',
                            'severity_default': 'medium'},
    'slowloris_dos': {   'description_ar': 'استنزاف خيوط اتصال الخادم عبر فتح اتصالات HTTP جزئية وإبقائها معلقة مما '
                                           'يحجب الخدمة عن المستخدمين الشرعيين.',
                         'description_en': 'Server thread or connection pool exhausted by holding numerous concurrent '
                                           'partial HTTP requests open indefinitely.',
                         'difficulty': 'hard',
                         'hacktricks': 'https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network',
                         'id': 'slowloris_dos',
                         'lesson': {   'deep_dive_links': [   {   'label': 'Cloudflare Slowloris Mitigation',
                                                                  'url': 'https://www.cloudflare.com/learning/ddos/ddos-attack-tools/slowloris/'},
                                                              {   'label': 'Apache mod_reqtimeout Guide',
                                                                  'url': 'https://httpd.apache.org/docs/2.4/mod/mod_reqtimeout.html'}],
                                       'level_1_foundations_en': 'Slowloris is a Denial of Service attack that '
                                                                 'requires very minimal bandwidth. Instead of flooding '
                                                                 'the target with high-volume traffic, the attacker '
                                                                 'opens hundreds of HTTP connections and sends partial '
                                                                 'HTTP headers very slowly (e.g. sending one header '
                                                                 'line every 15 seconds). Thread-based web servers '
                                                                 '(like classic Apache MPM worker) keep worker threads '
                                                                 'waiting, quickly consuming all connection slots and '
                                                                 'rejecting legitimate users.',
                                       'level_2_detection_en': 'Test server timeout handling by sending incomplete '
                                                               'HTTP headers and measuring the time elapsed before the '
                                                               'server closes the connection. HexaGuard Server '
                                                               'External measures header timeout thresholds without '
                                                               'exhausting server connection pools.',
                                       'level_3_practice': {   'challenge_prompt_en': 'Configure connection rate '
                                                                                      'limits and header read timeout '
                                                                                      'directives in Nginx or Apache '
                                                                                      'mod_reqtimeout to resist '
                                                                                      'Slowloris attacks.',
                                                               'guided_prompt_en': 'Review the architecture difference '
                                                                                   'between process-per-connection '
                                                                                   'servers (Apache prefork) and '
                                                                                   'event-loop servers (Nginx) '
                                                                                   'regarding Slowloris resilience.',
                                                               'sandbox_target': None},
                                       'level_4_remediation_en': 'In Nginx: configure `client_body_timeout 10s; '
                                                                 'client_header_timeout 10s; limit_conn_zone '
                                                                 '$binary_remote_addr zone=addr:10m; limit_conn addr '
                                                                 '50;`. In Apache: enable and configure '
                                                                 '`mod_reqtimeout`. Mapped to OWASP A05:2021-Security '
                                                                 'Misconfiguration.'},
                         'name_ar': 'هجمات حجب الخدمة بطيئة الاتصال (Slowloris DoS)',
                         'name_en': 'Slowloris Low-Bandwidth Denial of Service',
                         'owasp': 'https://owasp.org/www-community/attacks/Slowloris',
                         'portswigger': None,
                         'prerequisites': ['security_misconfig'],
                         'remediation_ar': 'ضبط مهلات استقبال الترويسات وتحديد الحد الأقصى للاتصالات لكل IP واعتماد '
                                           'بروكسي عكسي غير تزامني.',
                         'remediation_en': 'Configure strict client header timeouts, limit concurrent connections per '
                                           'IP, and use event-driven reverse proxies (Nginx/HAProxy).',
                         'scanner': 'server_ext',
                         'severity_default': 'medium'},
    'sqli': {   'description_ar': 'تداخل مدخلات غير موثوقة مع استعلامات قاعدة البيانات، مما يسمح بتسريب البيانات أو '
                                  'تجاوز المصادقة أو تلفها.',
                'description_en': 'Untrusted user inputs interfere with backend database queries, allowing data '
                                  'exfiltration or authentication bypass.',
                'difficulty': 'hard',
                'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/sql-injection',
                'id': 'sqli',
                'lesson': {   'deep_dive_links': [   {   'label': 'OWASP SQL Injection Prevention Cheat Sheet',
                                                         'url': 'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'},
                                                     {   'label': 'PortSwigger SQLi Tutorial',
                                                         'url': 'https://portswigger.net/web-security/sql-injection'},
                                                     {   'label': 'SQLAlchemy Security Practices',
                                                         'url': 'https://docs.sqlalchemy.org/en/20/core/tutorial.html'}],
                              'level_1_foundations_en': 'SQL Injection happens when untrusted user input is directly '
                                                        'concatenated into SQL statements without parametrization, '
                                                        'altering query structure. Attackers can bypass '
                                                        'authentication, extract confidential database records, alter '
                                                        'data, or execute operating system commands via database '
                                                        'features (e.g. xp_cmdshell). The Heartland Payment Systems '
                                                        'breach resulted from SQL injection, exposing 130 million '
                                                        'debit and credit cards and costing over $140 million in '
                                                        'penalties.',
                              'level_2_detection_en': 'To detect SQLi manually, supply syntax-breaking characters such '
                                                      "as single quotes (`'`), double dashes (`--`), or boolean "
                                                      "expressions (`' OR '1'='1`) into input parameters. Inspect "
                                                      'response text for database engine errors or differential '
                                                      'response timing. In HexaGuard, the DAST engine detects SQLi via '
                                                      'error-based heuristics, UNION extraction signatures, and blind '
                                                      'time-delay triggers (e.g. pg_sleep or WAITFOR DELAY).',
                              'level_3_practice': {   'challenge_prompt_en': 'Using the DVWA SQL Injection challenge, '
                                                                             'leverage UNION SELECT techniques to '
                                                                             'extract password hashes from the `users` '
                                                                             'table, crack the admin hash, and capture '
                                                                             'the proof flag.',
                                                      'guided_prompt_en': 'Start the DVWA container in the Adversarial '
                                                                          'Twin Sandbox. Navigate to SQL Injection, '
                                                                          "submit User ID `1' OR '1'='1`, and observe "
                                                                          'how the database returns records for all '
                                                                          'registered accounts simultaneously.',
                                                      'sandbox_target': 'sqli'},
                              'level_4_remediation_en': 'Enforce parameterized queries (Prepared Statements) across '
                                                        'all database interactions. In Python use '
                                                        "`cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))` "
                                                        'or an ORM like SQLAlchemy. Never format queries with '
                                                        'f-strings or string concatenation. Mapped to OWASP '
                                                        'A03:2021-Injection, PCI-DSS v4.0 Req 6.4.3, and ISO/IEC 27001 '
                                                        'A.14.2.1.'},
                'name_ar': 'حقن قواعد البيانات (SQLi)',
                'name_en': 'SQL Injection (SQLi)',
                'owasp': 'https://owasp.org/www-community/attacks/SQL_Injection',
                'portswigger': 'https://portswigger.net/web-security/sql-injection',
                'prerequisites': [],
                'remediation_ar': 'استخدام الاستعلامات المعلمة (Prepared Statements) أو أطر عمل الـ ORM الآمنة لربط '
                                  'المتغيرات.',
                'remediation_en': 'Use parameterized queries (prepared statements) and Object-Relational Mapping (ORM) '
                                  'frameworks.',
                'scanner': 'dast',
                'severity_default': 'high'},
    'ssrf': {   'description_ar': 'إجبار الخادم على إجراء طلبات غير مصرح بها إلى موارد داخلية أو سحابية أو شبكات '
                                  'معزولة.',
                'description_en': 'Coerces a backend server into making unauthorized HTTP requests to internal or '
                                  'third-party resources.',
                'difficulty': 'hard',
                'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery',
                'id': 'ssrf',
                'lesson': {   'deep_dive_links': [   {   'label': 'OWASP SSRF Prevention Cheat Sheet',
                                                         'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'},
                                                     {   'label': 'PortSwigger SSRF Academy',
                                                         'url': 'https://portswigger.net/web-security/ssrf'}],
                              'level_1_foundations_en': 'Server-Side Request Forgery (SSRF) occurs when a web '
                                                        'application fetches a remote resource without validating the '
                                                        'user-supplied destination URL. Attackers coerce the server to '
                                                        'act as a proxy into the internal network, accessing cloud '
                                                        'instance metadata services (e.g. AWS 169.254.169.254), '
                                                        'internal Kubernetes APIs, or loopback admin interfaces. The '
                                                        '2019 Capital One breach stemmed from an SSRF flaw in an '
                                                        'open-source WAF, allowing attackers to access AWS IAM '
                                                        'credentials and steal 100 million customer credit '
                                                        'applications.',
                              'level_2_detection_en': 'Identify parameters that accept URLs or file paths (e.g. '
                                                      '`url=`, `webhook=`, `image_url=`, `proxy=`). Supply loopback '
                                                      'addresses (`127.0.0.1`, `http://[::1]`) or cloud metadata '
                                                      'endpoints (`http://169.254.169.254/latest/meta-data/`). In '
                                                      'HexaGuard, DAST tests URL parameters by injecting loopback and '
                                                      'internal network IP payloads while verifying whether internal '
                                                      'services or metadata keys are returned.',
                              'level_3_practice': {   'challenge_prompt_en': 'Exploit an SSRF vulnerability in the '
                                                                             'local sandbox container to read local '
                                                                             'configuration metadata and capture the '
                                                                             'proof flag.',
                                                      'guided_prompt_en': 'Start OWASP Juice Shop in the Adversarial '
                                                                          'Twin Sandbox. Navigate to photo upload or '
                                                                          'URL import features, supply an internal '
                                                                          'test link, and observe how backend fetches '
                                                                          'loopback resources.',
                                                      'sandbox_target': 'ssrf'},
                              'level_4_remediation_en': 'Resolve domain names to IP addresses before initiating '
                                                        'connections; reject any IP falling into private ranges '
                                                        '(`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, '
                                                        '`127.0.0.0/8`, `169.254.169.254/32`). Disable automatic HTTP '
                                                        'redirect following in client libraries (e.g. '
                                                        '`allow_redirects=False`). Enforce IMDSv2 in AWS cloud '
                                                        'environments. Mapped to OWASP A10:2021-Server-Side Request '
                                                        'Forgery.'},
                'name_ar': 'تزوير الطلبات من جانب الخادم (SSRF)',
                'name_en': 'Server-Side Request Forgery (SSRF)',
                'owasp': 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
                'portswigger': 'https://portswigger.net/web-security/ssrf',
                'prerequisites': ['open_ports'],
                'remediation_ar': 'فرض قوائم بيضاء صارمة وحظر العناوين الخاصة وسيرفرات البيانات الوصفية وتعطيل إعادة '
                                  'التوجيه التلقائي.',
                'remediation_en': 'Enforce strict protocol/hostname allowlists, block private IP ranges (RFC '
                                  '1918/link-local), and disable HTTP redirects in fetching clients.',
                'scanner': 'dast',
                'severity_default': 'high'},
    'takeover': {   'description_ar': 'سجل DNS يشير إلى خدمة سحابية ملغاة أو منتهية الصلاحية يمكن للمهاجم تسجيلها '
                                      'والسيطرة على النطاق.',
                    'description_en': 'Dangling CNAME DNS record points to a decommissioned third-party cloud service '
                                      '(GitHub, AWS, S3) that can be claimed by an attacker.',
                    'difficulty': 'hard',
                    'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/subdomain-takeover',
                    'id': 'takeover',
                    'lesson': {   'deep_dive_links': [   {   'label': 'Can I take over XYZ? Reference Database',
                                                             'url': 'https://github.com/EdOverflow/can-i-take-over-xyz'},
                                                         {   'label': 'OWASP Subdomain Takeover Testing',
                                                             'url': 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover'}],
                                  'level_1_foundations_en': 'Subdomain Takeover happens when an organization '
                                                            'configures a DNS CNAME record pointing a subdomain (e.g. '
                                                            '`docs.company.com`) to a third-party service provider '
                                                            '(e.g. GitHub Pages, AWS S3, Zendesk, Heroku). When the '
                                                            'organization later cancels that service account without '
                                                            'removing the DNS record, an attacker can register the '
                                                            'unclaimed service name and serve arbitrary malicious '
                                                            'content under the trusted company subdomain.',
                                  'level_2_detection_en': 'Resolve subdomain CNAME records (`dig CNAME '
                                                          'sub.target.com`) and inspect HTTP responses for cloud '
                                                          "provider error fingerprints (e.g. 'There isn't a GitHub "
                                                          "Pages site here', 'NoSuchBucket' in AWS S3). HexaGuard DNS "
                                                          'Scanner verifies CNAME resolutions against signatures for '
                                                          'over 60 known third-party cloud providers.',
                                  'level_3_practice': {   'challenge_prompt_en': 'Conduct a subdomain enumeration '
                                                                                 'audit on a target domain to discover '
                                                                                 'dangling CNAME records pointing to '
                                                                                 'decommissioned S3 buckets.',
                                                          'guided_prompt_en': 'Use `dig CNAME` to trace an alias '
                                                                              'record and inspect how provider error '
                                                                              'responses indicate unclaimed resources.',
                                                          'sandbox_target': None},
                                  'level_4_remediation_en': 'Establish an automated decommissioning procedure: always '
                                                            'delete DNS CNAME records *before* terminating cloud '
                                                            'subscriptions. Continuously monitor external DNS zones '
                                                            'for dangling records using subjack or can-i-take-over-xyz '
                                                            'databases. Mapped to OWASP A05:2021-Security '
                                                            'Misconfiguration.'},
                    'name_ar': 'الاستيلاء على النطاقات الفرعية (Subdomain Takeover)',
                    'name_en': 'Subdomain Takeover',
                    'owasp': 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover',
                    'portswigger': None,
                    'prerequisites': [],
                    'remediation_ar': 'حذف سجلات CNAME غير المستخدمة والتحقق من تحرير النطاقات قبل إلغاء الخدمات '
                                      'السحابية.',
                    'remediation_en': 'Remove dangling DNS records; audit cloud assets before decommissioning '
                                      'SaaS/cloud buckets.',
                    'scanner': 'dns',
                    'severity_default': 'high'},
    'tls_compression_crime': {   'description_ar': 'ضغط البيانات على مستوى بروتوكول TLS يتيح استنتاج رموز الجلسات عبر '
                                                   'تحليل أحجام التشفير.',
                                 'description_en': 'TLS-level compression leaks plaintext token lengths through '
                                                   'ciphertext variations, enabling session recovery.',
                                 'difficulty': 'medium',
                                 'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssl-tls',
                                 'id': 'tls_compression_crime',
                                 'lesson': {   'deep_dive_links': [   {   'label': 'CRIME Attack Explained',
                                                                          'url': 'https://en.wikipedia.org/wiki/CRIME'},
                                                                      {   'label': 'SSLyze TLS Compression Scanner',
                                                                          'url': 'https://github.com/nabla-c0d3/sslyze'}],
                                               'level_1_foundations_en': 'The CRIME (Compression Ratio Info-leak Made '
                                                                         'Easy) attack exploits data compression when '
                                                                         'applied before encryption in TLS. Because '
                                                                         'compression algorithms replace repeated byte '
                                                                         'sequences with shorter tokens, an attacker '
                                                                         'who controls part of the plaintext (via '
                                                                         'cross-origin script injection) can '
                                                                         'brute-force secret session cookies by '
                                                                         'observing fluctuations in ciphertext length.',
                                               'level_2_detection_en': 'Test with SSLyze: `sslyze --compression '
                                                                       'target.com:443`. If the response indicates '
                                                                       '`compression_supported: True`, the server is '
                                                                       'vulnerable. In HexaGuard, the SSL Audit engine '
                                                                       'tests TLS Client Hello packets with DEFLATE '
                                                                       'compression support and flags servers that '
                                                                       'accept compression.',
                                               'level_3_practice': {   'challenge_prompt_en': 'Audit server '
                                                                                              'configurations across '
                                                                                              'Apache and Nginx to '
                                                                                              'verify TLS compression '
                                                                                              'is disabled while '
                                                                                              'preserving '
                                                                                              'application-level gzip '
                                                                                              'compression.',
                                                                       'guided_prompt_en': 'Inspect TLS ClientHello '
                                                                                           'and ServerHello packet '
                                                                                           'negotiation to determine '
                                                                                           'whether DEFLATE '
                                                                                           'compression is negotiated.',
                                                                       'sandbox_target': None},
                                               'level_4_remediation_en': 'Disable TLS compression. In Nginx: TLS '
                                                                         'compression is disabled by default in modern '
                                                                         'builds. In OpenSSL, ensure '
                                                                         '`SSL_OP_NO_COMPRESSION` flag is set. Note '
                                                                         'that application-level HTTP compression '
                                                                         '(e.g. gzip of HTML bodies) is separate from '
                                                                         'TLS compression. Mapped to OWASP '
                                                                         'A02:2021-Cryptographic Failures.'},
                                 'name_ar': 'تفعيل ضغط TLS وثغرة CRIME',
                                 'name_en': 'TLS Compression Enabled (CRIME Attack)',
                                 'owasp': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
                                 'portswigger': None,
                                 'prerequisites': ['weak_crypto'],
                                 'remediation_ar': 'تعطيل ضغط TLS بالكامل على خوادم الويب وموزعات الأحمال.',
                                 'remediation_en': 'Disable TLS-level compression completely on all web servers and '
                                                   'load balancers.',
                                 'scanner': 'ssl',
                                 'severity_default': 'medium'},
    'transitive_dependency_vuln': {   'description_ar': 'ثغرة كامنة داخل مكتبة فرعية غير مباشرة يتم تحميلها تلقائياً '
                                                        'دون إدراجها صراحة في ملف المشروع الرئيسي.',
                                      'description_en': 'Vulnerability nested deeply inside an indirect sub-dependency '
                                                        'not explicitly declared in primary manifest files.',
                                      'difficulty': 'hard',
                                      'hacktricks': 'https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-ci-cd',
                                      'id': 'transitive_dependency_vuln',
                                      'lesson': {   'deep_dive_links': [   {   'label': 'npm Overrides Documentation',
                                                                               'url': 'https://docs.npmjs.com/cli/v9/configuring-npm/package-json#overrides'},
                                                                           {   'label': 'OWASP Software Component '
                                                                                        'Verification Standard',
                                                                               'url': 'https://owasp.org/www-project-software-component-verification-standard/'}],
                                                    'level_1_foundations_en': 'Applications rarely import all '
                                                                              'dependencies directly; direct '
                                                                              'dependencies bring in dozens of '
                                                                              'indirect (transitive) sub-packages. '
                                                                              'When a vulnerability exists three or '
                                                                              'four levels deep in the dependency '
                                                                              'tree, developers may not even know the '
                                                                              'vulnerable library is loaded in '
                                                                              'production.',
                                                    'level_2_detection_en': 'Inspect full lockfiles '
                                                                            '(`package-lock.json`, `Pipfile.lock`, '
                                                                            '`poetry.lock`) or generate dependency '
                                                                            'trees (`npm ls <pkg>` or `pipdeptree`). '
                                                                            'HexaGuard Dependency Scanner analyzes '
                                                                            'lockfiles and traces transitive '
                                                                            'vulnerability paths back to their '
                                                                            'top-level root declarations.',
                                                    'level_3_practice': {   'challenge_prompt_en': 'Resolve a '
                                                                                                   'transitive '
                                                                                                   'dependency '
                                                                                                   'vulnerability in '
                                                                                                   'an npm project '
                                                                                                   'using the '
                                                                                                   '`overrides` field '
                                                                                                   'in `package.json` '
                                                                                                   'without waiting '
                                                                                                   'for the upstream '
                                                                                                   'maintainer to '
                                                                                                   'publish a patch.',
                                                                            'guided_prompt_en': 'Use `pipdeptree` or '
                                                                                                '`npm ls` to trace '
                                                                                                'which top-level '
                                                                                                'dependency pulls in a '
                                                                                                'vulnerable '
                                                                                                'sub-dependency.',
                                                                            'sandbox_target': None},
                                                    'level_4_remediation_en': 'In `package.json`, use the `overrides` '
                                                                              '(npm) or `resolutions` (yarn) directive '
                                                                              'to pin the transitive dependency to a '
                                                                              'safe version: `"overrides": { '
                                                                              '"vulnerable-pkg": ">=2.0.1" }`. In '
                                                                              'Python, add the secure sub-dependency '
                                                                              'explicitly to `requirements.txt`. '
                                                                              'Mapped to OWASP A06:2021.'},
                                      'name_ar': 'ثغرة في التبعيات غير المباشرة (Transitive Dependency)',
                                      'name_en': 'Transitive Sub-Dependency Vulnerability',
                                      'owasp': 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
                                      'portswigger': None,
                                      'prerequisites': ['vulnerable_dependency'],
                                      'remediation_ar': 'فحص ملفات التثبيت المقفلة وتحديث الحزمة الأب أو استخدام '
                                                        'توجيهات الاستبدال (overrides) في مدير الحزم.',
                                      'remediation_en': 'Inspect lockfiles (package-lock.json, poetry.lock); use '
                                                        'package manager overrides or upgrade the top-level parent '
                                                        'dependency.',
                                      'scanner': 'deps',
                                      'severity_default': 'high'},
    'unauthenticated_service': {   'description_ar': 'قواعد بيانات وخدمات إدارة مفتوحة على الشبكة العامة بدون مصادقة '
                                                     'تتيح الوصول الكامل للبيانات.',
                                   'description_en': 'Data stores or management daemons like Redis, Memcached, or '
                                                     'MongoDB exposed without authentication.',
                                   'difficulty': 'hard',
                                   'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-redis',
                                   'id': 'unauthenticated_service',
                                   'lesson': {   'deep_dive_links': [   {   'label': 'Redis Security Documentation',
                                                                            'url': 'https://redis.io/docs/management/security/'},
                                                                        {   'label': 'MongoDB Security Checklist',
                                                                            'url': 'https://www.mongodb.com/docs/manual/administration/security-checklist/'}],
                                                 'level_1_foundations_en': 'Many modern data stores (Redis, Memcached, '
                                                                           'Elasticsearch, MongoDB) are engineered for '
                                                                           'high throughput on internal trusted '
                                                                           'subnets and initially ship with '
                                                                           'authentication disabled. Exposing these '
                                                                           'ports (6379, 11211, 9200, 27017) directly '
                                                                           'to public interfaces grants attackers '
                                                                           'unrestricted read/write access and '
                                                                           'frequently leads to host takeover via SSH '
                                                                           'key writing or webshell deployment.',
                                                 'level_2_detection_en': 'Probe services with command-line clients '
                                                                         'without supplying credentials (e.g. '
                                                                         '`redis-cli -h target ping` or `curl '
                                                                         'http://target:9200/_cat/indices`). HexaGuard '
                                                                         'Network Recon tests detected database ports '
                                                                         'for unauthenticated command execution and '
                                                                         'returns findings with critical severity.',
                                                 'level_3_practice': {   'challenge_prompt_en': 'Identify an exposed '
                                                                                                'unauthenticated Redis '
                                                                                                'service, determine '
                                                                                                'its database '
                                                                                                'directory, and '
                                                                                                'configure proper '
                                                                                                'password '
                                                                                                'authentication '
                                                                                                'without disrupting '
                                                                                                'production clients.',
                                                                         'guided_prompt_en': 'Connect to a test Redis '
                                                                                             'container on port 6379 '
                                                                                             'without credentials and '
                                                                                             'execute `INFO` command '
                                                                                             'to view memory '
                                                                                             'statistics and connected '
                                                                                             'clients.',
                                                                         'sandbox_target': None},
                                                 'level_4_remediation_en': 'In `redis.conf`, set `bind 127.0.0.1` and '
                                                                           '`requirepass <STRONG_RANDOM_PASSWORD>`. '
                                                                           'Block external connections via cloud '
                                                                           'security groups or UFW. Never expose '
                                                                           'administrative datastores to `0.0.0.0`. '
                                                                           'Mapped to OWASP A01:2021-Broken Access '
                                                                           'Control and PCI-DSS v4.0 Req 1.3.'},
                                   'name_ar': 'خدمات شبكية حساسة بدون مصادقة (Redis, MongoDB)',
                                   'name_en': 'Exposed Unauthenticated Network Service',
                                   'owasp': 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
                                   'portswigger': None,
                                   'prerequisites': ['open_ports'],
                                   'remediation_ar': 'تفعيل المصادقة الإلزامية وربط الخدمات بالمضيف المحلي 127.0.0.1 '
                                                     'وعزل المنافذ بجدار حماية.',
                                   'remediation_en': 'Enable strong authentication (requirepass in Redis, auth in '
                                                     'Mongo), bind strictly to localhost, and firewall access.',
                                   'scanner': 'network',
                                   'severity_default': 'critical'},
    'unencrypted_http': {   'description_ar': 'سماح الخادم بتبادل البيانات عبر بروتوكول HTTP غير المشفر دون فرض '
                                              'التحويل التلقائي لـ HTTPS.',
                            'description_en': 'Web application allows communication over plain HTTP port 80 without '
                                              'enforcing automatic HTTPS redirection.',
                            'difficulty': 'easy',
                            'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssl-tls',
                            'id': 'unencrypted_http',
                            'lesson': {   'deep_dive_links': [   {   'label': 'Mozilla HTTP to HTTPS Redirect '
                                                                              'Guidelines',
                                                                     'url': 'https://infosec.mozilla.org/guidelines/web_security#http-redirects'},
                                                                 {   'label': "Let's Encrypt HTTPS Redirects",
                                                                     'url': 'https://letsencrypt.org/docs/'}],
                                          'level_1_foundations_en': 'Operating a web service on unencrypted HTTP (port '
                                                                    '80) without automatic redirection to HTTPS allows '
                                                                    'any passive attacker on the local network (Wi-Fi, '
                                                                    'ISP, transit network) to read transmitted session '
                                                                    'cookies, passwords, and sensitive pages in '
                                                                    'cleartext, or inject malicious ads and '
                                                                    'JavaScript.',
                                          'level_2_detection_en': 'Send an HTTP request via curl: `curl -I '
                                                                  'http://target.com`. Check if the server responds '
                                                                  'with a 301/308 redirect to `https://target.com`. If '
                                                                  'the server responds with HTTP 200 over port 80, it '
                                                                  'is unencrypted. HexaGuard Server External verifies '
                                                                  'redirect enforcement automatically.',
                                          'level_3_practice': {   'challenge_prompt_en': 'Configure Nginx to listen on '
                                                                                         'port 80 and return a '
                                                                                         'permanent `return 301 '
                                                                                         'https://$host$request_uri;` '
                                                                                         'redirect for all requests.',
                                                                  'guided_prompt_en': 'Execute `curl -I '
                                                                                      'http://target.com` and inspect '
                                                                                      'the status code. If it returns '
                                                                                      '200 OK, the connection is '
                                                                                      'completely unencrypted.',
                                                                  'sandbox_target': None},
                                          'level_4_remediation_en': 'In Nginx configure: `server { listen 80; '
                                                                    'server_name example.com; return 301 '
                                                                    'https://$host$request_uri; }`. Enforce HSTS so '
                                                                    'browsers never attempt HTTP on subsequent visits. '
                                                                    'Mapped to PCI-DSS v4.0 Req 4.1 and OWASP '
                                                                    'A02:2021.'},
                            'name_ar': 'خدمة HTTP غير مشفرة بدون إعادة توجيه لـ HTTPS',
                            'name_en': 'Unencrypted HTTP Port 80 Without HTTPS Redirect',
                            'owasp': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
                            'portswigger': None,
                            'prerequisites': ['missing_security_headers'],
                            'remediation_ar': 'ضبط إعادة التوجيه الدائم (HTTP 301) لكافة الطلبات نحو HTTPS مع تفعيل '
                                              'ترويسة HSTS.',
                            'remediation_en': 'Configure permanent HTTP 301 redirect to HTTPS for all incoming '
                                              'requests; enable HSTS.',
                            'scanner': 'server_ext',
                            'severity_default': 'medium'},
    'unpinned_dependency': {   'description_ar': 'تحديد إصدارات الحزم بعلامات عائمة تتيح سحب تحديثات خبيثة أو غير '
                                                 'متوافقة تلقائياً.',
                               'description_en': 'Dependencies declared with wildcards (*, >=, ^) without lockfiles, '
                                                 'exposing builds to silent malicious updates.',
                               'difficulty': 'medium',
                               'hacktricks': 'https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-ci-cd',
                               'id': 'unpinned_dependency',
                               'lesson': {   'deep_dive_links': [   {   'label': 'Python pip Hash-Checking Mode',
                                                                        'url': 'https://pip.pypa.io/en/stable/topics/secure-installs/#hash-checking-mode'},
                                                                    {   'label': 'NIST Secure Software Development '
                                                                                 'Framework (SSDF)',
                                                                        'url': 'https://csrc.nist.gov/projects/ssdf'}],
                                             'level_1_foundations_en': 'Specifying dependency versions with wildcards '
                                                                       '(`*`, `>=1.0`, or unpinned npm `^`) allows '
                                                                       'continuous integration pipelines and '
                                                                       'production deployments to pull down whatever '
                                                                       'new release is published to the public '
                                                                       'registry. If a maintainer account is hijacked '
                                                                       'or a malicious release is pushed, your build '
                                                                       'pipeline immediately executes the malicious '
                                                                       'code upon next deployment.',
                                             'level_2_detection_en': 'Audit `requirements.txt` or `package.json` for '
                                                                     'lines lacking strict version constraints (e.g. '
                                                                     '`requests` without `==`, or `"express": "*"`). '
                                                                     'HexaGuard Dependency Scanner flags floating and '
                                                                     'unpinned dependencies as build integrity risks.',
                                             'level_3_practice': {   'challenge_prompt_en': 'Convert a legacy floating '
                                                                                            'manifest into a fully '
                                                                                            'deterministic pinned '
                                                                                            'build using `pip-compile` '
                                                                                            'or `npm shrinkwrap` with '
                                                                                            'cryptographic hash '
                                                                                            'verification.',
                                                                     'guided_prompt_en': 'Review a requirements.txt '
                                                                                         'file with missing `==` '
                                                                                         'specifiers and simulate how '
                                                                                         'a new release might break '
                                                                                         'production builds.',
                                                                     'sandbox_target': None},
                                             'level_4_remediation_en': 'Pin exact versions: `package==1.2.3`. Commit '
                                                                       'lockfiles (`package-lock.json`, `poetry.lock`) '
                                                                       'to git. In pip, use hash-checking mode: `pip '
                                                                       'install --require-hashes -r requirements.txt`. '
                                                                       'Mapped to OWASP A08:2021-Software & Data '
                                                                       'Integrity Failures.'},
                               'name_ar': 'إصدارات تبعيات غير مقيدة (Floating Versions)',
                               'name_en': 'Unpinned Dependency Version Specifications',
                               'owasp': 'https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/',
                               'portswigger': None,
                               'prerequisites': [],
                               'remediation_ar': 'تحديد أرقام الإصدارات بدقة وإيداع ملفات القفل (lockfiles) في git '
                                                 'وتفعيل التحقق من تجزئة الحزم.',
                               'remediation_en': 'Pin exact versions in manifests (e.g. package==1.2.3), commit '
                                                 'lockfiles to version control, and verify package hashes.',
                               'scanner': 'deps',
                               'severity_default': 'medium'},
    'vulnerable_container_base_image': {   'description_ar': 'الاعتماد على وسوم عائمة (:latest) أو صور أساسية قديمة '
                                                             'تحتوي على حزم برمجية مصابة بثغرات أمنية حرجة.',
                                           'description_en': 'Dockerfile utilizes unpinned :latest tags or known '
                                                             'vulnerable base operating system images.',
                                           'difficulty': 'medium',
                                           'hacktricks': 'https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-ci-cd',
                                           'id': 'vulnerable_container_base_image',
                                           'lesson': {   'deep_dive_links': [   {   'label': 'Google Distroless Images',
                                                                                    'url': 'https://github.com/GoogleContainerTools/distroless'},
                                                                                {   'label': 'Trivy Container '
                                                                                             'Vulnerability Scanner',
                                                                                    'url': 'https://github.com/aquasecurity/trivy'}],
                                                         'level_1_foundations_en': 'Using generic tags like `FROM '
                                                                                   'node:latest` or `FROM python:3.7` '
                                                                                   'introduces instability and '
                                                                                   'security risks. Unpinned `:latest` '
                                                                                   'tags produce non-deterministic '
                                                                                   'builds where the base image '
                                                                                   'changes unpredictably. '
                                                                                   'Furthermore, using outdated base '
                                                                                   'distributions imports hundreds of '
                                                                                   'unpatched CVEs in the base OS '
                                                                                   'libraries (libc, openssl, curl).',
                                                         'level_2_detection_en': 'Inspect Dockerfile `FROM` lines for '
                                                                                 'missing tag specifications or use of '
                                                                                 '`:latest`. Run container '
                                                                                 'vulnerability scanners (Trivy, '
                                                                                 'Grype). HexaGuard Docker Scanner '
                                                                                 'audits base image declarations, '
                                                                                 'flags `:latest` tags, and runs '
                                                                                 'Trivy/Grype CVE analysis.',
                                                         'level_3_practice': {   'challenge_prompt_en': 'Migrate an '
                                                                                                        'application '
                                                                                                        'Dockerfile '
                                                                                                        'from a '
                                                                                                        'heavyweight '
                                                                                                        'outdated '
                                                                                                        'image to a '
                                                                                                        'hardened, '
                                                                                                        'minimal '
                                                                                                        'Distroless or '
                                                                                                        'Alpine base '
                                                                                                        'image pinned '
                                                                                                        'by '
                                                                                                        'cryptographic '
                                                                                                        'sha256 '
                                                                                                        'digest.',
                                                                                 'guided_prompt_en': 'Run `trivy image '
                                                                                                     'node:14` and '
                                                                                                     'review the '
                                                                                                     'hundreds of '
                                                                                                     'known CVEs '
                                                                                                     'present in '
                                                                                                     'obsolete base '
                                                                                                     'container '
                                                                                                     'images.',
                                                                                 'sandbox_target': None},
                                                         'level_4_remediation_en': 'Pin base images by exact digest: '
                                                                                   '`FROM '
                                                                                   'python:3.11-slim@sha256:abc123...`. '
                                                                                   'Prefer minimal base images like '
                                                                                   'Alpine or Google Container Tools '
                                                                                   'Distroless '
                                                                                   '(`gcr.io/distroless/static-debian11`). '
                                                                                   'Integrate container vulnerability '
                                                                                   'scanning (Trivy) into CI '
                                                                                   'pipelines. Mapped to CIS Docker '
                                                                                   'Benchmark 4.2.'},
                                           'name_ar': 'استخدام صور أساسية غير مقيدة أو مصابة بثغرات (CVE)',
                                           'name_en': 'Vulnerable Base Image & Unpinned Latest Tag',
                                           'owasp': 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
                                           'portswigger': None,
                                           'prerequisites': [],
                                           'remediation_ar': 'تثبيت الصور بالبصمة المشفرة sha256 وفحص الصور بانتظام '
                                                             'بأدوات Trivy أو Grype.',
                                           'remediation_en': 'Pin base images by exact cryptographic digest '
                                                             '(sha256:...) and scan container images with Trivy or '
                                                             'Grype in CI.',
                                           'scanner': 'docker',
                                           'severity_default': 'medium'},
    'vulnerable_dependency': {   'description_ar': 'احتواء حزم وبرمجيات الطرف الثالث على ثغرات أمنية معلنة رسمياً في '
                                                   'قواعد بيانات CVE.',
                                 'description_en': 'Third-party open source library contains known security '
                                                   'vulnerabilities (CVEs) documented in public advisories.',
                                 'difficulty': 'medium',
                                 'hacktricks': 'https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-ci-cd',
                                 'id': 'vulnerable_dependency',
                                 'lesson': {   'deep_dive_links': [   {   'label': 'OSV.dev Open Source Vulnerability '
                                                                                   'Database',
                                                                          'url': 'https://osv.dev/'},
                                                                      {   'label': 'OWASP Dependency-Check Project',
                                                                          'url': 'https://owasp.org/www-project-dependency-check/'}],
                                               'level_1_foundations_en': 'Modern software is constructed from '
                                                                         'thousands of open-source packages and '
                                                                         'libraries. When an attacker discovers a '
                                                                         'vulnerability in a ubiquitous library (such '
                                                                         'as Log4j/Log4Shell, CVE-2021-44228), every '
                                                                         'application utilizing that dependency '
                                                                         'becomes vulnerable to exploitation. The '
                                                                         'Log4Shell flaw enabled unauthenticated RCE '
                                                                         'on hundreds of millions of servers '
                                                                         'worldwide.',
                                               'level_2_detection_en': 'Run software composition analysis tools: '
                                                                       '`pip-audit`, `npm audit`, or query the OSV.dev '
                                                                       'batch API with your package manifest '
                                                                       '(`package.json`, `requirements.txt`). '
                                                                       "HexaGuard's Dependency Scanner parses "
                                                                       'manifests, resolves dependencies against '
                                                                       'OSV.dev and Snyk databases, and provides '
                                                                       'specific patched version numbers.',
                                               'level_3_practice': {   'challenge_prompt_en': 'Audit an application '
                                                                                              'dependency manifest to '
                                                                                              'identify high-severity '
                                                                                              'CVEs and formulate an '
                                                                                              'upgrade plan resolving '
                                                                                              'vulnerable versions '
                                                                                              'without introducing '
                                                                                              'breaking API changes.',
                                                                       'guided_prompt_en': 'Run `pip-audit` or '
                                                                                           'HexaGuard Dependency '
                                                                                           'Scanner against a '
                                                                                           'requirements.txt file with '
                                                                                           'outdated packages, and '
                                                                                           'observe how CVE '
                                                                                           'identifiers and CVSS '
                                                                                           'scores are returned.',
                                                                       'sandbox_target': None},
                                               'level_4_remediation_en': 'Update package manifests to secure releases '
                                                                         '(`pip install --upgrade <package>` or `npm '
                                                                         'update`). Integrate automated dependency '
                                                                         'scanning into CI/CD pipelines (e.g. GitHub '
                                                                         'Dependabot, Snyk, pip-audit in GitHub '
                                                                         'Actions). Maintain a Software Bill of '
                                                                         'Materials (SBOM). Mapped to OWASP '
                                                                         'A06:2021-Vulnerable and Outdated '
                                                                         'Components.'},
                                 'name_ar': 'ثغرات معروفة في حزم البرمجيات التابعة (CVE)',
                                 'name_en': 'Known Vulnerability in Dependency Package',
                                 'owasp': 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
                                 'portswigger': None,
                                 'prerequisites': [],
                                 'remediation_ar': 'ترقية الحزم للإصدارات الآمنة واستخدام أدوات تدقيق تلقائي والاحتفاظ '
                                                   'بسجل مكونات البرمجيات (SBOM).',
                                 'remediation_en': 'Upgrade affected packages to secure versions, implement automated '
                                                   'dependency auditing (Snyk, Dependabot), and maintain an SBOM.',
                                 'scanner': 'deps',
                                 'severity_default': 'high'},
    'weak_crypto': {   'description_ar': 'استخدام شفرات تشفير ضعيفة أو خوارزميات تجزئة مكسورة تسمح بفك تشفير البيانات.',
                       'description_en': 'Use of outdated or cryptographically broken ciphers, hash algorithms (MD5, '
                                         'SHA1), or static key exchanges.',
                       'difficulty': 'medium',
                       'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssl-tls',
                       'id': 'weak_crypto',
                       'lesson': {   'deep_dive_links': [   {   'label': 'Mozilla SSL Configuration Generator',
                                                                'url': 'https://ssl-config.mozilla.org/'},
                                                            {   'label': 'SSLyze TLS Scanner Project',
                                                                'url': 'https://github.com/nabla-c0d3/sslyze'}],
                                     'level_1_foundations_en': 'Cryptographic algorithms degrade over time as '
                                                               'cryptanalysis improves and compute power increases. '
                                                               'Ciphers utilizing 64-bit block sizes (3DES/Sweet32), '
                                                               'stream ciphers with known biases (RC4), and hash '
                                                               'algorithms susceptible to collision attacks (MD5, '
                                                               'SHA1) allow attackers who capture encrypted traffic to '
                                                               'decrypt communications or forge digital signatures.',
                                     'level_2_detection_en': 'Enumerate cipher suites using SSLyze: `sslyze --regular '
                                                             "target.com` or test with `openssl s_client -cipher 'RC4' "
                                                             '-connect target.com:443`. In HexaGuard, the SSL Scanner '
                                                             'evaluates cipher negotiations, flagging any cipher suite '
                                                             'utilizing CBC mode, 3DES, or static RSA key exchange.',
                                     'level_3_practice': {   'challenge_prompt_en': 'Configure an Nginx server '
                                                                                    '`ssl_ciphers` directive to '
                                                                                    'enforce forward secrecy and AEAD '
                                                                                    'ciphers while rejecting CBC and '
                                                                                    'legacy block ciphers.',
                                                             'guided_prompt_en': 'Test a remote HTTPS target with '
                                                                                 "`openssl s_client -cipher '3DES' "
                                                                                 '-connect target:443` to verify if '
                                                                                 'legacy ciphers are negotiated.',
                                                             'sandbox_target': None},
                                     'level_4_remediation_en': 'Configure modern cipher suites in Nginx: `ssl_ciphers '
                                                               "'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305'; "
                                                               'ssl_prefer_server_ciphers off;`. Mapped to OWASP '
                                                               'A02:2021-Cryptographic Failures and PCI-DSS v4.0 Req '
                                                               '4.1.'},
                       'name_ar': 'خوارزميات وتشفيرات ضعيفة (RC4, 3DES, CBC)',
                       'name_en': 'Weak Cryptographic Ciphers & Algorithms',
                       'owasp': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
                       'portswigger': None,
                       'prerequisites': [],
                       'remediation_ar': 'اعتماد شفرات التشفير الحديثة (AES-GCM) مع تبادل المفاتيح المؤقت (ECDHE) '
                                         'وتعطيل الشفرات القديمة.',
                       'remediation_en': 'Configure modern cipher suites favoring AEAD (AES-GCM, CHACHA20-POLY1305) '
                                         'with Ephemeral Diffie-Hellman (ECDHE).',
                       'scanner': 'ssl',
                       'severity_default': 'medium'},
    'weak_file_permissions': {   'description_ar': 'إعداد ملفات التكوين والشهادات بأذونات مفرطة تسمح لأي مستخدم محلي '
                                                   'بالقراءة والتعديل.',
                                 'description_en': 'Configuration files, web roots, or SSL certificates configured '
                                                   'with overly permissive permissions (e.g. 777 or world-writable).',
                                 'difficulty': 'medium',
                                 'hacktricks': 'https://book.hacktricks.xyz/linux-hardening/privilege-escalation',
                                 'id': 'weak_file_permissions',
                                 'lesson': {   'deep_dive_links': [   {   'label': 'Linux File Permissions & Security',
                                                                          'url': 'https://www.redhat.com/sysadmin/linux-file-permissions-acls'},
                                                                      {   'label': 'CIS Controls: Access Control '
                                                                                   'Management',
                                                                          'url': 'https://www.cisecurity.org/controls/'}],
                                               'level_1_foundations_en': 'Operating system file permissions regulate '
                                                                         'which users and services can read, write, '
                                                                         'and execute files. If web server '
                                                                         'configuration files (e.g. `.htaccess`, '
                                                                         '`nginx.conf`, `wp-config.php`) or private '
                                                                         'keys are world-writable (e.g. `chmod 777`), '
                                                                         'any local low-privileged user or compromised '
                                                                         'service can alter server logic, inject '
                                                                         'backdoors, or read database credentials.',
                                               'level_2_detection_en': 'Inspect file permissions using `ls -la '
                                                                       '/path/to/file` or `find /var/www -perm -o+w`. '
                                                                       'HexaGuard Server Internal verifies file '
                                                                       'ownership and permission bits across document '
                                                                       'roots and configuration paths, alerting if '
                                                                       'files are writable by non-root users.',
                                               'level_3_practice': {   'challenge_prompt_en': 'Audit a web application '
                                                                                              'root directory to '
                                                                                              'identify all '
                                                                                              'world-writable files '
                                                                                              'and apply standard '
                                                                                              '`chmod 644` (files) and '
                                                                                              '`chmod 755` '
                                                                                              '(directories) '
                                                                                              'permissions.',
                                                                       'guided_prompt_en': 'Run `ls -l` on '
                                                                                           '`/etc/shadow` and observe '
                                                                                           'that only root has read '
                                                                                           'access (`-rw-r-----`), '
                                                                                           'demonstrating proper '
                                                                                           'permission isolation.',
                                                                       'sandbox_target': None},
                                               'level_4_remediation_en': 'Set web root directories to `755` (or `750`) '
                                                                         'and files to `644` (or `640` for '
                                                                         'credentials). Sensitive private keys must be '
                                                                         '`600` owned by root. Run: `find '
                                                                         '/var/www/html -type d -exec chmod 750 {} + '
                                                                         '&& find /var/www/html -type f -exec chmod '
                                                                         '640 {} +`. Mapped to CIS Linux Benchmark '
                                                                         '6.1.'},
                                 'name_ar': 'أذونات ملفات متساهلة وغير آمنة (World-Writable)',
                                 'name_en': 'World-Writable Sensitive File Permissions',
                                 'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                                 'portswigger': None,
                                 'prerequisites': [],
                                 'remediation_ar': 'تطبيق صلاحيات وصول صارمة (600 أو 640 للملفات) وحصر الملكية على '
                                                   'مستخدمي النظام المخصصين.',
                                 'remediation_en': 'Enforce strict POSIX permissions (chmod 600/640 for configs, 750 '
                                                   'for directories) and assign dedicated system users.',
                                 'scanner': 'server',
                                 'severity_default': 'high'},
    'wp_default_admin': {   'description_ar': 'استمرار وجود حساب المدير الافتراضي admin مع عدم تفعيل المصادقة الثنائية '
                                              'أو حماية معدل الطلبات على صفحة الدخول.',
                            'description_en': "Default administrator username 'admin' remains active, paired with an "
                                              'unprotected /wp-login.php portal.',
                            'difficulty': 'easy',
                            'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress',
                            'id': 'wp_default_admin',
                            'lesson': {   'deep_dive_links': [   {   'label': 'WordPress Hardening: User Accounts',
                                                                     'url': 'https://wordpress.org/documentation/article/hardening-wordpress/#user-accounts'},
                                                                 {   'label': 'Brute Force Attacks on WordPress',
                                                                     'url': 'https://wordpress.org/documentation/article/brute-force-attacks/'}],
                                          'level_1_foundations_en': 'The default master username in WordPress was '
                                                                    'traditionally `admin`. Automated bots '
                                                                    'continuously attack `/wp-login.php` using '
                                                                    'brute-force dictionaries against the `admin` '
                                                                    'username. Having an active `admin` account leaves '
                                                                    'the application highly susceptible to credential '
                                                                    'compromise.',
                                          'level_2_detection_en': 'Attempt login with username `admin` and an '
                                                                  'arbitrary password at `/wp-login.php`. Observe the '
                                                                  'error message: WordPress historically indicated '
                                                                  "whether the username existed (e.g. 'The password "
                                                                  "you entered for the username admin is incorrect'). "
                                                                  'HexaGuard WordPress Scanner detects whether `admin` '
                                                                  'user is registered and whether 2FA hints are '
                                                                  'missing.',
                                          'level_3_practice': {   'challenge_prompt_en': 'Create a new administrative '
                                                                                         'user with a custom username, '
                                                                                         'transfer content ownership, '
                                                                                         "delete the 'admin' account, "
                                                                                         'and configure Two-Factor '
                                                                                         'Authentication via plugin.',
                                                                  'guided_prompt_en': 'Inspect `/wp-login.php` on a '
                                                                                      'test WordPress installation and '
                                                                                      'observe how error messages '
                                                                                      'confirm whether a user exists.',
                                                                  'sandbox_target': None},
                                          'level_4_remediation_en': 'Create a new administrator account with an '
                                                                    'unpredictable username. Reassign all posts to the '
                                                                    'new user and delete the default `admin` account. '
                                                                    'Install a 2FA plugin (e.g. WP 2FA) requiring TOTP '
                                                                    'tokens for all administrator logins. Restrict '
                                                                    '`/wp-admin` by IP in web server configuration. '
                                                                    'Mapped to OWASP A07:2021.'},
                            'name_ar': "حساب المدير الافتراضي 'admin' وغياب حماية تسجيل الدخول",
                            'name_en': "Active 'admin' User & Unprotected Login Portal",
                            'owasp': 'https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/',
                            'portswigger': None,
                            'prerequisites': ['wp_user_enumeration'],
                            'remediation_ar': 'حذف أو تغيير اسم حساب admin الافتراضي وتفعيل المصادقة الثنائية وقصر '
                                              'الدخول على عناوين IP محددة.',
                            'remediation_en': "Delete or rename the default 'admin' account; deploy 2FA (Two-Factor "
                                              'Authentication) and IP-based access restrictions.',
                            'scanner': 'wordpress',
                            'severity_default': 'medium'},
    'wp_sensitive_files': {   'description_ar': 'إتاحة ملفات حساسة مثل سجل الأخطاء debug.log أو نسخ احتياطية لملف '
                                                'wp-config.php تكشف بيانات قاعدة البيانات.',
                              'description_en': 'Exposure of /wp-content/debug.log or backup files like '
                                                'wp-config.php.bak leaking database credentials and salts.',
                              'difficulty': 'medium',
                              'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress',
                              'id': 'wp_sensitive_files',
                              'lesson': {   'deep_dive_links': [   {   'label': 'Debugging in WordPress',
                                                                       'url': 'https://wordpress.org/documentation/article/debugging-in-wordpress/'},
                                                                   {   'label': 'OWASP Information Disclosure',
                                                                       'url': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'}],
                                            'level_1_foundations_en': 'Enabling `WP_DEBUG_LOG` in WordPress causes PHP '
                                                                      'runtime errors, database queries, and stack '
                                                                      'traces to be written to '
                                                                      '`/wp-content/debug.log`. If left publicly '
                                                                      'accessible, attackers download the log to '
                                                                      'discover database passwords, API keys, and '
                                                                      'internal server paths. Similarly, temporary '
                                                                      'backups of `wp-config.php` created by editors '
                                                                      'expose database credentials and secret '
                                                                      'authentication keys.',
                                            'level_2_detection_en': 'Test URLs directly: `curl -I '
                                                                    'https://target.com/wp-content/debug.log` and '
                                                                    '`curl -I https://target.com/wp-config.php.bak`. '
                                                                    'If status code 200 is returned, sensitive files '
                                                                    'are exposed. HexaGuard WordPress Scanner probes '
                                                                    'for debug logs and config backup variations.',
                                            'level_3_practice': {   'challenge_prompt_en': 'Configure Nginx or Apache '
                                                                                           'server rules to deny web '
                                                                                           'access to '
                                                                                           '`/wp-content/debug.log` '
                                                                                           'and all `.log`, `.bak`, '
                                                                                           'and `.sql` file '
                                                                                           'extensions.',
                                                                    'guided_prompt_en': 'Test downloading '
                                                                                        '`/wp-content/debug.log` from '
                                                                                        'a test site and analyze the '
                                                                                        'debugging traces and database '
                                                                                        'errors inside.',
                                                                    'sandbox_target': None},
                                            'level_4_remediation_en': 'In `wp-config.php`, ensure '
                                                                      "`define('WP_DEBUG_DISPLAY', false);`. If "
                                                                      'logging is required, set a secure path outside '
                                                                      "the document root: `define('WP_DEBUG_LOG', "
                                                                      "'/var/log/wordpress/debug.log');`. Block access "
                                                                      'in Nginx: `location ~* \\.(log|bak|sql)$ { deny '
                                                                      'all; }`. Mapped to OWASP A05:2021.'},
                              'name_ar': 'كشف ملفات ووردبريس الحساسة (debug.log, wp-config)',
                              'name_en': 'Exposed WordPress Sensitive Files (debug.log / wp-config.php.bak)',
                              'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                              'portswigger': None,
                              'prerequisites': ['sensitive_file_leak'],
                              'remediation_ar': 'تعطيل تسجيل الأخطاء إلى ملفات عامة وحظر الوصول لكافة ملفات log و bak '
                                                'في إعدادات الخادم.',
                              'remediation_en': 'Disable WP_DEBUG_LOG or store debug logs outside web root; block '
                                                'direct web access to all .log and backup files.',
                              'scanner': 'wordpress',
                              'severity_default': 'critical'},
    'wp_user_enumeration': {   'description_ar': 'كشف أسماء المستخدمين والإداريين عبر واجهة REST API أو أرشيف المؤلفين '
                                                 '(?author=1).',
                               'description_en': 'Public REST API endpoint (/wp-json/wp/v2/users) or author archives '
                                                 'disclose valid administrative usernames.',
                               'difficulty': 'easy',
                               'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress#users-enumeration',
                               'id': 'wp_user_enumeration',
                               'lesson': {   'deep_dive_links': [   {   'label': 'WordPress REST API Handbook: '
                                                                                 'Security',
                                                                        'url': 'https://developer.wordpress.org/rest-api/using-the-rest-api/frequently-asked-questions/#can-i-disable-the-rest-api'},
                                                                    {   'label': 'WPScan User Enumeration Techniques',
                                                                        'url': 'https://wpscan.com/'}],
                                             'level_1_foundations_en': 'WordPress exposes a public REST API endpoint '
                                                                       'at `/wp-json/wp/v2/users` that lists user '
                                                                       'accounts, slugs, and display names by default. '
                                                                       'Similarly, querying `/?author=1` redirects to '
                                                                       '`/author/admin/`, confirming usernames. Having '
                                                                       'verified administrative usernames cuts the '
                                                                       'difficulty of credential attacks in half by '
                                                                       'allowing attackers to focus exclusively on '
                                                                       'passwords.',
                                             'level_2_detection_en': 'Send a GET request to '
                                                                     '`https://target.com/wp-json/wp/v2/users` or '
                                                                     '`https://target.com/?author=1`. If user accounts '
                                                                     'are listed or redirected, enumeration is active. '
                                                                     'HexaGuard WordPress Scanner queries these '
                                                                     'endpoints and alerts when valid user accounts '
                                                                     'are revealed.',
                                             'level_3_practice': {   'challenge_prompt_en': 'Implement a custom filter '
                                                                                            'in WordPress '
                                                                                            '`functions.php` to '
                                                                                            'restrict the REST API '
                                                                                            'users endpoint to '
                                                                                            'authenticated users only.',
                                                                     'guided_prompt_en': 'Execute `curl '
                                                                                         'https://target.com/wp-json/wp/v2/users` '
                                                                                         'and observe how user IDs and '
                                                                                         'login slugs are returned in '
                                                                                         'JSON format.',
                                                                     'sandbox_target': None},
                                             'level_4_remediation_en': 'In `functions.php` add: '
                                                                       "`add_filter('rest_endpoints', "
                                                                       'function($endpoints){ if (!is_user_logged_in() '
                                                                       "&& isset($endpoints['/wp/v2/users'])) { "
                                                                       "unset($endpoints['/wp/v2/users']); } return "
                                                                       '$endpoints; });`. Mapped to OWASP '
                                                                       'A05:2021-Security Misconfiguration.'},
                               'name_ar': 'تعداد أسماء المستخدمين عبر واجهة REST API',
                               'name_en': 'WordPress User Enumeration via REST API',
                               'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                               'portswigger': None,
                               'prerequisites': [],
                               'remediation_ar': 'حظر وصول المستخدمين غير المصادقين لواجهة users في REST API وتعطيل '
                                                 'معلمات أرشيف المؤلفين.',
                               'remediation_en': 'Disable public access to /wp-json/wp/v2/users for unauthenticated '
                                                 'users; disable author archive parameter scanning.',
                               'scanner': 'wordpress',
                               'severity_default': 'low'},
    'xmlrpc_exposure': {   'description_ar': 'إتاحة ملف xmlrpc.php تتيح للمهاجمين تنفيذ محاولات كسر كلمات المرور '
                                             'المكثفة وهجمات التضخيم DDoS.',
                           'description_en': 'xmlrpc.php is accessible, enabling amplified brute-force attacks via '
                                             'system.multicall and pingback SSRF/DDoS.',
                           'difficulty': 'easy',
                           'hacktricks': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress#xml-rpc',
                           'id': 'xmlrpc_exposure',
                           'lesson': {   'deep_dive_links': [   {   'label': 'WordPress XML-RPC Security Issues',
                                                                    'url': 'https://kinsta.com/blog/xmlrpc-php/'},
                                                                {   'label': 'HackTricks: WordPress Pentesting',
                                                                    'url': 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress'}],
                                         'level_1_foundations_en': 'The `xmlrpc.php` interface in WordPress was '
                                                                   'developed to allow remote publishing from mobile '
                                                                   'apps. However, its `system.multicall` method '
                                                                   'allows attackers to test hundreds of password '
                                                                   'combinations in a single HTTP request, bypassing '
                                                                   'standard login form rate limiting. Furthermore, '
                                                                   'the `pingback.ping` method can be abused to turn '
                                                                   'WordPress sites into distributed DDoS reflection '
                                                                   'proxies.',
                                         'level_2_detection_en': 'Send an HTTP POST to `/xmlrpc.php` with XML payload: '
                                                                 '`curl -X POST https://target.com/xmlrpc.php -d '
                                                                 "'<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'`. "
                                                                 'If it returns a list of supported XML-RPC methods, '
                                                                 'it is active. HexaGuard WordPress Scanner verifies '
                                                                 'xmlrpc accessibility automatically.',
                                         'level_3_practice': {   'challenge_prompt_en': 'Configure Nginx or Apache '
                                                                                        'rules to completely block '
                                                                                        'HTTP requests targeting '
                                                                                        '`xmlrpc.php` with a 403 '
                                                                                        'Forbidden response.',
                                                                 'guided_prompt_en': 'Send an XML-RPC method listing '
                                                                                     'query using curl to a test '
                                                                                     'WordPress site and inspect the '
                                                                                     'returned API methods.',
                                                                 'sandbox_target': None},
                                         'level_4_remediation_en': 'In Nginx add: `location = /xmlrpc.php { deny all; '
                                                                   'access_log off; log_not_found off; }`. In Apache '
                                                                   '`.htaccess`: `<Files xmlrpc.php> Order allow,deny '
                                                                   'Deny from all </Files>`. Mapped to OWASP '
                                                                   'A05:2021-Security Misconfiguration.'},
                           'name_ar': 'كشف واجهة ووردبريس البرمجية xmlrpc.php',
                           'name_en': 'WordPress XML-RPC API Exposed',
                           'owasp': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
                           'portswigger': None,
                           'prerequisites': [],
                           'remediation_ar': 'تعطيل وحظر الوصول لملف xmlrpc.php عبر إعدادات الخادم أو ملف htaccess.',
                           'remediation_en': 'Disable xmlrpc.php in web server configuration or block access via '
                                             '.htaccess/security plugins.',
                           'scanner': 'wordpress',
                           'severity_default': 'medium'},
    'xss': {   'description_ar': 'ثغرة تتيح للمهاجم حقن نصوص جافاسكريبت خبيثة تنفذ في متصفح الضحية لسرقة الجلسات أو '
                                 'تغيير الواجهة.',
               'description_en': 'Flaw allowing injection of malicious client-side JavaScript into trusted web '
                                 'applications.',
               'difficulty': 'easy',
               'hacktricks': 'https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting',
               'id': 'xss',
               'lesson': {   'deep_dive_links': [   {   'label': 'OWASP XSS Prevention Cheat Sheet',
                                                        'url': 'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'},
                                                    {   'label': 'PortSwigger Web Security Academy: XSS',
                                                        'url': 'https://portswigger.net/web-security/cross-site-scripting'},
                                                    {   'label': 'MDN: Content Security Policy',
                                                        'url': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'}],
                             'level_1_foundations_en': 'Cross-Site Scripting (XSS) occurs when an application includes '
                                                       'untrusted user data in dynamic web pages without adequate '
                                                       'validation or context-sensitive encoding. An attacker can '
                                                       "execute arbitrary script in the victim's browser, hijacking "
                                                       'sessions, stealing authorization tokens, defacing pages, or '
                                                       'redirecting to malware. In the 2018 British Airways breach, '
                                                       'attackers injected Magecart JavaScript into payment checkout '
                                                       'pages, harvesting credit card details of over 380,000 '
                                                       'customers.',
                             'level_2_detection_en': 'To detect XSS manually, inject benign canary probes (e.g., '
                                                     '`xss"\'><h1>test</h1>`) into query parameters, form fields, and '
                                                     'HTTP headers, observing whether special HTML delimiters are '
                                                     'rendered without entity encoding. In HexaGuard, the DAST engine '
                                                     "flags XSS via the 'xss_reflection' check and ZAP/Nuclei plugins "
                                                     'by submitting polyglot test payloads and verifying script '
                                                     'execution or DOM tree injection in responses.',
                             'level_3_practice': {   'challenge_prompt_en': 'Exploit a persistent or DOM-based XSS '
                                                                            'vulnerability in the feedback customer '
                                                                            'form or product search in the local Juice '
                                                                            'Shop sandbox to extract the secret admin '
                                                                            'authorization token.',
                                                     'guided_prompt_en': 'Launch the OWASP Juice Shop container in the '
                                                                         'Adversarial Twin Sandbox. Navigate to the '
                                                                         'top search bar and submit `<iframe '
                                                                         'src="javascript:alert(\'XSS\')">`. Verify '
                                                                         'the alert box triggers within your browser '
                                                                         'DOM context.',
                                                     'sandbox_target': 'xss'},
                             'level_4_remediation_en': 'Apply context-aware HTML entity encoding (e.g. DOMPurify for '
                                                       'rich HTML or framework-level escaping in React/Vue). Enforce a '
                                                       'strict Content Security Policy (CSP) header with `default-src '
                                                       "'self'; script-src 'self' 'nonce-...'; object-src 'none'`. "
                                                       'This maps to OWASP A03:2021-Injection, PCI-DSS v4.0 Req 6.4.1, '
                                                       'and ISO/IEC 27001 A.14.2.5.'},
               'name_ar': 'البرمجة النصية عبر المواقع (XSS)',
               'name_en': 'Cross-Site Scripting (XSS)',
               'owasp': 'https://owasp.org/www-community/attacks/xss/',
               'portswigger': 'https://portswigger.net/web-security/cross-site-scripting',
               'prerequisites': ['missing_csp', 'missing_security_headers'],
               'remediation_ar': 'تطبيق ترميز السياق للمخرجات واعتماد سياسة أمن محتوى (CSP) صارمة واستخدام أطر عمل '
                                 'حديثة تفلت المدخلات تلقائياً.',
               'remediation_en': 'Implement contextual output encoding, robust Content Security Policy (CSP), and use '
                                 'modern frameworks with auto-escaping.',
               'scanner': 'dast',
               'severity_default': 'medium'}}

# ── Blue Team / SOC Incident Taxonomy (E-02) ──────────────────────────────────
INCIDENT_TAXONOMY: dict[str, dict[str, Any]] = {   'brute_force': {   'description_ar': 'محاولات تسجيل دخول متكررة ومكثفة تستهدف خدمات التحكم عن بعد أو نماذج مصادقة '
                                         'الويب.',
                       'description_en': 'High-volume automated authentication attempts targeting SSH, RDP, or web '
                                         'logins.',
                       'id': 'brute_force',
                       'indicators': [   'Anomalous failed login spike',
                                         'Single IP trying multiple usernames',
                                         'Off-hours login after failure chain'],
                       'lesson': {   'deep_dive_links': [   {   'label': 'MITRE ATT&CK: Brute Force (T1110)',
                                                                'url': 'https://attack.mitre.org/techniques/T1110/'},
                                                            {   'label': 'Fail2Ban Hardening Guide',
                                                                'url': 'https://www.fail2ban.org/wiki/index.php/Main_Page'}],
                                     'level_1_foundations_en': 'Brute force attacks involve systematically attempting '
                                                               'passwords to gain unauthorized access. Variations '
                                                               'include dictionary attacks against single accounts, '
                                                               'and password spraying where an attacker tests a single '
                                                               'common password (e.g. `Winter2026!`) across thousands '
                                                               'of accounts to evade per-user lockout thresholds.',
                                     'level_2_detection_en': 'In Linux systems, inspect `/var/log/auth.log` for bursts '
                                                             "of 'Failed password for invalid user'. In Windows "
                                                             'environments, query Event ID 4625 (An account failed to '
                                                             'log on). HexaGuard SOC Case File #1 provides simulated '
                                                             'authentication logs of an SSH brute force attack against '
                                                             'a bastion host.',
                                     'level_3_practice': {   'challenge_prompt_en': 'Formulate a Fail2Ban jail '
                                                                                    'configuration and firewall rule '
                                                                                    'to automatically ban offending '
                                                                                    'IPs exceeding 5 failed SSH '
                                                                                    'authentication attempts within a '
                                                                                    '10-minute window.',
                                                             'guided_prompt_en': 'Open SOC Case Files (/casefiles) -> '
                                                                                 "Case 01: 'The Midnight Brute Force "
                                                                                 "Storm'. Parse the SSH authentication "
                                                                                 'logs to pinpoint the attacking IP '
                                                                                 'address and identify the compromised '
                                                                                 'username.',
                                                             'sandbox_target': None},
                                     'level_4_remediation_en': 'Deploy automated IP banning (Fail2Ban or CrowdSec). '
                                                               'Enforce Multi-Factor Authentication (MFA/FIDO2) across '
                                                               'all remote access services (SSH, VPN, RDP). In SSH, '
                                                               'enforce `PasswordAuthentication no` and require '
                                                               'ed25519 public keys. Mapped to MITRE ATT&CK Mitigation '
                                                               'M1032.'},
                       'log_sources': ['Auth.log / Secure', 'Windows Security 4625', 'Nginx / Apache access logs'],
                       'mitre_id': 'T1110',
                       'name_ar': 'التخمين المنهجي وكسر كلمات المرور',
                       'name_en': 'Password Spraying & Brute Force',
                       'prerequisites': [],
                       'remediation_ar': 'تفعيل حظر العناوين التلقائي ومعدل الطلبات، تطبيق المصادقة متعددة العوامل، '
                                         'وإلغاء مصادقة كلمات المرور لصالح مفاتيح SSH.',
                       'remediation_en': 'Enable Fail2Ban / IP rate limiting, enforce Multi-Factor Authentication '
                                         '(MFA), and disable password auth in favor of SSH keys.',
                       'severity_default': 'high',
                       'tactic': 'Credential Access'},
    'credential_dumping_lsass': {   'description_ar': 'استخراج كلمات السر وتذاكر الجلسات من ذاكرة نظام التشغيل (عملية '
                                                      'LSASS) أو من ملف shadow.',
                                    'description_en': 'Adversary extracts plaintext passwords or Kerberos tickets from '
                                                      'memory processes (LSASS) or disk files (/etc/shadow).',
                                    'id': 'credential_dumping_lsass',
                                    'indicators': [   'Mimikatz command strings in memory',
                                                      'Process access to lsass.exe with PROCESS_VM_READ permissions',
                                                      'Creation of lsass.dmp minidump via Taskmgr or procdump'],
                                    'lesson': {   'deep_dive_links': [   {   'label': 'MITRE ATT&CK: OS Credential '
                                                                                      'Dumping (T1003)',
                                                                             'url': 'https://attack.mitre.org/techniques/T1003/'},
                                                                         {   'label': 'Microsoft: Protect Derived '
                                                                                      'Domain Credentials with '
                                                                                      'Credential Guard',
                                                                             'url': 'https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/'}],
                                                  'level_1_foundations_en': 'Operating systems cache active '
                                                                            'authentication credentials and session '
                                                                            'tickets in memory to support single '
                                                                            'sign-on. Adversaries with local '
                                                                            'administrative privileges utilize tools '
                                                                            'like Mimikatz, ProcDump, or secret '
                                                                            'extraction scripts to dump the memory of '
                                                                            'the Local Security Authority Subsystem '
                                                                            'Service (lsass.exe) on Windows, or read '
                                                                            '`/etc/shadow` on Linux, harvesting '
                                                                            'plaintext credentials and NTLM/Kerberos '
                                                                            'hashes.',
                                                  'level_2_detection_en': 'In Windows, monitor Sysmon Event ID 10 '
                                                                          '(Process Access) where the TargetImage is '
                                                                          '`lsass.exe` and GrantedAccess includes '
                                                                          '`0x1010` or `0x1F0FFF`. On Linux, use '
                                                                          'Auditd to track open/read syscalls '
                                                                          'targeting `/etc/shadow` by processes other '
                                                                          'than standard authentication daemons.',
                                                  'level_3_practice': {   'challenge_prompt_en': 'Implement Windows '
                                                                                                 'Defender Credential '
                                                                                                 'Guard using Group '
                                                                                                 'Policy and verify '
                                                                                                 'that '
                                                                                                 'virtualization-based '
                                                                                                 'security (VBS) '
                                                                                                 'isolates LSASS '
                                                                                                 'secrets from dumping '
                                                                                                 'tools.',
                                                                          'guided_prompt_en': 'Review Sysmon Event 10 '
                                                                                              'logs showing an '
                                                                                              'unauthorized process '
                                                                                              'opening a handle to '
                                                                                              'lsass.exe with memory '
                                                                                              'read privileges.',
                                                                          'sandbox_target': None},
                                                  'level_4_remediation_en': 'Enable Windows Defender Credential Guard '
                                                                            'to isolate LSASS secrets in a Virtual '
                                                                            'Secure Mode container. Remove '
                                                                            '`SeDebugPrivilege` from local '
                                                                            'administrators where not required. In '
                                                                            'Linux, verify `/etc/shadow` is set to '
                                                                            '`chmod 640` and owned by `root:shadow`. '
                                                                            'Mapped to MITRE ATT&CK Mitigation M1027.'},
                                    'log_sources': [   'Windows Sysmon Event 10 (ProcessAccess to lsass.exe)',
                                                       'Auditd (Access to /etc/shadow)',
                                                       'Endpoint EDR'],
                                    'mitre_id': 'T1003',
                                    'name_ar': 'استخراج وتفريغ بيانات الاعتماد من الذاكرة (Credential Dumping)',
                                    'name_en': 'OS Credential Dumping (LSASS / /etc/shadow)',
                                    'prerequisites': ['privilege_escalation_suid'],
                                    'remediation_ar': 'تفعيل ميزة Credential Guard في ويندوز وتعطيل تخزين WDigest وحصر '
                                                      'صلاحية SeDebugPrivilege وحماية ملف shadow.',
                                    'remediation_en': 'Enable Credential Guard in Windows; disable WDigest caching; '
                                                      'restrict debug privileges (SeDebugPrivilege); protect '
                                                      '/etc/shadow.',
                                    'severity_default': 'critical',
                                    'tactic': 'Credential Access'},
    'data_exfil': {   'description_ar': 'نقل وسحب ملفات وبيانات حساسة أو قواعد بيانات خارج محيط المؤسسة دون تصريح عبر '
                                        'قنوات مشفرة أو خدمات تخزين سحابية.',
                      'description_en': 'Unauthorized extraction and compression of confidential data transferred '
                                        'across external channels.',
                      'id': 'data_exfil',
                      'indicators': [   'Large database query dumps followed by spike in outbound transfer',
                                        'Archive files created in temp directories',
                                        'Uploads to unauthorized cloud services'],
                      'lesson': {   'deep_dive_links': [   {   'label': 'MITRE ATT&CK: Exfiltration Over C2 Channel '
                                                                        '(T1041)',
                                                               'url': 'https://attack.mitre.org/techniques/T1041/'},
                                                           {   'label': 'GDPR Article 33: Data Breach Notification',
                                                               'url': 'https://gdpr-info.eu/art-33-gdpr/'}],
                                    'level_1_foundations_en': 'Data Exfiltration is the primary objective of data '
                                                              'breaches and extortion campaigns. Adversaries stage '
                                                              'data locally (often utilizing archiving utilities like '
                                                              '7-Zip or tar), encrypt or password-protect the archive, '
                                                              'and transfer it over encrypted protocols (HTTPS POST, '
                                                              'SFTP, cloud storage APIs like Mega or AWS S3) to evade '
                                                              'perimeter Data Loss Prevention (DLP) filters.',
                                    'level_2_detection_en': 'Monitor database query logs for abnormal bulk queries '
                                                            '(e.g. `SELECT *` returning millions of records). Monitor '
                                                            'network telemetry for outbound volume spikes to untrusted '
                                                            'IP ranges or unauthorized cloud storage services. '
                                                            'HexaGuard SOC Case File #3 guides investigation of SQL '
                                                            'injection-driven database exfiltration.',
                                    'level_3_practice': {   'challenge_prompt_en': 'Complete Case 03 by determining '
                                                                                   'the exact database tables leaked, '
                                                                                   'identifying the exfiltration '
                                                                                   'endpoint, and calculating the '
                                                                                   'regulatory breach notification '
                                                                                   'window under GDPR.',
                                                            'guided_prompt_en': 'Open SOC Case Files (/casefiles) -> '
                                                                                "Case 03: 'Database Breach & Data "
                                                                                "Exfiltration'. Analyze database audit "
                                                                                'logs and correlate the volume of data '
                                                                                'queried with the subsequent outbound '
                                                                                'HTTPS transfer.',
                                                            'sandbox_target': None},
                                    'level_4_remediation_en': 'Block the outbound destination IP address and terminate '
                                                              'active network sessions. Revoke affected database '
                                                              'credentials and encryption keys immediately. Preserve '
                                                              'database access logs to determine exact records '
                                                              'compromised for regulatory notification (GDPR Article '
                                                              '33 requires notification within 72 hours). Mapped to '
                                                              'MITRE ATT&CK Mitigation M1057.'},
                      'log_sources': ['DLP Alerts', 'Database Audit Logs', 'NetFlow Outbound Volume Logs'],
                      'mitre_id': 'T1041',
                      'name_ar': 'تسريب واستخراج البيانات الحساسة',
                      'name_en': 'Data Exfiltration & Unauthorized Access',
                      'prerequisites': ['sqli', 'sensitive_data_exposure'],
                      'remediation_ar': 'قطع قنوات الاتصال الخارجية النشطة، إبطال مفاتيح قواعد البيانات المسربة، حصر '
                                        'نطاق البيانات المتأثرة، وتفعيل خطة الاستجابة للحوادث.',
                      'remediation_en': 'Sever active outbound exfiltration channels, revoke compromised API/database '
                                        'keys, assess scope of leaked data, and notify incident response commander.',
                      'severity_default': 'critical',
                      'tactic': 'Exfiltration'},
    'defense_evasion_log_clearing': {   'description_ar': 'قيام المهاجم بحذف أو تعديل سجلات النظام والأحداث الأمنية '
                                                          'لإخفاء آثاره وإعاقة التحقيق الجنائي.',
                                        'description_en': 'Adversary deletes, truncates, or modifies system event logs '
                                                          'to eliminate evidence and hinder incident investigation.',
                                        'id': 'defense_evasion_log_clearing',
                                        'indicators': [   'Windows Event 1102 or Event 104',
                                                          'history -c execution in bash',
                                                          'Truncation of /var/log/auth.log or syslog to 0 bytes'],
                                        'lesson': {   'deep_dive_links': [   {   'label': 'MITRE ATT&CK: Indicator '
                                                                                          'Removal (T1070)',
                                                                                 'url': 'https://attack.mitre.org/techniques/T1070/'},
                                                                             {   'label': 'NIST SP 800-92: Guide to '
                                                                                          'Computer Security Log '
                                                                                          'Management',
                                                                                 'url': 'https://csrc.nist.gov/publications/detail/sp/800-92/final'}],
                                                      'level_1_foundations_en': 'To avoid detection and maintain '
                                                                                'persistent access, sophisticated '
                                                                                'adversaries manipulate or delete '
                                                                                'system logs before concluding an '
                                                                                'intrusion. Techniques include '
                                                                                'executing `wevtutil cl Security` on '
                                                                                'Windows (clearing the Security event '
                                                                                'log), running `history -c` or `unset '
                                                                                'HISTFILE` on Linux, and truncating '
                                                                                'log files (`> /var/log/auth.log`) '
                                                                                'with root privileges.',
                                                      'level_2_detection_en': 'In Windows environments, alert '
                                                                              "immediately on Event ID 1102: 'The "
                                                                              "audit log was cleared'. In Linux "
                                                                              'environments, monitor for sudden drops '
                                                                              'in log file size or auditd daemon '
                                                                              'stoppage. In SIEM systems, alert when a '
                                                                              'host stops forwarding syslog events '
                                                                              'unexpectedly.',
                                                      'level_3_practice': {   'challenge_prompt_en': 'Configure '
                                                                                                     'Rsyslog on Linux '
                                                                                                     'to forward all '
                                                                                                     'authentication '
                                                                                                     'and kernel '
                                                                                                     'events to an '
                                                                                                     'isolated, '
                                                                                                     'append-only '
                                                                                                     'remote log '
                                                                                                     'collector over '
                                                                                                     'TLS.',
                                                                              'guided_prompt_en': 'Observe how '
                                                                                                  'clearing Windows '
                                                                                                  'logs produces Event '
                                                                                                  'ID 1102 and examine '
                                                                                                  'why centralized '
                                                                                                  'remote logging '
                                                                                                  'preserves the '
                                                                                                  'forensic trail.',
                                                                              'sandbox_target': None},
                                                      'level_4_remediation_en': 'Forward all system, security, and '
                                                                                'application logs in real-time to an '
                                                                                'immutable, centralized SIEM '
                                                                                '(Elasticsearch, Splunk, Graylog). '
                                                                                'Configure SIEM storage with '
                                                                                'Write-Once-Read-Many (WORM) policies '
                                                                                'so even compromised local root '
                                                                                'accounts cannot delete remote '
                                                                                'historical records. Mapped to MITRE '
                                                                                'ATT&CK Mitigation M1022.'},
                                        'log_sources': [   'Syslog / Central SIEM',
                                                           'Windows Security Event 1102 (Log Cleared)',
                                                           'Auditd Daemon Logs'],
                                        'mitre_id': 'T1070',
                                        'name_ar': 'مسح السجلات والتهرب الدفاعي (Log Tampering)',
                                        'name_en': 'Defense Evasion & Security Log Clearing',
                                        'prerequisites': ['privilege_escalation_suid'],
                                        'remediation_ar': 'إرسال السجلات لحظياً إلى خادم SIEM مركزي معزول مع تفعيل '
                                                          'خاصية القراءة فقط بعد الكتابة (WORM).',
                                        'remediation_en': 'Stream logs in real-time to a tamper-proof central '
                                                          'SIEM/syslog server; enforce WORM (Write Once Read Many) '
                                                          'storage.',
                                        'severity_default': 'critical',
                                        'tactic': 'Defense Evasion'},
    'lateral_movement': {   'description_ar': 'تنقل المهاجم بين أجهزة وخوادم الشبكة الداخلية مستغلاً حسابات مسروقة أو '
                                              'أدوات إدارة عن بعد للسيطرة على بيئة العمل.',
                            'description_en': 'Adversary extends control across internal network hosts using harvested '
                                              'credentials or remote administration tools.',
                            'id': 'lateral_movement',
                            'indicators': [   'Unexpected internal SMB/RDP/SSH traffic',
                                              'Service creation on remote hosts',
                                              'Pass-the-Hash / Kerberoasting traces'],
                            'lesson': {   'deep_dive_links': [   {   'label': 'MITRE ATT&CK: Lateral Movement (T1021)',
                                                                     'url': 'https://attack.mitre.org/tactics/TA0008/'},
                                                                 {   'label': 'Microsoft: Active Directory '
                                                                              'Administrative Tier Model',
                                                                     'url': 'https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model'}],
                                          'level_1_foundations_en': 'Once an initial foothold is secured, adversaries '
                                                                    'move laterally across internal networks to locate '
                                                                    'sensitive databases, high-privilege domain '
                                                                    'controllers, or cloud management keys. Common '
                                                                    'techniques include Pass-the-Hash, PsExec / WMI '
                                                                    'execution, SSH key pivoting, and abuse of '
                                                                    'internal SMB shares.',
                                          'level_2_detection_en': 'Monitor internal network traffic for anomalous '
                                                                  'workstation-to-workstation connections on ports 445 '
                                                                  '(SMB), 3389 (RDP), or 22 (SSH). In Windows Active '
                                                                  'Directory logs, inspect Event ID 4624 with Logon '
                                                                  'Type 3 (Network) using privileged accounts. '
                                                                  'HexaGuard SOC Case File #4 guides forensic '
                                                                  'investigation of lateral movement.',
                                          'level_3_practice': {   'challenge_prompt_en': 'Perform root cause analysis '
                                                                                         'in Case 04 to identify the '
                                                                                         'compromised service account, '
                                                                                         'map the persistence '
                                                                                         'mechanism, and construct an '
                                                                                         'Active Directory tiering '
                                                                                         'defense model.',
                                                                  'guided_prompt_en': 'Navigate to SOC Case Files '
                                                                                      '(/casefiles) -> Case 04: '
                                                                                      "'Lateral Movement & Domain "
                                                                                      "Escalation'. Analyze the "
                                                                                      'internal NetFlow and Active '
                                                                                      'Directory telemetry to trace '
                                                                                      "the attacker's path from "
                                                                                      'workstation to database.',
                                                                  'sandbox_target': None},
                                          'level_4_remediation_en': 'Implement network segmentation: isolate '
                                                                    'workstations from direct communication with each '
                                                                    'other (Private VLANs). Enforce the Tiered '
                                                                    'Administrative Model in Active Directory: domain '
                                                                    'admin accounts must never log on to standard '
                                                                    'workstations. Deploy Microsoft LAPS to randomize '
                                                                    'local admin passwords. Mapped to MITRE ATT&CK '
                                                                    'Mitigation M1030.'},
                            'log_sources': [   'Internal NetFlow / Zeek',
                                               'Windows Event 4624 (Logon Type 3/10)',
                                               'Active Directory Security Log'],
                            'mitre_id': 'T1021',
                            'name_ar': 'التحرك الجانبي وتصعيد الصلاحيات',
                            'name_en': 'Lateral Movement & Privilege Escalation',
                            'prerequisites': ['brute_force'],
                            'remediation_ar': 'عزل الجهاز المصاب فورياً، إنهاء الجلسات المشبوهة، تجزئة الشبكة وفصل '
                                              'النطاقات، وتدوير كلمات سر الحسابات الإدارية.',
                            'remediation_en': 'Isolate compromised host, terminate anomalous internal sessions, '
                                              'segment VLANs, and rotate privileged domain credentials.',
                            'severity_default': 'critical',
                            'tactic': 'Lateral Movement'},
    'malware_beacon': {   'description_ar': 'إشارات دورية أو مشوهة التوقيت يرسلها برمجية خبيثة داخل النظام إلى خوادم '
                                            'المهاجم الخارجية لتلقي الأوامر.',
                          'description_en': 'Periodic or jittered outbound heartbeat signals established by implant '
                                            'communicating with adversary infrastructure.',
                          'id': 'malware_beacon',
                          'indicators': [   'Regular interval connections to newly registered domains',
                                            'DNS tunneling (TXT lookup high entropy)',
                                            'Unusual user-agents'],
                          'lesson': {   'deep_dive_links': [   {   'label': 'MITRE ATT&CK: Application Layer Protocol '
                                                                            '(T1071)',
                                                                   'url': 'https://attack.mitre.org/techniques/T1071/'},
                                                               {   'label': 'RITA: Real Intelligence Threat Analytics',
                                                                   'url': 'https://github.com/activecm/rita'}],
                                        'level_1_foundations_en': 'Command and Control (C2) beaconing represents the '
                                                                  'communication channel between compromised internal '
                                                                  'systems and threat actor infrastructure (e.g. '
                                                                  'Cobalt Strike, Sliver, Mythic). Implants transmit '
                                                                  'periodic or jittered HTTP/HTTPS requests, DNS '
                                                                  'queries, or WebSocket frames to retrieve adversary '
                                                                  'commands and exfiltrate host status.',
                                        'level_2_detection_en': 'Analyze perimeter proxy and firewall connection '
                                                                'intervals using statistical tools (e.g. RITA - Real '
                                                                'Intelligence Threat Analytics) to calculate delta '
                                                                'time regularity and identify periodic heartbeat '
                                                                'signals. Look for anomalous DNS TXT query volume or '
                                                                'high-entropy subdomain strings indicative of DNS '
                                                                'tunneling.',
                                        'level_3_practice': {   'challenge_prompt_en': 'Analyze a network packet '
                                                                                       'capture containing suspected '
                                                                                       'C2 beaconing, identify the '
                                                                                       'beacon frequency, decode the '
                                                                                       'HTTP payload headers, and '
                                                                                       'formulate an indicator of '
                                                                                       'compromise (IOC) list.',
                                                                'guided_prompt_en': 'Inspect firewall egress logs with '
                                                                                    'consistent timestamp differences '
                                                                                    '(e.g. connection every 60s +/- '
                                                                                    '10% jitter) and identify the '
                                                                                    'destination IP.',
                                                                'sandbox_target': None},
                                        'level_4_remediation_en': 'Isolate the beaconing host immediately via EDR host '
                                                                  'isolation. Block destination IP addresses and '
                                                                  'domain names across perimeter firewalls, web '
                                                                  'proxies, and DNS resolvers. Capture memory dumps '
                                                                  '(`volatility`) and disk images for malware reverse '
                                                                  'engineering before wiping the host. Mapped to MITRE '
                                                                  'ATT&CK Mitigation M1037.'},
                          'log_sources': ['DNS Query Logs', 'Firewall Egress Logs', 'Web Proxy / SSL Inspection'],
                          'mitre_id': 'T1071',
                          'name_ar': 'إشارات خوادم القيادة والتحكم (C2)',
                          'name_en': 'Command and Control (C2) Beaconing',
                          'prerequisites': ['phishing'],
                          'remediation_ar': 'حظر عناوين ونطاقات المهاجم على جدار الحماية وسيرفرات DNS، إنهاء العمليات '
                                            'الخبيثة، وأخذ لقطة جنائية للذاكرة والقرص.',
                          'remediation_en': 'Block destination IP/domains at perimeter firewall and DNS sinkhole, '
                                            'terminate suspicious processes, and preserve disk/memory image for '
                                            'forensic triage.',
                          'severity_default': 'critical',
                          'tactic': 'Command and Control'},
    'persistence_webshell': {   'description_ar': 'زراعة ملفات شفرات برمجية خبيثة داخل مجلدات الويب تضمن استمرارية '
                                                  'التحكم والوصول عن بعد.',
                                'description_en': 'Attacker deploys a persistent script (PHP, JSP, ASPX) inside web '
                                                  'directories to maintain continuous command execution.',
                                'id': 'persistence_webshell',
                                'indicators': [   'New file created in uploads or cache directory',
                                                  'POST requests to non-existent or newly dropped .php files',
                                                  'Web server process spawning cmd.exe or /bin/sh'],
                                'lesson': {   'deep_dive_links': [   {   'label': 'MITRE ATT&CK: Web Shell (T1505.003)',
                                                                         'url': 'https://attack.mitre.org/techniques/T1505/003/'},
                                                                     {   'label': 'CISA Alert: Detecting and Defending '
                                                                                  'Against Web Shells',
                                                                         'url': 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-114a'}],
                                              'level_1_foundations_en': 'After successfully exploiting a vulnerability '
                                                                        '(such as an unrestricted file upload, SQL '
                                                                        'injection write, or RCE), attackers deploy a '
                                                                        'web shell (e.g. `b374k`, `c99`, or one-line '
                                                                        'PHP eval scripts) into a publicly accessible '
                                                                        'directory. The web shell acts as an HTTP '
                                                                        'backdoor, accepting commands via parameters '
                                                                        'and executing them with the web server '
                                                                        "daemon's privileges.",
                                              'level_2_detection_en': 'Monitor web server process trees: a web server '
                                                                      'process (`nginx`, `httpd`, `w3wp.exe`) spawning '
                                                                      'an interactive shell (`/bin/sh`, `/bin/bash`, '
                                                                      '`cmd.exe`, `powershell.exe`) is an almost '
                                                                      'certain indicator of a web shell in action. '
                                                                      'Monitor File Integrity (FIM) for new script '
                                                                      'files created inside `/uploads/` or `/static/` '
                                                                      'directories.',
                                              'level_3_practice': {   'challenge_prompt_en': 'Perform forensic triage '
                                                                                             'on a compromised web '
                                                                                             'application root '
                                                                                             'directory to identify, '
                                                                                             'isolate, and safely '
                                                                                             'decode an obfuscated PHP '
                                                                                             'web shell backdoor.',
                                                                      'guided_prompt_en': 'Inspect web server access '
                                                                                          'logs for repeated POST '
                                                                                          'requests to standalone '
                                                                                          'scripts inside an uploads '
                                                                                          'directory with 200 OK '
                                                                                          'responses.',
                                                                      'sandbox_target': None},
                                              'level_4_remediation_en': 'In web server configurations, completely '
                                                                        'disable script execution in upload '
                                                                        'directories: in Nginx: `location /uploads/ { '
                                                                        'php_flag engine off; }` or `location ~ '
                                                                        '/uploads/.*\\.php$ { deny all; }`. Deploy '
                                                                        'File Integrity Monitoring (FIM) via Wazuh or '
                                                                        'OSSEC. Quarantine discovered web shell files '
                                                                        'for malware analysis. Mapped to MITRE ATT&CK '
                                                                        'Mitigation M1050.'},
                                'log_sources': [   'Web Server Access Logs',
                                                   'File Integrity Monitoring (FIM)',
                                                   'EDR Process Lineage'],
                                'mitre_id': 'T1505.003',
                                'name_ar': 'زراعة الأبواب الخلفية والويب شيل (Web Shell Persistence)',
                                'name_en': 'Web Shell Persistence & Backdoor Execution',
                                'prerequisites': ['rce', 'sensitive_file_leak'],
                                'remediation_ar': 'منع تنفيذ السكربتات في مجلدات الرفع واعتماد أدوات مراقبة سلامة '
                                                  'الملفات (FIM) وعزل الملفات الخبيثة.',
                                'remediation_en': 'Disable script execution in writable upload directories; deploy '
                                                  'File Integrity Monitoring (AIDE/Tripwire); quarantine webshell '
                                                  'files.',
                                'severity_default': 'critical',
                                'tactic': 'Persistence'},
    'phishing': {   'description_ar': 'إرسال رسائل بريد أو روابط خادعة تدفع الضحية للكشف عن بيانات الدخول أو تحميل '
                                      'ملفات خبيثة.',
                    'description_en': 'Adversaries send malicious emails or links to gain initial credential access or '
                                      'code execution.',
                    'id': 'phishing',
                    'indicators': [   'Suspicious sender domain',
                                      'Macro-enabled attachment',
                                      'Unusual outbound HTTP POST'],
                    'lesson': {   'deep_dive_links': [   {   'label': 'MITRE ATT&CK: Phishing (T1566)',
                                                             'url': 'https://attack.mitre.org/techniques/T1566/'},
                                                         {   'label': 'CISA Phishing Guidance',
                                                             'url': 'https://www.cisa.gov/stopransomware/phishing-guidance'}],
                                  'level_1_foundations_en': 'Phishing is the predominant Initial Access vector across '
                                                            'modern cyber campaigns. Threat actors craft deceptive '
                                                            'emails, SMS messages (smishing), or direct messages that '
                                                            'mimic trusted executives, IT support, or cloud providers '
                                                            '(Microsoft 365, Google Workspace). Victims are coerced '
                                                            'into submitting credentials into spoofed portals or '
                                                            'executing malicious attachments containing initial access '
                                                            'loaders (e.g. Qakbot, Emotet).',
                                  'level_2_detection_en': 'Analyze email gateway headers for SPF/DKIM verification '
                                                          'failures (`Authentication-Results: dkim=fail`). In proxy '
                                                          'and DNS telemetry, search for outbound connections to newly '
                                                          'registered domains (NRDs) occurring within minutes of an '
                                                          'employee opening a webmail link. In HexaGuard, SOC Case '
                                                          'File #2 guides forensic analysis of phishing-initiated '
                                                          'exfiltration.',
                                  'level_3_practice': {   'challenge_prompt_en': 'Complete the forensic triage in Case '
                                                                                 "02, extract the threat actor's "
                                                                                 'command-and-control IP from proxy '
                                                                                 'logs, and formulate an incident '
                                                                                 'containment plan.',
                                                          'guided_prompt_en': 'Navigate to SOC Case Files (/casefiles) '
                                                                              "-> Case 02: 'Phishing Campaign with "
                                                                              "Multi-Stage Exfiltration'. Inspect the "
                                                                              'mail server logs and proxy telemetry to '
                                                                              "trace the attacker's ingress vector.",
                                                          'sandbox_target': None},
                                  'level_4_remediation_en': 'Isolate compromised endpoints from the corporate network '
                                                            'immediately. Revoke all active session tokens and refresh '
                                                            'tokens in Azure AD/Okta. Reset user passwords and '
                                                            're-register MFA authenticators. Add the malicious domain '
                                                            'and IP to perimeter DNS sinkholes and proxy blocklists. '
                                                            'Mapped to MITRE ATT&CK Mitigation M1017.'},
                    'log_sources': ['Mail Gateway', 'Web Proxy / DNS', 'Endpoint EDR'],
                    'mitre_id': 'T1566',
                    'name_ar': 'التصيد الاحتيالي والهندسة الاجتماعية',
                    'name_en': 'Phishing & Social Engineering',
                    'prerequisites': [],
                    'remediation_ar': 'تفعيل معايير SPF/DKIM/DMARC الصارمة، عزل وفحص المرفقات، إلغاء الجلسات وإعادة '
                                      'تعيين كلمات المرور.',
                    'remediation_en': 'Enforce SPF/DKIM/DMARC, implement mail sandboxing, revoke compromised sessions, '
                                      'and reset credentials.',
                    'severity_default': 'high',
                    'tactic': 'Initial Access'},
    'privilege_escalation_suid': {   'description_ar': 'استغلال المستخدم المحلي لأذونات SUID الخاطئة أو صلاحيات sudo '
                                                       'غير المقيدة للوصول لحساب root.',
                                     'description_en': 'Local unprivileged user exploits misconfigured SUID binaries, '
                                                       'sudo permissions, or kernel bugs to gain root access.',
                                     'id': 'privilege_escalation_suid',
                                     'indicators': [   'Execution of SUID binaries outside /usr/bin',
                                                       'sudo -l commands in bash history',
                                                       'Spawning root shell via GTFOBins'],
                                     'lesson': {   'deep_dive_links': [   {   'label': 'GTFOBins: Curated List of Unix '
                                                                                       'Binaries for Privilege '
                                                                                       'Escalation',
                                                                              'url': 'https://gtfobins.github.io/'},
                                                                          {   'label': 'MITRE ATT&CK: Abuse Elevation '
                                                                                       'Control Mechanism (T1548)',
                                                                              'url': 'https://attack.mitre.org/techniques/T1548/'}],
                                                   'level_1_foundations_en': 'Privilege escalation is the phase where '
                                                                             'an attacker with limited initial user '
                                                                             'access escalates their privileges to '
                                                                             '`root` or `Administrator`. On Linux, '
                                                                             'common vectors include misconfigured '
                                                                             'SUID (Set User ID) binaries that allow '
                                                                             'executing programs with root permissions '
                                                                             '(e.g. `nmap`, `vim`, `find` listed in '
                                                                             'GTFOBins), or overly permissive '
                                                                             '`sudoers` configurations allowing '
                                                                             'commands without passwords.',
                                                   'level_2_detection_en': 'Audit Linux systems for SUID files using '
                                                                           '`find / -perm -4000 -type f 2>/dev/null`. '
                                                                           'Monitor `/var/log/audit/audit.log` for '
                                                                           'unusual binary invocations with effective '
                                                                           'UID 0. Inspect `/etc/sudoers` for '
                                                                           '`NOPASSWD: ALL` or wildcards.',
                                                   'level_3_practice': {   'challenge_prompt_en': 'Exploit an insecure '
                                                                                                  'SUID binary '
                                                                                                  'configuration in a '
                                                                                                  'test environment to '
                                                                                                  'elevate privileges '
                                                                                                  'from an '
                                                                                                  'unprivileged user '
                                                                                                  'to root and capture '
                                                                                                  'the system flag.',
                                                                           'guided_prompt_en': 'Identify SUID binaries '
                                                                                               'on a test Linux system '
                                                                                               'with `find / -perm '
                                                                                               '-4000` and compare '
                                                                                               'findings against the '
                                                                                               'GTFOBins database.',
                                                                           'sandbox_target': None},
                                                   'level_4_remediation_en': 'Remove SUID bit from binaries that do '
                                                                             'not strictly require it: `chmod u-s '
                                                                             '/path/to/binary`. In `/etc/sudoers`, '
                                                                             'specify full command paths without '
                                                                             'wildcards, and always require password '
                                                                             're-authentication. Deploy Linux Auditd '
                                                                             'rules monitoring execve syscalls for '
                                                                             'SUID executions. Mapped to MITRE ATT&CK '
                                                                             'Mitigation M1028.'},
                                     'log_sources': ['Auth.log / Auditd', 'Bash History', 'Linux Audit Logs (SYSCALL)'],
                                     'mitre_id': 'T1548',
                                     'name_ar': 'تصعيد الصلاحيات عبر ملفات SUID وثغرات Sudo',
                                     'name_en': 'Linux SUID / Sudo Privilege Escalation',
                                     'prerequisites': ['rce', 'weak_file_permissions'],
                                     'remediation_ar': 'تدقيق وإزالة بت SUID عن البرامج غير الضرورية وتقييد ملف '
                                                       'sudoers وتجنب استخدام الرموز البديلة.',
                                     'remediation_en': 'Audit SUID/SGID binaries (find / -perm -4000); restrict '
                                                       'sudoers configurations to explicit commands without wildcards.',
                                     'severity_default': 'high',
                                     'tactic': 'Privilege Escalation'},
    'ransomware_encryption': {   'description_ar': 'تشفير الملفات والبيانات الحساسة وحذف النسخ الاحتياطية لابتزاز '
                                                   'المؤسسة وتعطيل عمليات التشغيل.',
                                 'description_en': 'Adversaries encrypt data on target systems or wipe volume shadow '
                                                   'copies to interrupt access to system resources.',
                                 'id': 'ransomware_encryption',
                                 'indicators': [   'Massive spike in rapid file modification/renaming',
                                                   'vssadmin delete shadows command execution',
                                                   'Ransom note dropped in directories'],
                                 'lesson': {   'deep_dive_links': [   {   'label': 'MITRE ATT&CK: Data Encrypted for '
                                                                                   'Impact (T1486)',
                                                                          'url': 'https://attack.mitre.org/techniques/T1486/'},
                                                                      {   'label': 'CISA #StopRansomware Guide',
                                                                          'url': 'https://www.cisa.gov/stopransomware/ransomware-guide'}],
                                               'level_1_foundations_en': 'Ransomware encrypts critical files across '
                                                                         'endpoints, servers, and shared network '
                                                                         'storage, replacing them with locked '
                                                                         'extensions and dropping ransom notes '
                                                                         'demanding cryptocurrency payments. Prior to '
                                                                         'encryption, modern ransomware actors delete '
                                                                         'Volume Shadow Copies (`vssadmin delete '
                                                                         'shadows /all /quiet`) and disable Windows '
                                                                         'Recovery features to prevent local recovery.',
                                               'level_2_detection_en': 'Monitor Endpoint Detection and Response (EDR) '
                                                                       'alerts for suspicious process execution '
                                                                       'patterns: `vssadmin.exe delete shadows`, '
                                                                       '`wbadmin.exe delete catalog`, or `bcdedit.exe '
                                                                       '/set {default} bootstatuspolicy '
                                                                       'ignoreallfailures`. Detect anomalous spikes in '
                                                                       'file write/rename operations across file '
                                                                       'servers.',
                                               'level_3_practice': {   'challenge_prompt_en': 'Formulate a rapid '
                                                                                              'containment and '
                                                                                              'recovery playbook for '
                                                                                              'an enterprise '
                                                                                              'experiencing active '
                                                                                              'file encryption across '
                                                                                              'an internal file share '
                                                                                              'cluster.',
                                                                       'guided_prompt_en': 'Analyze EDR process '
                                                                                           'execution telemetry '
                                                                                           'showing the typical '
                                                                                           'pre-ransomware sequence: '
                                                                                           'execution of discovery '
                                                                                           'commands followed by '
                                                                                           'shadow copy deletion.',
                                                                       'sandbox_target': None},
                                               'level_4_remediation_en': 'Immediately isolate all affected endpoints '
                                                                         'and network subnets to prevent lateral '
                                                                         'encryption spreading. Do NOT power off '
                                                                         'systems immediately if volatile memory can '
                                                                         'be preserved for cryptographic key recovery. '
                                                                         'Restore operational infrastructure from '
                                                                         'immutable, offline, or air-gapped backups. '
                                                                         'Mapped to MITRE ATT&CK Mitigation M1053.'},
                                 'log_sources': [   'Endpoint EDR',
                                                    'Windows Event 7045 (Service Install)',
                                                    'File Integrity Monitoring (FIM)'],
                                 'mitre_id': 'T1486',
                                 'name_ar': 'انتشار برمجيات الفدية وتشفير البيانات (Ransomware)',
                                 'name_en': 'Ransomware Deployment & Data Encryption',
                                 'prerequisites': ['lateral_movement'],
                                 'remediation_ar': 'عزل الأجهزة المصابة فورا وقطع الاتصال بالشبكة، وتجنب دفع الفدية، '
                                                   'واستعادة الأنظمة من النسخ الاحتياطية المعزولة.',
                                 'remediation_en': 'Isolate affected network segments immediately, preserve memory '
                                                   'images for key recovery, restore from immutable offline backups.',
                                 'severity_default': 'critical',
                                 'tactic': 'Impact'}}

# ── Check Normalization Map (CHECK_MAP) ─────────────────────────────────────────
# Maps scanner-specific check IDs, rule IDs, and finding names to canonical types.
CHECK_MAP: dict[str, str] = {
    # DAST / Web Injection
    "xss":                           "xss",
    "xss_reflection":                "xss",
    "sqli":                          "sqli",
    "sql_injection":                 "sqli",
    "csrf":                          "csrf",
    "rce":                           "rce",
    "rce_exec":                      "rce",
    "command_injection":             "rce",
    "ssrf":                          "ssrf",
    "ssrf_internal":                 "ssrf",
    "open_redirect":                 "open_redirect",

    # Web Core / Headers / Cookies
    "broken_auth":                   "broken_auth",
    "missing_csp":                   "missing_csp",
    "csp":                           "missing_csp",
    "missing_hsts":                  "missing_security_headers",
    "missing_x_frame_options":       "missing_security_headers",
    "missing_x_content_type_options":"missing_security_headers",
    "missing_referrer_policy":       "missing_security_headers",
    "missing_permissions_policy":    "missing_security_headers",
    "missing_security_headers":      "missing_security_headers",
    "headers":                       "missing_security_headers",
    "session_fixation":              "session_fixation",
    "cookies":                       "session_fixation",
    "cors":                          "cors",

    # SAST checks
    "sensitive_data_exposure":       "sensitive_data_exposure",
    "deserialization":               "deserialization",
    "hardcoded_secrets":             "hardcoded_secrets",
    "insecure_command_execution":    "insecure_command_execution",
    "path_traversal":                "path_traversal",
    "bandit_b301":                   "deserialization",
    "bandit_b506":                   "deserialization",
    "bandit_b602":                   "rce",
    "bandit_b601":                   "insecure_command_execution",
    "bandit_b603":                   "insecure_command_execution",
    "bandit_b604":                   "insecure_command_execution",
    "bandit_b605":                   "insecure_command_execution",
    "bandit_b105":                   "hardcoded_secrets",
    "bandit_b106":                   "hardcoded_secrets",
    "bandit_b107":                   "hardcoded_secrets",
    "gitleaks_rule":                 "hardcoded_secrets",

    # Network checks
    "open_ports":                    "open_ports",
    "open_port":                     "open_ports",
    "service_version_exposure":      "service_version_exposure",
    "unauthenticated_service":       "unauthenticated_service",
    "legacy_insecure_protocol":      "legacy_insecure_protocol",
    "eol_os_exposure":               "eol_os_exposure",
    "eol_os":                        "eol_os_exposure",
    "shodan_cve":                    "service_version_exposure",
    "nvd_cve":                       "service_version_exposure",
    "shodan_tag":                    "info_disclosure",
    "greynoise":                     "info_disclosure",
    "abuseipdb":                     "info_disclosure",
    "attack_surface":                "info_disclosure",
    "nmap_unavailable":              "info_disclosure",

    # SSL checks
    "weak_crypto":                   "weak_crypto",
    "deprecated_protocols":          "deprecated_protocols",
    "certificate_issues":            "certificate_issues",
    "heartbleed_robot":              "heartbleed_robot",
    "tls_compression_crime":         "tls_compression_crime",
    "expired_ssl_cert":              "certificate_issues",
    "ssl_cert_expiring_soon":        "certificate_issues",
    "ssl_error":                     "certificate_issues",
    "ssl_overall":                   "certificate_issues",
    "weak_tls_version":              "deprecated_protocols",
    "sslyze-heartbleed":             "heartbleed_robot",
    "sslyze-robot":                  "heartbleed_robot",
    "sslyze-openssl-ccs":            "weak_crypto",
    "sslyze-tls-compression":        "tls_compression_crime",
    "sslyze-renegotiation-dos":      "weak_crypto",
    "ssl":                           "weak_crypto",

    # Dependencies
    "vulnerable_dependency":         "vulnerable_dependency",
    "transitive_dependency_vuln":    "transitive_dependency_vuln",
    "unpinned_dependency":           "unpinned_dependency",
    "abandoned_dependency":          "abandoned_dependency",
    "dependency_confusion_typosquatting": "dependency_confusion_typosquatting",
    "dep_vuln":                      "vulnerable_dependency",

    # Server Internal
    "security_misconfig":            "security_misconfig",
    "weak_file_permissions":         "weak_file_permissions",
    "directory_listing":             "directory_listing",
    "dangerous_http_methods":        "dangerous_http_methods",
    "server_banner_disclosure":      "server_banner_disclosure",
    "modsecurity_disabled":          "modsecurity_disabled",
    "header_server_disclosure":      "server_banner_disclosure",
    "header_x_powered_by":           "server_banner_disclosure",
    "http_methods":                  "dangerous_http_methods",

    # Server External
    "info_disclosure":               "info_disclosure",
    "default_credentials":           "default_credentials",
    "default_page_exposed":          "default_page_exposed",
    "unencrypted_http":              "unencrypted_http",
    "sensitive_file_leak":           "sensitive_file_leak",
    "slowloris_dos":                 "slowloris_dos",
    "os_detection":                  "info_disclosure",
    "https_not_available":           "unencrypted_http",
    "http_unreachable":              "info_disclosure",
    "https_redirect":                "unencrypted_http",

    # Docker
    "exposed_docker_api":            "exposed_docker_api",
    "privileged_containers":         "privileged_containers",
    "docker_root_user":              "docker_root_user",
    "docker_secret_leak":            "docker_secret_leak",
    "vulnerable_container_base_image": "vulnerable_container_base_image",
    "docker_cve":                    "vulnerable_container_base_image",

    # DNS & Email
    "takeover":                      "takeover",
    "missing_spf_dkim_dmarc":        "missing_spf_dkim_dmarc",
    "dns_zone_transfer":             "dns_zone_transfer",
    "missing_caa_record":            "missing_caa_record",
    "missing_dnssec_validation":     "missing_dnssec_validation",

    # WordPress
    "xmlrpc_exposure":               "xmlrpc_exposure",
    "outdated_plugins":              "outdated_plugins",
    "wp_user_enumeration":           "wp_user_enumeration",
    "wp_sensitive_files":            "wp_sensitive_files",
    "wp_default_admin":              "wp_default_admin",
}


def get_taxonomy() -> dict[str, dict[str, Any]]:
    """Return the entire master taxonomy."""
    return VULN_TAXONOMY


def get_vuln_type(vuln_type: str) -> Optional[dict[str, Any]]:
    """Retrieve details for a single canonical vuln_type, or None if unknown."""
    if not vuln_type:
        return None
    canon = vuln_type.strip().lower()
    return VULN_TAXONOMY.get(canon) or INCIDENT_TAXONOMY.get(canon)


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
    if lower_check in INCIDENT_TAXONOMY:
        return lower_check

    # 2. Exact match in CHECK_MAP
    if check_str in CHECK_MAP:
        return CHECK_MAP[check_str]
    if lower_check in CHECK_MAP:
        return CHECK_MAP[lower_check]

    # 3. Check prefixes
    if lower_check.startswith("ssrf"):
        return "ssrf"
    if lower_check.startswith("rce"):
        return "rce"
    if lower_check.startswith("sqli") or lower_check.startswith("sql_"):
        return "sqli"
    if lower_check.startswith("xss"):
        return "xss"
    if lower_check.startswith("csrf"):
        return "csrf"
    if lower_check.startswith("bandit_b301") or lower_check.startswith("bandit_b506"):
        return "deserialization"
    if lower_check.startswith("bandit_b602"):
        return "rce"
    if lower_check.startswith("bandit_b60"):
        return "insecure_command_execution"
    if lower_check.startswith("bandit_b105") or lower_check.startswith("bandit_b106") or lower_check.startswith("bandit_b107"):
        return "hardcoded_secrets"
    if lower_check.startswith("gitleaks"):
        return "hardcoded_secrets"
    if lower_check.startswith("sslyze-heartbleed") or lower_check.startswith("sslyze-robot"):
        return "heartbleed_robot"
    if lower_check.startswith("sslyze-tls-compression"):
        return "tls_compression_crime"
    if lower_check.startswith("sslyze"):
        return "weak_crypto"

    # 4. Title heuristics
    lower_title = title_str.lower()
    if lower_title:
        if "cross-site scripting" in lower_title or " xss" in lower_title or "xss " in lower_title:
            return "xss"
        if "sql injection" in lower_title or " sqli" in lower_title or "sqli " in lower_title:
            return "sqli"
        if "csrf" in lower_title or "cross-site request forgery" in lower_title:
            return "csrf"
        if "remote code execution" in lower_title or "command injection" in lower_title:
            return "rce"
        if "ssrf" in lower_title or "server-side request forgery" in lower_title or "server side request forgery" in lower_title:
            return "ssrf"
        if "open redirect" in lower_title:
            return "open_redirect"
        if "privileged container" in lower_title:
            return "privileged_containers"
        if "docker socket" in lower_title or "docker api" in lower_title:
            return "exposed_docker_api"
        if "subdomain takeover" in lower_title or "dangling cname" in lower_title:
            return "takeover"
        if "spf" in lower_title or "dmarc" in lower_title or "dkim" in lower_title:
            return "missing_spf_dkim_dmarc"
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
