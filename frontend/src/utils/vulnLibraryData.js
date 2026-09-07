// Vulnerability Library — مكتبة الثغرات الشاملة
// نفس نمط VULN_RESOURCES من huntGuideData.js مُوسَّع بكل محركات المشروع

export const SCANNER_TABS = [
  {
    id: 'dast',
    label: 'DAST',
    labelFull: 'Dynamic Testing (ZAP/Nuclei/Nikto)',
    icon: '🔍',
    color: 'from-orange-500 to-red-500',
    bgColor: 'bg-orange-500/10',
    borderColor: 'border-orange-500/30',
    textColor: 'text-orange-400',
    desc: 'ثغرات تكتشفها أدوات الفحص الديناميكي',
  },
  {
    id: 'sast',
    label: 'SAST',
    labelFull: 'Static Analysis (Bandit/Semgrep/Gitleaks)',
    icon: '🔬',
    color: 'from-purple-500 to-indigo-500',
    bgColor: 'bg-purple-500/10',
    borderColor: 'border-purple-500/30',
    textColor: 'text-purple-400',
    desc: 'ثغرات تكتشفها أدوات تحليل الكود الساكن',
  },
  {
    id: 'network',
    label: 'Network',
    labelFull: 'Network Scanner (Nmap)',
    icon: '🌐',
    color: 'from-blue-500 to-cyan-500',
    bgColor: 'bg-blue-500/10',
    borderColor: 'border-blue-500/30',
    textColor: 'text-blue-400',
    desc: 'ثغرات مرتبطة بالشبكة والمنافذ',
  },
  {
    id: 'ssl',
    label: 'SSL/TLS',
    labelFull: 'SSL/TLS Scanner',
    icon: '🔒',
    color: 'from-green-500 to-emerald-500',
    bgColor: 'bg-green-500/10',
    borderColor: 'border-green-500/30',
    textColor: 'text-green-400',
    desc: 'ثغرات في شهادات وبروتوكولات التشفير',
  },
  {
    id: 'deps',
    label: 'Dependencies',
    labelFull: 'Dependency Scanner (OSV.dev)',
    icon: '📦',
    color: 'from-yellow-500 to-amber-500',
    bgColor: 'bg-yellow-500/10',
    borderColor: 'border-yellow-500/30',
    textColor: 'text-yellow-400',
    desc: 'ثغرات في المكتبات وسلسلة التوريد',
  },
  {
    id: 'server',
    label: 'Server Config',
    labelFull: 'Server Configuration Audit',
    icon: '⚙️',
    color: 'from-slate-400 to-slate-600',
    bgColor: 'bg-slate-500/10',
    borderColor: 'border-slate-500/30',
    textColor: 'text-slate-400',
    desc: 'أخطاء تهيئة الخوادم',
  },
  {
    id: 'docker',
    label: 'Docker',
    labelFull: 'Docker Security Audit',
    icon: '🐳',
    color: 'from-sky-500 to-blue-500',
    bgColor: 'bg-sky-500/10',
    borderColor: 'border-sky-500/30',
    textColor: 'text-sky-400',
    desc: 'ثغرات الحاويات والبنية التحتية',
  },
  {
    id: 'dns',
    label: 'DNS/Email',
    labelFull: 'DNS & Email Security',
    icon: '📧',
    color: 'from-teal-500 to-green-500',
    bgColor: 'bg-teal-500/10',
    borderColor: 'border-teal-500/30',
    textColor: 'text-teal-400',
    desc: 'ثغرات بروتوكولات البريد والـ DNS',
  },
  {
    id: 'wordpress',
    label: 'WordPress',
    labelFull: 'WordPress Security Audit',
    icon: '🌀',
    color: 'from-blue-400 to-indigo-500',
    bgColor: 'bg-indigo-500/10',
    borderColor: 'border-indigo-500/30',
    textColor: 'text-indigo-400',
    desc: 'ثغرات WordPress والإضافات',
  },
];

// difficulty ordering: easy(1) < medium(2) < hard(3)
const DIFFICULTY_ORDER = { easy: 1, medium: 2, hard: 3 };

export const VULN_LIBRARY = {
  // ── DAST ────────────────────────────────────────────────────────
  dast: [
    {
      id: 'xss',
      label: 'Cross-Site Scripting (XSS)',
      difficulty: 'easy',
      summary: 'المهاجم يحقن كود JavaScript في صفحة يشاهدها مستخدم آخر. الأنواع الثلاثة: Reflected (مؤقت)، Stored (محفوظ بالـ DB)، DOM-based (بالمتصفح). يُستخدم لسرقة الكوكيز أو التحكم في الحساب.',
      portswigger: 'https://portswigger.net/web-security/cross-site-scripting',
      hacktricks: 'https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting',
      owasp: 'https://owasp.org/www-community/attacks/xss/',
      youtube: [{ title: 'XSS Bug Bounty — NahamSec', url: 'https://www.youtube.com/results?search_query=nahamsec+XSS+bug+bounty' }],
    },
    {
      id: 'sqli',
      label: 'SQL Injection',
      difficulty: 'hard',
      summary: 'تحقن كود SQL في استعلامات قاعدة البيانات عبر المدخلات. تسمح باستخراج البيانات أو تجاوز تسجيل الدخول أو تدمير البيانات. يُعدّ من أخطر ثغرات الويب.',
      portswigger: 'https://portswigger.net/web-security/sql-injection',
      hacktricks: 'https://book.hacktricks.xyz/pentesting-web/sql-injection',
      owasp: 'https://owasp.org/www-community/attacks/SQL_Injection',
      youtube: [{ title: 'SQL Injection Full Course', url: 'https://www.youtube.com/results?search_query=SQL+injection+bug+bounty+2024' }],
    },
    {
      id: 'ssrf',
      label: 'SSRF — Server-Side Request Forgery',
      difficulty: 'hard',
      summary: 'تجبر السيرفر على إرسال طلبات HTTP لجهات داخلية أو خارجية. تستخدم للوصول إلى metadata السحابة (AWS/GCP) أو شبكات داخلية محمية لا تصلها مباشرة.',
      portswigger: 'https://portswigger.net/web-security/ssrf',
      hacktricks: 'https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery',
      owasp: 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery',
      youtube: [{ title: 'SSRF Full Guide', url: 'https://www.youtube.com/results?search_query=SSRF+bug+bounty+2024' }],
    },
    {
      id: 'idor',
      label: 'IDOR / Broken Access Control',
      difficulty: 'medium',
      summary: 'تعديل معرّفات المستخدمين أو المستندات في الـ API للوصول لموارد مستخدمين آخرين. مثال: تغيير /api/user/1001 إلى 1002 ورؤية بيانات شخص آخر.',
      portswigger: 'https://portswigger.net/web-security/access-control/idor',
      hacktricks: 'https://book.hacktricks.xyz/pentesting-web/idor',
      owasp: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References',
      youtube: [{ title: 'IDOR — The Ultimate Guide', url: 'https://www.youtube.com/results?search_query=IDOR+bug+bounty+2024+tutorial' }],
    },
    {
      id: 'csrf',
      label: 'CSRF — Cross-Site Request Forgery',
      difficulty: 'medium',
      summary: 'تخدع المتصفح لإرسال طلب نيابةً عن مستخدم مسجّل دخوله. لا تحتاج المهاجم لمعرفة كلمة المرور — فقط يحتاج أن يفتح المستخدم رابطاً مفخّخاً.',
      portswigger: 'https://portswigger.net/web-security/csrf',
      hacktricks: 'https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery',
      owasp: 'https://owasp.org/www-community/attacks/csrf',
      youtube: [{ title: 'CSRF Practical Guide', url: 'https://www.youtube.com/results?search_query=CSRF+bug+bounty' }],
    },
    {
      id: 'takeover',
      label: 'Subdomain Takeover',
      difficulty: 'hard',
      summary: 'نطاق فرعي يشير بـ CNAME لخدمة خارجية (GitHub Pages، Heroku...) تم إلغاؤها. المهاجم يستطيع استئجار الخدمة وتحميل محتوى تحت نطاق الشركة الموثوق.',
      portswigger: 'https://portswigger.net/web-security/host-header/exploiting',
      hacktricks: 'https://book.hacktricks.xyz/pentesting-web/domain-subdomain-takeover',
      owasp: 'https://owasp.org/www-project-web-security-testing-guide/',
      youtube: [{ title: 'Subdomain Takeover — Full Guide', url: 'https://www.youtube.com/results?search_query=subdomain+takeover+bug+bounty+2024' }],
    },
    {
      id: 'cors',
      label: 'CORS Misconfiguration',
      difficulty: 'easy',
      summary: 'إعداد CORS متساهل يسمح لمواقع عشوائية بقراءة الردود من API الخاص بك. في أسوأ الحالات، أي موقع يستطيع قراءة بيانات جلسة المستخدم.',
      portswigger: 'https://portswigger.net/web-security/cors',
      hacktricks: 'https://book.hacktricks.xyz/pentesting-web/cors-bypass',
      owasp: 'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny',
      youtube: [{ title: 'CORS Bugs — Bug Bounty', url: 'https://www.youtube.com/results?search_query=CORS+misconfiguration+bug+bounty' }],
    },
  ],

  // ── SAST ────────────────────────────────────────────────────────
  sast: [
    {
      id: 'hardcoded_secrets',
      label: 'Hardcoded Secrets & Credentials',
      difficulty: 'easy',
      summary: 'كلمات مرور أو API keys أو tokens مكتوبة مباشرة في الكود المصدري. يكتشفها Gitleaks وSemgrep تلقائياً. خطرة جداً لأن فارق الإنتاج/التطوير يُضيّع حمايتها.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology#finding-api-keys-and-credentials',
      owasp: 'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
      extraResource: { label: 'Gitleaks Docs', url: 'https://github.com/gitleaks/gitleaks' },
      youtube: [{ title: 'Secret Detection with Gitleaks', url: 'https://www.youtube.com/results?search_query=gitleaks+secrets+scanning+tutorial' }],
    },
    {
      id: 'insecure_deserialization',
      label: 'Insecure Deserialization',
      difficulty: 'medium',
      summary: 'تحويل بيانات خارجية لكائنات برمجية بدون التحقق منها. تُمكّن المهاجم من تنفيذ أوامر أو تحقيق استمرارية. شائعة في Python (pickle) وJava وPHP.',
      portswigger: 'https://portswigger.net/web-security/deserialization',
      hacktricks: 'https://book.hacktricks.xyz/pentesting-web/deserialization',
      owasp: 'https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data',
      youtube: [{ title: 'Insecure Deserialization — RCE', url: 'https://www.youtube.com/results?search_query=insecure+deserialization+vulnerability+tutorial' }],
    },
    {
      id: 'command_injection',
      label: 'Command Injection / OS Injection',
      difficulty: 'hard',
      summary: 'تمرير مدخل المستخدم مباشرة لأوامر النظام (subprocess/os.system) بدون تنظيف. المهاجم يُلصق أوامر خاصة به: `; rm -rf /` أو `| curl attacker.com`. تؤدي لـ RCE كامل.',
      portswigger: 'https://portswigger.net/web-security/os-command-injection',
      hacktricks: 'https://book.hacktricks.xyz/pentesting-web/command-injection',
      owasp: 'https://owasp.org/www-community/attacks/Command_Injection',
      youtube: [{ title: 'Command Injection — Exploitation', url: 'https://www.youtube.com/results?search_query=command+injection+exploitation+tutorial' }],
    },
  ],

  // ── Network ─────────────────────────────────────────────────────
  network: [
    {
      id: 'open_ports',
      label: 'منافذ خدمات غير ضرورية مكشوفة',
      difficulty: 'easy',
      summary: 'اكتشاف منافذ مفتوحة تشغّل خدمات غير مقصودة للعامة (Database ports, admin panels, SMB). يكتشفها Nmap تلقائياً ويُحددها الأدمن للإغلاق فوراً.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/generic-methodologies-and-resources/pentesting-network',
      owasp: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Conduct_Search_Engine_Discovery_Reconnaissance_for_Information_Leakage',
      extraResource: { label: 'Nmap Reference Guide', url: 'https://nmap.org/book/man.html' },
      youtube: [{ title: 'Nmap Full Tutorial', url: 'https://www.youtube.com/results?search_query=nmap+port+scanning+tutorial+2024' }],
    },
    {
      id: 'service_version_exposure',
      label: 'كشف إصدارات الخدمات القديمة',
      difficulty: 'medium',
      summary: 'Nmap يكتشف إصدارات الخدمات (SSH 6.x، Apache 2.2...). الإصدارات القديمة تحمل CVEs معروفة وقابلة للاستغلال الآلي. أول ما يفعله المهاجم: nmap -sV للتعرف على الهدف.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/network-services-pentesting',
      owasp: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
      extraResource: { label: 'CVE Database', url: 'https://nvd.nist.gov/' },
      youtube: [{ title: 'Service Enumeration with Nmap', url: 'https://www.youtube.com/results?search_query=nmap+service+version+detection' }],
    },
  ],

  // ── SSL/TLS ──────────────────────────────────────────────────────
  ssl: [
    {
      id: 'weak_ciphers',
      label: 'Cipher Suites ضعيفة',
      difficulty: 'easy',
      summary: 'خوارزميات تشفير قديمة (RC4، 3DES، EXPORT، NULL) تُمكّن فك تشفير الاتصالات. حتى لو الـ TLS حديث، cipher suite ضعيف يجعله قابلاً للكسر بهجمات مثل BEAST.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssl',
      owasp: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography',
      extraResource: { label: 'SSL Labs Analyzer', url: 'https://www.ssllabs.com/ssltest/' },
      youtube: [{ title: 'SSL TLS Testing Guide', url: 'https://www.youtube.com/results?search_query=ssl+tls+security+testing+tutorial' }],
    },
    {
      id: 'deprecated_protocols',
      label: 'بروتوكولات TLS منتهية الصلاحية',
      difficulty: 'easy',
      summary: 'TLS 1.0 وTLS 1.1 وSSL 3.0 تحتوي على ثغرات بنيوية لا يمكن تصحيحها. هجمات مثل POODLE وBEAST تستهدفها مباشرة. المعيار الحالي: TLS 1.2 كحد أدنى، TLS 1.3 مثالي.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssl',
      owasp: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security',
      extraResource: { label: 'Mozilla SSL Config Generator', url: 'https://ssl-config.mozilla.org/' },
      youtube: [{ title: 'TLS Vulnerabilities Explained', url: 'https://www.youtube.com/results?search_query=TLS+vulnerabilities+POODLE+BEAST+explained' }],
    },
    {
      id: 'certificate_issues',
      label: 'مشاكل شهادة SSL',
      difficulty: 'medium',
      summary: 'تشمل: شهادة منتهية، موقَّعة ذاتياً، hostname مختلف، أو مصدر غير موثوق. تُفتح الباب لهجمات Man-in-the-Middle حيث يعترض المهاجم الاتصال دون علم المستخدم.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssl',
      owasp: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels',
      extraResource: { label: "Let's Encrypt Free Certs", url: 'https://letsencrypt.org/' },
      youtube: [{ title: 'SSL Certificate Issues Explained', url: 'https://www.youtube.com/results?search_query=ssl+certificate+security+issues' }],
    },
    {
      id: 'heartbleed_robot',
      label: 'Heartbleed / ROBOT / POODLE',
      difficulty: 'hard',
      summary: 'ثغرات بنيوية في تطبيقات OpenSSL. Heartbleed تُسرِّب الذاكرة الداخلية. ROBOT يسمح بفك تشفير RSA. POODLE يكسر SSL 3.0. كلها CVEs معروفة بدرجة حرجة.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssl#heartbleed',
      owasp: 'https://owasp.org/www-community/vulnerabilities/Heartbleed_Bug',
      extraResource: { label: 'Heartbleed CVE-2014-0160', url: 'https://heartbleed.com/' },
      youtube: [{ title: 'Heartbleed Explained', url: 'https://www.youtube.com/results?search_query=heartbleed+vulnerability+explained' }],
    },
  ],

  // ── Dependencies ─────────────────────────────────────────────────
  deps: [
    {
      id: 'known_cve_deps',
      label: 'مكتبات بـ CVEs معروفة',
      difficulty: 'easy',
      summary: 'استخدام مكتبات بإصدارات قديمة تحتوي ثغرات مُعلنة في قاعدة CVE. يفحصها OSV.dev ويقارن الإصدار الحالي بالإصلاحات المتاحة. أشهر مثال: Log4Shell في Log4j.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology#finding-vulnerabilities-in-dependencies',
      owasp: 'https://owasp.org/www-project-dependency-check/',
      extraResource: { label: 'OSV.dev Database', url: 'https://osv.dev/' },
      youtube: [{ title: 'Dependency Vulnerabilities — Log4Shell', url: 'https://www.youtube.com/results?search_query=dependency+vulnerabilities+log4shell+tutorial' }],
    },
    {
      id: 'transitive_deps',
      label: 'ثغرات في المكتبات الفرعية (Transitive)',
      difficulty: 'medium',
      summary: 'مكتبتك مباشرة آمنة، لكن مكتبة تعتمد عليها تجلب مكتبة أخرى ثالثة بها ثغرة. أصعب اكتشافاً لأن dependency tree قد يمتد لمئات المكتبات في مشاريع كبيرة.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology',
      owasp: 'https://owasp.org/www-community/Component_Analysis',
      extraResource: { label: 'npm audit docs', url: 'https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities' },
      youtube: [{ title: 'Transitive Dependencies Security', url: 'https://www.youtube.com/results?search_query=transitive+dependency+vulnerability+security' }],
    },
  ],

  // ── Server Config ────────────────────────────────────────────────
  server: [
    {
      id: 'missing_headers',
      label: 'رؤوس الأمان مفقودة (Security Headers)',
      difficulty: 'easy',
      summary: 'غياب headers مثل X-Frame-Options وContent-Security-Policy وX-Content-Type-Options يُسهّل هجمات Clickjacking وXSS والـ MIME sniffing. سريعة الإصلاح ولها أثر كبير.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/web-vulns-list#security-headers',
      owasp: 'https://owasp.org/www-project-secure-headers/',
      extraResource: { label: 'SecurityHeaders.com Scanner', url: 'https://securityheaders.com/' },
      youtube: [{ title: 'HTTP Security Headers Guide', url: 'https://www.youtube.com/results?search_query=http+security+headers+guide' }],
    },
    {
      id: 'directory_listing',
      label: 'Directory Listing مفعَّل',
      difficulty: 'easy',
      summary: 'الخادم يعرض قائمة كاملة بالملفات عند فتح مجلد. يكشف ملفات الإعداد، ملفات .env، ملفات النسخ الاحتياطي (.bak, .zip). يحدث عند غياب index.html وعدم تعطيل الخيار.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/web-server-exploits-by-method',
      owasp: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/09-Test_File_Permission',
      extraResource: { label: 'Apache DirectoryIndex docs', url: 'https://httpd.apache.org/docs/2.4/mod/mod_dir.html' },
      youtube: [{ title: 'Directory Listing — Bug Bounty', url: 'https://www.youtube.com/results?search_query=directory+listing+vulnerability+apache+nginx' }],
    },
    {
      id: 'default_credentials',
      label: 'بيانات اعتماد افتراضية',
      difficulty: 'medium',
      summary: 'خدمات مُنشأة بكلمات مرور افتراضية (admin/admin, root/root). شائعة في أجهزة IoT، لوحات إدارة الخوادم، قواعد البيانات الجديدة. هجمات Credential Stuffing تبدأ منها دائماً.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/pentesting-web/default-credentials',
      owasp: 'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
      extraResource: { label: 'Default Credentials DB', url: 'https://github.com/ihebski/DefaultCreds-cheat-sheet' },
      youtube: [{ title: 'Default Credentials Attack', url: 'https://www.youtube.com/results?search_query=default+credentials+penetration+testing' }],
    },
  ],

  // ── Docker ───────────────────────────────────────────────────────
  docker: [
    {
      id: 'exposed_docker_api',
      label: 'Docker API مكشوف على الشبكة',
      difficulty: 'medium',
      summary: 'Docker daemon يستمع على port 2375/2376 بدون مصادقة. أي شخص على الشبكة يستطيع تشغيل أي حاوية، رؤية كل الحاويات، أو تحقيق RCE كامل على السيرفر.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker',
      owasp: 'https://owasp.org/www-project-docker-security/',
      extraResource: { label: 'Docker Security Best Practices', url: 'https://docs.docker.com/engine/security/' },
      youtube: [{ title: 'Docker Security Pentesting', url: 'https://www.youtube.com/results?search_query=docker+security+pentesting+2024' }],
    },
    {
      id: 'privileged_containers',
      label: 'Privileged Containers / Dangerous Mounts',
      difficulty: 'hard',
      summary: 'تشغيل حاويات بـ --privileged أو تثبيت / من السيرفر المضيف. يُتيح الهروب من الحاوية (Container Escape) للوصول لنظام الملفات الكامل للسيرفر المضيف.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation',
      owasp: 'https://owasp.org/www-project-docker-security/',
      extraResource: { label: 'Docker Bench Security', url: 'https://github.com/docker/docker-bench-security' },
      youtube: [{ title: 'Container Escape — Privileged Mode', url: 'https://www.youtube.com/results?search_query=docker+container+escape+privileged' }],
    },
  ],

  // ── DNS/Email ────────────────────────────────────────────────────
  dns: [
    {
      id: 'missing_spf_dkim_dmarc',
      label: 'SPF / DKIM / DMARC مفقودة',
      difficulty: 'easy',
      summary: 'غياب سجلات البريد الأمنية يسمح لأي شخص بإرسال بريد مزيّف منسوب لنطاقك. يُستخدم في هجمات Phishing والتصيد الاحترافي باسم شركتك. سهل الفحص وسهل الإصلاح.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp/dmarc',
      owasp: 'https://owasp.org/www-project-devsecops-guideline/latest/02e-Email-Security',
      extraResource: { label: 'MXToolbox SPF Check', url: 'https://mxtoolbox.com/spf.aspx' },
      youtube: [{ title: 'SPF DKIM DMARC Explained', url: 'https://www.youtube.com/results?search_query=SPF+DKIM+DMARC+email+security+explained' }],
    },
    {
      id: 'dns_zone_transfer',
      label: 'DNS Zone Transfer مسموح',
      difficulty: 'medium',
      summary: 'خادم DNS يرسل قاعدة بيانات كاملة لأي طالب (AXFR). يكشف جميع subdomains بما فيها الداخلية والمستخدمة للتطوير. كنز للمهاجم في مرحلة الاستطلاع.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns#zone-transfer',
      owasp: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server',
      extraResource: { label: 'dig AXFR command', url: 'https://linux.die.net/man/1/dig' },
      youtube: [{ title: 'DNS Zone Transfer Attack', url: 'https://www.youtube.com/results?search_query=DNS+zone+transfer+attack+tutorial' }],
    },
  ],

  // ── WordPress ────────────────────────────────────────────────────
  wordpress: [
    {
      id: 'outdated_plugins',
      label: 'إضافات وقوالب WordPress قديمة',
      difficulty: 'easy',
      summary: 'إضافات WordPress بإصدارات قديمة هي المصدر الأكبر لاختراقات WordPress (90%+). أشهر أداة للكشف: WPScan. يكفي تشغيلها وتحديث ما يظهر كـ "Outdated".',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress',
      owasp: 'https://owasp.org/www-project-web-security-testing-guide/',
      extraResource: { label: 'WPScan Vulnerability DB', url: 'https://wpscan.com/wordpress-security-scanner' },
      youtube: [{ title: 'WordPress Pentesting WPScan', url: 'https://www.youtube.com/results?search_query=wordpress+pentesting+wpscan+tutorial' }],
    },
    {
      id: 'xmlrpc_exposure',
      label: 'XML-RPC مكشوف / مُفعَّل',
      difficulty: 'medium',
      summary: 'xmlrpc.php مُفعَّل بالإعداد الافتراضي ويسمح بهجمات Brute Force الضخمة بأقل طلبات ممكنة (كل طلب يجرب 200+ كلمة مرور). يُستخدم أيضاً في هجمات DDoS كـ Amplification Vector.',
      portswigger: null,
      hacktricks: 'https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress#xmlrpc',
      owasp: 'https://owasp.org/www-project-web-security-testing-guide/',
      extraResource: { label: 'WordPress XML-RPC Security', url: 'https://wordpress.org/documentation/article/xmlrpc-support/' },
      youtube: [{ title: 'XMLRPC WordPress Attack', url: 'https://www.youtube.com/results?search_query=wordpress+xmlrpc+attack+tutorial' }],
    },
  ],
};

// Utility: sort vulns by difficulty within each scanner tab
export function getSortedVulns(scannerId) {
  const vulns = VULN_LIBRARY[scannerId] || [];
  return [...vulns].sort(
    (a, b) => (DIFFICULTY_ORDER[a.difficulty] || 2) - (DIFFICULTY_ORDER[b.difficulty] || 2)
  );
}

// Utility: search across ALL scanner tabs
export function searchAllVulns(query) {
  if (!query || !query.trim()) return [];
  const q = query.trim().toLowerCase();
  const results = [];
  for (const [scannerId, vulns] of Object.entries(VULN_LIBRARY)) {
    for (const v of vulns) {
      if (
        v.label.toLowerCase().includes(q) ||
        v.id.toLowerCase().includes(q) ||
        scannerId.toLowerCase().includes(q) ||
        (v.summary && v.summary.toLowerCase().includes(q))
      ) {
        results.push({ ...v, scannerId });
      }
    }
  }
  return results;
}

export const DIFFICULTY_META = {
  easy:   { label: 'Easy / سهل',     color: 'bg-green-500/15 text-green-400 border-green-500/30',   dot: 'bg-green-400'  },
  medium: { label: 'Medium / متوسط', color: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30', dot: 'bg-yellow-400' },
  hard:   { label: 'Hard / صعب',     color: 'bg-red-500/15 text-red-400 border-red-500/30',          dot: 'bg-red-400'    },
};
