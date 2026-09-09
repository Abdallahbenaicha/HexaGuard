# سجل متابعة التدقيق والتطوير — HexaGuard / SecuraX

| المعرف | البند | الأولوية | الحالة | الاختبار المقابل / التحقق | ملاحظات وقرارات التصميم |
|---|---|---|---|---|---|
| **BASELINE** | توثيق الأساس واختبارات pytest الـ 186 القائمة | P0 | منجز ومختبر ✅ | `pytest -q` (186 passed) | خط الأساس سليم 100% بدون أي أخطاء مسبقة |
| **H-01** | فرض Target-Lock وحماية SSRF على مسار `/start-scan` وتوحيد الحراسة | P0 | منجز ومختبر ✅ | `test_audit_h01_start_scan.py` (4/4 passed) | توحيد حراسة SSRF و target_lock مركزياً في `before_request` وداخل `start_scan` |
| **H-02** | مراجعة وإلغاء إعفاءات CSRF غير المبررة وتأمين مسارات API | P0 | منجز ومختبر ✅ | `test_audit_h02_csrf.py` (3/3 passed) | إزالة كافة إعفاءات `@csrf.exempt` من مسارات الفحص وتفعيل توزيع `X-CSRFToken` و `csrftoken` cookie في `middleware.py` |
| **H-03** | تقييد التسجيل الذاتي المفتوح وحد المعدل ومنع منح `run_scan` فوراً | P0 | منجز ومختبر ✅ | `test_audit_h03_registration.py` (2/2 passed) | تعيين دور `viewer` افتراضياً بدون `run_scan` مع حد 3 تسجيلات/ساعة لكل IP ويتطلب ترقية المشرف |
| **H-04** | ضبط تزامن الخيوط وسقف الوظائف وحد المعدل المجمع لمنع استنزاف الموارد | P0 | منجز ومختبر ✅ | `test_audit_h04_concurrency.py` (2/2 passed) | إضافة `BoundedSemaphore` وقفل سقف المهام النشطة وطابور `queued` فعلي مع حد معدل مجمع 15 طلب/دقيقة للمستخدم |
| **F-01** | مشغل خلفي حقيقي للفحص المجدول (Background Worker / Scheduler) | P1 | منجز ومختبر ✅ | `test_audit_f01_scheduler.py` (3/3 passed) | خيط خلفي يفحص `next_run_at <= now` وينفذ المهمة عبر `job_manager` باحترام سقف H-04 وتحديث تاريخ التشغيل القادم |
| **F-02** | ربط صفحة الأسعار `PricingPage.jsx` وتدفق ترقية الاشتراك | P1 | منجز ومختبر ✅ | `test_audit_f02_pricing.py` (4/4 passed) | مسار `/pricing` نشط مع تدفق ترقية الخطة وتحديث الحصة الشهرية ودعم خيارات الاشتراك |
| **F-03** | حصة استهلاك الذكاء الاصطناعي وخيار عدم مشاركة البيانات (Opt-Out) | P1 | منجز ومختبر ✅ | `test_audit_f03_ai_quota.py` (4/4 passed) | حقل `ai_data_sharing_opt_out` وحظر Gemini السحابي عند تفعيله مع فرض سقف الحصة الشهرية وإرجاع 429 عند النفاد |
| **F-04** | فصل واجهة فحص الخادم الخارجي `ServerExtScanPage.jsx` عن White-box | P1 | منجز ومختبر ✅ | UI / Route verification | إنشاء `ServerExtScanPage.jsx` وربط مسار `/scan/server-ext` بفاحص الخادم الخارجي المستقل |
| **F-05** | نقطة فحص جاهزية أدوات DAST وتحذير المستخدم عند غياب أي أداة | P1 | منجز ومختبر ✅ | `test_audit_f05_scanner_status.py` (2/2 passed) | مسار `GET /api/scanners/status` وفحص الأدوات مع شريط تحذيري تفاعلي في واجهة DAST |
| **T-01** | قيد بيئة محلي صارم (`DEPLOYMENT_MODE=local`) لصفحة Bounty Radar | P0/P1 | منجز ومختبر ✅ | `test_audit_t01_bounty_gate.py` (3/3 passed) | حراسة مركزية `@bounty_bp.before_request` و decorator يرجع 404 لمنع الوصول سحابياً |
| **T-02** | تدقيق وإتمام دليل الصيد اليدوي وإضافة مسار مستقل والتغطية الكاملة | P1 | منجز ومختبر ✅ | UI / Link verification | تغطية CIDR و IP_ADDRESS و API وإضافة صفحة `/hunt/manual` مع فحص SSRF وربط بالموسوعة |
| **T-03** | موسوعة الثغرات التعليمية الشاملة للفاحصات الـ 11 والبحث والفلترة | P1 | منجز ومختبر ✅ | Vite build (2238 modules passed) | صفحة تعليمية مصنفة لـ 11 فاحصاً (بما فيها web و server_ext) مع بحث وفلترة وروابط معتمدة ومسار /learn |
| **Q-01** | تقسيم الملفات المتضخمة (`database.py`, `web_scanner.py`) | P2 | منجز ومختبر ✅ | regression suite (39/39 passed) | تقسيم modular إلى حزمتي backend/db و backend/scanners/web مع واجهة facade توافقية 100% |
| **Q-02** | اختبارات واجهة أمامية للمكونات الحرجة (Login, ScanForm, ReportView) | P2 | منجز ومختبر ✅ | npm test (10/10 passed) | اختبارات شاملة لنموذج الدخول وحماية CSRF، وفحص الأهداف وتطابق SSRF، وعرض النتائج وتدفق E2E الكامل |
| **Q-03** | دعم فحص CVE لصور Docker | P2 | منجز ومختبر ✅ | `test_audit_q03_docker_cve.py` (6/6 passed) | استدعاء فاحص صور Docker يدعم Trivy و Grype وقاعدة استخباراتية مدمجة للحزم الأساسية |
| **Q-04** | تفعيل نقاط EPSS في محرك تقييم المخاطر المباشر | P2 | منجز ومختبر ✅ | `test_audit_q04_risk_epss.py` (4/4 passed) | دمج احتمالية EPSS من FIRST.org مع كاش ذكي ورفع المعدل الزمني للثغرات المهددة بالاستغلال الفعلي |

---

## جدول تدقيق وإلغاء إعفاءات CSRF (معيار القبول H-02)

| المسار (Route) | الطريقة (Method) | المصادقة المستخدمة | حالة الإعفاء السابقة | القرار المتخذ | الدليل والتعليل الأمني |
|---|---|---|---|---|---|
| `/scan_url` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | يستدعى من واجهة React عبر الجلسة. أُلغي الإعفاء ويتم إرسال `X-CSRFToken` تلقائياً عبر Axios. |
| `/scan_network` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | مسار فحص شبكي حي. أُلغي الإعفاء لمنع إطلاق فحوصات غير مصرح بها عبر مواقع خبيثة. |
| `/analyze_code` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | رفع ملفات وتحليل كود SAST. حماية الإدخال بـ CSRF token إلزامي. |
| `/fix_config` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | مسار معالجة إعدادات الخادم. محمي بـ CSRF token. |
| `/scan_server` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | فحص خادم خارجي. أُلغي الإعفاء وتطبيقه على جلسة المستخدم. |
| `/scan_dast` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | تشغيل أدوات DAST الثقيلة. أُلغي الإعفاء لحماية موارد الخادم من طلبات CSRF. |
| `/scan_ssl` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | فحص شهادات وتشفير. محمي بـ CSRF token. |
| `/scan_dependencies` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | فحص تبعيات البرمجيات. محمي بـ CSRF token. |
| `/api/scan/async/web` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | إنشاء وظيفة فحص ويب غير متزامن. محمي بـ CSRF token. |
| `/api/scan/async/network` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | إنشاء وظيفة فحص شبكي غير متزامن. محمي بـ CSRF token. |
| `/api/scan/async/dast` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | إنشاء وظيفة DAST غير متزامنة. محمي بـ CSRF token. |
| `/api/scan/async/ssl` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | إنشاء وظيفة SSL غير متزامنة. محمي بـ CSRF token. |
| `/api/scan/async/server` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | إنشاء وظيفة فحص خادم غير متزامنة. محمي بـ CSRF token. |
| `/api/scan/job/<id>/dismiss` | DELETE | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | حذف حالة الوظيفة. محمي بـ CSRF لمنع مسح تقارير ومهام المستخدم خلسة. |
| `/api/scan/jobs/errors` | DELETE | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | حذف سجلات الأخطاء. محمي بـ CSRF. |
| `/scan_docker` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | فحص حاويات دوكر (ملف `extra_scans.py`). أُلغي الإعفاء. |
| `/scan_dns` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | فحص DNS وسجلات البريد (ملف `extra_scans.py`). أُلغي الإعفاء. |
| `/scan_wordpress` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | فحص مواقع ووردبريس (ملف `extra_scans.py`). أُلغي الإعفاء. |
| `/api/bounty/verify-policy` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | مسار التحقق من سياسة الهدف (ملف `bounty.py`). أُلغي الإعفاء. |
| `/api/bounty/recon/subdomains` | POST | Cookie Session (React) | `@csrf.exempt` | **أُزيل الإعفاء 🔒** | استطلاع النطاقات الفرعية (ملف `bounty.py`). أُلغي الإعفاء. |
| `/health` | GET | Public Probe | `@csrf.exempt` | **أُزيل (زائد)** | مسار GET آمن بطبيعته ولا يخضع لـ CSRF في معايير HTTP/WTF. |
| `/api/version` | GET | Public Probe | `@csrf.exempt` | **أُزيل (زائد)** | مسار GET لا يُعدل بيانات ولا يخضع لـ CSRF. |
| `/api/scan/jobs` | GET | Cookie Session (React) | `@csrf.exempt` | **أُزيل (زائد)** | مسار GET استعلامي. |
| `/api/scan/job/<id>` | GET | Cookie Session (React) | `@csrf.exempt` | **أُزيل (زائد)** | مسار GET استعلامي. |

