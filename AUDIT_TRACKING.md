# سجل متابعة التدقيق والتطوير — HexaGuard / SecuraX

| المعرف | البند | الأولوية | الحالة | الاختبار المقابل / التحقق | ملاحظات وقرارات التصميم |
|---|---|---|---|---|---|
| **BASELINE** | توثيق الأساس واختبارات pytest الـ 186 القائمة | P0 | منجز ومختبر ✅ | `pytest -q` (186 passed) | خط الأساس سليم 100% بدون أي أخطاء مسبقة |
| **H-01** | فرض Target-Lock وحماية SSRF على مسار `/start-scan` وتوحيد الحراسة | P0 | منجز ومختبر ✅ | `test_audit_h01_start_scan.py` (4/4 passed) | توحيد حراسة SSRF و target_lock مركزياً في `before_request` وداخل `start_scan` |
| **H-02** | مراجعة وإلغاء إعفاءات CSRF غير المبررة وتأمين مسارات API | P0 | لم يبدأ ⏳ | `test_csrf_protection_on_scans` | مسارات Session-based ملزمة بـ CSRF؛ مسارات Bearer token محمية بفحص Token صريح |
| **H-03** | تقييد التسجيل الذاتي المفتوح وحد المعدل ومنع منح `run_scan` فوراً | P0 | لم يبدأ ⏳ | `test_self_registration_restrictions` | دور `viewer` افتراضي بدون صلاحية فحص لحين موافقة المشرف + حد 3 تسجيلات/ساعة لكل IP |
| **H-04** | ضبط تزامن الخيوط وسقف الوظائف وحد المعدل المجمع لمنع استنزاف الموارد | P0 | لم يبدأ ⏳ | `test_global_scan_concurrency_cap` | إضافة `BoundedSemaphore` وقفل سقف المهام النشطة وطابور `queued` فعلي |
| **F-01** | مشغل خلفي حقيقي للفحص المجدول (Background Worker / Scheduler) | P1 | لم يبدأ ⏳ | `test_scheduled_scan_worker_execution` | خيط خلفي يفحص `next_run_at <= now` وينفذ المهمة عبر `job_manager` باحترام سقف H-04 |
| **F-02** | ربط صفحة الأسعار `PricingPage.jsx` وتدفق ترقية الاشتراك | P1 | لم يبدأ ⏳ | `test_subscription_upgrade_flow` | مسار `/pricing` نشط مع تدفق ترقية الخطة وتحديث الحصة الشهرية |
| **F-03** | حصة استهلاك الذكاء الاصطناعي وخيار عدم مشاركة البيانات (Opt-Out) | P1 | لم يبدأ ⏳ | `test_ai_quota_and_opt_out` | حقل `ai_data_sharing_opt_out` وحصة شهرية تفرض التراجع إلى وضع محلي/أوفلاين |
| **F-04** | فصل واجهة فحص الخادم الخارجي `ServerExtScanPage.jsx` عن White-box | P1 | لم يبدأ ⏳ | UI / Route verification | صفحة مستقلة لـ Black-box server headers / methods |
| **F-05** | نقطة فحص جاهزية أدوات DAST وتحذير المستخدم عند غياب أي أداة | P1 | لم يبدأ ⏳ | `test_scanner_tools_status_endpoint` | `GET /api/scanners/status` وفحص `shutil.which` لكل أداة (ZAP, Nikto, Nuclei) |
| **T-01** | قيد بيئة محلي صارم (`DEPLOYMENT_MODE=local`) لصفحة Bounty Radar | P0/P1 | لم يبدأ ⏳ | `test_bounty_local_only_gate` | decorator `@local_only_required` يرجع 404 في حال عدم ضبط المتغير على `local` |
| **T-02** | تدقيق وإتمام دليل الصيد اليدوي وإضافة مسار مستقل والتغطية الكاملة | P1 | لم يبدأ ⏳ | UI / Link verification | تغطية كافة أنواع الأصول (CIDR, IP, API...) وربط تفاعلي مع الموسوعة ومسار يدوي |
| **T-03** | موسوعة الثغرات التعليمية الشاملة للفاحصات الـ 11 والبحث والفلترة | P1 | لم يبدأ ⏳ | `EncyclopediaPage` Component tests | صفحة تعليمية بحتة بدون إدخال أهداف، مصنفة حسب 11 فاحصاً مع أمثلة تعليمية وروابط معتمدة |
| **Q-01** | تقسيم الملفات المتضخمة (`database.py`, `web_scanner.py`) | P2 | لم يبدأ ⏳ | regression suite | تقسيم تركيبي modular يحافظ على التوافق التام 100% |
| **Q-02** | اختبارات واجهة أمامية للمكونات الحرجة (Login, ScanForm) | P2 | لم يبدأ ⏳ | Vitest / Jest tests | اختبارات تأكيد الواجهة وسلوك الاستمارات |
| **Q-03** | دعم فحص CVE لصور Docker | P2 | لم يبدأ ⏳ | `test_docker_cve_scan` | استدعاء فاحص حاويات وتحليل الحزم |
| **Q-04** | تفعيل نقاط EPSS في محرك تقييم المخاطر المباشر | P2 | لم يبدأ ⏳ | `test_risk_engine_epss` | دمج EPSS score في حساب خطورة الثغرة أثناء وقت التشغيل |
