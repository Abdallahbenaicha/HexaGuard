# دليل الإجراءات البشرية الإلزامية (Manual Security Interventions)
## HexaGuard / SecuraX Platform

> [!CAUTION]
> هذا المستند يحتوي على إجراءات أمنية حرجة تتطلب صلاحيات وصول خارجية (External Credentials) ومفاتيح وصول بيئية لا يمتلك وكيل الذكاء الاصطناعي صلاحية تنفيذها آلياً. يجب على مهندس الأمن أو مالك المستودع تنفيذ هذه الخطوات يدوياً بشكل فوري ومستعجل.

---

### 1. إبطال وتدوير توكن GitHub المسرب (GitHub PAT Revocation)
- **السبب:** وُجدت توكنات وصول شخصية أو مفاتيح نشر في سجل الالتزامات (Git Commit History) أو أرشيف التكوين القديم.
- **الخطوات الإلزامية:**
  1. انتقل إلى حساب GitHub: `Settings` → `Developer Settings` → `Personal Access Tokens` (Tokens Classic أو Fine-grained).
  2. ابحث عن أي توكنات نشطة تم استخدامها في مشاريع HexaGuard السابقة وقم بعمل **Revoke** فوراً.
  3. أنشئ توكن جديد بصلاحيات محددة فقط (Least Privilege) وعين تاريخ انتهاء صلاحية لا يتجاوز 30-90 يوماً.
  4. حدّث إعدادات CI/CD في مستودع GitHub (`Settings` → `Secrets and variables` → `Actions`).

---

### 2. تدوير مفتاح التشفير العام للإنتاج (`SECRET_KEY` Rotation)
- **السبب:** مفتاح `SECRET_KEY` هو أساس توقيع جلسات المستخدمين (Session Cookies)، وتشفير رموز CSRF، والتواقيع المشفرة.
- **الخطوات الإلزامية:**
  1. قم بتوليد مفتاح عشوائي مشفر جديد (طول 64 بايت على الأقل) عبر الأمر:
     ```bash
     python -c "import secrets; print(secrets.token_urlsafe(64))"
     ```
  2. حدّث متغير البيئة `SECRET_KEY` في منصات الاستضافة الحية:
     - **Render.com:** لوحة التحكم → البيئة (Environment) → `SECRET_KEY`.
     - **HuggingFace Spaces:** الإعدادات (Settings) → `Variables and secrets`.
     - **ملف `.env` للإنتاج:** استبدل القيمة القديمة بالمفتاح الجديد.
  3. أعد تشغيل خادم الإنتاج لتفعيل المفتاح (سيؤدي ذلك إلى تسجيل خروج كافة الجلسات النشطة لضمان تطهيرها).

---

### 3. تدوير وتغيير كلمات مرور الحسابات الحية (Live Credential Rotation)
- **السبب:** وجود حسابات سابقة أو تجريبية قد تحمل كلمات مرور سهلة التخمين، ووجوب تطبيق سياسة التعقيد الصارمة (12 خانة كحد أدنى، عدم مطابقة أكثر 10,000 كلمة شائعة، أحرف كبيرة وصغيرة وأرقام ورموز خاصة).
- **الخطوات الإلزامية:**
  1. تشغيل سكربت فرض تدوير كلمات المرور على قاعدة الإنتاج الحية:
     ```bash
     python backend/scripts/enforce_password_rotation.py
     ```
     هذا السكربت يقوم بضبط `must_change_password = 1` وإبطال الهاشات الضعيفة، مع مسح الحسابات التجريبية الوهمية، دون طباعة أو تسريب أي أسرار في السجلات.
  2. ضبط متغيرات البيئة لكلمات مرور حسابات النظام في الإنتاج:
     ```env
     SECURAX_ADMIN_PASSWORD=YourStrongAdminPassword2026!
     SECURAX_ANALYST_PASSWORD=YourStrongAnalystPassword2026!
     PAYMENT_GATEWAY_SECRET=whsec_your_actual_live_gateway_secret
     ```
  3. تجربة المستخدم عند أول تسجيل دخول:
     عند محاولة تسجيل الدخول بحساب ملزم بتغيير كلمة المرور، تُرجع الخوادم استجابة HTTP 403 مصحوبة بالرمز `must_change_password`. توفر الواجهة رابطاً مباشراً وتوجيهاً آمناً إلى صفحة الملف الشخصي `/profile` لتمكين المستخدم من تعيين كلمة المرور الجديدة بسلاسة تامة.
  4. تفعيل المصادقة الثنائية (TOTP / MFA) لجميع الحسابات الإدارية والمحللين.

---

### 4. إعادة تشغيل خادم Flask المحلي والإنتاجي (Service Restart & Cache Flush)
- **السبب:** يقوم محرك متابعة الدكتوراه (`backend/blueprints/phd.py`) بتحميل البيانات ومطابقة الفهارس في الذاكرة المؤقتة (`_CACHE`) عند أول تشغيل. أي تحديث للجداول، أو ترحيل للبيانات، أو تحديث للملفات الشاملة يتطلب إعادة تشغيل لعملية Flask لتفريغ الكاش وتحميل الهيكلة الجديدة.
- **خطوات إعادة التشغيل على نظام Windows (محلياً):**
  1. التحقق من العملية النشطة على المنفذ 5000:
     ```powershell
     Get-NetTCPConnection -LocalPort 5000 -ErrorAction SilentlyContinue | Select-Object LocalAddress, LocalPort, OwningProcess
     ```
  2. إنهاء العملية السابقة (مثال PID 15340):
     ```powershell
     Stop-Process -Id <PID> -Force
     ```
  3. إعادة تشغيل الخادم من مجلد `backend`:
     ```powershell
     cd backend
     .\venv\Scripts\python.exe app.py
     ```
- **على خوادم الإنتاج (Render / Docker / Gunicorn):**
  إعادة تشغيل الحاوية أو الخدمة (Manual Deploy / Restart Service) لتطبيق متغيرات البيئة الجديدة وتحديث ذاكرة الكاش.

---

### 5. تطهير السجل التاريخي للمستودع (Git History Purge)
- **السبب:** حذف الملفات الحاوية على أسرار في commit لاحق لا يحذفها من تاريخ Git (`.git/objects`).
- **الخطوات الإلزامية:**
  1. قم بأخذ نسخة احتياطية محلية كاملة من المستودع خارج المجلد (`git clone --mirror`).
  2. استخدم أداة `git-filter-repo` (تُنفذ يدوياً بواسطة مالك المستودع حصراً، ولا تُنفذ آلياً):
     ```bash
     pip install git-filter-repo
     git filter-repo --invert-paths --path backend/backups --path .env --path backend/.env
     ```
  3. بعد التحقق من سلامة الفروع والاختبارات، قم بالدفع الإجباري الآمن إلى المستودع البعيد:
     ```bash
     git push origin --force --all
     git push origin --force --tags
     ```
  4. اطلب من جميع المطورين والمساهمين عمل `git clone` جديد بدلاً من الدمج لضمان عدم إعادة إرسال الكائنات القديمة.

---

### 6. التحقق من تطابق سياسات CORS ونطاقات الإنتاج
- تأكد من إضافة النطاق الرسمي للواجهة الأمامية في `ALLOWED_ORIGINS` داخل بيئة الإنتاج:
  ```env
  ALLOWED_ORIGINS=https://your-domain.com,https://hexaguard.vercel.app
  ```
- لا تستخدم أي تعبيرات نمطية أو wildcard تسمح بنطاقات فرعية غير موثوقة.

