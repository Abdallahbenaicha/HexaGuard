# AUDIT_REPORT.md — HexaGuard / SecuraX Security Platform

**تاريخ التدقيق:** 2026-08-20
**المدقق:** Antigravity Technical Audit (Principal Engineer + Security Auditor + SRE + QA Lead)
**الإصدار الممتحَن:** v2.1.0 (commit HEAD @ finalpfe-master)

---

## 1. الملخص التنفيذي

**HexaGuard** منصة أمنية متكاملة مبنية على Flask (Python 3.11+) في الخلفية وReact 19 في الواجهة.
المشروع **طموح ومنهجي على صعيد الهندسة**، لكنه يحمل **مخاطر حرجة وعالية** تجعله غير جاهز للإنتاج المفتوح دون معالجة فورية.

### أهم 5 مخاطر

| # | الخطر | الخطورة | الدليل |
|---|-------|---------|--------|
| 1 | كلمات مرور افتراضية ثابتة في الكود | **Critical** | `database.py:490-491` |
| 2 | SECRET_KEY ملتزَم في Git | **Critical** | `backend/.env:1` |
| 3 | 6 CVEs في التبعيات (Flask, Werkzeug, Click, idna, python-dotenv) | **High** | pip-audit |
| 4 | تعطيل CSRF تلقائياً لكامل `/api/*` | **High** | `extensions.py:51-58` |
| 5 | تقارير مشاركة عامة بلا انتهاء صلاحية | **High** | `reports.py:964-984` |

### تقييم صحة المشروع

| البُعد | التقييم |
|--------|---------|
| التنظيم والوثائق | 8/10 ✅ |
| الهندسة المعمارية | 7/10 ✅ |
| التشغيل والبنية التحتية | 6/10 ⚠️ |
| جودة الكود والاختبارات | 6/10 ⚠️ |
| الأمان | **4/10** ❌ |
| الأدوات والـ CI/CD | 7/10 ✅ |

---

## 2. نتائج pip-audit الرسمية (6 CVEs في 5 حزم)

> هذه نتائج **فعلية** من تشغيل `python -m pip_audit -r requirements.txt --format json`
> بتاريخ 2026-08-20.

| الحزمة | الإصدار | CVE | الخطورة | الإصدار المُصلَح | الوصف |
|--------|---------|-----|---------|-----------------|-------|
| flask | 3.1.2 | CVE-2026-27205 | Medium | **3.1.3** | Vary: Cookie header لا يُعيَّن في بعض أنماط الوصول للجلسة — Use of Cache Containing Sensitive Information |
| werkzeug | 3.1.5 | CVE-2026-27199 | Medium | **3.1.6** | `safe_join` تسمح بأسماء Windows device (مثل NUL) — قد يُسبب hang لا نهاية له على Windows |
| click | 8.3.1 | CVE-2026-7246 | **High** | **8.3.3** | ثغرة command injection في `click.edit()` |
| idna | 3.11 | CVE-2026-45409 | Medium | **3.15** | DoS عبر إدخال Unicode خاص يستهلك موارد كبيرة في `idna.encode()` |
| python-dotenv | 1.2.1 | CVE-2026-28684 | Medium | **1.2.2** | `set_key/unset_key` تتبع symbolic links — كتابة ملفات عشوائية |

### التوصية الفورية

```
# requirements.txt — حدِّث هذه الأسطر على الفور
flask>=3.1.3
werkzeug>=3.1.6
click>=8.3.3
idna>=3.15
python-dotenv>=1.2.2
```

---

## 3. النتائج التفصيلية لكل بُعد

---

### البُعد 1: التنظيمي (Organizational)

#### ✅ README.md (540 سطر، 25 كيلوبايت)
شامل: الغرض، الميزات، دليل التثبيت، خريطة الطريق.

**ملاحظة (منخفضة):** تناقض في الهوية —  
- `README.md:5` → "HexaGuard"  
- `gunicorn.conf.py:33` → `proc_name = "securax"`

#### ✅ CONTRIBUTING.md / LICENSE / SECURITY.md
جميعها موجودة. SECURITY.md يحتوي على سياسة إفصاح مسؤول.

#### ✅ CODEOWNERS / PR Templates
موجودة في `.github/`.

#### ⚠️ CHANGELOG.md — غير SemVer بالكامل
الخطورة: منخفضة.

#### ❌ ADR (Architecture Decision Records) — مفقود
قرارات مصيرية (SQLite في الإنتاج، تعطيل CSRF) غير موثّقة. الخطورة: متوسطة.

---

### البُعد 2: الهيكلي/المعماري

#### ✅ النمط المعماري — Monolith متعدد الطبقات
`blueprints/` → `database.py` → `scanners/` → `models.py` — منطقي ومتسق.

#### ⚠️ God File: database.py
**المسار:** `backend/database.py`  
**الحجم:** 1489 سطراً، 62 كيلوبايت — Schema + ORM + كل الاستعلامات في ملف واحد.  
الخطورة: متوسطة.

#### ⚠️ تسرّب المسؤوليات في reports.py
**المسار:** `backend/blueprints/reports.py` — 1006 سطر؛ 600+ منها منطق PDF داخل blueprint.  
الخطورة: منخفضة-متوسطة.

#### ⚠️ مخلفات بحثية في الجذر
`results/`, `research_logs/`, `papers/` — ينبغي فرعها أو إضافتها للـ `.gitignore`.

---

### البُعد 3: التشغيلي/العملي

#### 🔴 CRITICAL: .env ملتزَم في Git بمفتاح سري حقيقي

**المسار:** `backend/.env`  
**المحتوى الفعلي المُكتشَف:**
```
SECRET_KEY=hexaguard-audit-secret-key-2024-very-long-random-xK9mP2qR7vN4wL8j
FLASK_ENV=development
FLASK_DEBUG=1
```

**التأثير:** تزوير جلسات Flask بالكامل إذا استُخدم في الإنتاج.  
**التوصية:**
```bash
git filter-repo --path backend/.env --invert-paths
```
ثم توليد `SECRET_KEY` جديد وإضافته كمتغير بيئة في خادم الإنتاج فقط.

#### ⚠️ Docker بلا قيود موارد
لا `--memory` أو `--cpus` — قد يُؤدي إلى DoS. الخطورة: متوسطة-عالية.

#### ✅ Docker لا يعمل كـ root
`Dockerfile:20-21`: `useradd -m -u 1000 user` + `USER user` — ممتاز.

#### ✅ إدارة متغيرات البيئة
`.env.example` موجود ومفصّل. التحقق من `SECRET_KEY` في `app.py:39-43` يُوقف التشغيل إن كان فارغاً.

---

### البُعد 4: جودة الكود/الهندسة

#### 🔴 اختبارات مكسورة — TEST-01 (مخاطرة صامتة)

**الدليل الفعلي:**
- `tests/test_auth.py:49` → `client.post("/api/login", ...)`
- الـ endpoint الحقيقي في `blueprints/auth.py:195` → `@auth_bp.route("/api/auth/login", ...)`

**النتيجة:** اختبارات المصادقة تختبر endpoint غير موجود — تغطية زائفة تعطي ثقة كاذبة!  
الخطورة: متوسطة.

#### ✅ صفر TODO/FIXME/HACK في الكود
نتيجة grep الفعلية: **صفر نتائج** — استثنائي جداً لمشروع بهذا الحجم.

#### ✅ Type Hints موجودة ومتسقة
في `models.py`, `database.py`, `utils.py`.

#### ⚠️ تكرار نمط التحقق من UUID
`_UUID_RE.match(token)` في 5+ مواضع — يمكن استخراجه كـ decorator.

#### ✅ معالجة الأخطاء ممتازة
`middleware.py:87-92` يُعالج الأخطاء بدون كشف stack traces.

---

### البُعد 5: الأمني (Security)

#### 🔴 CRITICAL: كلمات مرور افتراضية ثابتة في الكود

**المسار:** `backend/database.py:490-491`

```python
admin_pw   = os.environ.get("SECURAX_ADMIN_PASSWORD",   "").strip() or "Admin@2024!"
analyst_pw = os.environ.get("SECURAX_ANALYST_PASSWORD", "").strip() or "Analyst@2024!"
```

هذه الكلمات موجودة أيضاً في `tests/test_auth.py:46` و`tests/test_api.py:43` — **مكشوفة علناً لأي شخص يقرأ المستودع**.  
الخطورة: **Critical**.

#### 🔴 HIGH: تعطيل CSRF تلقائياً لكامل `/api/*`

**المسار:** `backend/extensions.py:51-58`

```python
def _auto_exempt_api_from_csrf():
    if request.path.startswith("/api/") and request.endpoint:
        view = current_app.view_functions.get(request.endpoint)
        if view:
            csrf._exempt_views.add(f"{view.__module__}.{view.__name__}")
```

الحماية البديلة (CORS + Session Auth) صحيحة للـ SPA نظرياً، لكن:
1. CORS لا يحمي من هجمات same-origin
2. المتصفحات القديمة قد لا ترسل preflight لبعض الطلبات  

الخطورة: **High**.

#### 🔴 HIGH: تقارير مشاركة عامة بلا انتهاء صلاحية

**المسار:** `backend/blueprints/reports.py:964-984`

```python
@reports_bp.route("/public/report/<share_token>")
def public_report(share_token):
    "Public read-only report view - no login required."
    data = get_report_by_share_token(share_token)
```

- لا `expires_at` في الـ schema
- لا rate limiting
- لا logging للوصول  

الخطورة: **High** — تقارير أمنية حساسة مكشوفة للأبد.

#### 🟡 MEDIUM: نمط SQL ديناميكي في `update_user()`

**المسار:** `backend/database.py:665`

```python
_exec(f"UPDATE users SET {', '.join(fields)} WHERE id=?", tuple(values))
```

الحقول مُبنية داخلياً الآن، لكن النمط يُنشئ سطح هجوم مستقبلياً.  
الخطورة: متوسطة.

#### ✅ حماية SSRF — ممتاز
`utils.py` يحجب: 127.x, 10.x, 172.16.x, 192.168.x, 169.254.x, fc00::/7, metadata endpoints.  
نوعان: `check_ssrf()` و `check_ssrf_network()` — مصمَّم بدقة.

#### ✅ الحماية من Timing Attacks — ممتاز
`models.py:127-134`: `dummy_hash` يمنع تحديد وجود المستخدمين.

#### ✅ قفل الحساب — جيد
5 محاولات فاشلة → قفل 15 دقيقة.

#### ✅ TOTP (2FA) — صحيح
`pyotp` مع `valid_window=1`.

#### ✅ رؤوس HTTP الأمنية — ممتاز
`middleware.py`: HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, CSP مع nonce.

#### ✅ لا `shell=True` في الكود الإنتاجي
grep: **صفر نتائج** — 11 استخدام لـ `subprocess.run` كلها بقوائم args آمنة.

---

### البُعد 6: المقارنة بأفضل الممارسات

#### ✅ Flask + Blueprints — مناسب للحجم
FastAPI أفضل لعمليات غير متزامنة، لكن Flask يعمل بشكل كافٍ.

#### ⚠️ SQLite في الإنتاج
`gunicorn.conf.py:13` — `workers = 1` لتجنب تعارض الكتابة.  
لا horizontal scaling. الخطورة: متوسطة للبيئة المفتوحة.

#### ✅ React 19 + Vite — أحدث Stack لعام 2025-2026.

#### ❌ غياب OpenAPI/Swagger
عشرات endpoints بلا توثيق API آلي. الخطورة: متوسطة.

---

### البُعد 7: الأدوات (Tooling)

#### ✅ CI/CD Pipeline — جيد
`.github/workflows/ci.yml`: ruff + pytest + coverage + bandit + Docker build.  
Matrix: Python 3.11 و3.12.

#### ⚠️ CI بلا فحص CVE
لا `pip-audit` في الـ pipeline — CVE-2026-27205 في Flask مرّت دون إشعار.  
الخطورة: متوسطة.

#### ✅ Ruff كـ Linter
`pyproject.toml` يُهيّئه بشكل صحيح.

#### ⚠️ لا pre-commit hooks
لا `.pre-commit-config.yaml` — يمكن تجاوز الـ linting. الخطورة: منخفضة.

#### ⚠️ frontend-ci.yml بسيط جداً
لا `npm audit` للثغرات الأمنية في الواجهة.

---

### البُعد 8: Catch-all

#### ⚠️ src.rar في Git
`frontend/src.rar` (184 كيلوبايت) — يُضخّم المستودع ويُعقّد سجل Git.

#### ⚠️ Timeout 600s مفتوح
`gunicorn.conf.py:18` — 10 دقائق قد يُتيح هجوم exhaustion.

#### ✅ دعم i18n — ممتاز
الكود مُصمَّم للدعم الثنائي (عربي/إنجليزي) — منهجي.

---

## 4. مصفوفة المخاطر الكاملة

| المعرف | المسار | الوصف | الخطورة | الإصلاح |
|--------|--------|-------|---------|---------|
| CVE-01 | requirements.txt | Flask 3.1.2: CVE-2026-27205 | High | ترقية إلى 3.1.3 |
| CVE-02 | requirements.txt | Werkzeug 3.1.5: CVE-2026-27199 | Medium | ترقية إلى 3.1.6 |
| CVE-03 | requirements.txt | Click 8.3.1: CVE-2026-7246 (Command Injection) | **High** | ترقية إلى 8.3.3 |
| CVE-04 | requirements.txt | idna 3.11: CVE-2026-45409 (DoS) | Medium | ترقية إلى 3.15 |
| CVE-05 | requirements.txt | python-dotenv 1.2.1: CVE-2026-28684 | Medium | ترقية إلى 1.2.2 |
| SEC-01 | backend/.env:1 | SECRET_KEY ملتزَم في Git | **Critical** | git filter-repo + استبدال |
| SEC-02 | database.py:490-491 | كلمات مرور ثابتة في الكود | **Critical** | إلزام env vars في الإنتاج |
| SEC-03 | extensions.py:51-58 | إعفاء CSRF تلقائي لكل /api/* | **High** | X-CSRF-Token header |
| SEC-04 | reports.py:964-984 | تقارير عامة بلا انتهاء صلاحية | **High** | expires_at + rate limit |
| ARCH-01 | database.py:665 | SQL ديناميكي في update_user | Medium | whitelist الحقول |
| OPS-01 | gunicorn.conf.py:18 | Timeout 600s | Medium | تقليص + per-route limits |
| TEST-01 | tests/test_auth.py:46-50 | اختبارات بعناوين خاطئة | Medium | إصلاح URLs |

---

## 5. التوصيات مرتّبة حسب الأولوية

### 🚨 خلال 24 ساعة (حرج)

**1. ترقية التبعيات:**
```
flask>=3.1.3
werkzeug>=3.1.6
click>=8.3.3
idna>=3.15
python-dotenv>=1.2.2
```

**2. إزالة .env من Git:**
```bash
git filter-repo --path backend/.env --invert-paths
# ثم: توليد SECRET_KEY جديد، وإضافته كمتغير بيئة في خادم الإنتاج
```

**3. حماية _bootstrap_admin():**
```python
# database.py — أول سطرين في _bootstrap_admin()
if os.environ.get("FLASK_ENV") == "production":
    if not os.environ.get("SECURAX_ADMIN_PASSWORD"):
        raise RuntimeError("SECURAX_ADMIN_PASSWORD must be set in production!")
```

### ⚡ خلال أسبوع (عالي)

**4. إصلاح عناوين الاختبار:**
```python
# tests/test_auth.py:49 و tests/test_api.py:43
# قبل:  "/api/login"
# بعد:  "/api/auth/login"
```

**5. إضافة expires_at لـ share tokens:**
```sql
ALTER TABLE scan_reports ADD COLUMN share_expires_at TEXT;
```
وإضافة `@limiter.limit("20/minute")` على `/public/report/<share_token>`.

**6. إضافة pip-audit إلى CI:**
```yaml
# .github/workflows/ci.yml
- name: Check dependency CVEs
  run: pip-audit -r requirements.txt --fail-on-vuln
```

### 📋 خلال 4-8 أسابيع (استراتيجي)

7. استبدال الإعفاء التلقائي لـ CSRF بـ `X-CSRF-Token` header.

8. إضافة whitelist للحقول في `update_user()`:
```python
_ALLOWED_FIELDS = {"role", "permissions", "is_active", "password_hash",
                   "failed_attempts", "locked_until", "locked_target", "allowed_scanners"}
```

9. إضافة `pre-commit hooks` (`.pre-commit-config.yaml`).

10. توثيق OpenAPI بـ `flasgger`.

11. تفكيك `database.py` → `db/users.py`, `db/reports.py`, `db/jobs.py`.

12. كتابة ADR لقرارات: SQLite، CSRF exemption، single worker.

---

## 6. الملاحق

### A. الملفات المُراجَعة

| الملف | الحجم | الحالة |
|-------|-------|--------|
| `backend/app.py` | 4.7 كب | ✅ كامل |
| `backend/database.py` | 62 كب | ✅ كامل (1489 سطر) |
| `backend/models.py` | 5.8 كب | ✅ كامل |
| `backend/middleware.py` | 3.6 كب | ✅ كامل |
| `backend/extensions.py` | 2.4 كب | ✅ كامل |
| `backend/utils.py` | 14 كب | ✅ كامل |
| `backend/forms.py` | 6 كب | ✅ كامل |
| `backend/gunicorn.conf.py` | 1.2 كب | ✅ كامل |
| `backend/blueprints/auth.py` | 16.6 كب | ✅ كامل |
| `backend/blueprints/scans.py` | 44 كب | ⚠️ جزئي (500/1029 سطر) |
| `backend/blueprints/reports.py` | 47 كب | ⚠️ جزئي (endpoints أمنية كاملة) |
| `backend/blueprints/admin.py` | 16 كب | ✅ كامل |
| `backend/scanners/*` | ~180 كب | ⚠️ جزئي + grep |
| `backend/tests/` (11 ملف) | ~60 كب | ✅ 3 ملفات رئيسية كاملة |
| `backend/.env` | 133 بايت | ✅ كامل |
| `backend/Dockerfile` | 1.5 كب | ✅ كامل |
| `backend/requirements.txt` | 3 كب | ✅ كامل |
| `backend/pyproject.toml` | 2.7 كب | ✅ كامل |
| `.github/workflows/ci.yml` | 3.5 كب | ✅ كامل |
| `frontend/package.json` | 895 بايت | ✅ كامل |

### B. الأدوات المستخدمة فعلياً

| الأداة | الأمر | النتيجة |
|--------|-------|---------|
| pip show | `pip show flask werkzeug ... bcrypt pyotp` | إصدارات محقَّقة |
| **pip-audit** | `python -m pip_audit -r requirements.txt` | **6 CVEs في 5 حزم** |
| grep shell=True | كامل الكود | ✅ صفر نتائج في الكود الإنتاجي |
| grep TODO/FIXME/HACK | كامل الكود | ✅ صفر نتائج |
| grep eval/exec/os.system | كامل الكود | ✅ موجود فقط في بيانات توعية SAST |
| grep subprocess.run | كامل الكود | ✅ 11 استخدام — كلها args lists آمنة |

### C. القيود المُصرَّح بها

1. **Python 3.13 محلياً:** تعذّر تشغيل pytest (المطلوب 3.11-3.12).
2. **لا وصول لبيئة إنتاج حية:** كل الفحوصات على الكود المحلي.
3. **لا وصول لـ GitHub API:** لم نتحقق من إحصائيات PR/Issues الفعلية.
4. **الواجهة الأمامية React:** فُحصت بنية المشروع وpackage.json — لم تُفحص كل مكوّنات JSX.

---

*تم إعداد هذا التقرير بناءً على تدقيق ميداني فعلي للكود بتاريخ 2026-08-20.*
*يُحظر نشر هذا التقرير خارج الفريق قبل معالجة المخاطر: SEC-01، SEC-02، CVE-01، CVE-03.*
