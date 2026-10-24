# RUN_LOCAL.md — تشغيل HexaGuard/SecuraX محلياً

## المتطلبات
- Python 3.11+ (مثبّت: 3.13.1)
- Node.js 18+ (مثبّت: 22.14.0)
- npm 8+ (مثبّت: 10.9.2)

## التشغيل (أمر واحد)
```powershell
# Windows
.\run_local.ps1

# Linux / macOS
bash run_local.sh
```

## عناوين الدخول
| الخدمة | الرابط |
|---|---|
| الواجهة | http://localhost:3000 |
| Backend API | http://localhost:5000 |
| فحص الصحة | http://localhost:5000/health |

## الإيقاف
أغلق نافذتَي PowerShell اللتين فُتحتا، أو `Ctrl+C` في كل منهما.

## أعلام التطوير المحلي والمختبرات (Local Lab Flags)
> [!IMPORTANT]
> هذان العلمان مخصصان **لبيئة التطوير والمختبرات المحلية فقط (Local Lab Testing)** وهما **معطلان افتراضياً** لحماية المنظومة من هجمات SSRF.
> يقبل كل منهما القيم التالية للتفعيل: `true` أو `1` أو `yes` (غير حساس لحالة الأحرف).

- `ALLOW_LOCAL_LAB_TARGETS=false` (افتراضي: معطل):
  عند تفعيله (`1` / `true` / `yes`)، يسمح لحارس SSRF بتمرير عناوين Loopback المحلية (`127.0.0.0/8` و `::1`) لفحص تطبيقات المختبر المحلي مثل DVWA و JuiceShop. تبقى شبكات العناوين الخاصة (RFC-1918) ونقاط سحابية البيانات الوصفية (Metadata) محجوبة تماماً ولا يمكن تجاوزها.
- `DAST_ALLOW_INTERNAL=0` (افتراضي: معطل):
  عند تفعيله (`1` / `true` / `yes`)، يسمح لفاحص DAST باختبار الأهداف المحلية والمخبرية المعزولة.
- `ENABLE_LIVE_BOUNTY_SCANNING=false` — **لا تُغيّره أثناء التدقيق**

## أشهر 5 مشاكل وحلولها
1. **"SECRET_KEY is not set"** → احذف `backend/.env` وأعد التشغيل لتوليد مفتاح تلقائي
2. **منفذ 5000 مشغول** → `netstat -ano | findstr :5000` → أوقف العملية
3. **منفذ 3000 مشغول** → `netstat -ano | findstr :3000` → أوقف العملية
4. **"ModuleNotFoundError: openpyxl"** → `cd backend && .\venv\Scripts\Activate.ps1 && pip install openpyxl`
5. **الواجهة تُظهر "Network Error"** → تأكد أن الباكند يعمل على http://localhost:5000/health
