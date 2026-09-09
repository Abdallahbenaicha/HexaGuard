# سجل متابعة حلقة التعلّم والربح — HexaGuard (الجلسة الثانية)

| الجزء | العنوان | الأولوية | الحالة الدقيقة | تفاصيل آخر عمل / نقطة التوقف | الاختبار المقابل |
|---|---|---|---|---|---|
| **Part 0** | سجل المهارة (Skill Ledger) والتاكسونومي الموحدة | P0 (إلزامي) | منجز ومختبر بالكامل ✅ | بناء `backend/vuln_taxonomy.py` وجدول `skill_ledger` ومسار `/api/skill` وصفحة `/skills` مع حظر الترقية الآلية المباشرة | `test_skill_ledger.py` (6/6 passed) |
| **Part 1** | التوأم العدائي (Adversarial Twin) والـ Sandbox المحلي | P1 | منجز ومختبر بالكامل ✅ | بناء `backend/blueprints/sandbox.py` مزدوج الحراسة (`@local_only_required` + `@login_required`)، قائمة بيضاء ثابتة للصور، مؤقت إتلاف ذاتي، سقف حاويتين، والتحقق من الـ flag لترقية `practiced_verified` ومكون `SandboxLauncher.jsx` | `test_sandbox.py` (5/5 passed) |
| **Part 2** | الدروس اليدوية المعلقة (Shadow Manual Pass) والتطبيع | P0 (إلزامي) | منجز ومختبر بالكامل ✅ | تطبيع `check` لجميع الفاحصات الـ11، توليد `shadow_manual_tasks` عند كل `store_report()`، مسارات `/api/reports/<token>/shadow` و`/api/dashboard/shadow-backlog` ومكون `ShadowManualPanel.jsx` | `test_shadow_manual.py` (3/3 passed) |
| **Part 3** | الدوجو اليومي (Micro-Dojo) | P1 | منجز ومختبر بالكامل ✅ | بناء جدول `dojo_completions` ومسار `backend/blueprints/dojo.py` باختيار يومي حتمي وفق النواقص والمهام المعلقة، وحساب streak صادق، وصفحة `/dojo` وربطها في الشريط الجانبي | `test_dojo.py` (5/5 passed) |
| **Part 4** | ترتيب "تعلّم+اربح" في Bounty Radar | P1 | منجز ومختبر بالكامل ✅ | بناء خوارزمية `_calculate_learn_earn_score` المعتمدة على سياسة الأتمتة وجدوى المكافأة وفجوات سجل المهارات للمستخدم، وفرز `sort=learn_earn`، وشارة وخيار الفرز في الواجهة | `test_bounty_learn_earn.py` (5/5 passed) |
| **Part 5** | وضع الموجّه السقراطي في ARIA (Mentor Mode) | P2 | منجز ومختبر بالكامل ✅ | بناء الحث السقراطي `_SOCRATIC_MENTOR_SYSTEM_PROMPT` والبديل الأوفلاين السقراطي، ودعم عبارة التجاوز (`reveal solution` / `اكشف الحل`)، وحفظ الحصة وخيار F-03، وزر تفعيل وربط مباشر من الدوجو والـ Shadow Panel | `test_aria_mentor.py` (5/5 passed) |
| **Part 6** | الحلقة البحثية (Human Disagreement Dataset) | P3 (اختياري) | منجز ومختبر بالكامل ✅ | بناء مجلد `datasets/e3_human_disagreement/` مع `metadata.json` و`ground_truth.json`، ووحدة `backend/research_loop.py` ومسارات تسجيل التناقضات والإنذارات الكاذبة مع زر ونافذة مخصصة في الـ Shadow Panel | `test_research_loop.py` (4/4 passed) |

---
### ملاحظات الاعتماديات والتحقق المسبق (Section 0):
- **H-01 (SSRF + Target Lock):** منجز ومختبر بنجاح (`test_audit_h01_start_scan.py`).
- **T-01 (Local Only Gate):** منجز ومختبر بنجاح (`test_audit_t01_bounty_gate.py`). `@local_only_required` متاح لإعادة الاستخدام من `backend.blueprints.bounty`.
- **T-03 (Encyclopedia):** منجز ومختبر بنجاح في الواجهة (`/learn`).
