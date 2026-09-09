import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Compass, BookOpen, CheckCircle2, Award, Clock,
  ArrowRight, ExternalLink, Bot, Check, HelpCircle,
  ShieldAlert, Sparkles, ChevronRight, AlertCircle, FileText,
} from 'lucide-react';
import axios from 'axios';

export default function ShadowManualPanel({ reportToken, target, scanType }) {
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [completingType, setCompletingType] = useState(null);
  const [notes, setNotes] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [successMsg, setSuccessMsg] = useState('');

  // Research Loop E3 state
  const [disagreementTask, setDisagreementTask] = useState(null);
  const [disagreementType, setDisagreementType] = useState('false_positive');
  const [rationale, setRationale] = useState('');
  const [evidence, setEvidence] = useState('');

  const fetchTasks = async () => {
    if (!reportToken) return;
    try {
      setLoading(true);
      const res = await axios.get(`/api/reports/${reportToken}/shadow`);
      if (res.data?.ok) {
        setTasks(res.data.tasks || []);
      }
    } catch (err) {
      console.warn('Could not load shadow tasks:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTasks();
  }, [reportToken]);

  const handleComplete = async (vulnType) => {
    try {
      setSubmitting(true);
      const res = await axios.post(`/api/reports/${reportToken}/shadow/${vulnType}/complete`, {
        notes,
      });
      if (res.data?.ok) {
        setSuccessMsg(`تم توثيق إنجاز ممارسة ${vulnType} وتحديث سجل المهارة!`);
        setCompletingType(null);
        setNotes('');
        fetchTasks();
        setTimeout(() => setSuccessMsg(''), 4000);
      }
    } catch (err) {
      alert(err.response?.data?.error || 'فشل في إكمال المهمة اليدوية.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDisagreementSubmit = async () => {
    if (!disagreementTask || !rationale.trim()) return;
    try {
      setSubmitting(true);
      const res = await axios.post(`/api/reports/${reportToken}/disagreement`, {
        vuln_type: disagreementTask.vuln_type,
        disagreement_type: disagreementType,
        scanner_id: disagreementTask.meta?.scanner || scanType || 'manual',
        rationale: rationale.trim(),
        evidence: evidence.trim(),
      });
      if (res.data?.ok) {
        setSuccessMsg(`تم تسجيل التناقض (${disagreementType}) بنجاح وإدراجه في بيانات البحث E3!`);
        setDisagreementTask(null);
        setRationale('');
        setEvidence('');
        setTimeout(() => setSuccessMsg(''), 5000);
      }
    } catch (err) {
      alert(err.response?.data?.error || 'فشل في تسجيل التناقض.');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="p-5 bg-slate-900/60 border border-slate-800 rounded-2xl animate-pulse flex items-center gap-3 text-slate-400 text-xs">
        <div className="w-4 h-4 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <span>جاري تجهيز مسارات الممارسة اليدوية (Shadow Manual Pass)...</span>
      </div>
    );
  }

  if (!tasks || tasks.length === 0) {
    return null;
  }

  const pendingCount = tasks.filter((t) => t.status === 'pending').length;

  return (
    <div className="bg-gradient-to-br from-slate-900/90 via-slate-900/70 to-cyan-950/20 border border-cyan-500/20 rounded-2xl p-6 space-y-6 shadow-xl relative overflow-hidden">
      {/* Top ambient glow */}
      <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

      {/* Panel Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 rounded-xl">
            <Compass className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="font-orbitron font-bold text-white text-lg tracking-wide">
                الدروس اليدوية المعلقة — Shadow Manual Pass
              </h2>
              {pendingCount > 0 ? (
                <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  {pendingCount} معلقة للتطبيق
                </span>
              ) : (
                <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
                  <Check className="w-3 h-3" /> تم الإنجاز
                </span>
              )}
            </div>
            <p className="text-slate-400 text-xs mt-1">
              حوّل نتائج هذا الفحص الآلي إلى مهارة شخصية: اتبع دليل الصيد اليدوي لكل ثغرة مكتشفة ووثق تجربتك في سجل المهارة.
            </p>
          </div>
        </div>

        <Link
          to="/skills"
          className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-cyan-950/30 border border-cyan-500/30 hover:border-cyan-500/50 transition-all self-start sm:self-auto"
        >
          <Award className="w-3.5 h-3.5" />
          <span>فتح سجل المهارة</span>
          <ChevronRight className="w-3 h-3" />
        </Link>
      </div>

      {/* Success Notification */}
      {successMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-300 text-xs flex items-center gap-2 animate-fadeIn">
          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Tasks List */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {tasks.map((task) => {
          const isDone = task.status !== 'pending';
          const meta = task.meta || {};

          return (
            <div
              key={task.vuln_type}
              className={`p-4 rounded-xl border transition-all flex flex-col justify-between gap-4 ${
                isDone
                  ? 'bg-slate-900/50 border-emerald-500/30 shadow-sm'
                  : 'bg-slate-900/80 border-slate-750 hover:border-cyan-500/40 hover:shadow-md'
              }`}
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    {meta.scanner || scanType || 'web'}
                  </span>

                  {isDone ? (
                    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                      <CheckCircle2 className="w-3 h-3" />
                      <span>مُمارَس ذاتياً</span>
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">
                      <Clock className="w-3 h-3" />
                      <span>معلّق للتطبيق اليدوي</span>
                    </span>
                  )}
                </div>

                <div>
                  <h4 className="text-white font-semibold text-sm">{meta.name_ar || task.vuln_type}</h4>
                  <p className="text-xs font-mono text-cyan-400/90">{meta.name_en || task.vuln_type}</p>
                </div>
              </div>

              {/* Action Links & Buttons */}
              <div className="pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-3 text-xs">
                  <Link
                    to={`/hunt/manual?target=${encodeURIComponent(target || '')}&vuln_type=${encodeURIComponent(task.vuln_type)}`}
                    className="text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 transition-colors"
                  >
                    <Compass className="w-3.5 h-3.5" />
                    <span>دليل الصيد اليدوي</span>
                  </Link>
                  <Link
                    to={`/learn/vulnerabilities?search=${encodeURIComponent(task.vuln_type)}`}
                    className="text-slate-400 hover:text-slate-200 font-medium flex items-center gap-1 transition-colors"
                  >
                    <BookOpen className="w-3.5 h-3.5" />
                    <span>الموسوعة</span>
                  </Link>
                  <Link
                    to={`/chat?context=shadow&vuln_type=${encodeURIComponent(task.vuln_type)}&target=${encodeURIComponent(target || '')}&mentor=true`}
                    className="text-purple-400 hover:text-purple-300 font-medium flex items-center gap-1 transition-colors"
                    title="استشارة الموجّه السقراطي ARIA"
                  >
                    <Bot className="w-3.5 h-3.5" />
                    <span>الموجّه السقراطي</span>
                  </Link>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      setDisagreementTask(task);
                      setRationale('');
                      setEvidence('');
                    }}
                    className="px-2.5 py-1 bg-slate-800 hover:bg-slate-750 text-slate-300 hover:text-white rounded-lg text-xs font-semibold flex items-center gap-1 border border-slate-700 transition-all"
                    title="تسجيل تناقض بحثي / إنذار كاذب في بيانات E3"
                  >
                    <AlertCircle className="w-3 h-3 text-amber-400" />
                    <span>إنذار كاذب</span>
                  </button>

                  {!isDone && (
                    <button
                      onClick={() => {
                        setCompletingType(task.vuln_type);
                        setNotes('');
                      }}
                      className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1 transition-all shadow-sm"
                    >
                      <Check className="w-3 h-3" />
                      <span>أنجزتها يدوياً</span>
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Completion Modal */}
      {completingType && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl animate-fadeIn">
            <h3 className="font-semibold text-white text-base">توثيق التجربة اليدوية</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              تسجيل هذه الثغرة كـ <span className="text-amber-400 font-semibold">مُعلَن ذاتياً (Self-Reported)</span> داخل سجل المهارة الخاص بك.
            </p>

            <div className="space-y-2">
              <label className="text-xs text-slate-300 font-medium">ملاحظات التحقق / خلاصة التجربة (اختياري):</label>
              <textarea
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
                rows={3}
                placeholder="صف مسار استكشافك اليدوي أو حمولة الاختبار المستخدمة..."
                className="w-full bg-slate-850 border border-slate-700 rounded-xl p-3 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setCompletingType(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-750 text-slate-300 rounded-xl text-xs font-semibold"
              >
                إلغاء
              </button>
              <button
                onClick={() => handleComplete(completingType)}
                disabled={submitting}
                className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5"
              >
                {submitting ? 'جاري الحفظ...' : 'تأكيد الإنجاز'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Disagreement / False Positive Modal (Part 6 Research Loop) */}
      {disagreementTask && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-4 shadow-2xl animate-fadeIn">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-amber-500/15 border border-amber-500/30 flex items-center justify-center">
                <AlertCircle className="w-4 h-4 text-amber-400" />
              </div>
              <div>
                <h3 className="font-semibold text-white text-sm">تسجيل تناقض بحثي (E3 Research)</h3>
                <p className="text-[11px] text-slate-400 font-mono">{disagreementTask.vuln_type}</p>
              </div>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              مشاركتك تُسجّل كبيانات أرضية (Ground Truth) مستقلة في حزمة البحث <span className="text-cyan-400 font-mono">datasets/e3_human_disagreement/</span> لتقييم دقة الفواحص الآلية.
            </p>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-slate-300 font-medium block mb-1">نوع التناقض:</label>
                <select
                  value={disagreementType}
                  onChange={(e) => setDisagreementType(e.target.value)}
                  className="w-full bg-slate-850 border border-slate-700 rounded-xl p-2.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="false_positive">إنذار كاذب (False Positive) — التطبيق محمي أو الثغرة غير قابلة للاستغلال</option>
                  <option value="missed_by_scanner">مفقودة من الفاحص (Missed by Scanner) — وُجدت يدوياً فقط</option>
                  <option value="severity_dispute">خلاف في درجة الخطورة (Severity Dispute)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-300 font-medium block mb-1">السبب والتبرير الفني (إلزامي):</label>
                <textarea
                  value={rationale}
                  onChange={(e) => setRationale(e.target.value)}
                  rows={3}
                  placeholder="اشرح لماذا يعتبر الفحص غير دقيق (مثل: تم التحقق من وجود تعقيم برمجي، أو عدم إمكانية الوصول للسياق)..."
                  className="w-full bg-slate-850 border border-slate-700 rounded-xl p-3 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-300 font-medium block mb-1">الدليل أو الاستجابة الملاحظة (اختياري):</label>
                <input
                  type="text"
                  value={evidence}
                  onChange={(e) => setEvidence(e.target.value)}
                  placeholder="مثال: HTTP 403 Forbidden مع ترميز &lt;script&gt;"
                  className="w-full bg-slate-850 border border-slate-700 rounded-xl p-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setDisagreementTask(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-750 text-slate-300 rounded-xl text-xs font-semibold"
              >
                إلغاء
              </button>
              <button
                onClick={handleDisagreementSubmit}
                disabled={submitting || !rationale.trim()}
                className="px-4 py-2 bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5"
              >
                {submitting ? 'جاري التسجيل...' : 'تسجيل في حزمة البحث E3'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
