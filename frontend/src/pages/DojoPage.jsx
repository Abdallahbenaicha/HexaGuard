import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Zap, Flame, BookOpen, Compass, Box, CheckCircle2,
  AlertCircle, HelpCircle, ArrowRight, Award, Clock,
  Sparkles, Check, ChevronRight, RefreshCw, Bot
} from 'lucide-react';
import axios from 'axios';
import SandboxLauncher from '../components/SandboxLauncher';

export default function DojoPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedChoice, setSelectedChoice] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [answerResult, setAnswerResult] = useState(null);
  const [showSandbox, setShowSandbox] = useState(false);

  const fetchTodayDojo = async () => {
    try {
      setLoading(true);
      setError('');
      const res = await axios.get('/api/dojo/today');
      if (res.data?.ok) {
        setData(res.data);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'فشل في تحميل تحدي الدوجو اليومي.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTodayDojo();
  }, []);

  const handleAnswerSubmit = async () => {
    if (selectedChoice === null || !data) return;
    setSubmitting(true);
    try {
      const res = await axios.post('/api/dojo/answer', {
        vuln_type: data.vuln_type,
        question_id: data.question.id,
        choice_index: selectedChoice,
        date: data.date,
      });
      if (res.data?.ok) {
        setAnswerResult(res.data);
        if (res.data.correct) {
          setData((prev) => ({
            ...prev,
            today_completed: true,
            streak_days: res.data.streak_days,
          }));
        }
      }
    } catch (err) {
      alert(err.response?.data?.error || 'فشل في إرسال الإجابة.');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center text-slate-400 gap-3">
        <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <p className="font-mono text-sm">جاري تحضير جلسة الـ 15 دقيقة اليومية...</p>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="min-h-screen bg-slate-950 p-8 flex items-center justify-center">
        <div className="max-w-md w-full p-6 bg-slate-900 border border-slate-800 rounded-2xl text-center space-y-4">
          <AlertCircle className="w-10 h-10 text-rose-400 mx-auto" />
          <h2 className="text-lg font-bold text-white">خطأ في تحميل الدوجو</h2>
          <p className="text-slate-400 text-sm">{error || 'حدث خطأ غير متوقع.'}</p>
          <button
            onClick={fetchTodayDojo}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-xs font-semibold"
          >
            إعادة المحاولة
          </button>
        </div>
      </div>
    );
  }

  const meta = data.meta || {};
  const isShadowSource = data.source === 'shadow_backlog';

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 lg:p-10 font-inter">
      <div className="max-w-4xl mx-auto space-y-8">
        {/* Top Header: Title & Streak */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-6 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-gradient-to-br from-cyan-500/20 to-blue-500/20 rounded-2xl border border-cyan-500/30 text-cyan-400">
              <Zap className="w-7 h-7" />
            </div>
            <div>
              <h1 className="text-2xl lg:text-3xl font-orbitron font-bold text-white tracking-wide flex items-center gap-3">
                <span>الدوجو اليومي — Micro-Dojo</span>
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-500/30 font-mono">
                  15 Min / Day
                </span>
              </h1>
              <p className="text-slate-400 text-sm mt-1">
                جلسة تدريب سريعة وموجهة تجمع بين النظرية، والممارسة اليدوية، واختبار المعرفة.
              </p>
            </div>
          </div>

          {/* Honest Streak Badge */}
          <div className="flex items-center gap-3 self-start sm:self-auto">
            <div
              className={`flex items-center gap-2.5 px-4 py-2 rounded-2xl border transition-all ${
                data.streak_days > 0
                  ? 'bg-amber-500/10 border-amber-500/30 text-amber-300 shadow-lg shadow-amber-950/20'
                  : 'bg-slate-900 border-slate-800 text-slate-400'
              }`}
            >
              <Flame
                className={`w-5 h-5 ${
                  data.streak_days > 0 ? 'text-amber-400 fill-amber-400 animate-pulse' : 'text-slate-500'
                }`}
              />
              <div>
                <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                  سلسلة الأيام الصادقة
                </div>
                <div className="font-orbitron font-bold text-lg leading-none mt-0.5">
                  {data.streak_days} {data.streak_days === 1 ? 'يوم' : 'أيام'}
                </div>
              </div>
            </div>

            <Link
              to="/skills"
              className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white transition-colors"
              title="سجل المهارة"
            >
              <Award className="w-5 h-5" />
            </Link>
          </div>
        </div>

        {/* Challenge Origin Ribbon */}
        <div className="flex items-center justify-between px-5 py-3 rounded-2xl bg-slate-900/90 border border-slate-800 text-xs">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <span className="text-slate-400">تحدي تاريخ:</span>
            <span className="font-mono font-semibold text-slate-200">{data.date}</span>
          </div>
          <div>
            {isShadowSource ? (
              <span className="px-3 py-1 rounded-full bg-amber-500/15 text-amber-300 border border-amber-500/30 font-medium">
                🎯 مستخرج من درس فحص آلي معلّق (Shadow Pass)
              </span>
            ) : (
              <span className="px-3 py-1 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 font-medium">
                💡 سد فجوة تعلم من سجل المهارة (Skill Gap)
              </span>
            )}
          </div>
        </div>

        {/* ── Main Focused 15-Minute Card ────────────────────────────────────── */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-3xl p-6 lg:p-8 space-y-8 shadow-2xl relative overflow-hidden">
          {/* Header of the Card */}
          <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4 pb-6 border-b border-slate-800/80">
            <div>
              <span className="font-mono text-xs uppercase px-2.5 py-1 rounded-lg bg-slate-800 text-cyan-400 border border-slate-700">
                {meta.scanner || 'web'} Engine
              </span>
              <h2 className="text-2xl font-bold text-white mt-2">{meta.name_ar}</h2>
              <p className="text-xs font-mono text-cyan-400/90 mt-0.5">{meta.name_en}</p>
            </div>

            {data.today_completed ? (
              <div className="px-4 py-2 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4" />
                <span>تم إنجاز تحدي اليوم بنجاح ✅</span>
              </div>
            ) : (
              <div className="px-4 py-2 rounded-2xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-semibold flex items-center gap-2">
                <Clock className="w-4 h-4" />
                <span>بانتظار الإنجاز اليوم</span>
              </div>
            )}
          </div>

          {/* Section 1: Theory (5 Minutes) */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
              <BookOpen className="w-4 h-4" />
              <span>1. الجانب النظري والفهم العميق (5 دقائق)</span>
            </h3>
            <p className="text-slate-300 text-sm leading-relaxed">
              {meta.description_ar || meta.description_en}
            </p>
            {meta.remediation_ar && (
              <div className="p-4 rounded-xl bg-slate-850/80 border border-slate-750 text-xs text-slate-300 space-y-1">
                <strong className="text-cyan-400">الإصلاح الجذري الموصى به:</strong>
                <p className="mt-0.5">{meta.remediation_ar}</p>
              </div>
            )}
            <div className="flex items-center gap-4 pt-1 text-xs">
              <Link
                to={data.encyclopedia_link}
                className="text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1 transition-colors"
              >
                <span>مراجعة المرجع الكامل في الموسوعة</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>

          {/* Section 2: Hands-on Practice (5 Minutes) */}
          <div className="space-y-3 pt-4 border-t border-slate-800/80">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-blue-400 flex items-center gap-2">
                <Compass className="w-4 h-4" />
                <span>2. الممارسة اليدوية والتطبيق العملي (5 دقائق)</span>
              </h3>
              {data.sandbox_supported && (
                <button
                  onClick={() => setShowSandbox(!showSandbox)}
                  className="text-xs text-blue-400 hover:text-blue-300 font-semibold flex items-center gap-1.5 px-3 py-1 rounded-xl bg-blue-500/10 border border-blue-500/30 transition-all"
                >
                  <Box className="w-3.5 h-3.5" />
                  <span>{showSandbox ? 'إخفاء بيئة التدريب' : 'تشغيل الساندبوكس للتدريب'}</span>
                </button>
              )}
            </div>

            <p className="text-slate-400 text-xs leading-relaxed">
              افتح دليل منهجية الصيد اليدوي لاختبار هذه الثغرة خطوة بخطوة، أو استعن بـ ARIA في وضع التوجيه السقراطي لمناقشة أفكار الاستغلال.
            </p>

            <div className="flex flex-wrap items-center gap-3 text-xs pt-1">
              <Link
                to={`/hunt/manual?vuln_type=${data.vuln_type}`}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-750 text-slate-200 hover:text-white border border-slate-700 font-semibold flex items-center gap-2 transition-all"
              >
                <Compass className="w-4 h-4 text-cyan-400" />
                <span>دليل الصيد اليدوي المقابل</span>
              </Link>

              <Link
                to={`/chat?context=dojo&vuln_type=${data.vuln_type}&mentor=true`}
                className="px-4 py-2 rounded-xl bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 border border-purple-500/30 font-semibold flex items-center gap-2 transition-all"
              >
                <Bot className="w-4 h-4 text-purple-400" />
                <span>استشارة الموجّه السقراطي ARIA</span>
              </Link>
            </div>

            {/* Sandbox Drawer if toggled */}
            {showSandbox && (
              <div className="mt-4 pt-4 border-t border-slate-800 animate-fadeIn">
                <SandboxLauncher targetVulnType={data.vuln_type} onVerified={fetchTodayDojo} />
              </div>
            )}
          </div>

          {/* Section 3: Daily Quiz (5 Minutes) */}
          <div className="space-y-4 pt-4 border-t border-slate-800/80">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-amber-400 flex items-center gap-2">
              <HelpCircle className="w-4 h-4" />
              <span>3. سؤال التثبيت والتحدي اليومي (5 دقائق)</span>
            </h3>

            <div className="p-5 rounded-2xl bg-slate-850/90 border border-slate-750 space-y-4">
              <p className="text-white text-sm font-semibold leading-relaxed">
                {data.question.question_ar || data.question.question_en}
              </p>

              <div className="space-y-2">
                {(data.question.choices_ar || data.question.choices_en || []).map((choice, idx) => {
                  const isSelected = selectedChoice === idx;
                  return (
                    <button
                      key={idx}
                      onClick={() => setSelectedChoice(idx)}
                      disabled={submitting}
                      className={`w-full text-right p-3.5 rounded-xl border text-xs font-medium transition-all flex items-center justify-between ${
                        isSelected
                          ? 'bg-cyan-600/20 text-cyan-300 border-cyan-500 shadow-sm'
                          : 'bg-slate-900/60 text-slate-300 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <span>{choice}</span>
                      <div
                        className={`w-4 h-4 rounded-full border flex items-center justify-center ${
                          isSelected
                            ? 'border-cyan-400 bg-cyan-400 text-slate-950'
                            : 'border-slate-600'
                        }`}
                      >
                        {isSelected && <Check className="w-3 h-3 stroke-[3]" />}
                      </div>
                    </button>
                  );
                })}
              </div>

              {answerResult && (
                <div
                  className={`p-4 rounded-xl border text-xs leading-relaxed animate-fadeIn ${
                    answerResult.correct
                      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                      : 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                  }`}
                >
                  <div className="flex items-center gap-2 font-bold mb-1">
                    {answerResult.correct ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <AlertCircle className="w-4 h-4 text-rose-400" />
                    )}
                    <span>{answerResult.message}</span>
                  </div>
                  <p className="text-slate-300 mt-1">{answerResult.explanation}</p>
                </div>
              )}

              <div className="flex justify-end pt-2">
                <button
                  onClick={handleAnswerSubmit}
                  disabled={selectedChoice === null || submitting}
                  className="px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-xl text-xs font-semibold flex items-center gap-2 shadow-lg shadow-cyan-900/30 transition-all"
                >
                  {submitting ? 'جاري التحقق...' : 'تأكيد الإجابة وتوثيق اليوم'}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
