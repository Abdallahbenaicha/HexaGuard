import React, { useState, useEffect, useMemo } from 'react';
import { Link } from 'react-router-dom';
import {
  Award, Shield, CheckCircle2, AlertCircle, BookOpen,
  Search, Filter, ExternalLink, Zap, Target, ArrowUpRight,
  TrendingUp, Sparkles, Flame, Check, HelpCircle, Box
} from 'lucide-react';
import axios from 'axios';
import SandboxLauncher from '../components/SandboxLauncher';

const STATUS_BADGES = {
  practiced_verified: {
    labelAr: 'مُتحقَّق آلياً (Verified)',
    labelEn: 'Verified by Sandbox / Lab',
    badgeClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    icon: CheckCircle2,
    dotClass: 'bg-emerald-400',
  },
  practiced_self_reported: {
    labelAr: 'مُعلَن ذاتياً (Self-Reported)',
    labelEn: 'Self-Reported Hunt / Lab',
    badgeClass: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    icon: Award,
    dotClass: 'bg-amber-400',
  },
  theory_only: {
    labelAr: 'نظري فقط (Theory Only)',
    labelEn: 'Gap: Not Practiced Yet',
    badgeClass: 'bg-slate-700/30 text-slate-400 border-slate-700/50',
    icon: HelpCircle,
    dotClass: 'bg-slate-500',
  },
};

const DIFFICULTY_MAP = {
  easy: { label: 'سهل', color: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10' },
  medium: { label: 'متوسط', color: 'text-amber-400 border-amber-500/30 bg-amber-500/10' },
  hard: { label: 'متقدم', color: 'text-rose-400 border-rose-500/30 bg-rose-500/10' },
};

export default function SkillLedgerPage() {
  const [ledger, setLedger] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [scannerFilter, setScannerFilter] = useState('all');
  const [reportingItem, setReportingItem] = useState(null);
  const [reportNotes, setReportNotes] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [toastMessage, setToastMessage] = useState('');
  const [showSandbox, setShowSandbox] = useState(false);

  const fetchLedger = async () => {
    try {
      setLoading(true);
      const res = await axios.get('/api/skill/ledger');
      if (res.data && res.data.ok) {
        setLedger(res.data.ledger || []);
        setSummary(res.data.summary || null);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'فشل في تحميل سجل المهارة.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLedger();
  }, []);

  const handleSelfReport = async (e) => {
    e.preventDefault();
    if (!reportingItem) return;
    setSubmitting(true);
    try {
      const res = await axios.post('/api/skill/self-report', {
        vuln_type: reportingItem.vuln_type,
        notes: reportNotes,
      });
      if (res.data?.ok) {
        setToastMessage(`تم تسجيل ممارستك الذاتية لـ ${reportingItem.name_en} بنجاح!`);
        setReportingItem(null);
        setReportNotes('');
        fetchLedger();
        setTimeout(() => setToastMessage(''), 4000);
      }
    } catch (err) {
      alert(err.response?.data?.error || 'فشل في تسجيل الإقرار الذاتي.');
    } finally {
      setSubmitting(false);
    }
  };

  const filteredItems = useMemo(() => {
    return ledger.filter((item) => {
      const matchSearch =
        search === '' ||
        item.vuln_type.toLowerCase().includes(search.toLowerCase()) ||
        (item.name_en && item.name_en.toLowerCase().includes(search.toLowerCase())) ||
        (item.name_ar && item.name_ar.includes(search));

      const matchStatus =
        statusFilter === 'all' || item.status === statusFilter;

      const matchScanner =
        scannerFilter === 'all' || item.scanner === scannerFilter;

      return matchSearch && matchStatus && matchScanner;
    });
  }, [ledger, search, statusFilter, scannerFilter]);

  const uniqueScanners = useMemo(() => {
    const s = new Set(ledger.map((i) => i.scanner).filter(Boolean));
    return Array.from(s);
  }, [ledger]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 lg:p-10 font-inter">
      {/* Header Banner */}
      <div className="max-w-7xl mx-auto space-y-8">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-6 pb-6 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-3">
              <span className="p-2.5 bg-gradient-to-br from-cyan-500/20 to-blue-500/20 rounded-xl border border-cyan-500/30 text-cyan-400">
                <Award className="w-7 h-7" />
              </span>
              <div>
                <h1 className="text-2xl lg:text-3xl font-orbitron font-bold text-white tracking-wide">
                  سجل المهارة المعتمد — Skill Ledger
                </h1>
                <p className="text-slate-400 text-sm mt-1">
                  سجل حقيقي موثوق يوثق كفاءتك اليدوية والتطبيقية في فئات الثغرات، مع تفريق صارم بين الإعلان الذاتي والتحقق الآلي.
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowSandbox(!showSandbox)}
              className={`px-4 py-2.5 rounded-xl text-sm font-semibold flex items-center gap-2 border transition-all ${
                showSandbox
                  ? 'bg-blue-600 text-white border-blue-500 shadow-lg shadow-blue-900/30'
                  : 'bg-slate-850 hover:bg-slate-800 text-blue-400 border-blue-500/30'
              }`}
            >
              <Box className="w-4 h-4" />
              <span>{showSandbox ? 'إخفاء الساندبوكس' : 'بيئة التدريب (Sandbox)'}</span>
            </button>
            <Link
              to="/dojo"
              className="px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-xl text-sm font-semibold flex items-center gap-2 shadow-lg shadow-cyan-900/20 transition-all"
            >
              <Zap className="w-4 h-4" />
              <span>الدوجو اليومي</span>
            </Link>
            <Link
              to="/learn/vulnerabilities"
              className="px-4 py-2.5 bg-slate-800 hover:bg-slate-750 border border-slate-700 text-slate-200 rounded-xl text-sm font-semibold flex items-center gap-2 transition-all"
            >
              <BookOpen className="w-4 h-4" />
              <span>الموسوعة التعليمية</span>
            </Link>
          </div>
        </div>

        {/* Toast Alert */}
        {toastMessage && (
          <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 rounded-xl flex items-center gap-3 animate-fadeIn">
            <Check className="w-5 h-5 text-emerald-400" />
            <span className="text-sm font-medium">{toastMessage}</span>
          </div>
        )}

        {/* Stats Metrics Cards */}
        {summary && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800/80">
              <div className="flex items-center justify-between">
                <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">مجموع الفئات</span>
                <Target className="w-4 h-4 text-cyan-400" />
              </div>
              <p className="text-3xl font-orbitron font-bold text-white mt-2">{summary.total_skills}</p>
              <p className="text-xs text-slate-500 mt-1">11 فاحصاً معتمداً</p>
            </div>

            <div className="p-5 rounded-2xl bg-emerald-950/20 border border-emerald-500/30">
              <div className="flex items-center justify-between">
                <span className="text-emerald-400 text-xs font-semibold uppercase tracking-wider">مُتحقَّق آلياً</span>
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              </div>
              <p className="text-3xl font-orbitron font-bold text-emerald-300 mt-2">{summary.practiced_verified}</p>
              <div className="flex items-center gap-1.5 mt-1">
                <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                  <div
                    className="bg-emerald-500 h-full rounded-full transition-all duration-500"
                    style={{ width: `${summary.verified_pct}%` }}
                  />
                </div>
                <span className="text-xs text-emerald-400 font-mono">{summary.verified_pct}%</span>
              </div>
            </div>

            <div className="p-5 rounded-2xl bg-amber-950/20 border border-amber-500/30">
              <div className="flex items-center justify-between">
                <span className="text-amber-400 text-xs font-semibold uppercase tracking-wider">مُعلَن ذاتياً</span>
                <Award className="w-4 h-4 text-amber-400" />
              </div>
              <p className="text-3xl font-orbitron font-bold text-amber-300 mt-2">{summary.practiced_self_reported}</p>
              <p className="text-xs text-slate-500 mt-1">ممارسة يدوية مسجلة</p>
            </div>

            <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800">
              <div className="flex items-center justify-between">
                <span className="text-slate-400 text-xs font-semibold uppercase tracking-wider">فجوة التعلم (نظري فقط)</span>
                <Flame className="w-4 h-4 text-rose-400" />
              </div>
              <p className="text-3xl font-orbitron font-bold text-rose-300 mt-2">{summary.theory_only}</p>
              <p className="text-xs text-slate-500 mt-1">بانتظار الممارسة والتطبيق</p>
            </div>
          </div>
        )}

        {/* Sandbox Launcher Drawer/Section */}
        {showSandbox && (
          <div className="animate-fadeIn">
            <SandboxLauncher onVerified={() => fetchLedger()} />
          </div>
        )}

        {/* Filter Controls Bar */}
        <div className="flex flex-col md:flex-row gap-4 items-center justify-between bg-slate-900/60 p-4 rounded-2xl border border-slate-800">
          <div className="relative w-full md:w-80">
            <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="ابحث عن اسم الثغرة أو الرمز..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-slate-850 border border-slate-700/80 rounded-xl pl-10 pr-4 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>

          <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
            {/* Status Filter */}
            <div className="flex items-center gap-1 bg-slate-850 p-1 rounded-xl border border-slate-750 text-xs">
              <button
                onClick={() => setStatusFilter('all')}
                className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
                  statusFilter === 'all' ? 'bg-cyan-600 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                الكل
              </button>
              <button
                onClick={() => setStatusFilter('practiced_verified')}
                className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
                  statusFilter === 'practiced_verified' ? 'bg-emerald-600 text-white shadow-sm' : 'text-slate-400 hover:text-emerald-400'
                }`}
              >
                مُتحقَّق آلياً
              </button>
              <button
                onClick={() => setStatusFilter('practiced_self_reported')}
                className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
                  statusFilter === 'practiced_self_reported' ? 'bg-amber-600 text-white shadow-sm' : 'text-slate-400 hover:text-amber-400'
                }`}
              >
                مُعلَن ذاتياً
              </button>
              <button
                onClick={() => setStatusFilter('theory_only')}
                className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
                  statusFilter === 'theory_only' ? 'bg-slate-700 text-white shadow-sm' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                فجوة التعلم
              </button>
            </div>

            {/* Scanner Filter */}
            <select
              value={scannerFilter}
              onChange={(e) => setScannerFilter(e.target.value)}
              className="bg-slate-850 border border-slate-750 text-slate-300 text-xs rounded-xl px-3 py-2 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">كافة الفواحص (11)</option>
              {uniqueScanners.map((sc) => (
                <option key={sc} value={sc}>
                  فاحص: {sc.toUpperCase()}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Items Grid */}
        {loading ? (
          <div className="py-20 flex flex-col items-center justify-center text-slate-500 gap-3">
            <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
            <p className="text-sm font-mono">جاري تحميل سجل المهارة...</p>
          </div>
        ) : error ? (
          <div className="p-6 bg-rose-500/10 border border-rose-500/30 rounded-2xl text-rose-300 text-center">
            {error}
          </div>
        ) : filteredItems.length === 0 ? (
          <div className="py-16 text-center text-slate-500 bg-slate-900/40 rounded-2xl border border-slate-800">
            <Filter className="w-8 h-8 mx-auto mb-2 opacity-50" />
            <p className="text-sm">لا توجد مهارات مطابقة للفلتر المحدد.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {filteredItems.map((item) => {
              const statusCfg = STATUS_BADGES[item.status] || STATUS_BADGES.theory_only;
              const StatusIcon = statusCfg.icon;
              const diff = DIFFICULTY_MAP[item.difficulty] || DIFFICULTY_MAP.medium;

              return (
                <div
                  key={item.vuln_type}
                  className={`flex flex-col justify-between p-5 rounded-2xl border transition-all duration-200 hover:shadow-xl ${
                    item.status === 'practiced_verified'
                      ? 'bg-gradient-to-b from-slate-900 to-emerald-950/20 border-emerald-500/30 hover:border-emerald-500/50'
                      : item.status === 'practiced_self_reported'
                      ? 'bg-gradient-to-b from-slate-900 to-amber-950/20 border-amber-500/30 hover:border-amber-500/50'
                      : 'bg-slate-900/70 border-slate-800/80 hover:border-slate-700'
                  }`}
                >
                  <div className="space-y-3">
                    {/* Top Row: Scanner & Difficulty */}
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono uppercase px-2.5 py-0.5 rounded-lg bg-slate-800 border border-slate-700 text-slate-300">
                        {item.scanner}
                      </span>
                      <span className={`px-2 py-0.5 rounded-full border text-[11px] font-medium ${diff.color}`}>
                        {diff.label}
                      </span>
                    </div>

                    {/* Title & Info */}
                    <div>
                      <h3 className="font-semibold text-white text-base leading-snug">{item.name_ar}</h3>
                      <p className="text-xs font-mono text-cyan-400/90 mt-0.5">{item.name_en}</p>
                    </div>

                    {/* Status Badge */}
                    <div className="pt-1">
                      <span
                        className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold border ${statusCfg.badgeClass}`}
                      >
                        <StatusIcon className="w-3.5 h-3.5" />
                        <span>{statusCfg.labelAr}</span>
                      </span>
                    </div>

                    {/* Practice stats */}
                    <div className="text-xs text-slate-500 space-y-1 pt-1 border-t border-slate-800/80">
                      <div className="flex justify-between">
                        <span>عدد محاولات الممارسة:</span>
                        <span className="font-mono text-slate-300 font-semibold">{item.attempts_count}</span>
                      </div>
                      {item.last_practiced_at && (
                        <div className="flex justify-between">
                          <span>آخر ممارسة:</span>
                          <span className="font-mono text-slate-400">
                            {new Date(item.last_practiced_at).toLocaleDateString('ar-EG')}
                          </span>
                        </div>
                      )}
                      {item.evidence_ref && (
                        <div className="flex justify-between truncate">
                          <span>المرجع/الدليل:</span>
                          <span className="font-mono text-slate-400 truncate max-w-[160px]">{item.evidence_ref}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Actions Footer */}
                  <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between gap-2">
                    <Link
                      to={`/learn/vulnerabilities?search=${encodeURIComponent(item.vuln_type)}`}
                      className="text-xs text-slate-400 hover:text-cyan-400 flex items-center gap-1 font-medium transition-colors"
                      title="مراجعة في الموسوعة"
                    >
                      <BookOpen className="w-3.5 h-3.5" />
                      <span>الموسوعة</span>
                    </Link>

                    {item.status !== 'practiced_verified' && (
                      <button
                        onClick={() => {
                          setReportingItem(item);
                          setReportNotes('');
                        }}
                        className="px-3 py-1 bg-slate-800 hover:bg-slate-750 text-slate-200 hover:text-white border border-slate-700 rounded-lg text-xs font-semibold transition-all"
                      >
                        إقرار بممارسة
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Self-Report Modal */}
        {reportingItem && (
          <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 space-y-5 shadow-2xl animate-fadeIn">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2 text-amber-400">
                  <Award className="w-5 h-5" />
                  <h3 className="font-semibold text-white">إقرار ممارسة يدوية ذاتية</h3>
                </div>
                <button
                  onClick={() => setReportingItem(null)}
                  className="text-slate-400 hover:text-white text-lg leading-none"
                >
                  ×
                </button>
              </div>

              <div className="space-y-2 text-sm text-slate-300">
                <p>
                  أنت تسجل ممارسة ذاتية لثغرة: <strong className="text-cyan-400">{reportingItem.name_ar}</strong> (
                  {reportingItem.name_en})
                </p>
                <p className="text-xs text-slate-500">
                  ملاحظة أمنية: سيُسجل هذا كـ <span className="text-amber-400 font-semibold">مُعلَن ذاتياً (Self-Reported)</span>. للحصول على حالة التحقق الآلي (Verified)، يتطلب إكمال تحدي الساندبوكس وتقديم علم الإنجاز الحقيقي.
                </p>
              </div>

              <form onSubmit={handleSelfReport} className="space-y-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-400 mb-1">
                    ملاحظات / مرجع المختبر أو المنصة (اختياري)
                  </label>
                  <input
                    type="text"
                    placeholder="مثال: PortSwigger Lab, HackTheBox, Bug Bounty Triage"
                    value={reportNotes}
                    onChange={(e) => setReportNotes(e.target.value)}
                    className="w-full bg-slate-850 border border-slate-700 rounded-xl px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-amber-500"
                  />
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => setReportingItem(null)}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-750 text-slate-300 rounded-xl text-xs font-semibold"
                  >
                    إلغاء
                  </button>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-xl text-xs font-semibold flex items-center gap-1.5 shadow-lg shadow-amber-900/30"
                  >
                    {submitting ? 'جاري الحفظ...' : 'تأكيد التسجيل'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
