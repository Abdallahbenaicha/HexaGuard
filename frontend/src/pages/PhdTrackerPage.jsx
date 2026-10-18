import React, { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import { useLang } from '../context/LangContext';

const API = import.meta.env.VITE_API_BASE_URL || '';

/* ─── Status config ───────────────────────────────────────────────────────── */
const STATUS_CFG = {
  applied:     { cls: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40', dot: 'bg-emerald-400', label_en: 'Applied',     label_ar: 'مُقدَّم',      icon: '✓' },
  emailed:     { cls: 'bg-cyan-500/15    text-cyan-400    border-cyan-500/40',    dot: 'bg-cyan-400',    label_en: 'Emailed',     label_ar: 'تم التواصل',   icon: '✉' },
  planned:     { cls: 'bg-blue-500/15    text-blue-400    border-blue-500/40',    dot: 'bg-blue-400',    label_en: 'Planned',     label_ar: 'مخطط',          icon: '○' },
  interested:  { cls: 'bg-violet-500/15  text-violet-400  border-violet-500/40',  dot: 'bg-violet-400',  label_en: 'Interested',  label_ar: 'مهتم',          icon: '◎' },
  researching: { cls: 'bg-slate-500/15   text-slate-400   border-slate-500/40',   dot: 'bg-slate-400',   label_en: 'Researching', label_ar: 'قيد البحث',    icon: '⋯' },
  closed:      { cls: 'bg-red-500/10     text-red-500/70  border-red-500/20',     dot: 'bg-red-500/50',  label_en: 'Closed',      label_ar: 'مغلق',          icon: '✕' },
};

const PRIORITY_CFG = {
  high:   { cls: 'text-amber-400',  label_en: 'High',   label_ar: 'عالية',    bar: 'bg-amber-400' },
  medium: { cls: 'text-slate-400',  label_en: 'Medium', label_ar: 'متوسطة',   bar: 'bg-slate-500' },
  low:    { cls: 'text-slate-600',  label_en: 'Low',    label_ar: 'منخفضة',   bar: 'bg-slate-700' },
};

const DEADLINE_CFG = {
  active:   { cls: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400', label_en: 'Active',   label_ar: 'ساري' },
  upcoming: { cls: 'bg-blue-500/10    border-blue-500/30    text-blue-400',    label_en: 'Upcoming', label_ar: 'قادم' },
  expired:  { cls: 'bg-red-500/10     border-red-500/30     text-red-400/80',  label_en: 'Expired',  label_ar: 'منتهي' },
  unknown:  { cls: 'bg-slate-800/60   border-slate-700      text-slate-500',   label_en: 'Open',     label_ar: 'مفتوح' },
};

/* ─── Mini components ─────────────────────────────────────────────────────── */
function StatusBadge({ status, lang }) {
  const cfg = STATUS_CFG[status] || STATUS_CFG.researching;
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full border tracking-wider ${cfg.cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {lang === 'ar' ? cfg.label_ar : cfg.label_en}
    </span>
  );
}

function PriorityDot({ priority, lang }) {
  const cfg = PRIORITY_CFG[priority] || PRIORITY_CFG.medium;
  return (
    <span className={`text-[10px] font-semibold uppercase tracking-widest ${cfg.cls}`}>
      {lang === 'ar' ? cfg.label_ar : cfg.label_en}
    </span>
  );
}

function DeadlineBadge({ deadline_status, days_remaining, deadline, lang }) {
  const cfg = DEADLINE_CFG[deadline_status] || DEADLINE_CFG.unknown;
  const urgent = days_remaining != null && days_remaining > 0 && days_remaining <= 14;
  return (
    <span className={`inline-flex items-center gap-1.5 text-[10px] px-2 py-0.5 rounded-full border ${cfg.cls} ${urgent ? 'animate-pulse' : ''}`}>
      {deadline_status === 'active' && <span>⏳</span>}
      {deadline_status === 'expired' && <span>✕</span>}
      {deadline_status === 'upcoming' && <span>📅</span>}
      {deadline ? deadline : (lang === 'ar' ? cfg.label_ar : cfg.label_en)}
      {days_remaining != null && days_remaining > 0 && (
        <span className="font-mono font-bold">({days_remaining}d)</span>
      )}
    </span>
  );
}

/* ─── Opportunity Card ────────────────────────────────────────────────────── */
function OpportunityCard({ opp, lang, onExpand, expanded, onOpenSkillJourney, onOpenProposalHook, onOpenDossier }) {
  const isRtl = lang === 'ar';
  const priority = PRIORITY_CFG[opp.priority] || PRIORITY_CFG.medium;

  return (
    <div
      className={`group rounded-xl border transition-all duration-200 cursor-pointer
        ${expanded
          ? 'border-violet-500/50 bg-slate-900/80 shadow-lg shadow-violet-900/20'
          : 'border-slate-800 bg-slate-900/50 hover:border-slate-600 hover:shadow-md hover:shadow-slate-900/40'}`}
      onClick={() => onExpand(opp.id)}
    >
      <div className={`h-0.5 rounded-t-xl ${priority.bar} opacity-60`} />

      <div className="p-4">
        <div className="flex items-start justify-between gap-2 mb-2">
          <div className="flex items-center gap-2 flex-wrap">
            <StatusBadge status={opp.status} lang={lang} />
            <PriorityDot priority={opp.priority} lang={lang} />
          </div>
          <div className="flex items-center gap-2 text-slate-600 text-[10px] font-mono">
            {opp.num && <span>#{opp.num}</span>}
            {opp.source_type === 'saved_discovery' && (
              <span className="px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">LIVE_SAVED</span>
            )}
            {opp.source_file === 'user_added' && (
              <span className="px-1.5 py-0.5 rounded bg-violet-500/10 text-violet-400 border border-violet-500/20">+NEW</span>
            )}
          </div>
        </div>

        <h3 className="text-sm font-bold text-white leading-tight mb-0.5 line-clamp-1">
          {opp.institution || '—'}
        </h3>
        <div className="text-xs text-slate-400 mb-2">
          🌍 {opp.country || '—'}
          {opp.field && <span className="ml-2 text-slate-500">· {opp.field}</span>}
        </div>

        {opp.program && (
          <p className="text-[11px] text-slate-500 leading-relaxed line-clamp-2 mb-3">
            {opp.program}
          </p>
        )}

        {(opp.deadline || opp.deadline_status !== 'unknown') && (
          <DeadlineBadge
            deadline_status={opp.deadline_status}
            days_remaining={opp.days_remaining}
            deadline={opp.deadline}
            lang={lang}
          />
        )}

        {opp.funding && (
          <span className="ml-2 inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full bg-emerald-900/30 border border-emerald-700/30 text-emerald-400">
            💰 {opp.funding.length > 30 ? opp.funding.slice(0, 30) + '…' : opp.funding}
          </span>
        )}

        {expanded && (
          <div className="mt-4 pt-4 border-t border-slate-800 space-y-3 animate-in slide-in-from-top-2 duration-200">
            {opp.notes && (
              <div>
                <div className="text-[10px] uppercase tracking-wider text-slate-600 mb-1">{isRtl ? 'ملاحظات' : 'Notes'}</div>
                <p className="text-xs text-slate-400 leading-relaxed">{opp.notes}</p>
              </div>
            )}
            {opp.contact && (
              <div>
                <div className="text-[10px] uppercase tracking-wider text-slate-600 mb-1">{isRtl ? 'التواصل' : 'Contact'}</div>
                <p className="text-xs text-cyan-400/80 font-mono break-all">{opp.contact}</p>
              </div>
            )}
            {opp.verified && (
              <div>
                <div className="text-[10px] uppercase tracking-wider text-slate-600 mb-1">{isRtl ? 'التحقق' : 'Verified'}</div>
                <p className="text-xs text-slate-500">{opp.verified}</p>
              </div>
            )}

            {/* Cross-Module Integration Actions */}
            <div className="pt-2 flex flex-wrap gap-2" onClick={e => e.stopPropagation()}>
              <button
                onClick={() => onOpenSkillJourney && onOpenSkillJourney(opp)}
                className="px-3 py-1.5 rounded-lg bg-violet-600/20 hover:bg-violet-600/40 text-violet-300 border border-violet-500/30 text-xs font-semibold transition-all inline-flex items-center gap-1.5"
              >
                <span>🎓</span>
                <span>{isRtl ? 'الجاهزية والمهارات' : 'Skill Journey'}</span>
              </button>
              <button
                onClick={() => onOpenProposalHook && onOpenProposalHook(opp)}
                className="px-3 py-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/40 text-cyan-300 border border-cyan-500/30 text-xs font-semibold transition-all inline-flex items-center gap-1.5"
              >
                <span>✨</span>
                <span>{isRtl ? 'الخطاف ومسودة الإيميل' : 'Proposal Hook'}</span>
              </button>
              <button
                onClick={() => onOpenDossier && onOpenDossier(opp)}
                className="px-3 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/40 text-emerald-300 border border-emerald-500/30 text-xs font-semibold transition-all inline-flex items-center gap-1.5"
              >
                <span>📄</span>
                <span>{isRtl ? 'ملف الترشح والمصفوفة' : 'Dossier & Matrix'}</span>
              </button>
            </div>

            <div className="text-[9px] text-slate-700 font-mono pt-1">
              {isRtl ? 'المصدر:' : 'Source:'} {opp.source_file || opp.source_type}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* ─── Stat Card ───────────────────────────────────────────────────────────── */
function StatCard({ value, label, color, icon, sub }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-4 text-center group hover:border-slate-700 transition-colors">
      {icon && <div className="text-2xl mb-1">{icon}</div>}
      <div className={`text-3xl font-black font-mono tabular-nums ${color}`}>{value ?? '—'}</div>
      <div className="text-[10px] text-slate-500 uppercase tracking-wider mt-1">{label}</div>
      {sub && <div className="text-[9px] text-slate-600 mt-0.5">{sub}</div>}
    </div>
  );
}

/* ─── Add Opportunity Modal ───────────────────────────────────────────────── */
function AddOpportunityModal({ lang, onClose, onAdded }) {
  const isRtl = lang === 'ar';
  const [form, setForm] = useState({
    country: '', institution: '', program: '', field: '', funding: '',
    deadline: '', status: 'researching', priority: 'medium', notes: '', contact: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const res = await axios.post(`${API}/api/phd/opportunities`, form, { withCredentials: true });
      onAdded(res.data.opportunity);
      onClose();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to add');
    } finally {
      setLoading(false);
    }
  };

  const fields = [
    { key: 'institution', label_en: 'Institution *', label_ar: 'المؤسسة *', required: true },
    { key: 'country',     label_en: 'Country *',     label_ar: 'الدولة *',   required: true },
    { key: 'program',     label_en: 'Program/Position', label_ar: 'البرنامج / المنصب' },
    { key: 'field',       label_en: 'Field',          label_ar: 'المجال' },
    { key: 'funding',     label_en: 'Funding',        label_ar: 'التمويل' },
    { key: 'deadline',    label_en: 'Deadline (YYYY-MM-DD)', label_ar: 'الموعد النهائي' },
    { key: 'contact',     label_en: 'Contact / URL',  label_ar: 'التواصل / الرابط' },
    { key: 'notes',       label_en: 'Notes',          label_ar: 'ملاحظات', textarea: true },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" dir={isRtl ? 'rtl' : 'ltr'}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-lg rounded-2xl border border-slate-700 bg-slate-900 shadow-2xl shadow-black/60 overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-bold text-white">{isRtl ? '➕ إضافة فرصة جديدة' : '➕ Add New Opportunity'}</h2>
            <p className="text-xs text-slate-500 mt-0.5">{isRtl ? 'ستُضاف للمنصة فوراً وبشكل دائم' : 'Added to platform immediately and persisted'}</p>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors text-xl leading-none">✕</button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-3 max-h-[70vh] overflow-y-auto">
          {fields.map(f => (
            <div key={f.key}>
              <label className="block text-[11px] text-slate-400 mb-1 uppercase tracking-wider">
                {isRtl ? f.label_ar : f.label_en}
              </label>
              {f.textarea ? (
                <textarea
                  className="w-full rounded-lg bg-slate-800 border border-slate-700 text-sm text-white px-3 py-2 focus:outline-none focus:border-violet-500 placeholder-slate-600 resize-none h-20"
                  value={form[f.key]}
                  onChange={e => setForm(prev => ({ ...prev, [f.key]: e.target.value }))}
                />
              ) : (
                <input
                  type="text"
                  required={f.required}
                  className="w-full rounded-lg bg-slate-800 border border-slate-700 text-sm text-white px-3 py-2 focus:outline-none focus:border-violet-500 placeholder-slate-600"
                  value={form[f.key]}
                  onChange={e => setForm(prev => ({ ...prev, [f.key]: e.target.value }))}
                />
              )}
            </div>
          ))}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[11px] text-slate-400 mb-1 uppercase tracking-wider">{isRtl ? 'الحالة' : 'Status'}</label>
              <select className="w-full rounded-lg bg-slate-800 border border-slate-700 text-sm text-white px-3 py-2 focus:outline-none focus:border-violet-500"
                value={form.status} onChange={e => setForm(p => ({ ...p, status: e.target.value }))}>
                {Object.entries(STATUS_CFG).filter(([k]) => k !== 'closed').map(([k, v]) => (
                  <option key={k} value={k}>{isRtl ? v.label_ar : v.label_en}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-[11px] text-slate-400 mb-1 uppercase tracking-wider">{isRtl ? 'الأولوية' : 'Priority'}</label>
              <select className="w-full rounded-lg bg-slate-800 border border-slate-700 text-sm text-white px-3 py-2 focus:outline-none focus:border-violet-500"
                value={form.priority} onChange={e => setForm(p => ({ ...p, priority: e.target.value }))}>
                {Object.entries(PRIORITY_CFG).map(([k, v]) => (
                  <option key={k} value={k}>{isRtl ? v.label_ar : v.label_en}</option>
                ))}
              </select>
            </div>
          </div>

          {error && <div className="text-xs text-red-400 bg-red-950/40 border border-red-800 rounded-lg px-3 py-2">{error}</div>}

          <button type="submit" disabled={loading}
            className="w-full rounded-xl bg-gradient-to-r from-violet-600 to-purple-600 text-white font-bold py-2.5 text-sm hover:from-violet-500 hover:to-purple-500 transition-all disabled:opacity-50 mt-2">
            {loading ? '⟳' : (isRtl ? '✓ إضافة الفرصة' : '✓ Add Opportunity')}
          </button>
        </form>
      </div>
    </div>
  );
}

/* ─── Skill Journey Modal (Closed-Loop Integration) ───────────────────────── */
function SkillJourneyModal({ opp, lang, onClose }) {
  const isRtl = lang === 'ar';
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!opp) return;
    axios.get(`${API}/api/phd/opportunities/${opp.id}/skill-journey`, { withCredentials: true })
      .then(r => setData(r.data))
      .catch(e => setError(e.response?.data?.error || 'Failed to load skill journey'))
      .finally(() => setLoading(false));
  }, [opp]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" dir={isRtl ? 'rtl' : 'ltr'}>
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-2xl rounded-2xl border border-violet-500/40 bg-slate-900 shadow-2xl shadow-violet-950/50 overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-gradient-to-r from-violet-950/40 to-slate-900">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-violet-600/20 border border-violet-500/40 flex items-center justify-center text-violet-400 text-lg">
              🎓
            </div>
            <div>
              <h2 className="text-base font-bold text-white">
                {isRtl ? 'خارطة المتطلبات والجاهزية المهارية' : 'Research Prerequisites & Skill Journey'}
              </h2>
              <p className="text-xs text-slate-400 truncate max-w-md">
                {opp.institution} · {opp.program || opp.field}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors text-xl leading-none">✕</button>
        </div>

        <div className="p-6 space-y-5 max-h-[75vh] overflow-y-auto">
          {loading && (
            <div className="py-12 flex flex-col items-center justify-center gap-3">
              <div className="w-8 h-8 border-2 border-violet-500 border-t-transparent rounded-full animate-spin" />
              <div className="text-xs text-slate-400 font-mono">Analyzing opportunity requirements against Skill Ledger...</div>
            </div>
          )}

          {error && (
            <div className="p-4 rounded-xl bg-red-950/30 border border-red-500/30 text-red-400 text-xs">
              {error}
            </div>
          )}

          {!loading && data && (
            <>
              <div className="p-4 rounded-xl bg-gradient-to-r from-violet-900/20 via-slate-800/40 to-cyan-900/20 border border-violet-500/30 flex items-center justify-between gap-4">
                <div>
                  <div className="text-xs text-slate-400 font-mono uppercase tracking-wider mb-1">
                    {isRtl ? 'مؤشر الجاهزية الحقيقي (Skill Ledger)' : 'Live Candidate Readiness'}
                  </div>
                  <div className="text-2xl font-black text-white flex items-baseline gap-2">
                    <span className="text-violet-400">{data.readiness_pct}%</span>
                    <span className="text-xs text-slate-500 font-normal">
                      ({data.practiced_skills_count} / {data.total_required_skills} {isRtl ? 'مهارات مُثبتة' : 'skills practiced'})
                    </span>
                  </div>
                </div>
                <div className="w-24 h-3 bg-slate-800 rounded-full overflow-hidden border border-slate-700">
                  <div
                    className="h-full bg-gradient-to-r from-violet-500 to-cyan-400 rounded-full transition-all duration-500"
                    style={{ width: `${Math.min(100, data.readiness_pct)}%` }}
                  />
                </div>
              </div>

              <div className="space-y-3">
                <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center justify-between">
                  <span>{isRtl ? 'المتطلبات التقنية ومسارات التدريب' : 'Technical Prerequisites & Practice Pathway'}</span>
                  <span className="text-[10px] text-slate-500 font-normal">{isRtl ? 'مستخرجة من الكلمات المفتاحية' : 'Extracted from research scope'}</span>
                </div>

                <div className="space-y-2">
                  {data.skills?.map(s => (
                    <div
                      key={s.skill_id}
                      className="p-3.5 rounded-xl border border-slate-800 bg-slate-900/60 hover:border-slate-700 transition-all flex flex-wrap items-center justify-between gap-3"
                    >
                      <div className="flex items-center gap-3">
                        <span className={`w-2.5 h-2.5 rounded-full ${s.status === 'practiced' ? 'bg-emerald-400 shadow-sm shadow-emerald-400/50' : 'bg-amber-400'}`} />
                        <div>
                          <div className="text-xs font-bold text-white flex items-center gap-2">
                            <span>{isRtl ? s.name_ar : s.name_en}</span>
                            <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                              {s.tier}
                            </span>
                          </div>
                          <div className="text-[10px] text-slate-500 mt-0.5 font-mono">
                            {s.status === 'practiced'
                              ? `✓ ${isRtl ? 'مُمارس في السجل' : 'Practiced in Ledger'} (${s.practiced_count}x)`
                              : `○ ${isRtl ? 'يحتاج تدريب عملي' : 'Requires Hands-On Practice'}`}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <a
                          href={s.lesson_url}
                          className="px-3 py-1.5 rounded-lg bg-violet-600/30 hover:bg-violet-600/50 text-violet-300 border border-violet-500/40 text-xs font-semibold transition-all inline-flex items-center gap-1.5"
                        >
                          <span>📖</span>
                          <span>{isRtl ? 'دراسة المهارة' : 'Study Skill'}</span>
                        </a>
                        <a
                          href={s.dojo_url}
                          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold transition-all inline-flex items-center gap-1.5"
                        >
                          <span>⚔️</span>
                          <span>{isRtl ? 'تحدي الدوجو' : 'Dojo Lab'}</span>
                        </a>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-800/30 border border-slate-800 text-[10px] text-slate-500 leading-relaxed">
                ℹ️ {isRtl ? data.disclaimer_ar : data.disclaimer_en}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

/* ─── Proposal Hook Modal ─────────────────────────────────────────────────── */
function ProposalHookModal({ opp, lang, onClose }) {
  const isRtl = lang === 'ar';
  const [loading, setLoading] = useState(true);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!opp) return;
    axios.post(`${API}/api/phd/generate-proposal-hook`, {
      opportunity_id: opp.id,
      language: lang,
    }, { withCredentials: true })
      .then(r => setData(r.data))
      .catch(e => setError(e.response?.data?.error || 'Failed to generate proposal hook'))
      .finally(() => setLoading(false));
  }, [opp, lang]);

  const copyEmail = () => {
    if (!data?.full_email) return;
    navigator.clipboard.writeText(data.full_email);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" dir={isRtl ? 'rtl' : 'ltr'}>
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-2xl rounded-2xl border border-cyan-500/40 bg-slate-900 shadow-2xl shadow-cyan-950/50 overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-gradient-to-r from-cyan-950/40 to-slate-900">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-600/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 text-lg">
              ✨
            </div>
            <div>
              <h2 className="text-base font-bold text-white">
                {isRtl ? 'صياغة الخطاف البحثي ورسالة التواصل' : 'SecuraX AI Research Hook & Outreach Pitch'}
              </h2>
              <p className="text-xs text-slate-400 truncate max-w-md">
                {opp.institution} · {opp.program || opp.field}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors text-xl leading-none">✕</button>
        </div>

        <div className="p-6 space-y-4 max-h-[75vh] overflow-y-auto">
          {loading && (
            <div className="py-12 flex flex-col items-center justify-center gap-3">
              <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
              <div className="text-xs text-slate-400 font-mono">Synthesizing candidate profile with SecuraX research artifacts...</div>
            </div>
          )}

          {error && (
            <div className="p-4 rounded-xl bg-red-950/30 border border-red-500/30 text-red-400 text-xs">
              {error}
            </div>
          )}

          {!loading && data && (
            <>
              <div>
                <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 mb-1">
                  {isRtl ? 'عنوان الرسالة المقترح' : 'Subject Line'}
                </div>
                <div className="p-2.5 rounded-lg bg-slate-800/80 border border-slate-700 text-xs font-semibold text-cyan-300 select-all">
                  {data.subject_line}
                </div>
              </div>

              <div>
                <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 mb-1">
                  {isRtl ? 'الخطاف الفني (SecuraX Live Artifact Pitch)' : 'Technical Proof-of-Work Pitch'}
                </div>
                <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700/60 text-xs text-slate-200 leading-relaxed">
                  {data.securax_pitch}
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
                    {isRtl ? 'نص الرسالة الكامل المعدّ للمراجعة' : 'Full Outreach Draft'}
                  </span>
                  <button
                    onClick={copyEmail}
                    className="text-xs text-cyan-400 hover:text-cyan-300 font-bold inline-flex items-center gap-1"
                  >
                    {copied ? '✓ Copied!' : '📋 Copy Draft'}
                  </button>
                </div>
                <textarea
                  readOnly
                  value={data.full_email}
                  className="w-full h-44 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-300 p-3 font-mono leading-relaxed resize-none focus:outline-none"
                />
              </div>

              {data.suggested_attachments?.length > 0 && (
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-wider text-slate-500 mb-1">
                    {isRtl ? 'المرفقات الأكاديمية المقترحة' : 'Suggested Academic Attachments'}
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {data.suggested_attachments.map((att, i) => (
                      <span key={i} className="text-[10px] px-2 py-0.5 rounded-md bg-slate-800 text-slate-300 border border-slate-700">
                        📎 {att}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

/* ─── Academic Candidate Dossier & Submission Generator Modal (Gate 1.5) ────── */
function AcademicDossierModal({ opp, lang, onClose }) {
  const isRtl = lang === 'ar';
  const [loading, setLoading] = useState(true);
  const [matrixData, setMatrixData] = useState(null);
  const [portfolioData, setPortfolioData] = useState(null);
  const [error, setError] = useState(null);
  const [selectedDocs, setSelectedDocs] = useState([
    'academic_cv.pdf',
    'msc_degree_certificate.pdf',
    'master_thesis_abstract.pdf'
  ]);
  const [outreachText, setOutreachText] = useState('');
  const [activeTab, setActiveTab] = useState('matrix');
  const [exportingPdf, setExportingPdf] = useState(false);
  const [exportingZip, setExportingZip] = useState(false);
  const [copied, setCopied] = useState(false);

  // Gate 1.6 Briefing & Private Sharing State
  const [briefings, setBriefings] = useState([]);
  const [evidenceList, setEvidenceList] = useState([]);
  const [targetSupervisor, setTargetSupervisor] = useState(opp.pi_name || opp.supervisor || '');
  const [selectedEvidenceIds, setSelectedEvidenceIds] = useState([
    'pow_sast_engine',
    'pow_dast_harness',
    'pow_docker_auditor',
    'pow_unit_tests',
    'pow_msc_degree'
  ]);
  const [expiryDays, setExpiryDays] = useState(14);
  const [creatingBriefing, setCreatingBriefing] = useState(false);
  const [actionLoadingId, setActionLoadingId] = useState(null);
  const [createdShareResult, setCreatedShareResult] = useState(null);
  const [copiedToken, setCopiedToken] = useState(null);

  const fetchBriefings = () => {
    axios.get(`${API}/api/dossier/briefings`, { withCredentials: true })
      .then(res => setBriefings(res.data.briefings || []))
      .catch(() => {});
  };

  const fetchEvidence = () => {
    axios.get(`${API}/api/dossier/evidence`, { withCredentials: true })
      .then(res => setEvidenceList(res.data.evidence || []))
      .catch(() => {});
  };

  useEffect(() => {
    if (!opp) return;
    setLoading(true);
    fetchBriefings();
    fetchEvidence();
    Promise.all([
      axios.get(`${API}/api/dossier/portfolio`, { withCredentials: true }),
      axios.get(`${API}/api/dossier/opportunity/${opp.id}/matrix`, { withCredentials: true }),
    ])
      .then(([portRes, matRes]) => {
        setPortfolioData(portRes.data);
        setMatrixData(matRes.data);
        const cand = portRes.data.candidate || {};
        const inst = opp.institution || 'Admissions Committee';
        const field = opp.field || opp.program || 'Cybersecurity Research';
        setOutreachText(
          `Subject: [Prospective PhD Applicant] Master's Cybersecurity Researcher & SecuraX Artifact | ${cand.name || 'Abdallah Benaicha'}\n\n` +
          `Dear Admissions Committee and Faculty at ${inst},\n\n` +
          `I am writing to express my strong interest in pursuing doctoral research focusing on ${field}.\n\n` +
          `Graduating in the top 5% of my cohort (Rank: ${cand.class_rank || '3rd of 55'}) with a Master of Science in NICT from ${cand.university || "University of Mohamed Boudiaf – M'Sila"}, ` +
          `I engineered SecuraX (HexaGuard) — an automated vulnerability detection and taint tracing platform. ` +
          `SecuraX implements hybrid AST static analysis, dynamic DAST crawling, and live CVE telemetry.\n\n` +
          `I would welcome the opportunity to discuss how my empirical background and research artifact can directly advance your lab's active projects.\n\n` +
          `Sincerely,\n${cand.name || 'Abdallah Benaicha'}\nMaster of Science in Cybersecurity`
        );
      })
      .catch(e => setError(e.response?.data?.error || 'Failed to load dossier data'))
      .finally(() => setLoading(false));
  }, [opp]);

  const handleToggleDoc = (docFile) => {
    setSelectedDocs(prev =>
      prev.includes(docFile) ? prev.filter(d => d !== docFile) : [...prev, docFile]
    );
  };

  const handleExportPdf = async () => {
    setExportingPdf(true);
    try {
      const res = await axios.post(`${API}/api/dossier/export/pdf`, {
        opportunity_id: opp.id,
        selected_documents: selectedDocs,
        custom_statement: outreachText,
      }, {
        withCredentials: true,
        responseType: 'blob',
      });
      const blob = new Blob([res.data], { type: 'application/pdf' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `academic_dossier_${opp.id || 'general'}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch {
      alert(isRtl ? 'حدث خطأ أثناء تصدير PDF' : 'Error exporting PDF dossier');
    } finally {
      setExportingPdf(false);
    }
  };

  const handleExportZip = async () => {
    setExportingZip(true);
    try {
      const res = await axios.post(`${API}/api/dossier/export/zip`, {
        opportunity_id: opp.id,
        selected_documents: selectedDocs,
        custom_statement: outreachText,
      }, {
        withCredentials: true,
        responseType: 'blob',
      });
      const blob = new Blob([res.data], { type: 'application/zip' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `application_bundle_${opp.id || 'bundle'}.zip`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch {
      alert(isRtl ? 'حدث خطأ أثناء تصدير حزمة ZIP' : 'Error exporting ZIP bundle');
    } finally {
      setExportingZip(false);
    }
  };

  const handleCopyPitch = () => {
    navigator.clipboard.writeText(outreachText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleToggleEvidence = (id) => {
    setSelectedEvidenceIds(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  };

  const handleCreateBriefing = async () => {
    if (!targetSupervisor.trim()) {
      alert(isRtl ? 'يرجى إدخال اسم المشرف المستهدف' : 'Please specify the target supervisor or professor name');
      return;
    }
    setCreatingBriefing(true);
    try {
      const res = await axios.post(`${API}/api/dossier/briefings`, {
        opportunity_id: opp.id,
        target_supervisor: targetSupervisor.trim(),
        selected_evidence_ids: selectedEvidenceIds,
        selected_doc_ids: selectedDocs,
        custom_note: outreachText,
        expiry_days: Number(expiryDays) || 14,
        allow_downloads: true,
      }, { withCredentials: true });

      const newBriefing = res.data.briefing;
      const shareRes = await axios.post(`${API}/api/dossier/briefings/${newBriefing.id}/share`, {
        expiry_days: Number(expiryDays) || 14,
      }, { withCredentials: true });

      setCreatedShareResult(shareRes.data);
      fetchBriefings();
    } catch (err) {
      alert(err.response?.data?.error || (isRtl ? 'حدث خطأ أثناء إنشاء حزمة المشرف' : 'Failed to create briefing pack'));
    } finally {
      setCreatingBriefing(false);
    }
  };

  const handleRevokeShare = async (briefingId) => {
    if (!window.confirm(isRtl
      ? 'هل أنت متأكد من إلغاء المشاركة فورًا؟ الرابط سيصبح معطلاً (410 Gone) ولن يتمكن المشرف من قراءة أي ملفات.'
      : 'Are you sure you want to revoke access? The link will immediately return HTTP 410 Gone.')) {
      return;
    }
    setActionLoadingId(briefingId);
    try {
      await axios.post(`${API}/api/dossier/briefings/${briefingId}/revoke`, {}, { withCredentials: true });
      fetchBriefings();
      if (createdShareResult?.briefing?.id === briefingId) {
        setCreatedShareResult(null);
      }
    } catch (err) {
      alert(err.response?.data?.error || 'Failed to revoke access');
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleReShare = async (briefingId) => {
    setActionLoadingId(briefingId);
    try {
      const res = await axios.post(`${API}/api/dossier/briefings/${briefingId}/share`, {
        expiry_days: Number(expiryDays) || 14,
      }, { withCredentials: true });
      setCreatedShareResult(res.data);
      fetchBriefings();
    } catch (err) {
      alert(err.response?.data?.error || 'Failed to generate new share link');
    } finally {
      setActionLoadingId(null);
    }
  };

  const handleCopyShareUrl = (token) => {
    const fullUrl = `${window.location.origin}/reviewer?token=${token}`;
    navigator.clipboard.writeText(fullUrl);
    setCopiedToken(token);
    setTimeout(() => setCopiedToken(null), 2500);
  };

  const currentOppBriefings = briefings.filter(b => String(b.opportunity_id) === String(opp.id));

  const matchRate = matrixData?.overall_alignment_pct || matrixData?.match_rate || 0;
  const cand = portfolioData?.candidate || {};
  const docPool = cand.documents_pool || [
    { id: 'doc_cv', file: 'academic_cv.pdf', title: 'Academic CV (Curriculum Vitae)', provenance: '[VERIFIED EVIDENCE]' },
    { id: 'doc_msc_diploma', file: 'msc_degree_certificate.pdf', title: 'Master Degree Certificate & Transcripts', provenance: '[VERIFIED EVIDENCE]' },
    { id: 'doc_thesis_abstract', file: 'master_thesis_abstract.pdf', title: 'Master Thesis Abstract (SecuraX Architecture)', provenance: '[VERIFIED EVIDENCE]' },
    { id: 'doc_recommendation_1', file: 'recommendation_prof_akhrouf.pdf', title: 'Academic Reference - Prof. Samir Akhrouf', provenance: '[VERIFIED EVIDENCE]' },
  ];

  const getStatusBadge = (status) => {
    switch (status) {
      case 'MATCHED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">MATCHED</span>;
      case 'PARTIALLY_MATCHED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-300 border border-amber-500/30">PARTIAL</span>;
      case 'REQUIRES_MANUAL_REVIEW':
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">MANUAL REVIEW</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">MISSING</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6" dir={isRtl ? 'rtl' : 'ltr'}>
      <div className="absolute inset-0 bg-black/80 backdrop-blur-md" onClick={onClose} />
      <div className="relative w-full max-w-4xl rounded-2xl border border-emerald-500/30 bg-slate-900 shadow-2xl shadow-emerald-950/40 overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-gradient-to-r from-emerald-950/40 via-slate-900 to-cyan-950/40">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-emerald-600/20 border border-emerald-500/40 flex items-center justify-center text-emerald-400 text-xl font-bold">
              📄
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <span>{isRtl ? 'ملف الترشح الأكاديمي المخصص ومصفوفة الأدلة' : 'Academic Candidate Dossier & Submission Generator'}</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">Gate 1.5</span>
              </h2>
              <p className="text-xs text-slate-400 truncate max-w-lg">
                {opp.institution} · {opp.program || opp.field || 'Doctoral Program'} ({opp.country || 'Global'})
              </p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors text-2xl leading-none">✕</button>
        </div>

        {/* Modal Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {loading && (
            <div className="py-16 flex flex-col items-center justify-center gap-3">
              <div className="w-10 h-10 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
              <div className="text-xs text-slate-400 font-mono">Building empirical dossier & computing requirement-to-evidence matrix...</div>
            </div>
          )}

          {error && (
            <div className="p-4 rounded-xl bg-red-950/30 border border-red-500/30 text-red-400 text-xs">
              {error}
            </div>
          )}

          {!loading && matrixData && (
            <>
              {/* Candidate Provenance Strip */}
              <div className="p-4 rounded-xl bg-gradient-to-r from-slate-950 via-slate-900 to-slate-950 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="w-11 h-11 rounded-full bg-cyan-600/20 border border-cyan-500/30 flex items-center justify-center text-cyan-300 font-black text-sm">
                    AB
                  </div>
                  <div>
                    <div className="text-sm font-bold text-white flex items-center gap-2">
                      <span>{cand.name || 'Abdallah Benaicha'}</span>
                      <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">[VERIFIED EVIDENCE]</span>
                    </div>
                    <div className="text-xs text-slate-400">
                      M.Sc. in NICT · Univ. M'Sila · Rank: <span className="text-cyan-300 font-semibold">{cand.class_rank || '3rd of 55'}</span> · Final GPA: <span className="text-emerald-300 font-semibold">14.72 / 20</span>
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">{isRtl ? 'نسبة التوافق المثبتة' : 'Verified Alignment'}</div>
                    <div className="text-xl font-black text-emerald-400">{matchRate}%</div>
                  </div>
                  <div className="w-20 h-2.5 bg-slate-800 rounded-full overflow-hidden border border-slate-700">
                    <div
                      className="h-full bg-gradient-to-r from-emerald-500 to-cyan-400 rounded-full transition-all duration-500"
                      style={{ width: `${Math.min(100, matchRate)}%` }}
                    />
                  </div>
                </div>
              </div>

              {/* Navigation Tabs */}
              <div className="flex border-b border-slate-800 gap-2">
                <button
                  onClick={() => setActiveTab('matrix')}
                  className={`pb-2.5 px-3 text-xs font-bold transition-all border-b-2 flex items-center gap-1.5 ${
                    activeTab === 'matrix'
                      ? 'border-emerald-500 text-emerald-300'
                      : 'border-transparent text-slate-400 hover:text-white'
                  }`}
                >
                  <span>📊</span>
                  <span>{isRtl ? 'مصفوفة المطابقة (Evidence Matrix)' : 'Requirement-to-Evidence Matrix'}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                    {matrixData.matrix?.length || 0}
                  </span>
                </button>
                <button
                  onClick={() => setActiveTab('documents')}
                  className={`pb-2.5 px-3 text-xs font-bold transition-all border-b-2 flex items-center gap-1.5 ${
                    activeTab === 'documents'
                      ? 'border-emerald-500 text-emerald-300'
                      : 'border-transparent text-slate-400 hover:text-white'
                  }`}
                >
                  <span>📎</span>
                  <span>{isRtl ? 'فرز الوثائق ومحتويات الحزمة' : 'Document Curation'}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                    {selectedDocs.length} / {docPool.length}
                  </span>
                </button>
                <button
                  onClick={() => setActiveTab('pitch')}
                  className={`pb-2.5 px-3 text-xs font-bold transition-all border-b-2 flex items-center gap-1.5 ${
                    activeTab === 'pitch'
                      ? 'border-emerald-500 text-emerald-300'
                      : 'border-transparent text-slate-400 hover:text-white'
                  }`}
                >
                  <span>✉️</span>
                  <span>{isRtl ? 'مسودة التواصل المخصصة' : 'Faculty Outreach Pitch'}</span>
                </button>
                <button
                  onClick={() => setActiveTab('briefing')}
                  className={`pb-2.5 px-3 text-xs font-bold transition-all border-b-2 flex items-center gap-1.5 ${
                    activeTab === 'briefing'
                      ? 'border-purple-500 text-purple-300'
                      : 'border-transparent text-slate-400 hover:text-white'
                  }`}
                >
                  <span>🎯</span>
                  <span>{isRtl ? 'حزمة المشرف والمشاركة الخاصة' : 'Supervisor Pack & Private Sharing'}</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-purple-900/40 text-purple-300 border border-purple-500/30">
                    Gate 1.6
                  </span>
                  {currentOppBriefings.length > 0 && (
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                      {currentOppBriefings.length}
                    </span>
                  )}
                </button>
              </div>

              {/* Tab 1: Matrix */}
              {activeTab === 'matrix' && (
                <div className="space-y-4">
                  <div className="text-xs text-slate-400 flex items-center justify-between">
                    <span>{isRtl ? 'مطابقة متطلبات المنصب مع أدلة مشاريع ومؤهلات المترشح:' : 'Direct evidence mapping between doctoral vacancy prerequisites and candidate records:'}</span>
                    <span className="text-[11px] font-mono text-emerald-400 font-semibold">
                      {matrixData.matched_count} / {matrixData.total_requirements} {isRtl ? 'متطلبات مستوفاة' : 'requirements matched'}
                    </span>
                  </div>

                  <div className="overflow-x-auto rounded-xl border border-slate-800">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-950/80 text-slate-400 font-mono text-[10px] uppercase border-b border-slate-800">
                        <tr>
                          <th className="p-3 font-semibold">{isRtl ? 'متطلب الفرصة' : 'Opportunity Requirement'}</th>
                          <th className="p-3 font-semibold">{isRtl ? 'دليل المرشح (Candidate Evidence)' : 'Candidate Evidence'}</th>
                          <th className="p-3 font-semibold">{isRtl ? 'حالة المطابقة' : 'Status'}</th>
                          <th className="p-3 font-semibold">{isRtl ? 'تحليل الفجوة والإجراء' : 'Gap & Recommended Action'}</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 bg-slate-900/30">
                        {matrixData.matrix?.map((row, idx) => (
                          <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                            <td className="p-3 align-top min-w-[180px]">
                              <div className="font-bold text-white leading-snug">{row.requirement_name || row.requirement}</div>
                              <div className="text-[10px] text-slate-500 font-mono mt-0.5">{row.source_evidence}</div>
                            </td>
                            <td className="p-3 align-top min-w-[220px]">
                              <div className="text-slate-300 leading-relaxed">{row.candidate_evidence}</div>
                              <div className="mt-1">
                                <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded ${
                                  row.provenance?.includes('VERIFIED')
                                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                    : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                }`}>
                                  {row.provenance}
                                </span>
                              </div>
                            </td>
                            <td className="p-3 align-top whitespace-nowrap">
                              {getStatusBadge(row.match_status)}
                            </td>
                            <td className="p-3 align-top min-w-[200px]">
                              <div className="text-slate-400 text-[11px] leading-relaxed mb-1">{row.recommended_action || row.action}</div>
                              {row.action_url && (
                                <a
                                  href={row.action_url}
                                  className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 underline inline-flex items-center gap-1"
                                >
                                  <span>🚀</span>
                                  <span>{isRtl ? 'افتح المعمل في SecuraX' : 'Open in SecuraX Lab'}</span>
                                </a>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-[11px] text-slate-500 font-mono">
                    ℹ️ {matrixData.disclaimer}
                  </div>
                </div>
              )}

              {/* Tab 2: Document Curation */}
              {activeTab === 'documents' && (
                <div className="space-y-4">
                  <div className="text-xs text-slate-400">
                    {isRtl
                      ? 'حدد الوثائق المعتمدة لتضمينها في حزمة الترشح (ZIP) والملخص التنفيذي. لن يتم تصدير أي وثيقة خارج هذه القائمة:'
                      : 'Select curated documents to include in the submission bundle. Zero private notes or unapproved files will be exported:'}
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {docPool.map((doc, idx) => {
                      const isSelected = selectedDocs.includes(doc.file);
                      return (
                        <div
                          key={idx}
                          onClick={() => handleToggleDoc(doc.file)}
                          className={`p-3.5 rounded-xl border transition-all cursor-pointer flex items-start gap-3 ${
                            isSelected
                              ? 'bg-emerald-950/30 border-emerald-500/40 text-white'
                              : 'bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700'
                          }`}
                        >
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => {}}
                            className="mt-1 rounded bg-slate-900 border-slate-700 text-emerald-500 focus:ring-0"
                          />
                          <div className="flex-1 min-w-0">
                            <div className="text-xs font-bold leading-snug truncate">{doc.title || doc.file}</div>
                            <div className="text-[10px] font-mono text-slate-500 truncate mt-0.5">{doc.file}</div>
                            <div className="mt-1">
                              <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
                                {doc.provenance || '[VERIFIED EVIDENCE]'}
                              </span>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Tab 3: Faculty Outreach Pitch */}
              {activeTab === 'pitch' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-slate-400">
                      {isRtl ? 'مسودة الإيميل الموجهة للمشرف/لجنة القبول (قابلة للتعديل):' : 'Customized faculty outreach statement linking SecuraX to target lab:'}
                    </span>
                    <button
                      onClick={handleCopyPitch}
                      className="text-xs text-cyan-400 hover:text-cyan-300 font-bold inline-flex items-center gap-1"
                    >
                      {copied ? '✓ Copied!' : '📋 Copy Draft'}
                    </button>
                  </div>
                  <textarea
                    value={outreachText}
                    onChange={e => setOutreachText(e.target.value)}
                    className="w-full h-56 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 p-3.5 font-mono leading-relaxed resize-none focus:outline-none focus:border-emerald-500"
                  />
                  <div className="text-[11px] text-slate-500 font-mono">
                    🛡️ {isRtl ? 'تذكير أمني: SecuraX لا يقوم بالإرسال التلقائي. المراجعة اليدوية إلزامية.' : 'Privacy notice: SecuraX generates draft artifacts only. Manual candidate review required before submission.'}
                  </div>
                </div>
              )}

              {/* Tab 4: Gate 1.6 Supervisor Briefing & Private Sharing */}
              {activeTab === 'briefing' && (
                <div className="space-y-6">
                  {/* Gate 1.6 Privacy-by-Default Banner */}
                  <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-500/30 space-y-2">
                    <div className="flex items-center gap-2 text-sm font-bold text-purple-300">
                      <span>🛡️</span>
                      <span>{isRtl ? 'حزمة الإثبات الأكاديمي والمشاركة الخاصة للمشرفين (Gate 1.6)' : 'Private Supervisor Briefing Pack & Proof-of-Work Verification'}</span>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {isRtl
                        ? 'هذه الحزمة خاصة افتراضيًا (Private by default). يمكنك اختيار الأدلة الحقيقية والأكواد القابلة للتكرار بدقة لكل مشرف، وتوليد رابط سري مشفر ذي صلاحية مؤقتة. يمكنك إلغاء الرابط فورًا في أي وقت لقطع الوصول نهائيًا.'
                        : 'Private by default: build a tailored, cryptographically unguessable briefing link for a specific professor. You choose precisely which verified code artifacts, reproducible test commands, and academic records to share. Access can be revoked instantly at any time.'}
                    </p>
                    <div className="text-[10px] font-mono text-slate-400 flex items-center gap-3 pt-1">
                      <span>🔒 256-bit Entropy Tokens</span>
                      <span>•</span>
                      <span>🚫 Zero Database Leakage</span>
                      <span>•</span>
                      <span>⛔ Instant Revocation (HTTP 410)</span>
                    </div>
                  </div>

                  {/* Active Briefings Section */}
                  {currentOppBriefings.length > 0 && (
                    <div className="space-y-3">
                      <div className="text-xs font-bold text-white flex items-center gap-2">
                        <span>📡</span>
                        <span>{isRtl ? 'الحزم وروابط المشاركة الحالية لهذه الفرصة' : 'Active Briefing Packs for This Opportunity'}</span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-slate-800 text-slate-300">
                          {currentOppBriefings.length}
                        </span>
                      </div>

                      <div className="space-y-3">
                        {currentOppBriefings.map((b) => {
                          const isRevoked = Boolean(b.is_revoked);
                          const isExpired = b.expires_at && new Date(b.expires_at) < new Date();
                          const isActive = Boolean(b.is_shared) && !isRevoked && !isExpired;
                          const shareUrl = b.share_url ? `${window.location.origin}${b.share_url}` : `${window.location.origin}/reviewer?token=${b.share_token}`;

                          return (
                            <div
                              key={b.id}
                              className={`p-4 rounded-xl border transition-all ${
                                isActive
                                  ? 'bg-slate-950/70 border-purple-500/40 shadow-lg shadow-purple-950/20'
                                  : isRevoked
                                  ? 'bg-rose-950/10 border-rose-500/30'
                                  : 'bg-slate-950 border-slate-800'
                              }`}
                            >
                              <div className="flex flex-wrap items-start justify-between gap-3 mb-3">
                                <div>
                                  <div className="text-sm font-bold text-white flex items-center gap-2">
                                    <span>👤 {b.target_supervisor || 'Academic Supervisor'}</span>
                                    {isActive && (
                                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                                        ● ACTIVE SHARE
                                      </span>
                                    )}
                                    {isRevoked && (
                                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                                        ⛔ ACCESS REVOKED (HTTP 410)
                                      </span>
                                    )}
                                    {isExpired && !isRevoked && (
                                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                                        ⌛ EXPIRED (HTTP 410)
                                      </span>
                                    )}
                                  </div>
                                  <div className="text-[11px] text-slate-400 font-mono mt-1">
                                    <span>Created: {b.created_at ? new Date(b.created_at).toLocaleDateString() : 'Recent'}</span>
                                    {b.expires_at && (
                                      <span className="ml-3">
                                        · Expires: {new Date(b.expires_at).toLocaleDateString()}
                                      </span>
                                    )}
                                    {b.access_count !== undefined && (
                                      <span className="ml-3">
                                        · Requests: {b.access_count}
                                      </span>
                                    )}
                                  </div>
                                </div>

                                <div className="flex items-center gap-2">
                                  {isActive && (
                                    <button
                                      onClick={() => handleRevokeShare(b.id)}
                                      disabled={actionLoadingId === b.id}
                                      className="px-3 py-1.5 rounded-lg bg-rose-600/20 hover:bg-rose-600/30 text-rose-300 border border-rose-500/30 text-xs font-bold transition-all disabled:opacity-50 inline-flex items-center gap-1.5"
                                    >
                                      <span>⛔</span>
                                      <span>{isRtl ? 'إلغاء المشاركة فورًا' : 'Revoke Access'}</span>
                                    </button>
                                  )}
                                  {!isActive && (
                                    <button
                                      onClick={() => handleReShare(b.id)}
                                      disabled={actionLoadingId === b.id}
                                      className="px-3 py-1.5 rounded-lg bg-purple-600/20 hover:bg-purple-600/30 text-purple-300 border border-purple-500/30 text-xs font-bold transition-all disabled:opacity-50 inline-flex items-center gap-1.5"
                                    >
                                      <span>🔄</span>
                                      <span>{isRtl ? 'إعادة التفعيل برابط جديد' : 'Re-issue Secure Token'}</span>
                                    </button>
                                  )}
                                </div>
                              </div>

                              {isActive && (
                                <div className="space-y-2 pt-2 border-t border-slate-800">
                                  <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                                    {isRtl ? 'رابط المشاركة المشفر المخصص للمشرف:' : 'Private Unguessable Supervisor URL:'}
                                  </div>
                                  <div className="flex items-center gap-2">
                                    <input
                                      type="text"
                                      readOnly
                                      value={shareUrl}
                                      className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-cyan-300 selection:bg-cyan-900"
                                    />
                                    <button
                                      onClick={() => handleCopyShareUrl(b.share_token)}
                                      className="px-3 py-2 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/30 text-cyan-300 text-xs font-bold transition-all whitespace-nowrap"
                                    >
                                      {copiedToken === b.share_token ? '✓ Copied' : '📋 Copy'}
                                    </button>
                                    <a
                                      href={shareUrl}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="px-3 py-2 rounded-lg bg-purple-600/20 hover:bg-purple-600/30 border border-purple-500/30 text-purple-300 text-xs font-bold transition-all whitespace-nowrap inline-flex items-center gap-1"
                                    >
                                      <span>↗</span>
                                      <span>{isRtl ? 'معاينة المشرف' : 'View Portal'}</span>
                                    </a>
                                  </div>
                                  <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 text-[10px] font-mono text-slate-400 flex items-center justify-between">
                                    <span>Token: {b.share_token?.slice(0, 16)}...</span>
                                    <span>Git Commit: {portfolioData?.git_info?.commit_short || 'bb06123'}</span>
                                    <span className="text-emerald-400">Isolated Content Only</span>
                                  </div>
                                </div>
                              )}

                              {isRevoked && (
                                <div className="text-xs text-rose-400 font-mono pt-2 border-t border-rose-900/30 flex items-center gap-2">
                                  <span>🔒</span>
                                  <span>{isRtl ? 'تم سحب صلاحية هذا الرابط. سيحصل أي زائر على رمز الخطأ 410 Gone مع رسالة إغلاق الوصول.' : 'Access permanently revoked. Requests to this token return HTTP 410 Gone immediately.'}</span>
                                </div>
                              )}
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Create New Tailored Briefing Form */}
                  <div className="p-4 rounded-xl border border-slate-800 bg-slate-950 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="text-xs font-bold text-white flex items-center gap-2">
                        <span>✨</span>
                        <span>{isRtl ? 'تخصيص وإنشاء حزمة جديدة لمشرف محدد' : 'Create Tailored Briefing Pack for Specific Supervisor'}</span>
                      </div>
                      <span className="text-[10px] font-mono text-purple-400 bg-purple-950/40 px-2 py-0.5 rounded border border-purple-500/20">
                        Zero Leakage
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                      <div className="sm:col-span-2 space-y-1">
                        <label className="text-[11px] text-slate-400 font-semibold block">
                          {isRtl ? 'اسم المشرف / رئيس المختبر المستهدف:' : 'Target Academic Supervisor / Lab Director:'}
                        </label>
                        <input
                          type="text"
                          value={targetSupervisor}
                          onChange={e => setTargetSupervisor(e.target.value)}
                          placeholder="e.g. Prof. Dr. Christian Rossow / Admissions Committee"
                          className="w-full rounded-lg bg-slate-900 border border-slate-800 text-xs text-white px-3 py-2 focus:outline-none focus:border-purple-500"
                        />
                      </div>
                      <div className="space-y-1">
                        <label className="text-[11px] text-slate-400 font-semibold block">
                          {isRtl ? 'مدة صلاحية الرابط:' : 'Link Expiration Window:'}
                        </label>
                        <select
                          value={expiryDays}
                          onChange={e => setExpiryDays(Number(e.target.value))}
                          className="w-full rounded-lg bg-slate-900 border border-slate-800 text-xs text-white px-3 py-2 focus:outline-none focus:border-purple-500"
                        >
                          <option value={7}>7 {isRtl ? 'أيام' : 'Days'}</option>
                          <option value={14}>14 {isRtl ? 'يومًا (موصى به)' : 'Days (Recommended)'}</option>
                          <option value={30}>30 {isRtl ? 'يومًا' : 'Days'}</option>
                          <option value={90}>90 {isRtl ? 'يومًا' : 'Days'}</option>
                        </select>
                      </div>
                    </div>

                    {/* Proof-of-Work Evidence Checklist */}
                    <div className="space-y-2">
                      <label className="text-[11px] text-slate-400 font-semibold flex items-center justify-between">
                        <span>{isRtl ? 'اختر أدلة Proof-of-Work الحقيقية للمشاركة:' : 'Select Verified Proof-of-Work Artifacts to Include:'}</span>
                        <span className="text-[10px] font-mono text-emerald-400">
                          {selectedEvidenceIds.length} / {evidenceList.length || 5} {isRtl ? 'أدلة مختارة' : 'selected'}
                        </span>
                      </label>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-56 overflow-y-auto pr-1">
                        {evidenceList.map((item) => {
                          const isChecked = selectedEvidenceIds.includes(item.id);
                          return (
                            <div
                              key={item.id}
                              onClick={() => handleToggleEvidence(item.id)}
                              className={`p-2.5 rounded-lg border transition-all cursor-pointer flex items-start gap-2.5 ${
                                isChecked
                                  ? 'bg-purple-950/20 border-purple-500/40 text-white'
                                  : 'bg-slate-900/50 border-slate-800/80 text-slate-400 hover:border-slate-700'
                              }`}
                            >
                              <input
                                type="checkbox"
                                checked={isChecked}
                                onChange={() => {}}
                                className="mt-0.5 rounded bg-slate-900 border-slate-700 text-purple-500 focus:ring-0"
                              />
                              <div className="flex-1 min-w-0">
                                <div className="text-xs font-bold truncate leading-tight">{item.title}</div>
                                <div className="text-[10px] font-mono text-slate-500 truncate mt-0.5">
                                  {item.module} · {item.repo_path || item.type}
                                </div>
                                <div className="flex items-center gap-1.5 mt-1">
                                  <span className={`text-[9px] font-mono px-1.5 py-0.2 rounded ${
                                    item.verification_status === 'VERIFIED'
                                      ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                                      : 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                                  }`}>
                                    {item.verification_status}
                                  </span>
                                  {item.sha256 && (
                                    <span className="text-[9px] font-mono text-slate-500">
                                      SHA: {item.sha256.slice(0, 8)}...
                                    </span>
                                  )}
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Curated Documents Checklist */}
                    <div className="space-y-2">
                      <label className="text-[11px] text-slate-400 font-semibold block">
                        {isRtl ? 'الوثائق المعتمدة المرفقة بالحزمة:' : 'Curated Documents Attached to Pack:'}
                      </label>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {docPool.map((doc, idx) => {
                          const isSelected = selectedDocs.includes(doc.file);
                          return (
                            <div
                              key={idx}
                              onClick={() => handleToggleDoc(doc.file)}
                              className={`p-2.5 rounded-lg border transition-all cursor-pointer flex items-center gap-2.5 ${
                                isSelected
                                  ? 'bg-emerald-950/20 border-emerald-500/40 text-white'
                                  : 'bg-slate-900/50 border-slate-800/80 text-slate-400 hover:border-slate-700'
                              }`}
                            >
                              <input
                                type="checkbox"
                                checked={isSelected}
                                onChange={() => {}}
                                className="rounded bg-slate-900 border-slate-700 text-emerald-500 focus:ring-0"
                              />
                              <div className="flex-1 min-w-0">
                                <div className="text-xs font-semibold truncate leading-tight">{doc.title}</div>
                                <div className="text-[10px] font-mono text-slate-500 truncate">{doc.file}</div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    <button
                      onClick={handleCreateBriefing}
                      disabled={creatingBriefing}
                      className="w-full py-2.5 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-bold text-xs transition-all disabled:opacity-50 inline-flex items-center justify-center gap-2 shadow-lg shadow-purple-950/50"
                    >
                      {creatingBriefing ? <span className="animate-spin">⟳</span> : <span>🔒</span>}
                      <span>{isRtl ? 'إنشاء الحزمة وتوليد الرابط الخاص الآمن' : 'Generate Tailored Supervisor Pack & Private Link'}</span>
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>

        {/* Modal Footer / Action Buttons */}
        <div className="px-6 py-4 border-t border-slate-800 bg-slate-950 flex flex-wrap items-center justify-between gap-3">
          <div className="text-[11px] font-mono text-slate-500 flex items-center gap-2">
            <span>🛡️</span>
            <span>SHA-256 Manifest · ReportLab PDF Engine · Strict Provenance</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleExportPdf}
              disabled={loading || exportingPdf}
              className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white font-bold text-xs border border-slate-700 transition-all disabled:opacity-50 inline-flex items-center gap-2 shadow-md"
            >
              {exportingPdf ? <span className="animate-spin">⟳</span> : <span>📄</span>}
              <span>{isRtl ? 'تحميل تقرير PDF' : 'Download PDF Dossier'}</span>
            </button>

            <button
              onClick={handleExportZip}
              disabled={loading || exportingZip}
              className="px-4 py-2 rounded-xl bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 text-white font-bold text-xs transition-all disabled:opacity-50 inline-flex items-center gap-2 shadow-lg shadow-emerald-950/50"
            >
              {exportingZip ? <span className="animate-spin">⟳</span> : <span>📦</span>}
              <span>{isRtl ? 'تحميل الحزمة الكاملة (ZIP + Manifest)' : 'Export Full ZIP Bundle'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ─── Live Discovery View ─────────────────────────────────────────────────── */
function LiveDiscoveryView({ lang, onSaveToTracker, onOpenSkillJourney, onOpenDossier }) {
  const isRtl = lang === 'ar';
  const [query, setQuery] = useState('cybersecurity');
  const [results, setResults] = useState([]);
  const [sources, setSources] = useState([]);
  const [, setSourceStatus] = useState({});
  const [loading, setLoading] = useState(false);
  const [filterType, setFilterType] = useState('all');
  const [savedIds, setSavedIds] = useState(new Set());
  const [statusNote, setStatusNote] = useState('');
  const [isCached, setIsCached] = useState(false);
  const [showRegistry, setShowRegistry] = useState(true);
  const [runStats, setRunStats] = useState(null);

  const fetchSources = useCallback(() => {
    axios.get(`${API}/api/phd/discover/sources`, { withCredentials: true })
      .then(r => setSources(r.data.sources || []))
      .catch(() => {});
  }, []);

  const handleSearch = async (e) => {
    if (e) e.preventDefault();
    if (!query.trim()) return;
    setLoading(true);
    try {
      const res = await axios.post(`${API}/api/phd/discover`, { query: query.trim() }, { withCredentials: true });
      if (res.data?.ok) {
        setResults(res.data.results || []);
        setSourceStatus(res.data.source_status || {});
        setStatusNote(res.data.status_note || '');
        setIsCached(res.data.is_cached || false);
        setRunStats({
          sourcesAttempted: res.data.sources_attempted?.length || 0,
          newRecordsCount: res.data.new_records_count || 0,
          duplicatesMergedCount: res.data.duplicates_merged_count || 0,
          timestamp: res.data.search_timestamp,
        });
      }
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
      fetchSources();
    }
  };

  useEffect(() => {
    fetchSources();
    handleSearch();
  }, []);

  const handleSave = async (item) => {
    try {
      const res = await axios.post(`${API}/api/phd/discover/save`, {
        discovery_id: item.id,
        status: 'interested',
      }, { withCredentials: true });
      if (res.data?.ok) {
        setSavedIds(prev => new Set([...prev, item.id]));
        if (onSaveToTracker) onSaveToTracker(item);
      }
    } catch {
      /* ignore */
    }
  };

  const filteredResults = results.filter(r => {
    if (filterType === 'verified_vacancy') return r.record_type === 'verified_vacancy' || r.record_type === 'vacancy_lead';
    if (filterType === 'funded_research_project') return r.record_type === 'funded_research_project';
    if (filterType === 'research_lead') return r.record_type === 'research_lead';
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="p-6 rounded-2xl border border-violet-500/30 bg-slate-900/70 shadow-xl shadow-violet-950/20">
        <div className="flex items-center justify-between gap-4 mb-4 flex-wrap">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <span>🔭</span>
              <span>{isRtl ? 'محرك الاكتشاف الحي والمنح الرسمية (Live PhD Discovery)' : 'Live PhD Discovery & Verified Grants Engine'}</span>
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              {isRtl
                ? 'استعلام مباشر عبر بوابات الوظائف الأوروبية والبريطانية، والمراكز المعتمدة، وبوابات التمويل (NSF & OpenAlex). يتم الفصل النزيه بين مناصب الدكتوراه المؤكدة والمشاريع الممولة.'
                : 'Direct query across official European & UK vacancy portals, cybersecurity institutes, and grant databases. Strictly separates verified vacancies from funded research projects.'}
            </p>
          </div>
          {statusNote && (
            <div className={`px-3 py-1 rounded-full text-[11px] font-mono border ${isCached ? 'bg-amber-950/30 text-amber-300 border-amber-500/30' : 'bg-emerald-950/30 text-emerald-300 border-emerald-500/30'}`}>
              {statusNote}
            </div>
          )}
        </div>

        <form onSubmit={handleSearch} className="flex gap-2 mb-3">
          <input
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder={isRtl ? 'ابحث عن مجال بحثي (مثال: cybersecurity, vulnerability, AI security)...' : 'Search research keywords (e.g., cybersecurity, vulnerability, systems security)...'}
            className="flex-1 rounded-xl bg-slate-950 border border-slate-700 text-sm text-white px-4 py-2.5 focus:outline-none focus:border-violet-500 placeholder-slate-600 font-medium"
          />
          <button
            type="submit"
            disabled={loading}
            className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-violet-600 to-cyan-600 text-white font-bold text-xs hover:from-violet-500 hover:to-cyan-500 transition-all disabled:opacity-50 flex items-center gap-2"
          >
            {loading ? <span className="animate-spin">⟳</span> : <span>🔍</span>}
            <span>{isRtl ? 'تشغيل البحث الحي (Run Live Search)' : 'Run Live Search'}</span>
          </button>
        </form>

        {runStats && (
          <div className="mb-4 p-3 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between text-xs text-slate-300 flex-wrap gap-2 font-mono">
            <div>
              <span>📊 {isRtl ? 'نتائج الجولة الحية:' : 'Live Run Summary:'} </span>
              <span className="text-emerald-400 font-bold">{results.length} {isRtl ? 'فرصة مقبولة' : 'accepted'}</span>
              <span> · </span>
              <span className="text-cyan-400">{runStats.newRecordsCount} {isRtl ? 'سجل جديد' : 'new records'}</span>
              <span> · </span>
              <span className="text-amber-400">{runStats.duplicatesMergedCount} {isRtl ? 'تكرار موحّد' : 'duplicates merged'}</span>
            </div>
            <div className="text-[11px] text-slate-500">
              🕒 {new Date(runStats.timestamp).toLocaleTimeString()}
            </div>
          </div>
        )}

        <div className="pt-3 border-t border-slate-800/80">
          <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
            <span className="text-xs font-bold text-white flex items-center gap-1.5">
              <span>🌐</span>
              <span>{isRtl ? 'سجل شفافية مصادر البحث الـ 12 (Source Transparency Registry):' : 'Candidate Sources Transparency Registry (12 Portals):'}</span>
            </span>
            <button
              type="button"
              onClick={() => setShowRegistry(prev => !prev)}
              className="text-xs font-semibold text-violet-400 hover:text-violet-300 transition-colors flex items-center gap-1"
            >
              <span>{showRegistry ? (isRtl ? '▲ إخفاء تفاصيل المصادر' : '▲ Hide Source Registry') : (isRtl ? '▼ كشف تفاصيل وروابط المصادر الـ 12' : '▼ Reveal 12 Sources & Direct Links')}</span>
            </button>
          </div>

          {/* Quick status bar */}
          <div className="flex flex-wrap gap-2 items-center mb-3">
            {sources.map(s => {
              const isOk = s.status === 'ok';
              const isWaf = s.last_http_status === 403 || s.status === 'blocked_waf';
              const isNever = s.status === 'never_fetched';
              return (
                <div
                  key={s.id}
                  className={`text-[10px] px-2.5 py-1 rounded-lg border font-mono flex items-center gap-1.5 ${
                    isOk
                      ? 'bg-emerald-950/20 text-emerald-300 border-emerald-500/30'
                      : isWaf
                      ? 'bg-amber-950/20 text-amber-300 border-amber-500/30'
                      : isNever
                      ? 'bg-slate-800/40 text-slate-400 border-slate-700'
                      : 'bg-rose-950/20 text-rose-300 border-rose-500/30'
                  }`}
                >
                  <span className={`w-1.5 h-1.5 rounded-full ${isOk ? 'bg-emerald-400' : isWaf ? 'bg-amber-400' : isNever ? 'bg-slate-400' : 'bg-rose-400'}`} />
                  <span className="font-semibold">{s.name.split(' ')[0]}</span>
                  {s.last_http_status && <span className="opacity-75">[{s.last_http_status}]</span>}
                  {s.total_results > 0 && <span className="text-emerald-400 font-bold">({s.total_results})</span>}
                </div>
              );
            })}
          </div>

          {/* Detailed Registry Grid */}
          {showRegistry && (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 pt-2">
              {sources.map(s => {
                const isOk = s.status === 'ok';
                const isWaf = s.last_http_status === 403 || s.status === 'blocked_waf';
                const isNever = s.status === 'never_fetched';
                const typeColors = {
                  official_vacancy_portal: 'bg-emerald-950/40 text-emerald-300 border-emerald-500/30',
                  institution_career_page: 'bg-cyan-950/40 text-cyan-300 border-cyan-500/30',
                  funding_database: 'bg-blue-950/40 text-blue-300 border-blue-500/30',
                  research_metadata: 'bg-purple-950/40 text-purple-300 border-purple-500/30',
                  aggregator: 'bg-amber-950/40 text-amber-300 border-amber-500/30',
                };
                return (
                  <div key={s.id} className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col justify-between text-xs space-y-2">
                    <div>
                      <div className="flex items-start justify-between gap-2 mb-1.5">
                        <span className="font-bold text-white text-xs leading-snug">{s.name}</span>
                        <span className={`text-[9px] font-mono px-2 py-0.5 rounded border ${typeColors[s.source_type] || 'bg-slate-800 text-slate-300 border-slate-700'}`}>
                          {s.source_type?.replace(/_/g, ' ')}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-[10px] text-slate-400 font-mono mb-2">
                        <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800">
                          {s.access_method}
                        </span>
                        <span className={`px-1.5 py-0.5 rounded border font-bold ${
                          isOk ? 'bg-emerald-950 text-emerald-400 border-emerald-600/40' :
                          isWaf ? 'bg-amber-950 text-amber-400 border-amber-600/40' :
                          isNever ? 'bg-slate-800 text-slate-400 border-slate-700' :
                          'bg-rose-950 text-rose-400 border-rose-600/40'
                        }`}>
                          {isOk ? '200 OK' : isWaf ? '403 WAF Protected' : isNever ? 'Never Attempted' : `HTTP ${s.last_http_status || 'ERR'}`}
                        </span>
                      </div>
                      {s.coverage && (
                        <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed mb-1.5">
                          {s.coverage}
                        </p>
                      )}
                      {s.remediation_hint && (
                        <div className="p-2 rounded-lg bg-slate-900/90 border border-slate-800/90 text-[10px] text-cyan-300/90">
                          💡 {s.remediation_hint}
                        </div>
                      )}
                    </div>
                    <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[10px]">
                      <span className="font-mono text-slate-500">
                        {isRtl ? 'النتائج:' : 'Results:'} <strong className="text-white">{s.total_results || 0}</strong>
                      </span>
                      {s.direct_url && (
                        <a
                          href={s.direct_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="px-2 py-1 rounded bg-violet-600/20 hover:bg-violet-600/40 text-violet-300 border border-violet-500/30 font-semibold transition-all flex items-center gap-1"
                        >
                          <span>↗</span>
                          <span>{isRtl ? 'بحث مباشر' : 'Direct Search'}</span>
                        </a>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex gap-1.5 p-1 bg-slate-900 rounded-xl border border-slate-800 text-xs flex-wrap">
          <button
            onClick={() => setFilterType('all')}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all ${filterType === 'all' ? 'bg-slate-800 text-white' : 'text-slate-400 hover:text-white'}`}
          >
            {isRtl ? 'كل النتائج' : 'All Results'} ({results.length})
          </button>
          <button
            onClick={() => setFilterType('verified_vacancy')}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all flex items-center gap-1.5 ${filterType === 'verified_vacancy' ? 'bg-emerald-950/60 text-emerald-300 border border-emerald-500/40' : 'text-slate-400 hover:text-emerald-300'}`}
          >
            <span>🎯</span>
            <span>{isRtl ? 'مناصب دكتوراه معلنة' : 'Verified PhD Vacancies'}</span>
            <span className="text-[10px] font-mono px-1 rounded bg-emerald-500/20">
              {results.filter(r => r.record_type === 'verified_vacancy' || r.record_type === 'vacancy_lead').length}
            </span>
          </button>
          <button
            onClick={() => setFilterType('funded_research_project')}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all flex items-center gap-1.5 ${filterType === 'funded_research_project' ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-500/40' : 'text-slate-400 hover:text-cyan-300'}`}
          >
            <span>🔬</span>
            <span>{isRtl ? 'مشاريع بحثية ممولة (NSF)' : 'Funded Research Projects (Grants)'}</span>
            <span className="text-[10px] font-mono px-1 rounded bg-cyan-500/20">
              {results.filter(r => r.record_type === 'funded_research_project').length}
            </span>
          </button>
          <button
            onClick={() => setFilterType('research_lead')}
            className={`px-3 py-1.5 rounded-lg font-semibold transition-all flex items-center gap-1.5 ${filterType === 'research_lead' ? 'bg-violet-950/60 text-violet-300 border border-violet-500/40' : 'text-slate-400 hover:text-violet-300'}`}
          >
            <span>📚</span>
            <span>{isRtl ? 'أبحاث ومختبرات مرشحة (OpenAlex)' : 'Research Leads (Literature)'}</span>
            <span className="text-[10px] font-mono px-1 rounded bg-violet-500/20">
              {results.filter(r => r.record_type === 'research_lead').length}
            </span>
          </button>
        </div>

        <div className="text-xs text-slate-500 font-mono">
          {filteredResults.length} {isRtl ? 'سجل معروض' : 'records displayed'}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredResults.map(item => {
          const isVerified = item.record_type === 'verified_vacancy' || item.record_type === 'vacancy_lead';
          const isFundedProject = item.record_type === 'funded_research_project';
          const isSaved = savedIds.has(item.id);
          return (
            <div
              key={item.id}
              className={`rounded-2xl border p-5 transition-all flex flex-col justify-between ${
                isVerified
                  ? 'border-emerald-500/30 bg-slate-900/60 hover:border-emerald-500/50 hover:shadow-lg hover:shadow-emerald-950/20'
                  : isFundedProject
                  ? 'border-cyan-500/30 bg-slate-900/60 hover:border-cyan-500/50 hover:shadow-lg hover:shadow-cyan-950/20'
                  : 'border-slate-800 bg-slate-900/40 hover:border-violet-500/40 hover:shadow-md'
              }`}
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    {isVerified && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/15 text-emerald-300 border border-emerald-500/40">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                        <span>{isRtl ? 'منصب دكتوراه معلن' : 'VERIFIED PhD VACANCY'}</span>
                      </span>
                    )}
                    {isFundedProject && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-cyan-500/15 text-cyan-300 border border-cyan-500/40">
                        <span>🔬</span>
                        <span>{isRtl ? 'مشروع بحثي ممول (إشارة تمويل)' : 'FUNDED RESEARCH PROJECT (GRANT SIGNAL)'}</span>
                      </span>
                    )}
                    {!isVerified && !isFundedProject && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-violet-500/15 text-violet-300 border border-violet-500/40">
                        <span>📚</span>
                        <span>{isRtl ? 'مستخلص بحثي / توجيه أكاديمي' : 'RESEARCH LEAD (LITERATURE)'}</span>
                      </span>
                    )}

                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                      {item.source_name || item.source_id}
                    </span>
                  </div>

                  {item.deadline_status === 'active' && item.deadline && (
                    <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/30 px-2 py-0.5 rounded border border-emerald-500/20">
                      ⏳ {item.deadline}
                    </span>
                  )}
                </div>

                <h3 className="text-sm font-bold text-white mb-1.5 leading-snug line-clamp-2">
                  {item.program || item.description_snippet || 'Cybersecurity Research Opportunity'}
                </h3>

                <div className="text-xs text-slate-400 mb-3 flex items-center gap-2 flex-wrap">
                  <span className="text-white font-semibold">🏛️ {item.institution || 'Academic Institution'}</span>
                  <span>·</span>
                  <span>🌍 {item.country || 'Global'}</span>
                  {item.supervisor && (
                    <>
                      <span>·</span>
                      <span className="text-cyan-400">👤 {item.supervisor}</span>
                    </>
                  )}
                </div>

                {item.funding_evidence && (
                  <div className={`p-2.5 rounded-xl text-xs mb-3 leading-relaxed border ${
                    isVerified
                      ? 'bg-emerald-950/20 text-emerald-200/90 border-emerald-500/20'
                      : isFundedProject
                      ? 'bg-cyan-950/20 text-cyan-200/90 border-cyan-500/20'
                      : 'bg-slate-800/40 text-slate-400 border-slate-700/60'
                  }`}>
                    <div className="text-[9px] font-mono uppercase tracking-wider font-bold mb-0.5 text-slate-500">
                      {isRtl ? 'دليل التمويل والمصداقية الأكاديمية:' : 'Funding & Academic Evidence Semantics:'}
                    </div>
                    {item.funding_evidence}
                  </div>
                )}

                {item.deadline_raw && isFundedProject && (
                  <div className="text-[10px] font-mono text-amber-400/90 bg-amber-950/20 p-2 rounded-lg border border-amber-500/20 mb-3">
                    ℹ️ {item.deadline_raw}
                  </div>
                )}

                {item.description_snippet && (
                  <p className="text-[11px] text-slate-500 line-clamp-3 leading-relaxed mb-4">
                    {item.description_snippet}
                  </p>
                )}
              </div>

              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-2 flex-wrap">
                  <button
                    onClick={() => onOpenSkillJourney && onOpenSkillJourney(item)}
                    className="px-3 py-1.5 rounded-xl bg-violet-600/20 hover:bg-violet-600/40 text-violet-300 border border-violet-500/30 text-xs font-semibold transition-all inline-flex items-center gap-1.5"
                  >
                    <span>🎓</span>
                    <span>{isRtl ? 'الجاهزية والمهارات' : 'Skill Journey'}</span>
                  </button>

                  <button
                    onClick={() => onOpenDossier && onOpenDossier(item)}
                    className="px-3 py-1.5 rounded-xl bg-emerald-600/20 hover:bg-emerald-600/40 text-emerald-300 border border-emerald-500/30 text-xs font-semibold transition-all inline-flex items-center gap-1.5"
                  >
                    <span>📄</span>
                    <span>{isRtl ? 'ملف الترشح' : 'Dossier'}</span>
                  </button>

                  {item.application_url && (
                    <a
                      href={item.application_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-2.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-semibold transition-all inline-flex items-center gap-1"
                    >
                      <span>↗</span>
                      <span>{isRtl ? 'المصدر' : 'Source'}</span>
                    </a>
                  )}
                </div>

                <button
                  onClick={() => handleSave(item)}
                  disabled={isSaved}
                  className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition-all inline-flex items-center gap-1.5 ${
                    isSaved
                      ? 'bg-emerald-950/40 text-emerald-400 border border-emerald-500/30'
                      : 'bg-gradient-to-r from-violet-600 to-purple-600 text-white hover:from-violet-500 hover:to-purple-500 shadow-md shadow-violet-900/30'
                  }`}
                >
                  {isSaved ? <span>✓ {isRtl ? 'تم الحفظ في المتتبع' : 'Saved to Tracker'}</span> : <span>＋ {isRtl ? 'حفظ للمتتبع' : 'Save to Tracker'}</span>}
                </button>
              </div>
            </div>
          );
        })}

        {filteredResults.length === 0 && !loading && (
          <div className="col-span-full py-16 text-center text-slate-500 text-sm">
            {isRtl ? 'لا توجد نتائج مطابقة لبحثك' : 'No results found matching your search.'}
          </div>
        )}
      </div>
    </div>
  );
}

/* ─── Deadline Radar View ─────────────────────────────────────────────────── */
function DeadlineRadarView({ lang, onOpenSkillJourney, onOpenProposalHook, onOpenDossier }) {
  const isRtl = lang === 'ar';
  const [radar, setRadar] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios.get(`${API}/api/phd/radar`, { withCredentials: true })
      .then(r => setRadar(r.data.radar || null))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <div className="p-6 rounded-2xl border border-amber-500/30 bg-slate-900/70 shadow-xl flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <span>📡</span>
            <span>{isRtl ? 'رادار المواعيد الذكي والفرص الممولة' : 'Smart Deadline Radar & Funded Highlights'}</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-xl">
            {isRtl
              ? 'مراقبة المواعيد الحرجة (أقل من 45 يوم) والتقديم المفتوح (Rolling) والفرص ذات الأولوية العالية مع تصدير تقويم iCalendar.'
              : 'Live tracking of critical deadlines (< 45 days), rolling admissions, and top funded opportunities with iCalendar export.'}
          </p>
        </div>

        <a
          href={`${API}/api/phd/radar/export-ics`}
          target="_blank"
          rel="noopener noreferrer"
          className="px-4 py-2.5 rounded-xl bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 text-xs font-bold transition-all inline-flex items-center gap-2 shadow-lg shadow-amber-950/30"
        >
          <span>📅</span>
          <span>{isRtl ? 'تصدير للتقويم (.ICS)' : 'Export to iCalendar (.ICS)'}</span>
        </a>
      </div>

      {loading && (
        <div className="py-16 flex justify-center">
          <div className="w-8 h-8 border-2 border-amber-500 border-t-transparent rounded-full animate-spin" />
        </div>
      )}

      {!loading && radar && (
        <div className="space-y-6">
          {radar.critical_45d?.length > 0 && (
            <div className="p-5 rounded-2xl border border-rose-500/30 bg-rose-950/10">
              <h3 className="text-sm font-bold text-rose-400 mb-3 flex items-center gap-2">
                <span>🚨</span>
                <span>{isRtl ? 'مواعيد حرجة (أقل من 45 يوم)' : 'Critical Deadlines (< 45 Days)'}</span>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-rose-500/20">
                  {radar.critical_45d.length}
                </span>
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {radar.critical_45d.map(item => (
                  <div key={item.id} className="p-4 rounded-xl bg-slate-900/80 border border-rose-500/30 flex items-center justify-between gap-3">
                    <div>
                      <div className="text-xs font-bold text-white">{item.institution}</div>
                      <div className="text-[11px] text-slate-400">{item.country} · {item.field || item.program}</div>
                      <div className="text-[10px] font-mono text-rose-400 mt-1">⏳ {item.deadline_label}</div>
                    </div>
                    <div className="flex gap-1.5">
                      <button
                        onClick={() => onOpenProposalHook(item)}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-white border border-slate-700"
                      >
                        ✨ Hook
                      </button>
                      <button
                        onClick={() => onOpenDossier && onOpenDossier(item)}
                        className="px-2.5 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/40 text-xs text-emerald-300 border border-emerald-500/30"
                      >
                        📄 Dossier
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {radar.top_funded_high?.length > 0 && (
            <div className="p-5 rounded-2xl border border-emerald-500/30 bg-emerald-950/10">
              <h3 className="text-sm font-bold text-emerald-400 mb-3 flex items-center gap-2">
                <span>💰</span>
                <span>{isRtl ? 'فرص ممولة بالكامل ذات أولوية عالية' : 'Top Fully Funded Opportunities (High Priority)'}</span>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-500/20">
                  {radar.top_funded_high.length}
                </span>
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {radar.top_funded_high.map(item => (
                  <div key={item.id} className="p-4 rounded-xl bg-slate-900/80 border border-emerald-500/30 flex items-center justify-between gap-3">
                    <div>
                      <div className="text-xs font-bold text-white">{item.institution}</div>
                      <div className="text-[11px] text-slate-400">{item.country} · {item.funding_tier}</div>
                      {item.funding && <div className="text-[10px] text-emerald-400 font-mono mt-1">💵 {item.funding}</div>}
                    </div>
                    <div className="flex gap-1.5">
                      <button
                        onClick={() => onOpenSkillJourney(item)}
                        className="px-2.5 py-1.5 rounded-lg bg-violet-600/30 hover:bg-violet-600/50 text-xs text-violet-300 border border-violet-500/30"
                      >
                        🎓 Skills
                      </button>
                      <button
                        onClick={() => onOpenProposalHook(item)}
                        className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-white border border-slate-700"
                      >
                        ✨ Hook
                      </button>
                      <button
                        onClick={() => onOpenDossier && onOpenDossier(item)}
                        className="px-2.5 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/40 text-xs text-emerald-300 border border-emerald-500/30"
                      >
                        📄 Dossier
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ─── Upcoming step item ─────────────────────────────────────────────────── */
function UpcomingItem({ item }) {
  const daysKey = 'الأيام المتبقية';
  const days = item[daysKey];
  const urgent = days && parseInt(days) > 0 && parseInt(days) <= 7;
  return (
    <div className={`flex items-start gap-3 p-3 rounded-lg border transition-colors
      ${urgent ? 'border-amber-500/30 bg-amber-950/20' : 'border-slate-800 bg-slate-900/40'}`}>
      <div className={`text-xs font-mono font-bold shrink-0 w-8 text-center ${urgent ? 'text-amber-400' : 'text-slate-500'}`}>
        {days ? `${days}d` : '—'}
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-xs font-semibold text-white truncate">
          {item['الجهة'] || item['الفرصة / الحدث'] || '—'}
        </div>
        <div className="text-[10px] text-slate-500 mt-0.5 truncate">
          {item['المطلوب'] || item['الإجراء المطلوب'] || ''}
        </div>
      </div>
      {item['التاريخ'] && (
        <div className="text-[9px] text-slate-600 font-mono shrink-0">{item['التاريخ']?.slice?.(0, 10) || item['التاريخ']}</div>
      )}
    </div>
  );
}

/* ─── Application log item ────────────────────────────────────────────────── */
function AppLogItem({ app }) {
  return (
    <div className="flex items-start gap-3 p-3 rounded-lg border border-slate-800 bg-slate-900/40">
      <div className="text-[9px] text-slate-600 font-mono shrink-0 w-20">
        {(app['التاريخ'] || '').slice(0, 10)}
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-xs font-semibold text-white truncate">{app['الجهة / الأستاذ'] || '—'}</div>
        <div className="text-[10px] text-slate-500">{app['الإجراء'] || ''}</div>
      </div>
      <div className="text-[10px] text-cyan-400/70 shrink-0">{app['الحالة / الخطوة التالية']?.slice?.(0, 25) || ''}</div>
    </div>
  );
}

/* ─── Deduplication Audit Panel ───────────────────────────────────────────── */
function DeduplicationAuditPanel({ lang, onRefreshOpps }) {
  const isRtl = lang === 'ar';
  const [audit, setAudit] = useState(null);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState('');

  const fetchAudit = useCallback(() => {
    axios.get(`${API}/api/phd/dedup/audit`, { withCredentials: true })
      .then(r => { if (r.data?.ok) setAudit(r.data.audit); })
      .catch(() => {});
  }, []);

  useEffect(() => {
    fetchAudit();
  }, [fetchAudit]);

  const handleBackup = async () => {
    setLoading(true);
    setMsg('');
    try {
      const res = await axios.post(`${API}/api/phd/dedup/backup`, {}, { withCredentials: true });
      if (res.data?.ok) {
        setMsg(isRtl ? `✓ تم إنشاء نسخة احتياطية: ${res.data.backup_file}` : `✓ Backup created: ${res.data.backup_file}`);
      }
    } catch {
      setMsg(isRtl ? '✕ فشل إنشاء النسخة الاحتياطية' : '✕ Backup failed');
    } finally {
      setLoading(false);
    }
  };

  const handleApply = async () => {
    setLoading(true);
    setMsg('');
    try {
      const res = await axios.post(`${API}/api/phd/dedup/apply`, {}, { withCredentials: true });
      if (res.data?.ok) {
        setMsg(isRtl ? '✓ تم تطبيق توحيد التكرارات بنجاح دون حذف أي فرصة مختلفة.' : '✓ Deduplication applied successfully without deleting distinct vacancies.');
        fetchAudit();
        if (onRefreshOpps) onRefreshOpps();
      }
    } catch {
      setMsg(isRtl ? '✕ فشل تطبيق التوحيد' : '✕ Apply failed');
    } finally {
      setLoading(false);
    }
  };

  if (!audit) return null;

  return (
    <div className="rounded-2xl border border-violet-500/30 bg-slate-900/60 p-6 shadow-xl mb-4 space-y-4">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <span>🛡️</span>
            <span>{isRtl ? 'تدقيق وتوحيد سجلات ملفات الإكسيل (Workbook Deduplication & Provenance Audit)' : 'Workbook Deduplication & Provenance Audit (Gate 1.7)'}</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            {isRtl
              ? 'فحص شامل لـ 653 سجلاً فيزيائياً خاماً عبر ملفات الإكسيل. توحيد محافظ على الفرص المتطابقة مع إثراء السجل المعتمد، ووضع علامة مراجعة على المتشابهات دون حذف أي منصب دكتوراه مختلف.'
              : 'Audit of 653 raw physical records across all workbooks. Exact duplicates are merged non-destructively; fuzzy candidates are flagged for review without deleting distinct vacancies.'}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={handleBackup}
            disabled={loading}
            className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition-all flex items-center gap-1.5"
          >
            <span>📦</span>
            <span>{isRtl ? 'نسخة احتياطية (Backup)' : 'Create Backup'}</span>
          </button>
          <button
            onClick={handleApply}
            disabled={loading}
            className="px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-violet-600 to-cyan-600 text-white text-xs font-bold hover:from-violet-500 hover:to-cyan-500 transition-all flex items-center gap-1.5 shadow-md shadow-violet-900/30"
          >
            <span>🔄</span>
            <span>{isRtl ? 'إعادة تطبيق التوحيد (Apply Dedup)' : 'Apply Dedup'}</span>
          </button>
        </div>
      </div>

      {msg && (
        <div className="p-3 rounded-xl bg-violet-950/40 border border-violet-500/40 text-xs text-violet-300 font-mono">
          {msg}
        </div>
      )}

      {/* Metrics Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-center">
          <div className="text-[10px] font-mono text-slate-500 uppercase">{isRtl ? 'إجمالي السجلات الخام' : 'Raw Physical Rows'}</div>
          <div className="text-xl font-bold font-mono text-white mt-1">{audit.raw_physical_records}</div>
        </div>
        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-center">
          <div className="text-[10px] font-mono text-slate-500 uppercase">{isRtl ? 'السجلات المعتمدة الأساسية' : 'Authoritative Primary'}</div>
          <div className="text-xl font-bold font-mono text-cyan-400 mt-1">{audit.primary_authoritative_records}</div>
        </div>
        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-center">
          <div className="text-[10px] font-mono text-slate-500 uppercase">{isRtl ? 'سجلات ثانوية خام' : 'Raw Secondary'}</div>
          <div className="text-xl font-bold font-mono text-slate-300 mt-1">{audit.raw_secondary_parsed}</div>
        </div>
        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-center">
          <div className="text-[10px] font-mono text-slate-500 uppercase">{isRtl ? 'تكرارات متطابقة دُمجت' : 'Exact Merged'}</div>
          <div className="text-xl font-bold font-mono text-amber-400 mt-1">{audit.exact_duplicates_merged}</div>
        </div>
        <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-center">
          <div className="text-[10px] font-mono text-slate-500 uppercase">{isRtl ? 'متشابهات وُضعت للمراجعة' : 'Fuzzy Flagged'}</div>
          <div className="text-xl font-bold font-mono text-purple-400 mt-1">{audit.fuzzy_duplicates_flagged}</div>
        </div>
        <div className="p-3 rounded-xl bg-emerald-950/30 border border-emerald-500/30 text-center">
          <div className="text-[10px] font-mono text-emerald-400 uppercase font-bold">{isRtl ? 'الفرص الفريدة الموحدة' : 'Unique Consolidated'}</div>
          <div className="text-xl font-bold font-mono text-emerald-300 mt-1">{audit.consolidated_unique_records}</div>
        </div>
      </div>

      {/* Missing Fields Breakdown */}
      {audit.missing_fields && (
        <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800/80">
          <div className="text-xs font-bold text-white mb-2 flex items-center gap-1.5">
            <span>🔍</span>
            <span>{isRtl ? 'تحليل الحقول الناقصة عبر قاعدة البيانات (Missing Fields Integrity):' : 'Missing Fields Integrity Analysis:'}</span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs font-mono">
            <div className="p-2 rounded bg-slate-900 border border-slate-800 flex justify-between">
              <span className="text-slate-400">{isRtl ? 'بدون مؤسسة:' : 'No Institution:'}</span>
              <span className="text-amber-400 font-bold">{audit.missing_fields.institution}</span>
            </div>
            <div className="p-2 rounded bg-slate-900 border border-slate-800 flex justify-between">
              <span className="text-slate-400">{isRtl ? 'بدون دولة:' : 'No Country:'}</span>
              <span className="text-emerald-400 font-bold">{audit.missing_fields.country}</span>
            </div>
            <div className="p-2 rounded bg-slate-900 border border-slate-800 flex justify-between">
              <span className="text-slate-400">{isRtl ? 'بدون برنامج:' : 'No Program:'}</span>
              <span className="text-amber-400 font-bold">{audit.missing_fields.program}</span>
            </div>
            <div className="p-2 rounded bg-slate-900 border border-slate-800 flex justify-between">
              <span className="text-slate-400">{isRtl ? 'بدون موعد نهائي:' : 'No Deadline:'}</span>
              <span className="text-slate-300 font-bold">{audit.missing_fields.deadline}</span>
            </div>
            <div className="p-2 rounded bg-slate-900 border border-slate-800 flex justify-between">
              <span className="text-slate-400">{isRtl ? 'بدون تفاصيل تمويل:' : 'No Funding Info:'}</span>
              <span className="text-slate-300 font-bold">{audit.missing_fields.funding}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ─── Source Badge ────────────────────────────────────────────────────────── */
function SourceBadge({ src }) {
  if (src.role === 'primary') {
    return (
      <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-emerald-500/30 bg-emerald-950/20">
        <span className="text-emerald-400 text-xs font-bold">PRIMARY</span>
        <span className="text-[10px] text-emerald-300/70 font-mono truncate">{src.file}</span>
        <span className="text-emerald-400 text-xs font-mono ml-auto">{src.records} records</span>
      </div>
    );
  }
  return (
    <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-800 bg-slate-900/30">
      <span className="text-slate-500 text-[10px] font-bold uppercase">+ADD</span>
      <span className="text-[10px] text-slate-500 font-mono truncate">{src.file}</span>
      {src.new_records_added && <span className="text-slate-400 text-xs font-mono ml-auto">+{src.new_records_added}</span>}
      {src.error && <span className="text-red-400 text-[10px] ml-auto truncate">ERR: {src.error.slice(0, 30)}</span>}
    </div>
  );
}

/* ─── TABS ─────────────────────────────────────────────────────────────────── */
const TABS = [
  { id: 'opportunities', en: 'All Opportunities', ar: 'كل الفرص',       emoji: '🎯' },
  { id: 'discovery',     en: 'Live Discovery',    ar: 'اكتشاف حي',      emoji: '🔭' },
  { id: 'radar',         en: 'Deadline Radar',    ar: 'رادار المواعيد', emoji: '📡' },
  { id: 'upcoming',      en: 'Upcoming',          ar: 'خطوات قادمة',    emoji: '📅' },
  { id: 'applications',  en: 'Applications',      ar: 'سجل التقديمات',  emoji: '📋' },
  { id: 'profile',       en: 'Profile',           ar: 'ملفي',           emoji: '👤' },
  { id: 'sources',       en: 'Data Sources',      ar: 'مصادر البيانات', emoji: '📊' },
];

/* ─── Main Page ───────────────────────────────────────────────────────────── */
export default function PhdTrackerPage() {
  const { lang } = useLang();
  const isRtl = lang === 'ar';

  const [tab, setTab] = useState('opportunities');
  const [stats, setStats] = useState(null);
  const [opps, setOpps] = useState([]);
  const [upcoming, setUpcoming] = useState([]);
  const [applications, setApplications] = useState([]);
  const [profile, setProfile] = useState(null);
  const [documents, setDocuments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters & Search
  const [filterStatus, setFilterStatus] = useState('');
  const [filterPriority, setFilterPriority] = useState('');
  const [filterDeadline, setFilterDeadline] = useState('');
  const [searchQ, setSearchQ] = useState('');
  const [expandedId, setExpandedId] = useState(null);
  const [totalOpps, setTotalOpps] = useState(0);

  // Modals
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedOppForSkills, setSelectedOppForSkills] = useState(null);
  const [selectedOppForHook, setSelectedOppForHook] = useState(null);
  const [selectedOppForDossier, setSelectedOppForDossier] = useState(null);

  const debounceRef = useRef(null);

  const fetchStats = () => axios.get(`${API}/api/phd/stats`, { withCredentials: true });

  const fetchOpps = useCallback(() => {
    const params = new URLSearchParams();
    if (filterStatus)   params.set('status', filterStatus);
    if (filterPriority) params.set('priority', filterPriority);
    if (filterDeadline) params.set('deadline_status', filterDeadline);
    if (searchQ)        params.set('q', searchQ);
    params.set('limit', '60');
    return axios.get(`${API}/api/phd/opportunities?${params}`, { withCredentials: true });
  }, [filterStatus, filterPriority, filterDeadline, searchQ]);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      fetchStats(),
      fetchOpps(),
      axios.get(`${API}/api/phd/upcoming`,      { withCredentials: true }),
      axios.get(`${API}/api/phd/applications`,  { withCredentials: true }),
      axios.get(`${API}/api/phd/profile`,       { withCredentials: true }),
      axios.get(`${API}/api/phd/documents`,     { withCredentials: true }),
    ]).then(([sRes, oRes, uRes, aRes, pRes, dRes]) => {
      setStats(sRes.data.stats || null);
      setOpps(oRes.data.opportunities || []);
      setTotalOpps(oRes.data.total || 0);
      setUpcoming(uRes.data.upcoming || []);
      setApplications(aRes.data.applications || []);
      setProfile(pRes.data.profile || null);
      setDocuments(dRes.data.documents || []);
    })
    .catch(e => setError(e.response?.data?.error || e.message || 'Failed to load'))
    .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      fetchOpps().then(r => {
        setOpps(r.data.opportunities || []);
        setTotalOpps(r.data.total || 0);
      }).catch(() => {});
    }, 300);
    return () => clearTimeout(debounceRef.current);
  }, [filterStatus, filterPriority, filterDeadline, searchQ]);

  const handleExpand = (id) => setExpandedId(prev => prev === id ? null : id);

  const handleOppAdded = (newOpp) => {
    setOpps(prev => [newOpp, ...prev]);
    setTotalOpps(prev => prev + 1);
    fetchStats().then(r => setStats(r.data.stats)).catch(() => {});
  };

  const handleReload = async () => {
    setLoading(true);
    try {
      await axios.post(`${API}/api/phd/reload`, {}, { withCredentials: true });
      const [sRes, oRes] = await Promise.all([fetchStats(), fetchOpps()]);
      setStats(sRes.data.stats);
      setOpps(oRes.data.opportunities || []);
      setTotalOpps(oRes.data.total || 0);
    } catch {
      /* ignore */
    }
    finally { setLoading(false); }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-300" dir={isRtl ? 'rtl' : 'ltr'}>
      {showAddModal && (
        <AddOpportunityModal lang={lang} onClose={() => setShowAddModal(false)} onAdded={handleOppAdded} />
      )}

      {selectedOppForSkills && (
        <SkillJourneyModal
          opp={selectedOppForSkills}
          lang={lang}
          onClose={() => setSelectedOppForSkills(null)}
        />
      )}

      {selectedOppForHook && (
        <ProposalHookModal
          opp={selectedOppForHook}
          lang={lang}
          onClose={() => setSelectedOppForHook(null)}
        />
      )}

      {selectedOppForDossier && (
        <AcademicDossierModal
          opp={selectedOppForDossier}
          lang={lang}
          onClose={() => setSelectedOppForDossier(null)}
        />
      )}

      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-2 mb-4">
            <div className="h-px flex-1 bg-gradient-to-r from-transparent via-slate-700 to-transparent" />
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest px-3">PhD Intelligence CRM</span>
            <div className="h-px flex-1 bg-gradient-to-r from-transparent via-slate-700 to-transparent" />
          </div>

          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <h1 className="text-3xl sm:text-4xl font-black text-white">
                {isRtl ? 'متتبع ' : ''}
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-pink-400 via-violet-400 to-purple-500">
                  {isRtl ? 'الدكتوراه' : 'PhD'}
                </span>
                {isRtl ? ' الشخصي' : ' Tracker'}
              </h1>
              <p className="mt-1.5 text-slate-400 text-sm max-w-xl">
                {isRtl
                  ? 'نظام متكامل لمتابعة فرص الدكتوراه — البيانات الحقيقية من ملفاتك والاكتشاف الحي.'
                  : 'Integrated PhD opportunity tracker — real data from your XLSX files and live discovery.'}
              </p>
              {stats?.primary_file && (
                <div className="mt-2 text-[10px] text-slate-600 font-mono">
                  📁 {stats.primary_file} · {stats.total_opportunities} {isRtl ? 'فرصة' : 'opportunities'}
                </div>
              )}
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <button
                onClick={() => setShowAddModal(true)}
                className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-violet-600 to-purple-600 text-white text-xs font-bold hover:from-violet-500 hover:to-purple-500 transition-all shadow-lg shadow-violet-900/30"
              >
                <span>＋</span>
                {isRtl ? 'إضافة فرصة' : 'Add Opportunity'}
              </button>
              <button
                onClick={handleReload}
                className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-700 text-slate-400 text-xs font-semibold hover:border-slate-500 hover:text-white transition-all"
              >
                ↺ {isRtl ? 'تحديث' : 'Reload'}
              </button>
            </div>
          </div>
        </div>

        {/* Stats Row */}
        {!loading && stats && (
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 mb-6">
            <StatCard value={stats.total_opportunities} label={isRtl ? 'إجمالي' : 'Total'} color="text-violet-400" icon="🎯" />
            <StatCard value={stats.applied_count} label={isRtl ? 'مُقدَّم' : 'Applied'} color="text-emerald-400" icon="✓" />
            <StatCard value={stats.emailed_count} label={isRtl ? 'تواصل' : 'Emailed'} color="text-cyan-400" icon="✉" />
            <StatCard value={stats.active_opportunities} label={isRtl ? 'ساري' : 'Active'} color="text-amber-400" icon="⏳" />
            <StatCard value={stats.countries_count} label={isRtl ? 'دول' : 'Countries'} color="text-pink-400" icon="🌍" />
            <StatCard value={stats.documents_ready} label={isRtl ? 'وثائق' : 'Docs Ready'} color="text-blue-400" icon="📄" />
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-1 p-1 bg-slate-900 rounded-xl border border-slate-800 mb-6 overflow-x-auto">
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex-shrink-0 flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg text-xs font-semibold transition-all duration-200 ${
                tab === t.id
                  ? 'bg-slate-800 text-white shadow'
                  : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              <span>{t.emoji}</span>
              <span>{isRtl ? t.ar : t.en}</span>
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {loading && (
          <div className="py-20 flex flex-col items-center justify-center gap-3">
            <div className="w-8 h-8 border-2 border-violet-500 border-t-transparent rounded-full animate-spin" />
            <div className="text-xs text-slate-500 font-mono">Loading data...</div>
          </div>
        )}

        {error && (
          <div className="rounded-xl border border-red-500/30 bg-red-950/20 p-4 text-xs text-red-400 mb-6">
            ✕ {error}
          </div>
        )}

        {!loading && (
          <>
            {/* Opportunities Tab */}
            {tab === 'opportunities' && (
              <div>
                <div className="flex flex-col sm:flex-row gap-2 mb-4">
                  <input
                    type="text"
                    placeholder={isRtl ? '🔍 بحث في المؤسسات، البرامج، الدول...' : '🔍 Search institutions, programs, countries...'}
                    value={searchQ}
                    onChange={e => setSearchQ(e.target.value)}
                    className="flex-1 rounded-lg bg-slate-900 border border-slate-700 text-sm text-slate-200 placeholder-slate-600 px-3 py-2 focus:outline-none focus:border-violet-500"
                  />
                  <select
                    value={filterStatus}
                    onChange={e => setFilterStatus(e.target.value)}
                    className="rounded-lg bg-slate-900 border border-slate-700 text-sm text-slate-300 px-3 py-2 focus:outline-none focus:border-violet-500"
                  >
                    <option value="">{isRtl ? 'كل الحالات' : 'All Status'}</option>
                    {Object.entries(STATUS_CFG).map(([k, v]) => (
                      <option key={k} value={k}>{isRtl ? v.label_ar : v.label_en}</option>
                    ))}
                  </select>
                  <select
                    value={filterPriority}
                    onChange={e => setFilterPriority(e.target.value)}
                    className="rounded-lg bg-slate-900 border border-slate-700 text-sm text-slate-300 px-3 py-2 focus:outline-none focus:border-violet-500"
                  >
                    <option value="">{isRtl ? 'كل الأولويات' : 'All Priority'}</option>
                    {Object.entries(PRIORITY_CFG).map(([k, v]) => (
                      <option key={k} value={k}>{isRtl ? v.label_ar : v.label_en}</option>
                    ))}
                  </select>
                  <select
                    value={filterDeadline}
                    onChange={e => setFilterDeadline(e.target.value)}
                    className="rounded-lg bg-slate-900 border border-slate-700 text-sm text-slate-300 px-3 py-2 focus:outline-none focus:border-violet-500"
                  >
                    <option value="">{isRtl ? 'كل المواعيد' : 'All Deadlines'}</option>
                    {Object.entries(DEADLINE_CFG).map(([k, v]) => (
                      <option key={k} value={k}>{isRtl ? v.label_ar : v.label_en}</option>
                    ))}
                  </select>
                </div>

                <div className="text-xs text-slate-500 mb-3">
                  {isRtl
                    ? `عرض ${opps.length} من ${totalOpps} فرصة`
                    : `Showing ${opps.length} of ${totalOpps} opportunities`}
                  {(filterStatus || filterPriority || filterDeadline || searchQ) && (
                    <button onClick={() => { setFilterStatus(''); setFilterPriority(''); setFilterDeadline(''); setSearchQ(''); }}
                      className="ml-3 text-violet-400 hover:text-violet-300 underline">
                      {isRtl ? 'مسح الفلاتر' : 'Clear filters'}
                    </button>
                  )}
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  {opps.map(o => (
                    <OpportunityCard
                      key={o.id}
                      opp={o}
                      lang={lang}
                      onExpand={handleExpand}
                      expanded={expandedId === o.id}
                      onOpenSkillJourney={setSelectedOppForSkills}
                      onOpenProposalHook={setSelectedOppForHook}
                      onOpenDossier={setSelectedOppForDossier}
                    />
                  ))}
                </div>

                {opps.length === 0 && (
                  <div className="text-center py-16 text-slate-500 text-sm">
                    {isRtl ? 'لا توجد نتائج مطابقة' : 'No matching results'}
                  </div>
                )}
              </div>
            )}

            {/* Live Discovery Tab */}
            {tab === 'discovery' && (
              <LiveDiscoveryView
                lang={lang}
                onSaveToTracker={(_item) => {
                  fetchOpps().then(r => {
                    setOpps(r.data.opportunities || []);
                    setTotalOpps(r.data.total || 0);
                  });
                }}
                onOpenSkillJourney={setSelectedOppForSkills}
                onOpenDossier={setSelectedOppForDossier}
              />
            )}

            {/* Deadline Radar Tab */}
            {tab === 'radar' && (
              <DeadlineRadarView
                lang={lang}
                onOpenSkillJourney={setSelectedOppForSkills}
                onOpenProposalHook={setSelectedOppForHook}
                onOpenDossier={setSelectedOppForDossier}
              />
            )}

            {/* Upcoming Tab */}
            {tab === 'upcoming' && (
              <div>
                <div className="text-xs text-slate-500 mb-4">
                  {isRtl ? `${upcoming.length} خطوة قادمة` : `${upcoming.length} upcoming steps`}
                </div>
                <div className="space-y-2">
                  {upcoming.map((item, i) => <UpcomingItem key={i} item={item} lang={lang} />)}
                  {upcoming.length === 0 && (
                    <div className="text-center py-12 text-slate-500 text-sm">
                      {isRtl ? 'لا توجد خطوات قادمة' : 'No upcoming steps'}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Applications Tab */}
            {tab === 'applications' && (
              <div>
                <div className="text-xs text-slate-500 mb-4">
                  {isRtl ? `${applications.length} تقديم` : `${applications.length} applications`}
                </div>
                <div className="space-y-2">
                  {applications.map((app, i) => <AppLogItem key={i} app={app} lang={lang} />)}
                  {applications.length === 0 && (
                    <div className="text-center py-12 text-slate-500 text-sm">
                      {isRtl ? 'لا توجد تقديمات مسجّلة' : 'No applications logged'}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Profile Tab */}
            {tab === 'profile' && profile && (
              <div className="space-y-6">
                <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
                  <h2 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                    🎓 {isRtl ? 'الملف الأكاديمي' : 'Academic Profile'}
                  </h2>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {Object.entries(profile.fields || {}).map(([k, v]) => (
                      <div key={k} className="p-3 rounded-lg bg-slate-800/50 border border-slate-700/50">
                        <div className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">{k}</div>
                        <div className="text-xs text-white">{v}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {profile.references?.length > 0 && (
                  <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
                    <h2 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                      👥 {isRtl ? 'المرجعون' : 'References'}
                    </h2>
                    <div className="space-y-2">
                      {profile.references.map((ref, i) => (
                        <div key={i} className="flex items-center gap-3 p-3 rounded-lg bg-slate-800/40 border border-slate-700/40">
                          <div className="flex-1">
                            <div className="text-xs font-semibold text-white">{ref.name}</div>
                            <div className="text-[10px] text-cyan-400/70 font-mono">{ref.email}</div>
                          </div>
                          {ref.note && <div className="text-[10px] text-slate-500 text-right max-w-32">{ref.note}</div>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {documents.length > 0 && (
                  <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
                    <h2 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
                      📄 {isRtl ? 'الوثائق والملفات' : 'Documents & Files'}
                    </h2>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {documents.map((doc, i) => {
                        const isReady = doc.status && doc.status.includes('جاهز');
                        return (
                          <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-slate-800/40 border border-slate-700/40">
                            <span className={`text-xs mt-0.5 ${isReady ? 'text-emerald-400' : 'text-slate-500'}`}>
                              {isReady ? '✓' : '○'}
                            </span>
                            <div className="flex-1 min-w-0">
                              <div className="text-xs font-semibold text-white truncate">{doc.file}</div>
                              {doc.target && <div className="text-[10px] text-slate-500 truncate">{doc.target}</div>}
                            </div>
                            {doc.status && (
                              <span className={`text-[9px] font-mono shrink-0 ${isReady ? 'text-emerald-400' : 'text-slate-500'}`}>
                                {doc.status.slice(0, 15)}
                              </span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Sources Tab */}
            {tab === 'sources' && stats && (
              <div className="space-y-4">
                <DeduplicationAuditPanel
                  lang={lang}
                  onRefreshOpps={() => {
                    fetchOpps().then(r => {
                      setOpps(r.data.opportunities || []);
                      setTotalOpps(r.data.total || 0);
                    });
                    fetchStats();
                  }}
                />

                <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
                  <h2 className="text-sm font-bold text-white mb-1 flex items-center gap-2">
                    📊 {isRtl ? 'مصادر البيانات (Gate 1.3 — ADD-ONLY)' : 'Data Sources (Gate 1.3 — ADD-ONLY)'}
                  </h2>
                  <p className="text-[11px] text-slate-500 mb-4">
                    {isRtl
                      ? 'الملف الأساسي هو المرجع الوحيد. الملفات الثانوية تُضيف فقط بدون تغيير أي بيانات موجودة.'
                      : 'Primary file is the authoritative source. Secondary files ADD-ONLY without modifying existing data.'}
                  </p>
                  <div className="space-y-2">
                    {(stats.sources || []).map((src, i) => <SourceBadge key={i} src={src} />)}
                  </div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
                  <h2 className="text-sm font-bold text-white mb-4">📈 {isRtl ? 'إثبات عدد السجلات' : 'Record Count Evidence'}</h2>
                  <div className="space-y-2">
                    {Object.entries(stats.record_counts || {}).map(([file, count]) => (
                      <div key={file} className="flex items-center justify-between p-2 rounded-lg bg-slate-800/40">
                        <span className="text-[10px] text-slate-500 font-mono truncate max-w-xs">{file}</span>
                        <span className="text-sm font-mono font-bold text-white">{count}</span>
                      </div>
                    ))}
                    <div className="flex items-center justify-between p-2 rounded-lg bg-violet-900/20 border border-violet-500/20 mt-3">
                      <span className="text-xs text-violet-400 font-bold">{isRtl ? 'المجموع الكلي' : 'TOTAL IMPORTED'}</span>
                      <span className="text-lg font-mono font-black text-violet-400">{stats.total_opportunities}</span>
                    </div>
                  </div>
                </div>

                <div className="rounded-xl border border-slate-800 bg-slate-900/50 p-6">
                  <h2 className="text-sm font-bold text-white mb-4">🗂️ {isRtl ? 'توزيع الحالات' : 'Status Breakdown'}</h2>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                    {Object.entries(stats.by_status || {}).map(([st, cnt]) => {
                      const cfg = STATUS_CFG[st] || STATUS_CFG.researching;
                      return (
                        <div key={st} className={`p-3 rounded-lg border ${cfg.cls} flex items-center justify-between`}>
                          <span className="text-xs font-semibold">{isRtl ? cfg.label_ar : cfg.label_en}</span>
                          <span className="text-lg font-mono font-black">{cnt}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
