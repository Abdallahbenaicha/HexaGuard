import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { useLang } from '../context/LangContext';

const API = import.meta.env.VITE_API_BASE_URL || '';

/* ── Helpers ─────────────────────────────────────────────────────────────── */
const statusConfig = {
  complete:    { label_en: 'Complete',    label_ar: 'مكتمل',    cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' },
  in_progress: { label_en: 'In Progress', label_ar: 'جارٍ',     cls: 'bg-amber-500/10  text-amber-400  border-amber-500/30'  },
  planned:     { label_en: 'Planned',     label_ar: 'مخطط',     cls: 'bg-slate-500/10  text-slate-400  border-slate-500/30'  },
};

function StatusBadge({ status, lang }) {
  const cfg = statusConfig[status] || statusConfig.planned;
  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase tracking-wider ${cfg.cls}`}>
      {lang === 'ar' ? cfg.label_ar : cfg.label_en}
    </span>
  );
}

function TechTag({ tag }) {
  return (
    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
      {tag}
    </span>
  );
}

/* ── Phase Card ──────────────────────────────────────────────────────────── */
function PhaseCard({ phase, lang, isExpanded, onToggle }) {
  const isRtl = lang === 'ar';
  const title = isRtl ? phase.title_ar : phase.title_en;
  const summary = isRtl ? phase.summary_ar : phase.summary_en;

  return (
    <div
      className="group relative rounded-2xl border border-slate-800 bg-slate-900/60 backdrop-blur overflow-hidden transition-all duration-300 hover:border-slate-600 hover:shadow-2xl cursor-pointer"
      style={{ borderLeftColor: phase.color, borderLeftWidth: '3px' }}
      onClick={onToggle}
      dir={isRtl ? 'rtl' : 'ltr'}
    >
      {/* Glow accent */}
      <div
        className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none"
        style={{ background: `radial-gradient(ellipse at ${isRtl ? 'right' : 'left'} top, ${phase.color}12 0%, transparent 60%)` }}
      />

      {/* Header */}
      <div className="relative px-6 pt-5 pb-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div
              className="w-10 h-10 rounded-xl flex items-center justify-center text-lg flex-shrink-0"
              style={{ background: `${phase.color}20`, border: `1px solid ${phase.color}40` }}
            >
              {phase.emoji}
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">
                  Phase {phase.order} — {phase.date_label}
                </span>
                <StatusBadge status={phase.status} lang={lang} />
              </div>
              <h3 className="text-base font-bold text-white mt-0.5 leading-snug">{title}</h3>
            </div>
          </div>

          {/* Expand chevron */}
          <svg
            className={`w-4 h-4 text-slate-500 flex-shrink-0 mt-1 transition-transform duration-300 ${isExpanded ? 'rotate-180' : ''}`}
            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </div>

        {/* Summary always visible */}
        <p className="mt-3 text-sm text-slate-400 leading-relaxed">{summary}</p>

        {/* Tech tags */}
        {phase.tech_tags?.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mt-3">
            {phase.tech_tags.map(t => <TechTag key={t} tag={t} />)}
          </div>
        )}
      </div>

      {/* Expanded content */}
      {isExpanded && (
        <div className="px-6 pb-6 space-y-4 border-t border-slate-800 pt-4">
          {/* Decisions */}
          {phase.decisions?.length > 0 && (
            <div>
              <h4 className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">
                {lang === 'ar' ? '⚡ قرارات معمارية' : '⚡ Architectural Decisions'}
              </h4>
              <div className="space-y-2">
                {phase.decisions.map(d => (
                  <div key={d.key} className="flex gap-2 items-start">
                    <span className="text-[10px] font-bold text-slate-500 mt-0.5 font-mono flex-shrink-0">{d.key}</span>
                    <span className="text-xs text-slate-300 leading-relaxed">
                      {lang === 'ar' ? d.text_ar : d.text_en}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Lessons */}
          {phase.lessons?.length > 0 && (
            <div>
              <h4 className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">
                {lang === 'ar' ? '📘 دروس مستفادة' : '📘 Lessons Learned'}
              </h4>
              <div className="space-y-1.5">
                {phase.lessons.map((l, i) => (
                  <div key={i} className="flex gap-2 items-start">
                    <span className="text-emerald-400 text-xs mt-0.5 flex-shrink-0">✓</span>
                    <span className="text-xs text-slate-300 leading-relaxed">
                      {lang === 'ar' ? l.text_ar : l.text_en}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Key files */}
          {phase.key_files?.length > 0 && (
            <div>
              <h4 className="text-[10px] font-bold uppercase tracking-widest text-slate-500 mb-2">
                {lang === 'ar' ? '📁 الملفات الرئيسية' : '📁 Key Files'}
              </h4>
              <div className="flex flex-wrap gap-1.5">
                {phase.key_files.map(f => (
                  <span key={f} className="text-[10px] font-mono px-2 py-1 rounded bg-slate-950 text-cyan-400 border border-cyan-900/40">
                    {f}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ── Stats Banner ─────────────────────────────────────────────────────────── */
function StatBanner({ stats, lang }) {
  if (!stats) return null;
  const items = [
    { label: lang === 'ar' ? 'مراحل' : 'Phases',    val: stats.total_phases,    color: 'text-cyan-400' },
    { label: lang === 'ar' ? 'مكتمل' : 'Complete',   val: stats.complete,        color: 'text-emerald-400' },
    { label: lang === 'ar' ? 'جارٍ' : 'In Progress', val: stats.in_progress,    color: 'text-amber-400' },
    { label: lang === 'ar' ? 'قرارات' : 'Decisions', val: stats.total_decisions, color: 'text-purple-400' },
    { label: lang === 'ar' ? 'دروس' : 'Lessons',     val: stats.total_lessons,  color: 'text-pink-400' },
  ];
  return (
    <div className="grid grid-cols-3 sm:grid-cols-5 gap-3 mb-8">
      {items.map(item => (
        <div key={item.label} className="rounded-xl border border-slate-800 bg-slate-900/50 p-3 text-center">
          <div className={`text-2xl font-black font-mono ${item.color}`}>{item.val}</div>
          <div className="text-[10px] text-slate-500 uppercase tracking-wider mt-0.5">{item.label}</div>
        </div>
      ))}
    </div>
  );
}

/* ── Page ─────────────────────────────────────────────────────────────────── */
export default function JourneyPage() {
  const { lang } = useLang();
  const [phases, setPhases] = useState([]);
  const [stats, setStats]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]   = useState(null);
  const [expanded, setExpanded] = useState({});

  useEffect(() => {
    Promise.all([
      axios.get(`${API}/api/journey`, { withCredentials: true }),
      axios.get(`${API}/api/journey/meta/stats`, { withCredentials: true }),
    ])
      .then(([pRes, sRes]) => {
        setPhases(pRes.data.phases || []);
        setStats(sRes.data.stats || null);
      })
      .catch(e => setError(e.response?.data?.error || 'Failed to load'))
      .finally(() => setLoading(false));
  }, []);

  const togglePhase = id => setExpanded(prev => ({ ...prev, [id]: !prev[id] }));

  const isRtl = lang === 'ar';

  return (
    <div className="space-y-6 animate-in fade-in duration-300" dir={isRtl ? 'rtl' : 'ltr'}>
      <div className="max-w-4xl mx-auto">

        {/* Page Header */}
        <div className="mb-8">
          <div className="flex items-center gap-2 mb-3">
            <div className="h-px flex-1 bg-gradient-to-r from-transparent via-slate-700 to-transparent" />
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest px-3">Build Journey</span>
            <div className="h-px flex-1 bg-gradient-to-r from-transparent via-slate-700 to-transparent" />
          </div>
          <h1 className="text-3xl sm:text-4xl font-black text-white leading-tight">
            {isRtl ? 'كيف بُنيَ ' : 'How '}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-purple-500">SecuraX</span>
            {isRtl ? '' : ' Was Built'}
          </h1>
          <p className="mt-3 text-slate-400 text-sm max-w-xl">
            {isRtl
              ? 'رحلة البناء الكاملة: القرارات المعمارية، الدروس المستفادة، والملفات المرجعية لكل مرحلة.'
              : 'The complete build journey: architectural decisions, lessons learned, and key files for each phase.'}
          </p>
        </div>

        {/* Stats */}
        <StatBanner stats={stats} lang={lang} />

        {/* Content */}
        {loading && (
          <div className="flex justify-center py-20">
            <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          </div>
        )}

        {error && (
          <div className="rounded-xl border border-red-800 bg-red-950/40 p-6 text-center text-red-400 text-sm">
            {error}
          </div>
        )}

        {!loading && !error && (
          <div className="space-y-4">
            {phases.map(phase => (
              <PhaseCard
                key={phase.id}
                phase={phase}
                lang={lang}
                isExpanded={!!expanded[phase.id]}
                onToggle={() => togglePhase(phase.id)}
              />
            ))}
          </div>
        )}

        {/* Footer note */}
        <div className="mt-10 text-center text-[11px] text-slate-600">
          {isRtl
            ? 'هذه الصفحة نفسها جزء من مرحلة Gate 1 في رحلة البناء.'
            : 'This page itself is part of Gate 1 in the build journey.'}
        </div>
      </div>
    </div>
  );
}
