import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useLang } from '../context/LangContext';

const API = import.meta.env.VITE_API_BASE_URL || '';

/* ── Severity config ─────────────────────────────────────────────────────── */
const SEV = {
  critical: { cls: 'bg-red-500/10 text-red-400 border-red-500/30',     dot: 'bg-red-500' },
  high:     { cls: 'bg-orange-500/10 text-orange-400 border-orange-500/30', dot: 'bg-orange-500' },
  medium:   { cls: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30', dot: 'bg-yellow-500' },
  low:      { cls: 'bg-sky-500/10 text-sky-400 border-sky-500/30',       dot: 'bg-sky-500' },
  info:     { cls: 'bg-slate-500/10 text-slate-400 border-slate-500/30', dot: 'bg-slate-400' },
};

function SevBadge({ sev }) {
  const cfg = SEV[sev] || SEV.info;
  return (
    <span className={`flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full border ${cfg.cls}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {sev}
    </span>
  );
}

/* ── Category filter pill ─────────────────────────────────────────────────── */
function CatPill({ cat, active, onClick, lang }) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold transition-all duration-200 border ${
        active
          ? 'border-cyan-500 bg-cyan-500/15 text-cyan-300'
          : 'border-slate-700 bg-slate-900 text-slate-400 hover:border-slate-500 hover:text-slate-200'
      }`}
    >
      {lang === 'ar' ? cat.label_ar : cat.label_en}
    </button>
  );
}

/* ── Intel Item Card ─────────────────────────────────────────────────────── */
function IntelCard({ item, lang }) {
  const isRtl = lang === 'ar';
  const title = (isRtl && item.title_ar) ? item.title_ar : item.title;

  return (
    <div
      className="group rounded-xl border border-slate-800 bg-slate-900/60 p-4 hover:border-slate-600 transition-all duration-200 hover:shadow-lg"
      dir={isRtl ? 'rtl' : 'ltr'}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1.5">
            <SevBadge sev={item.severity} />
            {item.kev && (
              <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-red-600/20 text-red-400 border border-red-600/30 uppercase">KEV</span>
            )}
            {item.epss != null && (
              <span className="text-[10px] font-mono text-purple-400">EPSS {(item.epss * 100).toFixed(0)}%</span>
            )}
          </div>
          <h3 className="text-sm font-semibold text-white leading-snug line-clamp-2 group-hover:text-cyan-300 transition-colors">
            {title}
          </h3>
          <div className="flex items-center gap-2 mt-1.5 flex-wrap">
            <span className="text-[10px] text-slate-500">{item.source}</span>
            <span className="text-[10px] text-slate-600">·</span>
            <span className="text-[10px] text-slate-500">{item.published}</span>
          </div>
          {item.tags?.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {item.tags.slice(0, 4).map(t => (
                <span key={t} className="text-[9px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">#{t}</span>
              ))}
            </div>
          )}
        </div>
        {item.source_url && (
          <a
            href={item.source_url}
            target="_blank"
            rel="noopener noreferrer"
            onClick={e => e.stopPropagation()}
            className="flex-shrink-0 p-1.5 rounded-md bg-slate-800 text-slate-400 hover:bg-cyan-900/50 hover:text-cyan-400 transition-colors"
            title="Open source"
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
            </svg>
          </a>
        )}
      </div>
    </div>
  );
}

/* ── Stats row ───────────────────────────────────────────────────────────── */
function StatsRow({ stats, lang }) {
  if (!stats) return null;
  const isRtl = lang === 'ar';
  const items = [
    { label: isRtl ? 'إجمالي العناصر' : 'Total Items',  val: stats.total_items,  color: 'text-cyan-400' },
    { label: isRtl ? 'CVE / KEV'      : 'CVE + KEV',    val: (stats.by_category?.cve || 0) + (stats.by_category?.kev || 0), color: 'text-red-400' },
    { label: isRtl ? 'حرج'            : 'Critical',     val: stats.by_severity?.critical || 0, color: 'text-red-400' },
    { label: isRtl ? 'KEV موثق'       : 'KEV Items',    val: stats.kev_items, color: 'text-orange-400' },
    { label: isRtl ? 'فئات'           : 'Categories',   val: stats.categories, color: 'text-purple-400' },
  ];
  return (
    <div className="grid grid-cols-3 sm:grid-cols-5 gap-3 mb-6" dir={isRtl ? 'rtl' : 'ltr'}>
      {items.map(i => (
        <div key={i.label} className="rounded-xl border border-slate-800 bg-slate-900/50 p-3 text-center">
          <div className={`text-2xl font-black font-mono ${i.color}`}>{i.val}</div>
          <div className="text-[10px] text-slate-500 uppercase tracking-wider mt-0.5">{i.label}</div>
        </div>
      ))}
    </div>
  );
}

/* ── Page ─────────────────────────────────────────────────────────────────── */
export default function IntelligencePage() {
  const { lang } = useLang();
  const [feeds, setFeeds]     = useState([]);
  const [items, setItems]     = useState([]);
  const [stats, setStats]     = useState(null);
  const [activeCat, setActiveCat] = useState('');
  const [search, setSearch]   = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  const isRtl = lang === 'ar';

  useEffect(() => {
    Promise.all([
      axios.get(`${API}/api/intelligence/feeds`, { withCredentials: true }),
      axios.get(`${API}/api/intelligence/stats`, { withCredentials: true }),
    ]).then(([fRes, sRes]) => {
      setFeeds(fRes.data.feeds || []);
      setStats(sRes.data.stats || null);
    }).catch(() => {});
  }, []);

  const loadItems = useCallback((cat, q) => {
    setLoading(true);
    const endpoint = q.length >= 2
      ? `${API}/api/intelligence/search?q=${encodeURIComponent(q)}`
      : `${API}/api/intelligence/recent?category=${encodeURIComponent(cat)}&limit=50`;
    axios.get(endpoint, { withCredentials: true })
      .then(r => setItems(r.data.items || []))
      .catch(e => setError(e.response?.data?.error || 'Failed to load'))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { loadItems(activeCat, search); }, [activeCat, search, loadItems]);

  return (
    <div className="space-y-6 animate-in fade-in duration-300" dir={isRtl ? 'rtl' : 'ltr'}>
      <div className="max-w-4xl mx-auto">

        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-2 mb-3">
            <div className="h-px flex-1 bg-gradient-to-r from-transparent via-slate-700 to-transparent" />
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest px-3">Cyber Intelligence</span>
            <div className="h-px flex-1 bg-gradient-to-r from-transparent via-slate-700 to-transparent" />
          </div>
          <h1 className="text-3xl sm:text-4xl font-black text-white">
            {isRtl ? 'مركز ' : ''}
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-400 to-orange-400">
              {isRtl ? 'الاستخبارات السيبرانية' : 'Cyber Intelligence'}
            </span>
            {!isRtl && ' Center'}
          </h1>
          <p className="mt-2 text-slate-400 text-sm max-w-xl">
            {isRtl
              ? 'CVE حية، CISA KEV، إرشادات أمنية، أبحاث، أدوات، لوائح، مؤتمرات وحوادث — في مكان واحد.'
              : 'Live CVEs, CISA KEV, advisories, research, tools, regulations, conferences & incidents — all in one place.'}
          </p>
        </div>

        {/* Stats */}
        <StatsRow stats={stats} lang={lang} />

        {/* Search */}
        <div className="relative mb-5">
          <svg className={`absolute top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 ${isRtl ? 'right-3' : 'left-3'}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            value={search}
            onChange={e => { setSearch(e.target.value); setActiveCat(''); }}
            placeholder={isRtl ? 'ابحث بالكلمة المفتاحية...' : 'Search by keyword, CVE ID, tag...'}
            className={`w-full bg-slate-900 border border-slate-700 rounded-xl py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors ${isRtl ? 'pr-9 pl-4' : 'pl-9 pr-4'}`}
          />
        </div>

        {/* Category filters */}
        {!search && (
          <div className="flex flex-wrap gap-2 mb-6">
            <CatPill
              cat={{ label_en: 'All Feeds', label_ar: 'الكل' }}
              active={activeCat === ''}
              onClick={() => setActiveCat('')}
              lang={lang}
            />
            {feeds.map(f => (
              <CatPill key={f.id} cat={f} active={activeCat === f.id} onClick={() => setActiveCat(f.id)} lang={lang} />
            ))}
          </div>
        )}

        {/* Items grid */}
        {loading ? (
          <div className="flex justify-center py-16">
            <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : error ? (
          <div className="rounded-xl border border-red-800 bg-red-950/40 p-6 text-center text-red-400 text-sm">{error}</div>
        ) : items.length === 0 ? (
          <div className="text-center py-16 text-slate-500">
            {isRtl ? 'لا توجد نتائج.' : 'No items found.'}
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {items.map(item => (
              <IntelCard key={item.id} item={item} lang={lang} />
            ))}
          </div>
        )}

        {/* ARIA callout */}
        <div className="mt-8 rounded-xl border border-purple-800/40 bg-purple-950/20 p-4">
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 rounded-lg bg-purple-900/50 flex items-center justify-center text-purple-400 flex-shrink-0">✦</div>
            <div>
              <div className="text-sm font-semibold text-purple-300">
                {isRtl ? 'ARIA AI — التوليف الاستخباراتي' : 'ARIA AI — Intelligence Synthesis'}
              </div>
              <div className="text-xs text-slate-400 mt-0.5">
                {isRtl
                  ? 'لتحليل عميق عبر المصادر، اسأل ARIA مباشرة في صفحة المحادثة.'
                  : 'For deep cross-source analysis, ask ARIA directly from the Chat page.'}
              </div>
            </div>
          </div>
        </div>

        {/* Source note */}
        <div className="mt-4 text-center text-[11px] text-slate-600">
          {isRtl
            ? 'البيانات: NVD / CISA KEV / arXiv / FIRST. التحديث الحي يتطلب تكوين مفاتيح API.'
            : 'Data: NVD / CISA KEV / arXiv / FIRST. Live refresh requires API key configuration.'}
        </div>
      </div>
    </div>
  );
}
