import { useState, useMemo, useRef } from 'react';
import {
  BookOpen, Search, ChevronDown, ChevronUp,
  ExternalLink, Shield, Filter, X, AlertTriangle,
  Zap, Code, Globe, Lock, Package, Settings,
  Layers, Mail, Layout,
} from 'lucide-react';
import {
  SCANNER_TABS,
  VULN_LIBRARY,
  DIFFICULTY_META,
  getSortedVulns,
  searchAllVulns,
} from '../utils/vulnLibraryData';

// ── Icon map per scanner tab ────────────────────────────────────────────────
const SCANNER_ICONS = {
  dast:      Zap,
  sast:      Code,
  network:   Globe,
  ssl:       Lock,
  deps:      Package,
  server:    Settings,
  docker:    Layers,
  dns:       Mail,
  wordpress: Layout,
};

// ── Difficulty Badge ─────────────────────────────────────────────────────────
function DifficultyBadge({ level }) {
  const meta = DIFFICULTY_META[level] || DIFFICULTY_META.medium;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-bold rounded-full border ${meta.color}`}>
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${meta.dot}`} />
      {level.charAt(0).toUpperCase() + level.slice(1)}
    </span>
  );
}

// ── Resource Link Button ──────────────────────────────────────────────────────
function ResourceBtn({ href, label, icon }) {
  if (!href) return null;
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 hover:border-slate-500 transition-all"
    >
      {icon}
      {label}
      <ExternalLink className="w-2.5 h-2.5 opacity-60" />
    </a>
  );
}

// ── Single Vuln Card ──────────────────────────────────────────────────────────
function VulnCard({ vuln, highlight = '' }) {
  const [expanded, setExpanded] = useState(false);

  // Highlight matching text
  function hl(text) {
    if (!highlight) return text;
    const regex = new RegExp(`(${highlight.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
    const parts = text.split(regex);
    return parts.map((p, i) =>
      regex.test(p)
        ? <mark key={i} className="bg-cyan-500/30 text-cyan-200 rounded px-0.5">{p}</mark>
        : p
    );
  }

  return (
    <div
      className={`
        rounded-xl border transition-all duration-200
        ${expanded
          ? 'border-slate-600 bg-slate-800/80'
          : 'border-slate-700/60 bg-slate-800/40 hover:border-slate-600 hover:bg-slate-800/70'}
      `}
    >
      {/* Header */}
      <button
        className="w-full flex items-center justify-between gap-3 px-4 py-3.5 text-left"
        onClick={() => setExpanded(e => !e)}
        aria-expanded={expanded}
        aria-label={`Toggle details for ${vuln.label}`}
      >
        <div className="flex items-center gap-2.5 min-w-0">
          <Shield className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
          <span className="text-sm font-semibold text-slate-200 truncate">
            {hl(vuln.label)}
          </span>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          <DifficultyBadge level={vuln.difficulty} />
          {expanded
            ? <ChevronUp className="w-3.5 h-3.5 text-slate-500" />
            : <ChevronDown className="w-3.5 h-3.5 text-slate-500" />}
        </div>
      </button>

      {/* Expanded body */}
      {expanded && (
        <div className="px-4 pb-4 space-y-4 border-t border-slate-700/50 pt-3">
          {/* Arabic summary */}
          <p className="text-sm text-slate-300 leading-relaxed">{vuln.summary}</p>

          {/* Resources */}
          <div className="flex flex-wrap gap-2">
            {vuln.portswigger && (
              <ResourceBtn
                href={vuln.portswigger}
                label="PortSwigger"
                icon={<img src="https://portswigger.net/favicon.ico" className="w-3 h-3" alt="" onError={e => e.target.style.display='none'} />}
              />
            )}
            {vuln.hacktricks && (
              <ResourceBtn
                href={vuln.hacktricks}
                label="HackTricks"
                icon={<span className="text-xs">🃏</span>}
              />
            )}
            {vuln.owasp && (
              <ResourceBtn
                href={vuln.owasp}
                label="OWASP"
                icon={<span className="text-xs">🔴</span>}
              />
            )}
            {vuln.extraResource && (
              <ResourceBtn
                href={vuln.extraResource.url}
                label={vuln.extraResource.label}
                icon={<ExternalLink className="w-3 h-3" />}
              />
            )}
            {vuln.youtube?.map((yt, i) => (
              <ResourceBtn
                key={i}
                href={yt.url}
                label={yt.title.length > 25 ? yt.title.slice(0, 25) + '…' : yt.title}
                icon={<span className="text-xs">▶</span>}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Scanner Accordion ────────────────────────────────────────────────────────
function ScannerAccordion({ tab, isOpen, onToggle, filterDifficulty, searchQuery }) {
  const Icon = SCANNER_ICONS[tab.id] || Shield;
  const vulns = useMemo(() => {
    let list = getSortedVulns(tab.id);
    if (filterDifficulty) list = list.filter(v => v.difficulty === filterDifficulty);
    return list;
  }, [tab.id, filterDifficulty]);

  if (vulns.length === 0) return null;

  return (
    <div
      className={`
        rounded-2xl border transition-all duration-200
        ${isOpen
          ? `border-slate-600 ${tab.bgColor} shadow-lg`
          : 'border-slate-700/50 bg-slate-800/30 hover:border-slate-600'}
      `}
    >
      {/* Accordion trigger */}
      <button
        className="w-full flex items-center justify-between gap-4 px-5 py-4 text-left"
        onClick={onToggle}
        aria-expanded={isOpen}
        id={`scanner-tab-${tab.id}`}
      >
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-xl ${tab.bgColor} border ${tab.borderColor}`}>
            <Icon className={`w-4 h-4 ${tab.textColor}`} />
          </div>
          <div>
            <div className={`text-sm font-bold ${tab.textColor}`}>{tab.label}</div>
            <div className="text-xs text-slate-500 mt-0.5">{tab.desc}</div>
          </div>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0">
          <span className="text-xs text-slate-500 font-mono">{vulns.length} ثغرة</span>
          {isOpen
            ? <ChevronUp className="w-4 h-4 text-slate-400" />
            : <ChevronDown className="w-4 h-4 text-slate-500" />}
        </div>
      </button>

      {/* Accordion content */}
      {isOpen && (
        <div className="px-4 pb-4 space-y-2 border-t border-slate-700/50 pt-3">
          <div className="text-xs text-slate-500 mb-3 px-1">
            {tab.labelFull}
          </div>
          {vulns.map(v => (
            <VulnCard key={v.id} vuln={v} highlight={searchQuery} />
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main Page ────────────────────────────────────────────────────────────────
export default function VulnLibraryPage() {
  const [searchQuery, setSearchQuery]           = useState('');
  const [filterDifficulty, setFilterDifficulty] = useState('');
  const [openScanners, setOpenScanners]         = useState(new Set(['dast']));
  const searchRef = useRef(null);

  // Computed: search results (cross-scanner)
  const searchResults = useMemo(() => {
    if (!searchQuery.trim()) return null;
    return searchAllVulns(searchQuery);
  }, [searchQuery]);

  function toggleScanner(id) {
    setOpenScanners(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function clearSearch() {
    setSearchQuery('');
    searchRef.current?.focus();
  }

  // Total vuln count across all scanners
  const totalVulns = Object.values(VULN_LIBRARY).reduce((sum, arr) => sum + arr.length, 0);
  const totalScanners = SCANNER_TABS.length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50">
      {/* ── Hero Header ─────────────────────────────────────────────── */}
      <div className="relative overflow-hidden bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 border-b border-slate-800">
        {/* Decorative background */}
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
          <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-500/5 rounded-full blur-3xl" />
        </div>

        <div className="relative max-w-4xl mx-auto px-6 py-12">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-500/30">
              <BookOpen className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white tracking-tight">
                Vulnerability Learning Center
              </h1>
              <p className="text-sm text-slate-400 mt-0.5">مكتبة الثغرات الشاملة — مرجع تعليمي موحَّد</p>
            </div>
          </div>

          <p className="text-slate-400 text-sm max-w-2xl leading-relaxed mb-6">
            مرجع شامل لكل الثغرات التي تكتشفها محركات SecuraX الـ{totalScanners} — مرتبة حسب الفاحص والصعوبة،
            مع شروح عملية مختصرة وروابط للتعمّق في كل ثغرة.
          </p>

          {/* Stats bar */}
          <div className="flex flex-wrap gap-4 mb-8">
            {[
              { label: 'فئة فاحص', value: totalScanners },
              { label: 'نوع ثغرة', value: totalVulns },
              { label: 'مستوى صعوبة', value: 3 },
            ].map(s => (
              <div key={s.label} className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800/60 border border-slate-700">
                <span className="text-lg font-bold text-cyan-400">{s.value}</span>
                <span className="text-xs text-slate-400">{s.label}</span>
              </div>
            ))}
          </div>

          {/* ── Search bar ──────────────────────────────────────────── */}
          <div className="relative">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input
              ref={searchRef}
              id="vuln-search"
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="ابحث عن ثغرة أو فئة فاحص... (XSS, SSRF, Docker, SSL...)"
              className="
                w-full pl-10 pr-10 py-3 rounded-xl
                bg-slate-800 border border-slate-700 text-slate-200
                placeholder:text-slate-500 text-sm
                focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30
                transition-all
              "
            />
            {searchQuery && (
              <button
                onClick={clearSearch}
                className="absolute right-3 top-1/2 -translate-y-1/2 p-1 rounded-full hover:bg-slate-700 text-slate-500 hover:text-slate-300 transition-colors"
                aria-label="Clear search"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* ── Difficulty Filter ────────────────────────────────────── */}
          <div className="flex items-center gap-3 mt-4">
            <Filter className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
            <span className="text-xs text-slate-500">فلتر الصعوبة:</span>
            <div className="flex gap-2">
              {['', 'easy', 'medium', 'hard'].map(d => {
                const meta = d ? DIFFICULTY_META[d] : null;
                const active = filterDifficulty === d;
                return (
                  <button
                    key={d || 'all'}
                    onClick={() => setFilterDifficulty(d)}
                    className={`
                      px-3 py-1 text-xs font-semibold rounded-lg border transition-all
                      ${active
                        ? d
                          ? `${meta.color} ring-1 ring-offset-1 ring-offset-slate-900 ring-current`
                          : 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                        : 'text-slate-500 border-slate-700 hover:border-slate-500 hover:text-slate-300 bg-transparent'}
                    `}
                    id={`difficulty-filter-${d || 'all'}`}
                  >
                    {d
                      ? d.charAt(0).toUpperCase() + d.slice(1)
                      : 'الكل'}
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* ── Content area ─────────────────────────────────────────────── */}
      <div className="max-w-4xl mx-auto px-6 py-8 space-y-4">

        {/* ── Search Results Mode ──────────────────────────────────── */}
        {searchResults !== null ? (
          <div>
            <div className="flex items-center gap-2 mb-4">
              <Search className="w-4 h-4 text-cyan-400" />
              <span className="text-sm font-semibold text-slate-300">
                نتائج البحث عن &quot;{searchQuery}&quot;
              </span>
              <span className="text-xs text-slate-500 ml-1">
                — {searchResults.length} نتيجة
              </span>
            </div>

            {searchResults.length === 0 ? (
              <div className="flex flex-col items-center gap-3 py-16 text-center">
                <AlertTriangle className="w-10 h-10 text-slate-600" />
                <p className="text-slate-400 text-sm">لا توجد نتائج لـ &quot;{searchQuery}&quot;</p>
                <p className="text-slate-600 text-xs">جرّب كلمة مختلفة مثل: xss، docker، ssl، ssrf</p>
              </div>
            ) : (
              <div className="space-y-2">
                {searchResults.map(v => (
                  <div key={`${v.scannerId}-${v.id}`} className="relative">
                    {/* Scanner badge above card */}
                    <div className="absolute -top-2 left-4 z-10">
                      {(() => {
                        const tab = SCANNER_TABS.find(t => t.id === v.scannerId);
                        return tab ? (
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${tab.bgColor} ${tab.textColor} border ${tab.borderColor}`}>
                            {tab.label}
                          </span>
                        ) : null;
                      })()}
                    </div>
                    <div className="pt-3">
                      <VulnCard vuln={v} highlight={searchQuery} />
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          /* ── Normal Accordion Mode ──────────────────────────────────── */
          <>
            {/* Info banner */}
            <div className="flex items-start gap-3 p-4 rounded-xl bg-cyan-500/5 border border-cyan-500/20 text-xs text-cyan-300">
              <BookOpen className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <p>
                الثغرات مرتبة تلقائياً داخل كل فئة من الأسهل للأصعب.
                انقر على اسم الفئة لعرض ثغراتها. استخدم البحث للعثور على أي ثغرة من أي فئة فوراً.
              </p>
            </div>

            {/* Scanner accordions */}
            {SCANNER_TABS.map(tab => (
              <ScannerAccordion
                key={tab.id}
                tab={tab}
                isOpen={openScanners.has(tab.id)}
                onToggle={() => toggleScanner(tab.id)}
                filterDifficulty={filterDifficulty}
                searchQuery={searchQuery}
              />
            ))}
          </>
        )}
      </div>
    </div>
  );
}
