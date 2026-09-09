import { useState, useMemo, useRef } from 'react';
import {
  BookOpen, Search, ChevronDown, ChevronUp,
  ExternalLink, Shield, Filter, X, ShieldAlert,
  Zap, Code, Globe, Lock, Package, Settings,
  Layers, Mail, Layout, Play, ChevronRight, ChevronsUpDown,
  Server,
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
  web:        Globe,
  dast:       Zap,
  sast:       Code,
  network:    Globe,
  ssl:        Lock,
  deps:       Package,
  server:     Settings,
  server_ext: Server,
  docker:     Layers,
  dns:        Mail,
  wordpress:  Layout,
};

// ── Difficulty Badge Component ───────────────────────────────────────────────
function DifficultyBadge({ level }) {
  const meta = DIFFICULTY_META[level] || DIFFICULTY_META.medium;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-full border shadow-sm ${meta.color}`}>
      <span className={`w-2 h-2 rounded-full shadow-sm ${meta.dot}`} />
      {meta.label}
    </span>
  );
}

// ── External Learning Resource Button ────────────────────────────────────────
function ResourceBtn({ href, label, icon, variant = 'slate' }) {
  if (!href) return null;

  const variants = {
    purple: 'bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 hover:text-purple-200 border-purple-500/30 hover:border-purple-500/50 shadow-purple-500/5',
    amber:  'bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 hover:text-amber-200 border-amber-500/30 hover:border-amber-500/50 shadow-amber-500/5',
    cyan:   'bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 hover:text-cyan-200 border-cyan-500/30 hover:border-cyan-500/50 shadow-cyan-500/5',
    red:    'bg-red-500/10 hover:bg-red-500/20 text-red-300 hover:text-red-200 border-red-500/30 hover:border-red-500/50 shadow-red-500/5',
    slate:  'bg-slate-800 hover:bg-slate-750 text-slate-300 hover:text-white border-slate-700 hover:border-slate-600 shadow-slate-900/50',
  };

  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className={`inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-xl border transition-all duration-150 hover:shadow-md ${variants[variant] || variants.slate}`}
    >
      {icon}
      <span>{label}</span>
      <ExternalLink className="w-3 h-3 opacity-60 ml-0.5" />
    </a>
  );
}

// ── Single Standalone Vulnerability Card Component ───────────────────────────
function VulnCard({ vuln, highlight = '', scannerLabel = '' }) {
  // Highlight matching text helper
  function hl(text) {
    if (!highlight || !text) return text;
    const regex = new RegExp(`(${highlight.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
    const parts = text.split(regex);
    return parts.map((p, i) =>
      regex.test(p)
        ? <mark key={i} className="bg-cyan-500/30 text-cyan-200 rounded px-1">{p}</mark>
        : p
    );
  }

  return (
    <div className="flex flex-col bg-slate-900/90 border border-slate-800 hover:border-slate-700/80 rounded-2xl p-5 shadow-lg shadow-black/20 hover:shadow-cyan-500/5 transition-all duration-200">
      {/* Card Header: Category & Difficulty Badge */}
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="min-w-0">
          {scannerLabel && (
            <span className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider block mb-1">
              {scannerLabel}
            </span>
          )}
          <h3 className="text-base font-bold text-white leading-snug">
            {hl(vuln.label)}
          </h3>
        </div>
        <div className="flex-shrink-0">
          <DifficultyBadge level={vuln.difficulty} />
        </div>
      </div>

      {/* Card Body: Comprehensive Technical Description */}
      <p className="text-slate-300 text-sm leading-relaxed mb-4 flex-1">
        {hl(vuln.summary)}
      </p>

      {/* Key Remediation Tip */}
      {vuln.remediation && (
        <div className="mb-4 p-3 rounded-xl bg-slate-950/70 border border-slate-800/80 text-xs text-slate-300 flex items-start gap-2.5">
          <ShieldAlert className="w-4 h-4 text-emerald-400 mt-0.5 flex-shrink-0" />
          <div>
            <strong className="text-emerald-300 font-semibold block mb-0.5">Mitigation & Defense:</strong>
            <span className="text-slate-400 leading-normal">{vuln.remediation}</span>
          </div>
        </div>
      )}

      {/* Card Footer: External Learning Resource Action Buttons */}
      <div className="pt-3.5 border-t border-slate-800/80 mt-auto">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-2.5 flex items-center gap-1.5">
          <BookOpen className="w-3.5 h-3.5 text-cyan-400" />
          <span>Learning References & Labs</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {vuln.portswigger && (
            <ResourceBtn
              href={vuln.portswigger}
              label="PortSwigger Academy"
              variant="purple"
              icon={<span className="text-xs font-mono font-bold text-purple-400">PS</span>}
            />
          )}
          {vuln.hacktricks && (
            <ResourceBtn
              href={vuln.hacktricks}
              label="HackTricks"
              variant="amber"
              icon={<span className="text-xs">🃏</span>}
            />
          )}
          {vuln.owasp && (
            <ResourceBtn
              href={vuln.owasp}
              label="OWASP Guide"
              variant="cyan"
              icon={<Shield className="w-3 h-3 text-cyan-400" />}
            />
          )}
          {vuln.extraResource && (
            <ResourceBtn
              href={vuln.extraResource.url}
              label={vuln.extraResource.label}
              variant="slate"
              icon={<ExternalLink className="w-3 h-3 text-slate-400" />}
            />
          )}
          {vuln.youtube?.map((yt, i) => (
            <ResourceBtn
              key={i}
              href={yt.url}
              label="Video Lab"
              variant="red"
              icon={<Play className="w-3 h-3 text-red-400 fill-red-400/20" />}
            />
          ))}
        </div>
      </div>
    </div>
  );
}

// ── Category / Scanner Collapsible Accordion Component ───────────────────────
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
        rounded-2xl border transition-all duration-200 overflow-hidden
        ${isOpen
          ? `border-slate-700 bg-slate-900/60 shadow-xl shadow-black/30`
          : 'border-slate-800 bg-slate-900/30 hover:border-slate-700 hover:bg-slate-900/50'}
      `}
    >
      {/* Accordion Trigger Header */}
      <button
        className="w-full flex items-center justify-between gap-4 px-6 py-5 text-left transition-colors"
        onClick={onToggle}
        aria-expanded={isOpen}
        id={`scanner-tab-${tab.id}`}
      >
        <div className="flex items-center gap-4 min-w-0">
          <div className={`p-3 rounded-2xl ${tab.bgColor} border ${tab.borderColor} flex-shrink-0`}>
            <Icon className={`w-5 h-5 ${tab.textColor}`} />
          </div>
          <div className="min-w-0">
            <div className="flex items-center gap-2.5 flex-wrap">
              <span className={`text-base font-bold ${tab.textColor}`}>{tab.label}</span>
              <span className="text-slate-500 text-xs hidden sm:inline">•</span>
              <span className="text-xs text-slate-400 hidden sm:inline">{tab.labelFull}</span>
            </div>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed line-clamp-1 sm:line-clamp-none">
              {tab.desc}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3.5 flex-shrink-0">
          <span className="text-xs font-mono font-medium text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-2.5 py-1 rounded-full">
            {vulns.length} {vulns.length === 1 ? 'Vulnerability' : 'Vulnerabilities'}
          </span>
          <div className="w-8 h-8 rounded-xl bg-slate-800 flex items-center justify-center text-slate-400">
            {isOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </div>
      </button>

      {/* Accordion Content: Responsive Card Grid */}
      {isOpen && (
        <div className="px-6 pb-6 pt-2 border-t border-slate-800/80 bg-slate-950/40">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5 mt-3">
            {vulns.map(v => (
              <VulnCard
                key={v.id}
                vuln={v}
                highlight={searchQuery}
                scannerLabel={tab.label}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main Vulnerability Library Page Component ────────────────────────────────
export default function VulnLibraryPage() {
  const [searchQuery, setSearchQuery]           = useState('');
  const [filterDifficulty, setFilterDifficulty] = useState('');
  // Open first 3 scanners by default
  const [openScanners, setOpenScanners]         = useState(new Set(['dast', 'sast', 'network']));
  const searchRef = useRef(null);

  // Cross-scanner search query
  const searchResults = useMemo(() => {
    if (!searchQuery.trim()) return null;
    return searchAllVulns(searchQuery);
  }, [searchQuery]);

  // Toggle single scanner accordion
  function toggleScanner(id) {
    setOpenScanners(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  // Quick controls: Expand all / Collapse all
  function expandAll() {
    setOpenScanners(new Set(SCANNER_TABS.map(t => t.id)));
  }

  function collapseAll() {
    setOpenScanners(new Set());
  }

  function clearSearch() {
    setSearchQuery('');
    searchRef.current?.focus();
  }

  // Summary counts
  const totalVulns = Object.values(VULN_LIBRARY).reduce((sum, arr) => sum + arr.length, 0);
  const totalScanners = SCANNER_TABS.length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50">
      {/* ── Hero Header ─────────────────────────────────────────────── */}
      <div className="relative overflow-hidden bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 border-b border-slate-800">
        {/* Ambient background glows */}
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
          <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-indigo-500/5 rounded-full blur-3xl" />
        </div>

        <div className="relative max-w-6xl mx-auto px-6 py-12">
          {/* Header Title & Icon */}
          <div className="flex items-center gap-3.5 mb-4">
            <div className="p-3.5 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-indigo-500/20 border border-cyan-500/30 shadow-lg shadow-cyan-500/10">
              <BookOpen className="w-7 h-7 text-cyan-400" />
            </div>
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider text-cyan-400 mb-0.5">
                Knowledge & Security Research
              </div>
              <h1 className="text-3xl font-black text-white tracking-tight">
                Vulnerability Learning Center
              </h1>
            </div>
          </div>

          <p className="text-slate-300 text-sm max-w-3xl leading-relaxed mb-6">
            A comprehensive, curated encyclopedia of vulnerabilities detected across all {totalScanners} SecuraX scanning engines.
            Organized by engine category and exploitation difficulty, each finding features detailed technical analysis,
            actionable defense strategies, and direct links to hands-on labs and official documentation.
          </p>

          {/* Stats Bar */}
          <div className="flex flex-wrap gap-4 mb-8">
            {[
              { label: 'Scanner Engines', value: totalScanners },
              { label: 'Cataloged Vulnerabilities', value: totalVulns },
              { label: 'Difficulty Tiers', value: '3 (Easy, Med, Hard)' },
              { label: 'Direct Labs & Resources', value: '75+' },
            ].map((s, idx) => (
              <div key={idx} className="flex items-center gap-2.5 px-3.5 py-2 rounded-xl bg-slate-800/80 border border-slate-700/80 shadow-sm">
                <span className="text-lg font-bold text-cyan-400 font-mono">{s.value}</span>
                <span className="text-xs text-slate-400 font-medium">{s.label}</span>
              </div>
            ))}
          </div>

          {/* ── Search Bar ──────────────────────────────────────────── */}
          <div className="relative max-w-2xl">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              ref={searchRef}
              id="vuln-search"
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search by vulnerability name, CVE, scanner type, or keyword (XSS, SQLi, Docker, SSL...)"
              className="
                w-full pl-11 pr-10 py-3.5 rounded-xl
                bg-slate-800/90 border border-slate-700 text-white
                placeholder:text-slate-400 text-sm
                focus:outline-none focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20
                transition-all shadow-inner
              "
            />
            {searchQuery && (
              <button
                onClick={clearSearch}
                className="absolute right-3.5 top-1/2 -translate-y-1/2 p-1 rounded-full hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
                aria-label="Clear search"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>

          {/* ── Filter Toolbar ───────────────────────────────────────── */}
          <div className="flex items-center justify-between gap-4 mt-5 flex-wrap">
            {/* Difficulty Filter */}
            <div className="flex items-center gap-2.5 flex-wrap">
              <Filter className="w-4 h-4 text-slate-400 flex-shrink-0" />
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Filter Difficulty:</span>
              <div className="flex gap-2">
                {[
                  { value: '', label: 'All Levels' },
                  { value: 'easy', label: 'Easy' },
                  { value: 'medium', label: 'Medium' },
                  { value: 'hard', label: 'Hard' },
                ].map(d => {
                  const active = filterDifficulty === d.value;
                  return (
                    <button
                      key={d.value}
                      onClick={() => setFilterDifficulty(d.value)}
                      className={`
                        px-3 py-1.5 rounded-lg text-xs font-semibold transition-all border
                        ${active
                          ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-sm'
                          : 'bg-slate-800/60 text-slate-400 border-slate-700 hover:text-white hover:border-slate-600'}
                      `}
                    >
                      {d.label}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Expand / Collapse All */}
            {!searchResults && (
              <div className="flex items-center gap-2">
                <button
                  onClick={expandAll}
                  className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800/70 border border-slate-700 text-slate-300 hover:text-white hover:border-slate-600 transition-colors"
                >
                  Expand All
                </button>
                <button
                  onClick={collapseAll}
                  className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-800/70 border border-slate-700 text-slate-300 hover:text-white hover:border-slate-600 transition-colors"
                >
                  Collapse All
                </button>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Main Content Area ────────────────────────────────────────── */}
      <div className="max-w-6xl mx-auto px-6 py-8">
        {/* Global Search Results Mode */}
        {searchResults ? (
          <div>
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <span>Search Results for</span>
                <span className="text-cyan-400 font-mono">"{searchQuery}"</span>
                <span className="text-sm font-normal text-slate-400 font-mono">({searchResults.length} found)</span>
              </h2>
              <button
                onClick={clearSearch}
                className="text-xs text-cyan-400 hover:underline flex items-center gap-1"
              >
                Clear search & view categories
              </button>
            </div>

            {searchResults.length === 0 ? (
              <div className="p-12 text-center rounded-2xl bg-slate-900/60 border border-slate-800">
                <div className="text-4xl mb-3">🔍</div>
                <h3 className="text-base font-bold text-white mb-1">No vulnerabilities matched your search</h3>
                <p className="text-xs text-slate-400 max-w-md mx-auto mb-4">
                  Try searching with generic terms like "injection", "docker", "ssl", or "xss".
                </p>
                <button
                  onClick={clearSearch}
                  className="px-4 py-2 text-xs font-semibold rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white transition-colors"
                >
                  View All Vulnerabilities
                </button>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
                {searchResults.map(v => (
                  <VulnCard
                    key={`${v.scannerId}-${v.id}`}
                    vuln={v}
                    highlight={searchQuery}
                    scannerLabel={v.scannerId.toUpperCase()}
                  />
                ))}
              </div>
            )}
          </div>
        ) : (
          /* Normal Accordion Mode by Scanner */
          <div className="space-y-4">
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
          </div>
        )}
      </div>
    </div>
  );
}
