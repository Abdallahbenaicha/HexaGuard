import React, { useState, useEffect, useMemo, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import {
  BookOpen, Search, Shield, Filter, X, ShieldAlert,
  Zap, Code, Globe, Lock, Package, Settings,
  Layers, Mail, Layout, Server, CheckCircle2,
  ArrowRight, Box, Compass, Sparkles, AlertTriangle
} from 'lucide-react';
import AssessmentMethodologyBanner from '../components/AssessmentMethodologyBanner';

// ── Scanner Engine Configuration ───────────────────────────────────────────
const SCANNER_META = {
  all:        { label: 'All Modules', icon: BookOpen, color: 'text-cyan-400', border: 'border-cyan-500/30', bg: 'bg-cyan-500/10' },
  dast:       { label: 'DAST Engine', icon: Zap, color: 'text-orange-400', border: 'border-orange-500/30', bg: 'bg-orange-500/10' },
  web:        { label: 'Web Core', icon: Globe, color: 'text-cyan-400', border: 'border-cyan-500/30', bg: 'bg-cyan-500/10' },
  sast:       { label: 'SAST Engine', icon: Code, color: 'text-purple-400', border: 'border-purple-500/30', bg: 'bg-purple-500/10' },
  network:    { label: 'Network Recon', icon: Globe, color: 'text-blue-400', border: 'border-blue-500/30', bg: 'bg-blue-500/10' },
  ssl:        { label: 'SSL/TLS Audit', icon: Lock, color: 'text-emerald-400', border: 'border-emerald-500/30', bg: 'bg-emerald-500/10' },
  deps:       { label: 'Dependencies', icon: Package, color: 'text-yellow-400', border: 'border-yellow-500/30', bg: 'bg-yellow-500/10' },
  server:     { label: 'Server Internal', icon: Settings, color: 'text-slate-300', border: 'border-slate-500/30', bg: 'bg-slate-500/10' },
  server_ext: { label: 'Server External', icon: Server, color: 'text-indigo-400', border: 'border-indigo-500/30', bg: 'bg-indigo-500/10' },
  docker:     { label: 'Docker Security', icon: Layers, color: 'text-sky-400', border: 'border-sky-500/30', bg: 'bg-sky-500/10' },
  dns:        { label: 'DNS & Email', icon: Mail, color: 'text-pink-400', border: 'border-pink-500/30', bg: 'bg-pink-500/10' },
  wordpress:  { label: 'WordPress Audit', icon: Layout, color: 'text-teal-400', border: 'border-teal-500/30', bg: 'bg-teal-500/10' },
  incident:   { label: 'Blue Team Incidents', icon: Shield, color: 'text-rose-400', border: 'border-rose-500/30', bg: 'bg-rose-500/10' },
};

const DIFFICULTY_META = {
  easy:   { label: 'Easy', color: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30', dot: 'bg-emerald-400' },
  medium: { label: 'Medium', color: 'bg-amber-500/10 text-amber-400 border-amber-500/30', dot: 'bg-amber-400' },
  hard:   { label: 'Hard', color: 'bg-rose-500/10 text-rose-400 border-rose-500/30', dot: 'bg-rose-400' },
};

export default function VulnLibraryPage() {
  const navigate = useNavigate();
  const searchRef = useRef(null);

  const [taxonomyData, setTaxonomyData] = useState({ offensive: [], incidents: [], stats: {} });
  const [userLedger, setUserLedger] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedScanner, setSelectedScanner] = useState('all');
  const [selectedDifficulty, setSelectedDifficulty] = useState('');
  const [selectedMastery, setSelectedMastery] = useState('all');
  const [sandboxOnly, setSandboxOnly] = useState(false);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      setError(null);
      try {
        const [taxRes, skillRes] = await Promise.all([
          axios.get('/api/learn/taxonomy'),
          axios.get('/api/skill/ledger').catch(() => ({ data: { ledger: [] } }))
        ]);

        if (taxRes.data?.ok) {
          setTaxonomyData({
            offensive: taxRes.data.offensive || [],
            incidents: taxRes.data.incidents || [],
            stats: taxRes.data.stats || {}
          });
        } else {
          setError('Failed to load curriculum taxonomy.');
        }

        // Build user ledger lookup
        const ledgerMap = {};
        const items = skillRes.data?.ledger || [];
        items.forEach(item => {
          if (item.vuln_type) {
            ledgerMap[item.vuln_type] = item.status;
          }
        });
        setUserLedger(ledgerMap);
      } catch (err) {
        setError('Failed to load education system data.');
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  // Combine and normalize items
  const allCurriculumItems = useMemo(() => {
    const offensiveItems = (taxonomyData.offensive || []).map(item => ({
      ...item,
      track: item.scanner,
      trackLabel: SCANNER_META[item.scanner]?.label || item.scanner.toUpperCase(),
      trackType: 'offensive',
    }));

    const incidentItems = (taxonomyData.incidents || []).map(item => ({
      ...item,
      track: 'incident',
      trackLabel: 'Incident Response',
      trackType: 'incident',
    }));

    return [...offensiveItems, ...incidentItems];
  }, [taxonomyData]);

  // Filtering
  const filteredItems = useMemo(() => {
    return allCurriculumItems.filter(item => {
      // Scanner filter
      if (selectedScanner !== 'all' && item.track !== selectedScanner) {
        return false;
      }

      // Difficulty filter
      if (selectedDifficulty && item.difficulty !== selectedDifficulty) {
        return false;
      }

      // Sandbox filter
      if (sandboxOnly && !item.has_sandbox) {
        return false;
      }

      // Mastery filter
      const userStatus = userLedger[item.id] || 'unstarted';
      if (selectedMastery === 'mastered') {
        if (userStatus !== 'practiced_verified' && userStatus !== 'practiced_self_reported') {
          return false;
        }
      } else if (selectedMastery === 'verified') {
        if (userStatus !== 'practiced_verified') {
          return false;
        }
      } else if (selectedMastery === 'unstarted') {
        if (userStatus === 'practiced_verified' || userStatus === 'practiced_self_reported') {
          return false;
        }
      }

      // Search filter
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const titleMatch = (item.name_en || '').toLowerCase().includes(query) || (item.name || '').toLowerCase().includes(query);
        const descMatch = (item.summary || item.description_en || '').toLowerCase().includes(query);
        const cweMatch = (item.cwe || '').toLowerCase().includes(query);
        const owaspMatch = (item.owasp || '').toLowerCase().includes(query);
        const mitreMatch = (item.mitre_id || '').toLowerCase().includes(query);
        const idMatch = (item.id || '').toLowerCase().includes(query);

        if (!titleMatch && !descMatch && !cweMatch && !owaspMatch && !mitreMatch && !idMatch) {
          return false;
        }
      }

      return true;
    });
  }, [allCurriculumItems, selectedScanner, selectedDifficulty, selectedMastery, sandboxOnly, searchQuery, userLedger]);

  const clearSearch = () => {
    setSearchQuery('');
    searchRef.current?.focus();
  };

  const resetFilters = () => {
    setSearchQuery('');
    setSelectedScanner('all');
    setSelectedDifficulty('');
    setSelectedMastery('all');
    setSandboxOnly(false);
  };

  // Summary counts
  const totalTopics = allCurriculumItems.length;
  const offensiveCount = taxonomyData.offensive.length;
  const incidentCount = taxonomyData.incidents.length;
  const verifiedMasteredCount = Object.values(userLedger).filter(s => s === 'practiced_verified').length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50">
      {/* ── Hero Header ─────────────────────────────────────────────── */}
      <div className="relative overflow-hidden bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 border-b border-slate-800">
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
          <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-indigo-500/5 rounded-full blur-3xl" />
        </div>

        <div className="relative max-w-7xl mx-auto px-6 py-10">
          <div className="flex items-center gap-3.5 mb-3">
            <div className="p-3.5 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-indigo-500/20 border border-cyan-500/30 shadow-lg shadow-cyan-500/10">
              <BookOpen className="w-7 h-7 text-cyan-400" />
            </div>
            <div>
              <div className="text-xs font-semibold uppercase tracking-wider text-cyan-400 mb-0.5">
                HexaGuard Unified Curriculum
              </div>
              <h1 className="text-3xl font-black text-white tracking-tight">
                Vulnerability Catalog & Interactive Lessons
              </h1>
            </div>
          </div>

          <p className="text-slate-300 text-sm max-w-3xl leading-relaxed mb-6">
            Authoritative, 4-level pedagogical curriculum spanning all 11 offensive scanning engines
            and Blue Team incident playbooks. Master theoretical foundations, detection heuristics,
            containerized sandbox practice, and verified remediation reporting.
          </p>

          {/* Stats Bar */}
          <div className="flex flex-wrap gap-3 mb-6">
            <div className="flex items-center gap-2.5 px-3.5 py-2 rounded-xl bg-slate-800/80 border border-slate-700/80">
              <span className="text-lg font-bold text-cyan-400 font-mono">{totalTopics || 68}</span>
              <span className="text-xs text-slate-400 font-medium">Curriculum Topics</span>
            </div>
            <div className="flex items-center gap-2.5 px-3.5 py-2 rounded-xl bg-slate-800/80 border border-slate-700/80">
              <span className="text-lg font-bold text-orange-400 font-mono">{offensiveCount || 58}</span>
              <span className="text-xs text-slate-400 font-medium">Offensive Vulnerabilities</span>
            </div>
            <div className="flex items-center gap-2.5 px-3.5 py-2 rounded-xl bg-slate-800/80 border border-slate-700/80">
              <span className="text-lg font-bold text-rose-400 font-mono">{incidentCount || 10}</span>
              <span className="text-xs text-slate-400 font-medium">Blue Team Incidents</span>
            </div>
            <div className="flex items-center gap-2.5 px-3.5 py-2 rounded-xl bg-slate-800/80 border border-slate-700/80">
              <span className="text-lg font-bold text-emerald-400 font-mono">{verifiedMasteredCount}</span>
              <span className="text-xs text-slate-400 font-medium">Skills Verified</span>
            </div>
          </div>

          {/* ── Assessment Methodology Primer Banner ─────────────────── */}
          <div className="mt-2">
            <AssessmentMethodologyBanner />
          </div>
        </div>
      </div>

      {/* ── Main Catalog Content ────────────────────────────────────── */}
      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Search & Filter Bar */}
        <div className="space-y-4 mb-8">
          <div className="flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
            {/* Search Input */}
            <div className="relative flex-1 max-w-xl">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                ref={searchRef}
                id="curriculum-search"
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search topics (e.g. XSS, SQLi, SSRF, Docker, Ransomware, CVE, CWE)..."
                className="
                  w-full pl-11 pr-10 py-3 rounded-xl
                  bg-slate-900 border border-slate-800 text-white
                  placeholder:text-slate-500 text-sm
                  focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30
                  transition-all
                "
              />
              {searchQuery && (
                <button
                  onClick={clearSearch}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 p-1 rounded-full hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
                  aria-label="Clear search"
                >
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>

            {/* Quick Filters */}
            <div className="flex items-center gap-2 flex-wrap">
              {/* Difficulty Dropdown */}
              <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs">
                <Filter className="w-3.5 h-3.5 text-slate-400" />
                <select
                  value={selectedDifficulty}
                  onChange={e => setSelectedDifficulty(e.target.value)}
                  className="bg-transparent text-slate-300 font-medium focus:outline-none cursor-pointer"
                >
                  <option value="" className="bg-slate-900 text-slate-300">All Difficulties</option>
                  <option value="easy" className="bg-slate-900 text-slate-300">Easy</option>
                  <option value="medium" className="bg-slate-900 text-slate-300">Medium</option>
                  <option value="hard" className="bg-slate-900 text-slate-300">Hard</option>
                </select>
              </div>

              {/* Mastery Filter */}
              <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs">
                <CheckCircle2 className="w-3.5 h-3.5 text-slate-400" />
                <select
                  value={selectedMastery}
                  onChange={e => setSelectedMastery(e.target.value)}
                  className="bg-transparent text-slate-300 font-medium focus:outline-none cursor-pointer"
                >
                  <option value="all" className="bg-slate-900 text-slate-300">All Mastery Status</option>
                  <option value="mastered" className="bg-slate-900 text-slate-300">Completed / Practiced</option>
                  <option value="verified" className="bg-slate-900 text-slate-300">Verified by Engine</option>
                  <option value="unstarted" className="bg-slate-900 text-slate-300">Not Completed</option>
                </select>
              </div>

              {/* Live Sandbox Toggle */}
              <button
                onClick={() => setSandboxOnly(!sandboxOnly)}
                className={`
                  inline-flex items-center gap-1.5 px-3 py-2 text-xs font-semibold rounded-xl border transition-all
                  ${sandboxOnly
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 shadow-sm'
                    : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white hover:border-slate-700'}
                `}
              >
                <Box className="w-3.5 h-3.5" />
                <span>Live Sandbox Only</span>
              </button>
            </div>
          </div>

          {/* Track Filter Tabs */}
          <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-thin scrollbar-thumb-slate-800">
            {Object.entries(SCANNER_META).map(([trackKey, meta]) => {
              const Icon = meta.icon;
              const active = selectedScanner === trackKey;
              return (
                <button
                  key={trackKey}
                  onClick={() => setSelectedScanner(trackKey)}
                  className={`
                    inline-flex items-center gap-2 px-3.5 py-1.5 rounded-xl text-xs font-semibold whitespace-nowrap transition-all border
                    ${active
                      ? `${meta.bg} ${meta.color} ${meta.border} shadow-sm shadow-black/40`
                      : 'bg-slate-900/60 text-slate-400 border-slate-800/80 hover:border-slate-700 hover:text-white'}
                  `}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{meta.label}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Results Info */}
        <div className="flex items-center justify-between gap-4 mb-6 text-xs text-slate-400">
          <span>
            Showing <strong className="text-white font-semibold">{filteredItems.length}</strong> of {totalTopics} topics
          </span>
          {(searchQuery || selectedScanner !== 'all' || selectedDifficulty || selectedMastery !== 'all' || sandboxOnly) && (
            <button
              onClick={resetFilters}
              className="text-cyan-400 hover:underline flex items-center gap-1"
            >
              Reset all filters
            </button>
          )}
        </div>

        {/* Loading State */}
        {loading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[1, 2, 3, 4, 5, 6].map(i => (
              <div key={i} className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 animate-pulse h-64 flex flex-col justify-between">
                <div>
                  <div className="h-4 bg-slate-800 rounded w-1/3 mb-4" />
                  <div className="h-6 bg-slate-800 rounded w-3/4 mb-3" />
                  <div className="h-3 bg-slate-800 rounded w-full mb-2" />
                  <div className="h-3 bg-slate-800 rounded w-2/3" />
                </div>
                <div className="h-9 bg-slate-800 rounded-xl w-full" />
              </div>
            ))}
          </div>
        ) : filteredItems.length === 0 ? (
          /* Empty Search / Filter State */
          <div className="p-12 text-center rounded-2xl bg-slate-900/40 border border-slate-800 max-w-lg mx-auto">
            <div className="w-12 h-12 rounded-2xl bg-slate-800/80 border border-slate-700 flex items-center justify-center text-2xl mx-auto mb-4">
              🔍
            </div>
            <h3 className="text-base font-bold text-white mb-1.5">No matching curriculum topics</h3>
            <p className="text-xs text-slate-400 leading-relaxed mb-5">
              We couldn't find any lessons matching your search query and active filters.
            </p>
            <button
              onClick={resetFilters}
              className="px-4 py-2 text-xs font-semibold rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white transition-colors"
            >
              Clear Filters & Show All
            </button>
          </div>
        ) : (
          /* Card Grid: Index / Catalog (Single-Topic view rules applied) */
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredItems.map(item => {
              const trackMeta = SCANNER_META[item.track] || SCANNER_META.web;
              const diffMeta = DIFFICULTY_META[item.difficulty] || DIFFICULTY_META.medium;
              const TrackIcon = trackMeta.icon;
              const userStatus = userLedger[item.id];
              const isVerified = userStatus === 'practiced_verified';
              const isSelfReported = userStatus === 'practiced_self_reported';
              const isMastered = isVerified || isSelfReported;

              return (
                <div
                  key={item.id}
                  className="flex flex-col bg-slate-900/80 border border-slate-800 hover:border-slate-700/90 rounded-2xl p-5 shadow-lg shadow-black/30 hover:shadow-cyan-500/5 transition-all duration-200 group"
                >
                  {/* Card Header: Scanner Track Badge & Difficulty */}
                  <div className="flex items-center justify-between gap-2 mb-3">
                    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-bold rounded-lg border ${trackMeta.bg} ${trackMeta.color} ${trackMeta.border}`}>
                      <TrackIcon className="w-3 h-3" />
                      <span>{trackMeta.label}</span>
                    </span>

                    <div className="flex items-center gap-1.5">
                      {item.has_sandbox && (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-bold rounded-md bg-cyan-500/10 text-cyan-400 border border-cyan-500/30" title="Containerized practice target available">
                          <Box className="w-2.5 h-2.5" />
                          <span>Sandbox</span>
                        </span>
                      )}
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-bold rounded-full border ${diffMeta.color}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${diffMeta.dot}`} />
                        {diffMeta.label}
                      </span>
                    </div>
                  </div>

                  {/* Title */}
                  <h3 className="text-base font-bold text-white group-hover:text-cyan-300 transition-colors leading-snug mb-1.5">
                    {item.name_en || item.name}
                  </h3>

                  {/* Identifiers (CWE / OWASP / MITRE) */}
                  <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400 mb-3 flex-wrap">
                    {item.cwe && <span className="bg-slate-800/80 px-1.5 py-0.5 rounded border border-slate-700/60">{item.cwe}</span>}
                    {item.owasp && <span className="bg-slate-800/80 px-1.5 py-0.5 rounded border border-slate-700/60">{item.owasp}</span>}
                    {item.mitre_id && <span className="bg-rose-500/10 text-rose-400 px-1.5 py-0.5 rounded border border-rose-500/30">{item.mitre_id}</span>}
                  </div>

                  {/* Summary */}
                  <p className="text-slate-300 text-xs leading-relaxed mb-4 line-clamp-3 flex-1">
                    {item.summary || item.description_en}
                  </p>

                  {/* Mastery Status Pill */}
                  {isMastered && (
                    <div className="mb-3.5 px-3 py-1.5 rounded-xl bg-slate-950/70 border border-slate-800/80 flex items-center justify-between text-xs">
                      <span className="text-slate-400 text-[11px] font-medium">Skill Ledger:</span>
                      {isVerified ? (
                        <span className="inline-flex items-center gap-1 text-emerald-400 font-bold text-[11px]">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Mastered (Verified)</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-cyan-400 font-bold text-[11px]">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>Practiced (Self-Reported)</span>
                        </span>
                      )}
                    </div>
                  )}

                  {/* Card Action CTA */}
                  <div className="pt-3 border-t border-slate-800/80 mt-auto">
                    <Link
                      to={`/learn/${item.id}`}
                      className={`
                        w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 text-xs font-bold rounded-xl transition-all
                        ${isMastered
                          ? 'bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 hover:border-slate-600'
                          : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-md shadow-cyan-600/20 hover:shadow-cyan-500/30'}
                      `}
                    >
                      <span>{isMastered ? 'Review Lesson' : 'Start Lesson'}</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
