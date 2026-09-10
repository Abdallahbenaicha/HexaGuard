import { useState, useEffect } from 'react';
import {
  Compass, Shield, CheckCircle2, AlertTriangle, ArrowRight,
  Terminal, Search, Database, Layers, ExternalLink, Zap,
  BookOpen, ChevronRight, Filter, Play, Check, HelpCircle
} from 'lucide-react';
import { Link } from 'react-router-dom';
import axios from 'axios';

export default function GetStartedPage() {
  const [methodology, setMethodology] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activePhaseIndex, setActivePhaseIndex] = useState(0);
  const [matrixFilter, setMatrixFilter] = useState('');

  useEffect(() => {
    async function fetchMethodology() {
      try {
        const res = await axios.get('/api/learn/methodology');
        if (res.data?.ok) {
          setMethodology(res.data.methodology);
        }
      } catch (err) {
        console.error('Failed to load assessment methodology:', err);
      } finally {
        setLoading(false);
      }
    }
    fetchMethodology();
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-xs text-slate-400 font-mono">Loading Assessment Framework...</span>
        </div>
      </div>
    );
  }

  const phases = methodology?.phases || [];
  const activePhase = phases[activePhaseIndex] || phases[0];
  const decisionMatrix = methodology?.decision_matrix || [];

  const filteredMatrix = matrixFilter
    ? decisionMatrix.filter(row =>
        row.asset_type.toLowerCase().includes(matrixFilter.toLowerCase()) ||
        row.goal.toLowerCase().includes(matrixFilter.toLowerCase()) ||
        row.recommended_primary.toLowerCase().includes(matrixFilter.toLowerCase())
      )
    : decisionMatrix;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50 font-inter">
      {/* ── Hero Section ─────────────────────────────────────────────── */}
      <div className="relative overflow-hidden border-b border-slate-800 bg-gradient-to-b from-slate-900 via-slate-900/90 to-slate-950 py-14 px-6">
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute top-10 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl" />
          <div className="absolute bottom-10 right-1/4 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl" />
        </div>

        <div className="relative max-w-6xl mx-auto">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-4">
            <Compass className="w-4 h-4 animate-spin-slow" />
            <span>Curriculum Foundation • Module 0</span>
          </div>

          <h1 className="text-3xl md:text-4xl font-black text-white tracking-tight mb-4">
            How to Run an Assessment: The Universal Methodology
          </h1>

          <p className="text-slate-300 text-base max-w-3xl leading-relaxed mb-8">
            Assessments fail when tools are run randomly without context. HexaGuard's 7-Phase Methodology
            establishes the disciplined operational path from ambiguous scope to verified remediation —
            applicable across bug bounty hunting, internal penetration tests, and SOC compliance reviews.
          </p>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: 'Methodology Phases', value: '7 Phased Lifecycle' },
              { label: 'Diagnostic Engines', value: '11 Integrated Scanners' },
              { label: 'Triage Benchmark', value: 'CVSS v3.1 + EPSS v3' },
              { label: 'Practice Target', value: '127.0.0.1 Safe Sandboxes' },
            ].map((stat, i) => (
              <div key={i} className="px-4 py-3 rounded-xl bg-slate-900/80 border border-slate-800">
                <div className="text-sm font-bold text-cyan-400 font-mono">{stat.value}</div>
                <div className="text-xs text-slate-400 mt-0.5">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Main Content Container ───────────────────────────────────── */}
      <div className="max-w-6xl mx-auto px-6 py-12 space-y-16">

        {/* ── Section 1: The 7 Phases Interactive Stepper ─────────────── */}
        <section className="space-y-6">
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-cyan-400 mb-1">
                Operational Framework
              </div>
              <h2 className="text-2xl font-black text-white tracking-tight">
                The 7-Phase Assessment Lifecycle
              </h2>
            </div>
            <p className="text-xs text-slate-400 max-w-md">
              Click through each sequential phase to understand the prerequisites, actions, common pitfalls,
              and matching HexaGuard tools.
            </p>
          </div>

          {/* Phase Nav Pills */}
          <div className="flex items-center gap-2 overflow-x-auto pb-2 border-b border-slate-800 scrollbar-thin">
            {phases.map((p, idx) => {
              const isActive = idx === activePhaseIndex;
              return (
                <button
                  key={p.id}
                  onClick={() => setActivePhaseIndex(idx)}
                  className={`flex items-center gap-2.5 px-4 py-2.5 rounded-xl text-xs font-bold whitespace-nowrap transition-all ${
                    isActive
                      ? 'bg-gradient-to-r from-cyan-500 to-indigo-600 text-white shadow-lg shadow-cyan-500/20 scale-[1.02]'
                      : 'bg-slate-900 hover:bg-slate-850 text-slate-400 hover:text-slate-200 border border-slate-800'
                  }`}
                >
                  <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[11px] font-mono ${
                    isActive ? 'bg-white/20 text-white font-black' : 'bg-slate-800 text-slate-400'
                  }`}>
                    {p.number}
                  </span>
                  <span>{p.title}</span>
                </button>
              );
            })}
          </div>

          {/* Active Phase Card */}
          {activePhase && (
            <div className="rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 border border-slate-800 p-6 md:p-8 space-y-6 shadow-xl">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800/80">
                <div>
                  <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1.5">
                    <span>PHASE 0{activePhase.number}</span>
                    <span>•</span>
                    <span className="uppercase tracking-wider">{activePhase.tagline}</span>
                  </div>
                  <h3 className="text-xl font-bold text-white">
                    {activePhase.number}. {activePhase.title}
                  </h3>
                  <p className="text-sm text-slate-300 mt-2 max-w-3xl leading-relaxed">
                    {activePhase.summary}
                  </p>
                </div>

                {activePhase.route_cta && (
                  <Link
                    to={activePhase.route_cta}
                    className="inline-flex items-center gap-2 px-4 py-2 text-xs font-bold rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-300 hover:text-white border border-slate-700 transition-all self-start md:self-center"
                  >
                    <span>Launch Phase Tool</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </Link>
                )}
              </div>

              {/* Key Steps */}
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3">
                  Key Actions & Deliverables
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {activePhase.key_steps?.map((step, sIdx) => (
                    <div key={sIdx} className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 space-y-2">
                      <div className="flex items-center gap-2 text-xs font-bold text-white">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                        <span>{step.title}</span>
                      </div>
                      <p className="text-xs text-slate-400 leading-relaxed">
                        {step.detail}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Bottom Metadata: Common Pitfalls & HexaGuard Tooling */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t border-slate-800/80 text-xs">
                <div className="p-4 rounded-xl bg-rose-500/5 border border-rose-500/20 space-y-1.5">
                  <div className="flex items-center gap-2 font-bold text-rose-300">
                    <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
                    <span>Common Pitfalls to Avoid</span>
                  </div>
                  <ul className="space-y-1 text-slate-300 list-disc list-inside">
                    {activePhase.common_pitfalls?.map((pit, pIdx) => (
                      <li key={pIdx}>{pit}</li>
                    ))}
                  </ul>
                </div>

                <div className="p-4 rounded-xl bg-cyan-500/5 border border-cyan-500/20 space-y-1.5">
                  <div className="flex items-center gap-2 font-bold text-cyan-300">
                    <Zap className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                    <span>HexaGuard Platform Integration</span>
                  </div>
                  <p className="text-slate-300 leading-relaxed">
                    {activePhase.hexaguard_tooling}
                  </p>
                </div>
              </div>
            </div>
          )}
        </section>

        {/* ── Section 2: Engine Selection Decision Matrix ─────────────── */}
        <section className="space-y-6">
          <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-cyan-400 mb-1">
                Diagnostic Decision Table
              </div>
              <h2 className="text-2xl font-black text-white tracking-tight">
                Engine Selection Matrix: What Scanner to Run First
              </h2>
            </div>
            {/* Search filter for matrix */}
            <div className="relative w-full md:w-72">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="text"
                value={matrixFilter}
                onChange={e => setMatrixFilter(e.target.value)}
                placeholder="Filter by asset or engine..."
                className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div className="overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/60 shadow-lg">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-900 border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
                    <th className="py-3.5 px-4">Asset Type</th>
                    <th className="py-3.5 px-4">Testing Goal</th>
                    <th className="py-3.5 px-4">Primary Engine</th>
                    <th className="py-3.5 px-4 hidden md:table-cell">Secondary</th>
                    <th className="py-3.5 px-4">Rationale & Launch</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {filteredMatrix.map((row, idx) => (
                    <tr key={idx} className="hover:bg-slate-850/50 transition-colors">
                      <td className="py-3.5 px-4 font-semibold text-white whitespace-nowrap">
                        {row.asset_type}
                      </td>
                      <td className="py-3.5 px-4 text-slate-300">
                        {row.goal}
                      </td>
                      <td className="py-3.5 px-4">
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-mono font-bold uppercase text-[11px]">
                          <Zap className="w-3 h-3 text-cyan-400" />
                          {row.recommended_primary}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 hidden md:table-cell text-slate-400 font-mono text-[11px]">
                        {row.secondary?.join(', ')}
                      </td>
                      <td className="py-3.5 px-4">
                        <div className="flex items-center justify-between gap-3">
                          <span className="text-slate-400 text-[11px] line-clamp-2 max-w-xs">
                            {row.rationale}
                          </span>
                          <Link
                            to={row.scan_route}
                            className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 hover:text-white border border-cyan-500/40 text-xs font-semibold whitespace-nowrap transition-colors"
                          >
                            <span>Run Scan</span>
                            <ChevronRight className="w-3 h-3" />
                          </Link>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>

        {/* ── Section 3: Triage & Deep Dive Standards ─────────────────── */}
        <section className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900 to-slate-950 border border-slate-800 space-y-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-orange-500/10 text-orange-400 border border-orange-500/30">
                <Filter className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">
                  Triage Philosophy: CVSS vs EPSS v3
                </h3>
                <span className="text-xs text-slate-400">Separating theoretical flaws from real threat</span>
              </div>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Never prioritize vulnerabilities based on CVSS base score alone. CVSS measures theoretical severity
              in a vacuum, whereas EPSS (Exploit Prediction Scoring System) analyzes the probability of real-world exploitation
              in the wild within the next 30 days.
            </p>
            <div className="space-y-2 text-xs">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-start gap-2.5">
                <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 font-mono font-bold text-[10px]">P1 CRITICAL</span>
                <span className="text-slate-300">CVSS High/Critical + EPSS &gt; 50% or CISA KEV listing: Immediate patch required.</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-start gap-2.5">
                <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 font-mono font-bold text-[10px]">P2 ELEVATED</span>
                <span className="text-slate-300">Internet-facing service with known public PoC, regardless of CVSS floor.</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-start gap-2.5">
                <span className="px-2 py-0.5 rounded bg-blue-500/20 text-blue-400 font-mono font-bold text-[10px]">P3 HYGIENE</span>
                <span className="text-slate-300">Missing hardening headers and defense-in-depth flags remediated in normal release cycle.</span>
              </div>
            </div>
          </div>

          <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900 to-slate-950 border border-slate-800 space-y-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">
                  The Four-Level Lesson Bridge
                </h3>
                <span className="text-xs text-slate-400">Connecting triage directly to curriculum</span>
              </div>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Every finding uncovered by HexaGuard's scanners maps directly to a canonical encyclopedia lesson
              structured into four escalating mastery tiers:
            </p>
            <div className="space-y-2 text-xs">
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                <span className="font-bold text-white">Level 1 — Foundations</span>
                <span className="text-slate-400 text-[11px]">Core concept & real-world breach impact</span>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                <span className="font-bold text-white">Level 2 — Detection</span>
                <span className="text-slate-400 text-[11px]">Manual recognition & exact scanner signals</span>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                <span className="font-bold text-white">Level 3 — Practice</span>
                <span className="text-slate-400 text-[11px]">Adversarial Twin Sandbox flag capture</span>
              </div>
              <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                <span className="font-bold text-white">Level 4 — Defend & Report</span>
                <span className="text-slate-400 text-[11px]">Code/config patches & compliance mapping</span>
              </div>
            </div>
            <Link
              to="/learn/vulnerabilities"
              className="inline-flex items-center gap-2 text-xs font-bold text-cyan-400 hover:text-cyan-300 transition-colors pt-1"
            >
              <span>Explore All Encyclopedia Lessons</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </section>

        {/* ── Section 4: Next Steps Callouts ──────────────────────────── */}
        <div className="p-8 rounded-2xl bg-gradient-to-r from-cyan-950/40 via-slate-900 to-indigo-950/40 border border-cyan-500/30 flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="space-y-2">
            <h3 className="text-lg font-black text-white">
              Ready to begin your first assessment?
            </h3>
            <p className="text-xs text-slate-300 max-w-xl">
              Now that you understand the methodology, select a practice target in the Adversarial Twin Sandbox
              or dispatch a diagnostic engine across an authorized test scope.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Link
              to="/learn/vulnerabilities"
              className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white font-bold text-xs shadow-md shadow-cyan-500/20 transition-all"
            >
              Browse Lessons
            </Link>
            <Link
              to="/scan"
              className="px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white border border-slate-700 font-bold text-xs transition-colors"
            >
              Open Scanner Hub
            </Link>
          </div>
        </div>

      </div>
    </div>
  );
}
