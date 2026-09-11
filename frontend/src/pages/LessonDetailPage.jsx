import { useState, useEffect } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import {
  ArrowLeft, Shield, AlertTriangle, CheckCircle2,
  ExternalLink, Box, Terminal, Zap, Code, Globe, Lock,
  Package, Settings, Layers, Mail, Layout, Server,
  ChevronRight, Sparkles, MessageSquare, Check, Copy, BookOpen,
  Code2, Network, ShieldAlert, Container
} from 'lucide-react';
import SandboxLauncher from '../components/SandboxLauncher';
import MasteryMatrix from '../components/MasteryMatrix';

const SCANNER_META = {
  web:        { label: 'Web Core', icon: Globe, color: 'text-cyan-400', border: 'border-cyan-500/30', bg: 'bg-cyan-500/10' },
  dast:       { label: 'DAST Active', icon: Zap, color: 'text-purple-400', border: 'border-purple-500/30', bg: 'bg-purple-500/10' },
  sast:       { label: 'SAST Code', icon: Code2, color: 'text-amber-400', border: 'border-amber-500/30', bg: 'bg-amber-500/10' },
  network:    { label: 'Network Ports', icon: Network, color: 'text-blue-400', border: 'border-blue-500/30', bg: 'bg-blue-500/10' },
  ssl:        { label: 'SSL / TLS', icon: Lock, color: 'text-emerald-400', border: 'border-emerald-500/30', bg: 'bg-emerald-500/10' },
  deps:       { label: 'Dependencies', icon: Box, color: 'text-orange-400', border: 'border-orange-500/30', bg: 'bg-orange-500/10' },
  server:     { label: 'Headers', icon: Shield, color: 'text-rose-400', border: 'border-rose-500/30', bg: 'bg-rose-500/10' },
  server_ext: { label: 'Server Hardening', icon: ShieldAlert, color: 'text-pink-400', border: 'border-pink-500/30', bg: 'bg-pink-500/10' },
  docker:     { label: 'Container', icon: Container, color: 'text-indigo-400', border: 'border-indigo-500/30', bg: 'bg-indigo-500/10' },
  dns:        { label: 'DNS & Mail', icon: Globe, color: 'text-teal-400', border: 'border-teal-500/30', bg: 'bg-teal-500/10' },
  wordpress:  { label: 'CMS', icon: AlertTriangle, color: 'text-yellow-400', border: 'border-yellow-500/30', bg: 'bg-yellow-500/10' },
};

function CapabilityBadge({ capabilityKey, matrix }) {
  if (!matrix?.capabilities) return null;
  const cap = matrix.capabilities[capabilityKey] || { state: 'NOT_STARTED' };
  const state = cap.state || 'NOT_STARTED';

  const cfg = {
    NOT_STARTED: { labelAr: 'لم تبدأ', cls: 'bg-slate-800/80 text-slate-400 border-slate-700' },
    INTRODUCED: { labelAr: 'مُستَهلّة', cls: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30' },
    PRACTICED: { labelAr: 'مُمارَسَة', cls: 'bg-amber-500/10 text-amber-400 border-amber-500/30' },
    DEMONSTRATED: { labelAr: 'مُثبَتَة', cls: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' },
    MASTERED: { labelAr: 'مُتقَنَة', cls: 'bg-purple-500/15 text-purple-300 border-purple-500/40' },
  }[state] || { labelAr: state, cls: 'bg-slate-800 text-slate-400 border-slate-700' };

  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[10px] font-mono font-semibold border ${cfg.cls}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      <span>{capabilityKey}: {cfg.labelAr}</span>
    </span>
  );
}

const DIFFICULTY_COLORS = {
  easy:   'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  medium: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  hard:   'bg-rose-500/10 text-rose-400 border-rose-500/30',
};

const SEVERITY_COLORS = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/40',
  high:     'bg-orange-500/20 text-orange-400 border-orange-500/40',
  medium:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
  low:      'bg-blue-500/20 text-blue-400 border-blue-500/40',
};

export default function LessonDetailPage() {
  const { vulnId } = useParams();
  const navigate = useNavigate();

  const [topic, setTopic] = useState(null);
  const [topicType, setTopicType] = useState('offensive');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeLevel, setActiveLevel] = useState(1);
  const [copied, setCopied] = useState(false);
  const [skillStatus, setSkillStatus] = useState('theory_only');
  const [masteryMatrix, setMasteryMatrix] = useState(null);

  useEffect(() => {
    async function loadTopicData() {
      setLoading(true);
      setError(null);
      try {
        const [topicRes, skillRes, masteryRes] = await Promise.all([
          axios.get(`/api/learn/taxonomy/${vulnId}`),
          axios.get('/api/skill/ledger').catch(() => ({ data: { ledger: [] } })),
          axios.get(`/api/learning/mastery/${vulnId}`).catch(() => ({ data: { matrix: null } })),
        ]);

        if (topicRes.data?.ok) {
          setTopic(topicRes.data.topic);
          setTopicType(topicRes.data.topic_type || 'offensive');

          const userLedger = skillRes.data?.ledger || [];
          const userItem = userLedger.find(item => item.vuln_type === vulnId);
          if (userItem) {
            setSkillStatus(userItem.status);
          }
          if (masteryRes.data?.ok && masteryRes.data?.matrix) {
            setMasteryMatrix(masteryRes.data.matrix);
          }
        } else {
          setError(topicRes.data?.error || 'Topic not found');
        }
      } catch (err) {
        setError(err.response?.data?.error || `Failed to load lesson for '${vulnId}'.`);
      } finally {
        setLoading(false);
      }
    }
    if (vulnId) {
      loadTopicData();
    }
  }, [vulnId]);

  function copyText(text) {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function openAriaMentor() {
    navigate(`/chat?prompt=${encodeURIComponent(`I am studying ${topic?.name_en || vulnId} in HexaGuard's curriculum. Can you act as my Socratic Red-Team mentor and guide me through the attack mechanics and verification without revealing the direct solution?`)}`);
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-xs text-slate-400 font-mono">Loading Canonical Curriculum...</span>
        </div>
      </div>
    );
  }

  if (error || !topic) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6">
        <div className="max-w-md w-full p-8 rounded-2xl bg-slate-900 border border-slate-800 text-center space-y-4">
          <div className="w-12 h-12 rounded-2xl bg-rose-500/10 border border-rose-500/30 text-rose-400 flex items-center justify-center mx-auto">
            <AlertTriangle className="w-6 h-6" />
          </div>
          <h2 className="text-lg font-bold text-white">Lesson Not Found</h2>
          <p className="text-xs text-slate-400 leading-relaxed">
            {error || `The topic identifier '${vulnId}' is not cataloged in the canonical taxonomy.`}
          </p>
          <Link
            to="/learn/vulnerabilities"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Return to Catalog</span>
          </Link>
        </div>
      </div>
    );
  }

  const lesson = topic.lesson || {};
  const practice = lesson.level_3_practice || {};
  const deepDiveLinks = lesson.deep_dive_links || [];
  const prerequisites = topic.prerequisites || [];
  const scannerInfo = SCANNER_META[topic.scanner] || { label: topic.scanner || 'Scanner', icon: Shield, color: 'text-cyan-400', border: 'border-cyan-500/30', bg: 'bg-cyan-500/10' };
  const ScannerIcon = scannerInfo.icon;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-50 font-inter pb-20">
      {/* ── Top Bar / Breadcrumb ─────────────────────────────────────── */}
      <div className="border-b border-slate-800/80 bg-slate-900/50 backdrop-blur-sm sticky top-0 z-20">
        <div className="max-w-5xl mx-auto px-6 py-3.5 flex items-center justify-between gap-4">
          <Link
            to="/learn/vulnerabilities"
            className="inline-flex items-center gap-2 text-xs font-semibold text-slate-400 hover:text-cyan-300 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Vulnerability Catalog</span>
          </Link>

          <div className="flex items-center gap-3">
            {/* Skill Ledger Badge */}
            <div className={`px-2.5 py-1 rounded-full text-[11px] font-bold border flex items-center gap-1.5 ${
              skillStatus === 'practiced_verified'
                ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                : skillStatus === 'practiced_self_reported'
                ? 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30'
                : 'bg-slate-800 text-slate-400 border-slate-700'
            }`}>
              <span className={`w-2 h-2 rounded-full ${
                skillStatus === 'practiced_verified'
                  ? 'bg-emerald-400 shadow-sm shadow-emerald-400/50'
                  : skillStatus === 'practiced_self_reported'
                  ? 'bg-cyan-400'
                  : 'bg-slate-500'
              }`} />
              <span className="capitalize">
                {skillStatus === 'practiced_verified' ? 'Verified in Ledger' : skillStatus === 'practiced_self_reported' ? 'Self-Reported' : 'Theory Only'}
              </span>
            </div>

            <button
              onClick={openAriaMentor}
              className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-semibold rounded-lg bg-indigo-500/10 hover:bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 transition-all"
            >
              <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
              <span>Ask Mentor</span>
            </button>
          </div>
        </div>
      </div>

      {/* ── Topic Header ─────────────────────────────────────────────── */}
      <div className="relative overflow-hidden border-b border-slate-800 bg-gradient-to-b from-slate-900 via-slate-900/80 to-slate-950 py-10 px-6">
        <div className="absolute top-0 right-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="max-w-5xl mx-auto space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            {/* Scanner Engine badge */}
            {topicType === 'offensive' ? (
              <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold border ${scannerInfo.bg} ${scannerInfo.color} ${scannerInfo.border}`}>
                <ScannerIcon className="w-3.5 h-3.5" />
                <span>{scannerInfo.label}</span>
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold border bg-indigo-500/10 text-indigo-400 border-indigo-500/30">
                <Shield className="w-3.5 h-3.5" />
                <span>Blue Team SOC • {topic.mitre_id} ({topic.tactic})</span>
              </span>
            )}

            {/* Difficulty Badge */}
            {topic.difficulty && (
              <span className={`px-2.5 py-1 rounded-lg text-xs font-bold uppercase tracking-wider border ${DIFFICULTY_COLORS[topic.difficulty] || DIFFICULTY_COLORS.medium}`}>
                {topic.difficulty}
              </span>
            )}

            {/* Severity Default */}
            {topic.severity_default && (
              <span className={`px-2.5 py-1 rounded-lg text-xs font-bold uppercase tracking-wider border ${SEVERITY_COLORS[topic.severity_default] || SEVERITY_COLORS.medium}`}>
                {topic.severity_default}
              </span>
            )}
          </div>

          <div>
            <h1 className="text-2xl md:text-3xl font-black text-white tracking-tight">
              {topic.name_en}
            </h1>
            {topic.name_ar && (
              <div className="text-xs text-slate-400 mt-1 font-medium" dir="rtl">
                {topic.name_ar}
              </div>
            )}
          </div>

          <p className="text-sm text-slate-300 leading-relaxed max-w-3xl">
            {topic.description_en}
          </p>

          {/* Suggested Prerequisites */}
          {prerequisites.length > 0 && (
            <div className="pt-2 flex items-center gap-2 flex-wrap">
              <span className="text-xs font-semibold text-slate-400">Prerequisites:</span>
              {prerequisites.map(preId => (
                <Link
                  key={preId}
                  to={`/learn/${preId}`}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800/90 hover:bg-slate-750 text-cyan-300 border border-slate-700 text-xs transition-colors"
                >
                  <BookOpen className="w-3 h-3" />
                  <span>{preId}</span>
                </Link>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── 4-Level Curriculum Stepper / Nav ──────────────────────────── */}
      <div className="max-w-5xl mx-auto px-6 pt-8 space-y-8">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { level: 1, title: 'Foundations', subtitle: 'Concept & Real Breach' },
            { level: 2, title: 'Detection', subtitle: 'Manual & Scanner Signals' },
            { level: 3, title: 'Practice', subtitle: 'Sandbox & Challenge' },
            { level: 4, title: 'Defend & Report', subtitle: 'Code Fix & Compliance' },
          ].map(item => {
            const isActive = activeLevel === item.level;
            return (
              <button
                key={item.level}
                onClick={() => setActiveLevel(item.level)}
                className={`p-4 rounded-xl text-left transition-all border ${
                  isActive
                    ? 'bg-gradient-to-br from-slate-900 to-cyan-950/40 border-cyan-500/50 shadow-lg shadow-cyan-500/10'
                    : 'bg-slate-900/60 hover:bg-slate-850/70 border-slate-800'
                }`}
              >
                <div className={`text-xs font-mono font-bold ${isActive ? 'text-cyan-400' : 'text-slate-500'}`}>
                  LEVEL 0{item.level}
                </div>
                <div className="text-sm font-bold text-white mt-0.5">{item.title}</div>
                <div className="text-[11px] text-slate-400 mt-0.5">{item.subtitle}</div>
              </button>
            );
          })}
        </div>

        {/* ── Active Level Display ───────────────────────────────────── */}
        <div className="rounded-2xl bg-slate-900/80 border border-slate-800 p-6 md:p-8 space-y-6 shadow-xl">
          {/* LEVEL 1: FOUNDATIONS */}
          {activeLevel === 1 && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-800">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                    <BookOpen className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-white">Level 1: Foundations & Real-World Impact</h3>
                    <p className="text-xs text-slate-400">Core architectural concept, threat mechanics, and documented breach precedent.</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <CapabilityBadge capabilityKey="knowledge" matrix={masteryMatrix} />
                  <CapabilityBadge capabilityKey="impact_analysis" matrix={masteryMatrix} />
                </div>
              </div>

              <div className="space-y-4">
                <div className="p-5 rounded-xl bg-slate-950/80 border border-slate-800/80">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-400 mb-2">Technical Analysis</h4>
                  <p className="text-sm text-slate-200 leading-relaxed whitespace-pre-line">
                    {lesson.level_1_foundations_en}
                  </p>
                </div>
              </div>

              <div className="flex justify-end">
                <button
                  onClick={() => setActiveLevel(2)}
                  className="inline-flex items-center gap-2 px-4 py-2 text-xs font-bold rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-colors"
                >
                  <span>Proceed to Level 2: Detection</span>
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* LEVEL 2: DETECTION */}
          {activeLevel === 2 && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-800">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-orange-500/10 text-orange-400 border border-orange-500/30">
                    <Terminal className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-white">Level 2: Detection & Scanner Signals</h3>
                    <p className="text-xs text-slate-400">How to manually recognize the flaw, and what exact signal HexaGuard surfaces.</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <CapabilityBadge capabilityKey="recognition" matrix={masteryMatrix} />
                  <CapabilityBadge capabilityKey="manual_detection" matrix={masteryMatrix} />
                </div>
              </div>

              <div className="p-5 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-orange-400">
                  Recognition & Diagnostic Signal
                </h4>
                <p className="text-sm text-slate-200 leading-relaxed whitespace-pre-line">
                  {lesson.level_2_detection_en}
                </p>
              </div>

              {topicType === 'offensive' && topic.scanner && (
                <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400">
                      <Zap className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="text-xs font-bold text-white">Diagnostic Engine: {scannerInfo.label}</div>
                      <div className="text-[11px] text-slate-400">Run this scanner directly against your authorized target.</div>
                    </div>
                  </div>
                  <Link
                    to={`/scan/${topic.scanner}`}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-cyan-500/20 text-cyan-300 hover:bg-cyan-500/30 border border-cyan-500/40 transition-colors"
                  >
                    <span>Launch Scanner</span>
                    <ChevronRight className="w-3 h-3" />
                  </Link>
                </div>
              )}

              <div className="flex items-center justify-between pt-2">
                <button
                  onClick={() => setActiveLevel(1)}
                  className="inline-flex items-center gap-1 text-xs font-semibold text-slate-400 hover:text-white"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  <span>Back to Foundations</span>
                </button>
                <button
                  onClick={() => setActiveLevel(3)}
                  className="inline-flex items-center gap-2 px-4 py-2 text-xs font-bold rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-colors"
                >
                  <span>Proceed to Level 3: Practice</span>
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* LEVEL 3: PRACTICE */}
          {activeLevel === 3 && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/30">
                    <Box className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-white">Level 3: Hands-On Practice & Challenge</h3>
                    <p className="text-xs text-slate-400">Step-by-step guided lab, independent flag challenge, and live sandbox.</p>
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  <CapabilityBadge capabilityKey="lab_exploitation" matrix={masteryMatrix} />
                  <CapabilityBadge capabilityKey="validation" matrix={masteryMatrix} />
                  <button
                    onClick={openAriaMentor}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/40 text-xs font-bold transition-all shadow-sm"
                  >
                    <Sparkles className="w-4 h-4 text-indigo-400" />
                    <span>Socratic Mentor</span>
                  </button>
                </div>
              </div>

              {/* Guided & Challenge Prompts */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-5 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-2">
                  <span className="text-[11px] font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded-md border border-cyan-500/20">
                    Part A • Guided Walkthrough
                  </span>
                  <p className="text-xs text-slate-300 leading-relaxed pt-1 whitespace-pre-line">
                    {practice.guided_prompt_en}
                  </p>
                </div>

                <div className="p-5 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-2">
                  <span className="text-[11px] font-bold uppercase tracking-wider text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded-md border border-amber-500/20">
                    Part B • Independent Challenge
                  </span>
                  <p className="text-xs text-slate-300 leading-relaxed pt-1 whitespace-pre-line">
                    {practice.challenge_prompt_en}
                  </p>
                </div>
              </div>

              {/* Live Sandbox Container or Safe Mode Guidance */}
              {practice.sandbox_target ? (
                <div className="space-y-3">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                    Adversarial Twin Local Practice Target
                  </h4>
                  <SandboxLauncher
                    targetVulnType={practice.sandbox_target}
                    onVerified={() => setSkillStatus('practiced_verified')}
                  />
                </div>
              ) : (
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 text-xs text-slate-400 flex items-start gap-3">
                  <Shield className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-slate-300 block mb-0.5">Non-Containerized Practice Mode</span>
                    <span>
                      This topic covers architectural, static code, configuration, or network protocol controls.
                      Practice is conducted through local code review, CLI probing, or configuration auditing as outlined
                      in the challenge prompt without spinning up an isolated container.
                    </span>
                  </div>
                </div>
              )}

              <div className="flex items-center justify-between pt-2">
                <button
                  onClick={() => setActiveLevel(2)}
                  className="inline-flex items-center gap-1 text-xs font-semibold text-slate-400 hover:text-white"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  <span>Back to Detection</span>
                </button>
                <button
                  onClick={() => setActiveLevel(4)}
                  className="inline-flex items-center gap-2 px-4 py-2 text-xs font-bold rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition-colors"
                >
                  <span>Proceed to Level 4: Defend & Report</span>
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {/* LEVEL 4: DEFEND & REPORT */}
          {activeLevel === 4 && (
            <div className="space-y-6 animate-in fade-in duration-200">
              <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-slate-800">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    <Shield className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-white">Level 4: Defend, Remediate & Comply</h3>
                    <p className="text-xs text-slate-400">Hardened configuration, secure coding snippets, and regulatory compliance mapping.</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <CapabilityBadge capabilityKey="remediation" matrix={masteryMatrix} />
                  <CapabilityBadge capabilityKey="reporting" matrix={masteryMatrix} />
                </div>
              </div>

              {/* Remediation Prose & Snippet */}
              <div className="p-5 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-400">
                    Defensive Standard & Patch Guidance
                  </h4>
                  <button
                    onClick={() => copyText(lesson.level_4_remediation_en)}
                    className="inline-flex items-center gap-1 text-[11px] text-slate-400 hover:text-white transition-colors"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <p className="text-sm text-slate-200 leading-relaxed whitespace-pre-line">
                  {lesson.level_4_remediation_en}
                </p>
              </div>

              {/* Incident link if blue team */}
              {topicType === 'incident' && (
                <div className="p-4 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <Shield className="w-5 h-5 text-indigo-400" />
                    <div>
                      <div className="text-xs font-bold text-white">SOC Incident Investigation Ready</div>
                      <div className="text-[11px] text-slate-300">Test your forensic triage against simulated enterprise SIEM logs.</div>
                    </div>
                  </div>
                  <Link
                    to="/casefiles"
                    className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold transition-colors"
                  >
                    <span>Open Case Files</span>
                    <ChevronRight className="w-3 h-3" />
                  </Link>
                </div>
              )}

              <div className="flex items-center justify-between pt-2">
                <button
                  onClick={() => setActiveLevel(3)}
                  className="inline-flex items-center gap-1 text-xs font-semibold text-slate-400 hover:text-white"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  <span>Back to Practice</span>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* ── Mastery Matrix Section ───────────────────────────────────── */}
        <div className="pt-2">
          <MasteryMatrix vulnType={vulnId} initialMatrix={masteryMatrix} />
        </div>

        {/* ── Supplementary Deep Dive Links (Capped at 3, strictly at the end) ── */}
        {deepDiveLinks.length > 0 && (
          <div className="pt-6 border-t border-slate-800 space-y-3">
            <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-400">
              <ExternalLink className="w-4 h-4 text-cyan-400" />
              <span>Supplementary External References (Going Further)</span>
            </div>
            <div className="flex flex-wrap gap-3">
              {deepDiveLinks.map((link, idx) => (
                <a
                  key={idx}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded-xl bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 hover:border-slate-700 transition-all shadow-sm"
                >
                  <span>{link.label}</span>
                  <ExternalLink className="w-3 h-3 opacity-60 ml-0.5" />
                </a>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
