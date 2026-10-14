import React, { useState, useEffect } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import axios from 'axios';
import { useLang } from '../context/LangContext';
import {
  Shield,
  Cpu,
  Terminal,
  Database,
  ExternalLink,
  Download,
  CheckCircle2,
  Sparkles,
  GraduationCap,
  Mail,
  Code2,
  FileCheck,
  ChevronRight,
  Globe,
  Lock,
  Clock,
  AlertCircle,
  Copy,
  Check,
  FileText
} from 'lucide-react';

const API = import.meta.env.VITE_API_URL || '';

const ARCHITECTURE_MODULES = [
  {
    id: 'sast',
    title_en: 'Autonomous AST & SAST Engine',
    title_ar: 'محرك التحليل الاستاتيكي وشجرة البنية (AST)',
    icon: Code2,
    badge: 'Code Level',
    badgeColor: 'bg-violet-500/10 text-violet-400 border-violet-500/30',
    metrics: '50+ CWE Rules · Zero Overhead',
    desc_en: 'Abstract Syntax Tree (AST) static taint tracer evaluating data flow graphs for injection vulnerabilities, cryptographic flaws, and authorization bypasses without executing the target program.',
    desc_ar: 'محلل مسارات البيانات الاستاتيكية عبر شجرة البنية المجردة لكشف ثغرات الحقن، والتشفير الضعيف، وتجاوز الصلاحيات قبل تشغيل الكود.',
    academic_interest: 'Relevant to labs working on Static Program Analysis, Compilers, and Formal Verification.'
  },
  {
    id: 'dast',
    title_en: 'Dynamic Reconnaissance & DAST Harness',
    title_ar: 'الاستطلاع الديناميكي وفحص DAST الميداني',
    icon: Terminal,
    badge: 'Runtime',
    badgeColor: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
    metrics: 'Real-time Crawl · IDOR/SSRF Verification',
    desc_en: 'Asynchronous crawler executing targeted active probes with automated rate limiting and non-destructive payloads to confirm real-world exploitability with zero collateral risk.',
    desc_ar: 'زاحف ويب غير متزامن يرسل حزم اختبارية نشطة غير تخريبية لتأكيد قابلية الاستغلال الميدانية دون تعطيل الخوادم.',
    academic_interest: 'Relevant to labs researching Automated Fuzzing, Web Security, and Attack Surface Mapping.'
  },
  {
    id: 'intel',
    title_en: 'Real-time CVE/KEV Threat Intelligence',
    title_ar: 'استخبارات التهديدات الحية (CVE / KEV)',
    icon: Database,
    badge: 'Intelligence',
    badgeColor: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    metrics: 'CISA KEV Integration · CVSS v3.1 Matrix',
    desc_en: 'Continuous ingestion engine aggregating actively exploited vulnerabilities from CISA KEV and National Vulnerability Databases, mapping them directly to the target system telemetry.',
    desc_ar: 'محرك استيعاب مستمر يربط قواعد الثغرات المستغلة عالمياً (CISA KEV) ببيانات المراقبة الحية للأنظمة المفحوصة.',
    academic_interest: 'Relevant to labs investigating Cyber Threat Intelligence, Vulnerability Forecasting, and AI SOC automation.'
  },
  {
    id: 'ledger',
    title_en: 'Skill Ledger & Dojo Verification',
    title_ar: 'سجل المهارات المعتمد ومختبر الدوجو',
    icon: Shield,
    badge: 'Empirical Verification',
    badgeColor: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    metrics: 'Cryptographic Ledger · Hands-On CTF Matrix',
    desc_en: 'Mathematical and empirical competence verification system tracking hands-on vulnerability challenges and remediation actions with zero self-reported bias.',
    desc_ar: 'نظام توثيق تجريبي يقيس الكفاءة العملية للباحث عبر تحديات حية وتتبع الإجراءات الترقيعية دون أي تحيز نظري.',
    academic_interest: 'Relevant to labs developing Security Education, Adversarial Simulation, and Human Factors in Security.'
  }
];

export default function ReviewerPortalPage() {
  const { lang } = useLang();
  const isRtl = lang === 'ar';
  const [searchParams, setSearchParams] = useSearchParams();
  const token = searchParams.get('token');

  // Shared Briefing state (when token is provided)
  const [briefing, setBriefing] = useState(null);
  const [briefingLoading, setBriefingLoading] = useState(!!token);
  const [briefingError, setBriefingError] = useState(null);
  const [tokenInput, setTokenInput] = useState('');
  const [copiedCmd, setCopiedCmd] = useState(null);

  // General showcase state (when no token)
  const [selectedModule, setSelectedModule] = useState(ARCHITECTURE_MODULES[0]);
  const [downloadSuccess, setDownloadSuccess] = useState(false);

  useEffect(() => {
    if (!token) return;

    let isMounted = true;
    axios.get(`${API}/api/dossier/briefings/shared/${token}`)
      .then(res => {
        if (res.data?.ok) {
          setBriefing(res.data);
        } else {
          setBriefingError({
            type: 'error',
            message: res.data?.error || 'Failed to load briefing pack'
          });
        }
      })
      .catch(err => {
        const status = err.response?.status;
        const errData = err.response?.data || {};
        if (status === 410) {
          setBriefingError({
            type: errData.status || 'revoked',
            title: errData.status === 'expired' ? 'Briefing Link Expired' : 'Access Revoked by Candidate',
            message: errData.error || 'Access to this academic briefing is no longer available.'
          });
        } else if (status === 403) {
          setBriefingError({
            type: 'private',
            title: 'Briefing Currently Private',
            message: errData.error || 'This academic briefing pack is private and not authorized for external viewing.'
          });
        } else {
          setBriefingError({
            type: 'not_found',
            title: 'Briefing Not Found',
            message: errData.error || 'The requested briefing pack token is invalid or does not exist.'
          });
        }
      })
      .finally(() => {
        if (isMounted) setBriefingLoading(false);
      });
    return () => { isMounted = false; };
  }, [token]);

  const handleCopy = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const handleManualTokenSubmit = (e) => {
    e.preventDefault();
    if (tokenInput.trim()) {
      setSearchParams({ token: tokenInput.trim() });
    }
  };

  const downloadPaperOverview = () => {
    const reportText = `# SecuraX (HexaGuard) — Academic Research Overview & Technical Abstract

## Candidate Information
- **Name:** Abdallah Benaicha
- **Degree:** Master of Science in Cybersecurity (NICT, 2024–2026)
- **Institution:** University of Mohamed Boudiaf – M'Sila
- **Target:** Prospective Doctoral / PhD Researcher

## Research Abstract
SecuraX addresses the critical bottleneck in automated vulnerability lifecycle management by unifying static Abstract Syntax Tree (AST) taint analysis, dynamic runtime crawling, and live threat intelligence into a unified, reproducible telemetry pipeline. Designed from the ground up as a production-grade working artifact, SecuraX demonstrates empirical zero-day discovery heuristics, automated patch synthesis, and verifiable skill tracking.
`;

    const blob = new Blob([reportText], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'SecuraX_Academic_Research_Abstract.md';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    setDownloadSuccess(true);
    setTimeout(() => setDownloadSuccess(false), 2500);
  };

  /* ──────────────────────────────────────────────────────────────────────────
     VIEW A: SHARED SUPERVISOR BRIEFING PACK (WHEN TOKEN IS PRESENT)
     ────────────────────────────────────────────────────────────────────────── */
  if (token) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-100 p-4 sm:p-8 md:p-12 font-sans selection:bg-violet-500 selection:text-white" dir={isRtl ? 'rtl' : 'ltr'}>
        <div className="max-w-5xl mx-auto space-y-8">
          {/* Top Bar */}
          <div className="flex items-center justify-between border-b border-slate-800 pb-4">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-violet-600 to-indigo-600 flex items-center justify-center font-black text-white text-sm shadow-lg shadow-violet-900/30">
                SX
              </div>
              <div>
                <span className="text-xs font-black text-white tracking-wider">SECURAX</span>
                <span className="text-[10px] ml-2 px-2 py-0.5 rounded bg-violet-500/20 text-violet-300 font-mono border border-violet-500/30">
                  Supervisor Briefing Portal
                </span>
              </div>
            </div>
            <button
              onClick={() => setSearchParams({})}
              className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
            >
              ← {isRtl ? 'العودة للمنصة العامة' : 'Exit to Public Overview'}
            </button>
          </div>

          {/* Loading State */}
          {briefingLoading && (
            <div className="py-24 flex flex-col items-center justify-center gap-3">
              <div className="w-10 h-10 border-2 border-violet-500 border-t-transparent rounded-full animate-spin" />
              <div className="text-xs text-slate-400 font-mono">Authenticating secure token & decrypting briefing pack...</div>
            </div>
          )}

          {/* Error / Revocation / Expiration Cards */}
          {briefingError && !briefingLoading && (
            <div className="p-8 rounded-3xl bg-slate-900/90 border border-slate-800 shadow-2xl text-center max-w-xl mx-auto space-y-4">
              <div className="w-14 h-14 rounded-2xl mx-auto flex items-center justify-center text-2xl shadow-inner
                bg-rose-500/10 text-rose-400 border border-rose-500/20">
                {briefingError.type === 'revoked' ? <Lock className="w-7 h-7" /> :
                 briefingError.type === 'expired' ? <Clock className="w-7 h-7" /> :
                 <AlertCircle className="w-7 h-7" />}
              </div>
              <div>
                <h2 className="text-lg font-bold text-white mb-1">
                  {briefingError.title || 'Access Restricted'}
                </h2>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {briefingError.message}
                </p>
              </div>
              <div className="pt-2">
                <button
                  onClick={() => setSearchParams({})}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs text-white font-semibold transition"
                >
                  Return to Overview
                </button>
              </div>
            </div>
          )}

          {/* Active Supervisor Briefing Content */}
          {briefing && !briefingLoading && (
            <div className="space-y-8 animate-in fade-in duration-300">
              {/* Header Box */}
              <div className="p-6 sm:p-8 rounded-3xl bg-gradient-to-br from-slate-900 via-slate-900/90 to-violet-950/30 border border-violet-500/30 shadow-2xl relative overflow-hidden">
                <div className="relative z-10 space-y-4">
                  <div className="flex items-center justify-between gap-3 flex-wrap">
                    <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-semibold">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                      <span>{isRtl ? 'حزمة ترشح مخصصة ومعتمدة' : 'Tailored Academic Briefing Pack'}</span>
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">
                      ID: {token.slice(0, 8)}... · Cryptographically Sealed
                    </span>
                  </div>

                  <div>
                    <h1 className="text-2xl sm:text-3xl font-black text-white tracking-tight leading-tight">
                      {briefing.title}
                    </h1>
                    <div className="mt-2 text-xs sm:text-sm text-cyan-400 font-medium">
                      🎯 {isRtl ? 'مُعد خصيصاً للدكتور/المختبر:' : 'Curated for:'} <span className="text-white font-bold">{briefing.target_supervisor}</span>
                    </div>
                  </div>

                  {briefing.opportunity && (
                    <div className="p-3 rounded-xl bg-slate-950/60 border border-slate-800 text-xs text-slate-300 flex items-center gap-2 flex-wrap">
                      <span className="text-slate-500 font-mono">Target PhD Program:</span>
                      <span className="text-white font-semibold">{briefing.opportunity.institution}</span>
                      <span>·</span>
                      <span className="text-slate-300">{briefing.opportunity.program || briefing.opportunity.field}</span>
                      <span>·</span>
                      <span className="text-slate-400">({briefing.opportunity.country || 'Global'})</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Candidate Credentials Strip */}
              <div className="p-5 rounded-2xl bg-slate-900 border border-slate-800 flex items-center justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 rounded-full bg-cyan-600/20 border border-cyan-500/30 flex items-center justify-center text-cyan-300 font-black text-base">
                    AB
                  </div>
                  <div>
                    <div className="text-sm font-bold text-white flex items-center gap-2">
                      <span>{briefing.candidate?.name || 'Abdallah Benaicha'}</span>
                      <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                        [VERIFIED EVIDENCE]
                      </span>
                    </div>
                    <div className="text-xs text-slate-400 mt-0.5">
                      {briefing.candidate?.degree} · <span className="text-cyan-300 font-semibold">{briefing.candidate?.university}</span>
                    </div>
                    <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                      Class Rank: <span className="text-white font-bold">{briefing.candidate?.class_rank}</span> · Final GPA: <span className="text-emerald-300 font-bold">{briefing.candidate?.gpa}</span>
                    </div>
                  </div>
                </div>

                <div className="text-right">
                  <div className="text-[10px] font-mono text-slate-500 uppercase">Primary Faculty Reference</div>
                  <div className="text-xs text-slate-300 font-semibold">Prof. Samir Akhrouf</div>
                  <div className="text-[10px] text-slate-500 font-mono">samir.akhrouf@univ-msila.dz</div>
                </div>
              </div>

              {/* Candidate Outreach Pitch */}
              {briefing.custom_statement && (
                <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-2">
                  <div className="text-xs font-bold uppercase tracking-wider text-violet-400">
                    Candidate Research Alignment Pitch
                  </div>
                  <div className="text-xs text-slate-200 leading-relaxed whitespace-pre-line p-3.5 rounded-xl bg-slate-950 border border-slate-800/80 font-mono">
                    {briefing.custom_statement}
                  </div>
                </div>
              )}

              {/* Requirement-to-Evidence Matrix */}
              {briefing.matrix?.length > 0 && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div>
                      <h2 className="text-base font-bold text-white">Requirement-to-Evidence Alignment Matrix</h2>
                      <p className="text-xs text-slate-400">Direct mapping between opportunity requirements and candidate's demonstrated evidence.</p>
                    </div>
                  </div>

                  <div className="overflow-x-auto rounded-2xl border border-slate-800">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="bg-slate-900/80 border-b border-slate-800 text-[10px] font-mono text-slate-400 uppercase">
                          <th className="p-3">Requirement</th>
                          <th className="p-3">Candidate Demonstrated Evidence</th>
                          <th className="p-3">Status</th>
                          <th className="p-3">Gap & Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 bg-slate-950/40">
                        {briefing.matrix.map((row, idx) => (
                          <tr key={idx} className="hover:bg-slate-900/30 transition-colors">
                            <td className="p-3 font-semibold text-white max-w-xs">{row.requirement_name || row.requirement}</td>
                            <td className="p-3 text-slate-300 max-w-sm leading-relaxed">{row.candidate_evidence}</td>
                            <td className="p-3 whitespace-nowrap">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                                row.match_status === 'MATCHED'
                                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30'
                                  : row.match_status === 'PARTIALLY_MATCHED'
                                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                                  : 'bg-purple-500/20 text-purple-300 border-purple-500/30'
                              }`}>
                                {row.match_status}
                              </span>
                            </td>
                            <td className="p-3 text-[11px] text-slate-400">{row.gap || row.action || '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Selected Proof-of-Work Artifacts */}
              {briefing.selected_evidence?.length > 0 && (
                <div className="space-y-4">
                  <div>
                    <h2 className="text-base font-bold text-white">Selected Proof-of-Work Artifacts (Code & Tests)</h2>
                    <p className="text-xs text-slate-400">Authentic repository modules with cryptographic SHA-256 hashes and copyable reproduction commands.</p>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {briefing.selected_evidence.map((item) => (
                      <div key={item.id} className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-3 flex flex-col justify-between">
                        <div className="space-y-2">
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-violet-500/10 text-violet-300 border border-violet-500/20">
                              {item.category?.replace('_', ' ')}
                            </span>
                            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                              {item.status}
                            </span>
                          </div>

                          <h3 className="text-sm font-bold text-white leading-snug">{item.title}</h3>
                          <p className="text-xs text-slate-400 leading-relaxed">{item.description}</p>

                          {item.repo_path && (
                            <div className="text-[11px] text-slate-500 font-mono flex items-center gap-1.5 truncate">
                              <span>📁</span>
                              <span className="truncate">{item.repo_path}</span>
                            </div>
                          )}

                          {item.integrity_hash && (
                            <div className="text-[10px] font-mono text-slate-500 truncate bg-slate-950 p-1.5 rounded border border-slate-800/80">
                              SHA-256: {item.integrity_hash}
                            </div>
                          )}
                        </div>

                        {item.reproducible_cmd && (
                          <div className="pt-2 border-t border-slate-800/80 space-y-1.5">
                            <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
                              <span>Reproducible Terminal Command</span>
                              <button
                                onClick={() => handleCopy(item.reproducible_cmd, item.id)}
                                className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1"
                              >
                                {copiedCmd === item.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                <span>{copiedCmd === item.id ? 'Copied' : 'Copy'}</span>
                              </button>
                            </div>
                            <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-[10px] font-mono text-cyan-300 select-all break-all">
                              {item.reproducible_cmd}
                            </div>
                            {item.actual_result && (
                              <div className="text-[10px] text-slate-400 leading-relaxed">
                                <span className="text-emerald-400 font-bold">Measured: </span>
                                {item.actual_result}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Curated Documents Downloads */}
              {briefing.selected_documents?.length > 0 && (
                <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-3">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <FileText className="w-4 h-4 text-emerald-400" />
                    <span>Curated Academic Documents Authorized for this Briefing</span>
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
                    {briefing.selected_documents.map((doc, idx) => (
                      <div key={idx} className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <div className="text-xs font-bold text-white truncate">{doc.title || doc.file}</div>
                          <div className="text-[10px] font-mono text-slate-500">{doc.provenance || '[VERIFIED EVIDENCE]'}</div>
                        </div>
                        <a
                          href={`${API}/api/dossier/briefings/shared/${token}/download/${doc.id || doc.file}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="px-2.5 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 text-xs font-bold inline-flex items-center gap-1 transition shrink-0"
                        >
                          <Download className="w-3.5 h-3.5" />
                          <span>Get</span>
                        </a>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Disclaimer */}
              <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/80 text-[11px] text-slate-500 leading-relaxed font-mono">
                🛡️ {briefing.disclaimer}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  /* ──────────────────────────────────────────────────────────────────────────
     VIEW B: PUBLIC GENERAL OVERVIEW (WHEN NO TOKEN IN QUERY)
     ────────────────────────────────────────────────────────────────────────── */
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6 md:p-12 font-sans selection:bg-violet-500 selection:text-white">
      <div className="max-w-6xl mx-auto space-y-10">

        {/* Top Navigation & Status */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-violet-600 to-indigo-600 flex items-center justify-center font-black text-white shadow-lg shadow-violet-900/30">
              SX
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-black text-white tracking-wider">SECURAX</span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-violet-500/20 text-violet-300 font-mono border border-violet-500/30">
                  Academic Reviewer Portal
                </span>
              </div>
              <p className="text-xs text-slate-400">Live Engineering & Research Artifact for Doctoral Review</p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={downloadPaperOverview}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-semibold text-slate-200 transition"
            >
              <Download className="w-3.5 h-3.5 text-violet-400" />
              <span>{downloadSuccess ? (isRtl ? 'تم التنزيل!' : 'Abstract Downloaded!') : (isRtl ? 'تحميل الملخص البحثي (MD)' : 'Download Research Abstract')}</span>
            </button>
            <Link
              to="/dashboard"
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-violet-600 hover:bg-violet-500 text-xs font-semibold text-white transition shadow-sm"
            >
              <span>{isRtl ? 'دخول المنصة التفاعلية' : 'Launch Live Platform'}</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>

        {/* Supervisor Access Key Banner */}
        <div className="p-4 sm:p-5 rounded-2xl bg-gradient-to-r from-violet-950/40 via-slate-900 to-slate-900 border border-violet-500/30 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-violet-600/20 border border-violet-500/30 flex items-center justify-center text-violet-300">
              <Lock className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-white">Have a Private Supervisor Briefing Access Token?</div>
              <div className="text-[11px] text-slate-400">Enter the token shared by the candidate to decrypt your tailored briefing pack.</div>
            </div>
          </div>
          <form onSubmit={handleManualTokenSubmit} className="flex items-center gap-2 w-full sm:w-auto">
            <input
              type="text"
              placeholder="Paste briefing token..."
              value={tokenInput}
              onChange={e => setTokenInput(e.target.value)}
              className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-violet-500 font-mono w-full sm:w-60"
            />
            <button
              type="submit"
              className="px-3 py-1.5 rounded-lg bg-violet-600 hover:bg-violet-500 text-xs font-bold text-white transition shrink-0"
            >
              Unlock
            </button>
          </form>
        </div>

        {/* Hero Section: Candidate & Thesis Overview */}
        <div className="p-8 rounded-3xl bg-gradient-to-br from-slate-900 via-slate-900/90 to-violet-950/40 border border-slate-800 relative overflow-hidden shadow-2xl">
          <div className="absolute top-0 right-0 w-96 h-96 bg-violet-600/10 rounded-full blur-3xl pointer-events-none" />

          <div className="relative z-10 max-w-3xl space-y-4">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-semibold">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>{isRtl ? 'باحث ماستر مرشح للدكتوراه (2026 / 2027)' : 'Prospective PhD Candidate · 2026/2027 Admissions'}</span>
            </div>

            <h1 className="text-2xl md:text-4xl font-extrabold text-white tracking-tight leading-tight">
              {isRtl
                ? 'SecuraX: منصة القياس الأمني المؤتمت وتدقيق الثغرات بالذكاء الاصطناعي'
                : 'SecuraX: Autonomous Vulnerability Telemetry & Hybrid Security Intelligence'}
            </h1>

            <p className="text-sm md:text-base text-slate-300 leading-relaxed">
              {isRtl
                ? 'أطروحة ماستر ونظام متكامل تم تصميمه كإثبات كفاءة حي (Live Research Artifact) في جامعة محمد بوضياف – المسيلة. يوفر بنية تحتية هندسية متطورة تجمع بين التحليل الاستاتيكي (SAST)، الاستطلاع الديناميكي (DAST)، واستخبارات التهديدات النشطة (CVE/KEV).'
                : 'Master of Science thesis research and production-grade working artifact developed at University of Mohamed Boudiaf – M’Sila. Bridges automated static program analysis, dynamic simulation, and active threat telemetry into an empirical security orchestration engine.'}
            </p>

            {/* Academic Credentials Badges */}
            <div className="pt-2 flex flex-wrap gap-2 text-xs font-mono">
              <span className="px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700/80 text-slate-300">
                🎓 Univ. Mohamed Boudiaf – M'Sila
              </span>
              <span className="px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700/80 text-violet-300">
                🛡️ OSCP / eJPT / Sec+ Mapped
              </span>
              <span className="px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700/80 text-cyan-300">
                🚀 Full-Stack Hybrid Engine
              </span>
              <span className="px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700/80 text-emerald-300">
                📄 100% Reproducible Testbeds
              </span>
            </div>
          </div>
        </div>

        {/* Architectural Blueprint Explorer */}
        <div className="space-y-4">
          <div>
            <span className="text-xs font-bold uppercase tracking-widest text-violet-400">
              Interactive System Architecture
            </span>
            <h2 className="text-xl md:text-2xl font-bold text-white mt-1">
              {isRtl ? 'المعمارية البرمجية والوحدات البحثية' : 'Core Research Modules & Architecture'}
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Click any module to inspect technical design decisions, empirical metrics, and PhD research lab alignment.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {ARCHITECTURE_MODULES.map((mod) => {
              const Icon = mod.icon;
              const isSelected = selectedModule.id === mod.id;
              return (
                <div
                  key={mod.id}
                  onClick={() => setSelectedModule(mod)}
                  className={`p-5 rounded-2xl border cursor-pointer transition-all duration-200 flex flex-col justify-between ${
                    isSelected
                      ? 'bg-slate-900 border-violet-500 shadow-lg shadow-violet-900/20 ring-1 ring-violet-500/30'
                      : 'bg-slate-900/40 border-slate-800 hover:border-slate-700 hover:bg-slate-900/60'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between gap-2 mb-3">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${isSelected ? 'bg-violet-600 text-white' : 'bg-slate-800 text-slate-400'}`}>
                        <Icon className="w-4 h-4" />
                      </div>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${mod.badgeColor}`}>
                        {mod.badge}
                      </span>
                    </div>

                    <h3 className="font-bold text-sm text-white leading-snug mb-1">
                      {isRtl ? mod.title_ar : mod.title_en}
                    </h3>
                    <p className="text-[11px] text-slate-400 line-clamp-2">
                      {isRtl ? mod.desc_ar : mod.desc_en}
                    </p>
                  </div>

                  <div className="mt-4 pt-3 border-t border-slate-800/80 text-[10px] font-mono text-slate-500 flex items-center justify-between">
                    <span>{mod.metrics}</span>
                    <span className="text-violet-400">{isSelected ? 'Active' : 'Inspect'}</span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Module Deep-Dive Panel */}
          {selectedModule && (
            <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-4">
                <div>
                  <span className="text-[10px] text-violet-400 font-mono uppercase tracking-wider">Module Specification</span>
                  <h3 className="text-lg font-bold text-white">{isRtl ? selectedModule.title_ar : selectedModule.title_en}</h3>
                </div>
                <div className="text-xs font-mono px-3 py-1 rounded-md bg-slate-800 border border-slate-700 text-slate-300">
                  {selectedModule.metrics}
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">Technical Description</h4>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {isRtl ? selectedModule.desc_ar : selectedModule.desc_en}
                  </p>
                </div>

                <div className="p-4 rounded-xl bg-violet-950/20 border border-violet-500/20">
                  <div className="flex items-center gap-1.5 text-xs font-bold text-violet-400 mb-2">
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>Doctoral Lab Synergy & Research Value</span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {selectedModule.academic_interest}
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Contact & Discussion CTA */}
        <div className="p-8 rounded-3xl bg-gradient-to-r from-violet-900/30 via-slate-900 to-indigo-900/30 border border-violet-500/30 flex flex-col sm:flex-row items-center justify-between gap-6 shadow-xl">
          <div className="space-y-1 text-center sm:text-left">
            <h3 className="text-lg font-bold text-white">Interested in Discussing Research Synergy?</h3>
            <p className="text-xs text-slate-400 max-w-xl">
              I welcome inquiries regarding doctoral admission, fully funded PhD research positions, and technical discussions on automated vulnerability discovery.
            </p>
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <a
              href="mailto:contact@securax.local?subject=PhD%20Inquiry%20from%20Research%20Reviewer"
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-violet-600 hover:bg-violet-500 text-xs font-bold text-white transition shadow-lg shadow-violet-900/40"
            >
              <Mail className="w-4 h-4" />
              <span>Contact Candidate</span>
            </a>
          </div>
        </div>

      </div>
    </div>
  );
}
