import React, { useState, useEffect } from "react";
import axios from "axios";
import { useLang } from "../context/LangContext";
import { Link, useNavigate } from "react-router-dom";
import {
  AlertCircle, RefreshCw, CheckCircle2, ChevronRight, Award,
  GraduationCap, FileText, Download, ShieldCheck, Sparkles,
  BookOpen, ExternalLink, Play, Target, Zap, ArrowRight, Search
} from "lucide-react";

// ── Real learning destinations — every entry must point to a verified route ──
// Domains map to: (a) internal /learn/:vulnId or /tracks, (b) official external URL
// Verified against actual VulnLibraryPage / tracks catalogue in the repo.
const CERT_LEARNING_MAP = {
  secplus: {
    track: "soc-analyst",           // verified track id in tracks.py
    track_label_en: "SOC Analyst Track",
    track_label_ar: "مسار محلل SOC",
    domains: [
      {
        code: "1.0",
        name: "General Security Concepts",
        weight: "12%",
        // Maps to vuln types in the skill ledger / learning library
        internal_lessons: [
          { id: "security_misconfig",      label: "Security Misconfiguration" },
          { id: "weak_crypto",             label: "Weak Cryptography" },
          { id: "missing_security_headers",label: "Security Headers" },
        ],
        official_url: "https://www.comptia.org/certifications/security#examdetails",
        official_label: "CompTIA Security+ Exam Objectives",
      },
      {
        code: "2.0",
        name: "Threats, Vulnerabilities & Mitigations",
        weight: "22%",
        internal_lessons: [
          { id: "xss",              label: "Cross-Site Scripting (XSS)" },
          { id: "sqli",             label: "SQL Injection" },
          { id: "phishing",         label: "Phishing & Social Engineering" },
          { id: "brute_force",      label: "Brute Force Attacks" },
        ],
        official_url: "https://www.comptia.org/certifications/security",
        official_label: "CompTIA Security+ Domain 2",
      },
      {
        code: "3.0",
        name: "Security Architecture",
        weight: "18%",
        internal_lessons: [
          { id: "missing_csp",             label: "Content Security Policy" },
          { id: "missing_security_headers", label: "HTTP Security Headers" },
        ],
        official_url: "https://www.comptia.org/certifications/security",
        official_label: "CompTIA Security+ Domain 3",
      },
      {
        code: "4.0",
        name: "Security Operations",
        weight: "28%",
        internal_lessons: [
          { id: "security_misconfig", label: "Security Misconfiguration" },
          { id: "info_disclosure",    label: "Information Disclosure" },
        ],
        official_url: "https://www.comptia.org/certifications/security",
        official_label: "CompTIA Security+ Domain 4",
      },
      {
        code: "5.0",
        name: "Security Program Management & Oversight",
        weight: "20%",
        internal_lessons: [
          { id: "missing_spf_dkim_dmarc", label: "SPF / DKIM / DMARC" },
        ],
        official_url: "https://www.comptia.org/certifications/security",
        official_label: "CompTIA Security+ Domain 5",
      },
    ],
  },
  ejpt: {
    track: "bug-bounty-hunter",     // verified track id in tracks.py
    track_label_en: "Bug Bounty Hunter Track",
    track_label_ar: "مسار صائد الثغرات",
    domains: [
      {
        code: "1.0",
        name: "Assessment Methodologies",
        weight: "25%",
        internal_lessons: [
          { id: "info_disclosure",  label: "Information Gathering" },
          { id: "open_ports",       label: "Port & Service Enumeration" },
        ],
        official_url: "https://ine.com/certifications/ejpt-certification",
        official_label: "eJPT Official Syllabus",
      },
      {
        code: "2.0",
        name: "Host & Network Auditing",
        weight: "25%",
        internal_lessons: [
          { id: "security_misconfig", label: "Host Misconfiguration" },
          { id: "weak_crypto",        label: "Weak Encryption" },
        ],
        official_url: "https://ine.com/certifications/ejpt-certification",
        official_label: "eJPT Domain 2",
      },
      {
        code: "3.0",
        name: "Host & Network Penetration Testing",
        weight: "35%",
        internal_lessons: [
          { id: "rce",          label: "Remote Code Execution" },
          { id: "broken_auth",  label: "Authentication Bypass" },
          { id: "sqli",         label: "SQL Injection" },
        ],
        official_url: "https://ine.com/certifications/ejpt-certification",
        official_label: "eJPT Domain 3",
      },
      {
        code: "4.0",
        name: "Web Application Penetration Testing",
        weight: "15%",
        internal_lessons: [
          { id: "xss",             label: "Cross-Site Scripting" },
          { id: "csrf",            label: "CSRF" },
          { id: "open_redirect",   label: "Open Redirect" },
        ],
        official_url: "https://ine.com/certifications/ejpt-certification",
        official_label: "eJPT Domain 4",
      },
    ],
  },
  oscp: {
    track: "ejpt-oscp-readiness",   // verified track id in tracks.py
    track_label_en: "eJPT to OSCP Readiness Track",
    track_label_ar: "مسار الجاهزية لـ eJPT / OSCP",
    domains: [
      {
        code: "1.0",
        name: "Penetration Testing Methodology & Recon",
        weight: "20%",
        internal_lessons: [
          { id: "info_disclosure",  label: "Information Disclosure / OSINT" },
          { id: "security_misconfig", label: "Service Misconfiguration" },
        ],
        official_url: "https://www.offsec.com/courses/pen-200/",
        official_label: "OffSec PEN-200 Curriculum",
      },
      {
        code: "2.0",
        name: "Web Application Attacks & Exploitation",
        weight: "25%",
        internal_lessons: [
          { id: "xss",          label: "XSS" },
          { id: "sqli",         label: "SQL Injection" },
          { id: "rce",          label: "Remote Code Execution" },
        ],
        official_url: "https://www.offsec.com/courses/pen-200/",
        official_label: "OffSec Web Attacks Module",
      },
      {
        code: "3.0",
        name: "Privilege Escalation & Client-Side Attacks",
        weight: "25%",
        internal_lessons: [
          { id: "broken_auth",        label: "Authentication Bypass" },
          { id: "session_fixation",   label: "Session Fixation" },
          { id: "deserialization",    label: "Insecure Deserialization" },
        ],
        official_url: "https://www.offsec.com/courses/pen-200/",
        official_label: "OffSec Privilege Escalation Module",
      },
      {
        code: "4.0",
        name: "Tunneling, Pivoting & Reporting",
        weight: "30%",
        internal_lessons: [
          { id: "sensitive_data_exposure", label: "Sensitive Data Exposure" },
          { id: "weak_crypto",             label: "Weak Crypto" },
          { id: "missing_csp",             label: "Missing Security Controls" },
        ],
        official_url: "https://www.offsec.com/courses/pen-200/",
        official_label: "OffSec Advanced Techniques",
      },
    ],
  },
};

const CERT_STATIC_META = {
  secplus: {
    id: "secplus",
    title: "CompTIA Security+ (SY0-701)",
    tag: "Security Fundamentals",
    badgeColor: "bg-blue-500/10 text-blue-500 border-blue-500/30",
    phdCategory_en: "Foundational Compliance / Baseline",
    phdCategory_ar: "متطلب الحوكمة والامتثال الأساسي",
    phdRoi_en: "Essential baseline for security governance labs and defense-sponsored research programs (e.g. DAAD, NATO centers).",
    phdRoi_ar: "متطلب أساسي لمختبرات حوكمة الأمن والمشاريع الممولة دولياً وأكاديمياً.",
    academicTier: "Tier B · Core Requirement",
    description: "Global baseline cybersecurity certification covering core security principles, threat analysis, architecture, operations, and governance.",
  },
  ejpt: {
    id: "ejpt",
    title: "eJPT (Junior Penetration Tester)",
    tag: "Offensive Hands-On",
    badgeColor: "bg-amber-500/10 text-amber-500 border-amber-500/30",
    phdCategory_en: "Empirical Testbed Qualification",
    phdCategory_ar: "التأهيل التجريبي للمختبرات العملية",
    phdRoi_en: "Validates empirical security testing capabilities, demonstrating candidate can design and execute live vulnerability testbeds.",
    phdRoi_ar: "إثبات عملي للكفاءة في فحص الأنظمة الحية، ما يثبت قدرة الباحث على تصميم تجارب الأمان التطبيقية.",
    academicTier: "Tier A · Hands-On Qualifier",
    description: "Hands-on entry-level penetration testing certification focusing on real assessment methodology, scanning, and web application exploitation.",
  },
  oscp: {
    id: "oscp",
    title: "OSCP (OffSec Certified Professional)",
    tag: "Advanced Offensive",
    badgeColor: "bg-purple-500/10 text-purple-500 border-purple-500/30",
    phdCategory_en: "RA Scholarship & Coursework Waiver",
    phdCategory_ar: "إعفاء المقررات وتأهيل وظائف المساعد البحثي (RA)",
    phdRoi_en: "The Gold Standard for funded Research Assistantships (RA): Exempts from initial coursework and qualifies for immediate high-paying lab grants.",
    phdRoi_ar: "المعيار الذهبي لتأهيل وظائف البحث المدفوعة (RA): يعفي من المقررات التمهيدية ويمنح أولوية قصوى للمنح الممولة.",
    academicTier: "Tier S · Full Grant Qualifier",
    description: "Rigorous offensive security certification testing real-world penetration testing methodology, manual vulnerability discovery, exploitation, and reporting.",
  },
};

const ACADEMIC_GATEWAYS = [
  {
    id: "ielts_toefl",
    title_en: "IELTS Academic (7.0+) / TOEFL iBT (95+)",
    title_ar: "آيلتس أكاديمي (7.0+) / توفل (95+)",
    type: "Mandatory Admission Gateway",
    type_ar: "بوابة قبول إلزامية",
    badge: "Language Prerequisite",
    badgeColor: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    desc_en: "Required for 90% of global doctoral scholarships (DAAD, Vanier, HKPFS, Marie Curie). Bypasses preliminary interview linguistic hurdles.",
    desc_ar: "مطلوب في أكثر من 90% من منح الدكتوراه العالمية (DAAD, Vanier, HKPFS, Marie Curie). يضمن تجاوز عقبة المقابلة اللغوية الأولية.",
    action_en: "Minimum Target: 7.0 Overall (no band below 6.5)",
    action_ar: "الهدف الأدنى: 7.0 إجمالي (لا يقل قسم عن 6.5)",
    status: "Preparation Mode",
    action_url: "https://www.ielts.org/",
    action_url_label: "IELTS Official Site",
  },
  {
    id: "gre_waiver",
    title_en: "GRE Quantitative (165+) / Artifact Waiver",
    title_ar: "اختبار GRE الكمي (165+) / إعفاء الإنجاز التطبيقي",
    type: "North America Qualifier / EU Waived",
    type_ar: "مطلوب في أمريكا الشمالية / معفى في أوروبا",
    badge: "Analytical Gateway",
    badgeColor: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    desc_en: "Mandatory in top US/Canadian computer science departments. Waived across European labs (ETH, Inria, CISPA) when presenting a live artifact like SecuraX.",
    desc_ar: "إلزامي في كبرى جامعات أمريكا وكندا. يُعفى منه في معظم مختبرات أوروبا عند تقديم نظام حي مثبت مثل SecuraX.",
    action_en: "SecuraX Live Demo functions as equivalent research evidence",
    action_ar: "عرض SecuraX الحي يحل محل الاختبار في المختبرات الأوروبية",
    status: "Waiver Qualified by SecuraX",
    action_url: "https://www.ets.org/gre",
    action_url_label: "GRE Official Site",
  },
];

const DEFAULT_ORDER = ["secplus", "ejpt", "oscp"];

// ── Domain lesson action button — links to real /learn/:vulnId route ──────────
function DomainLesson({ lesson, navigate }) {
  return (
    <button
      id={`lesson-btn-${lesson.id}`}
      onClick={() => navigate(`/learn/${lesson.id}`)}
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[10px] font-mono
                 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30
                 hover:bg-emerald-500/20 hover:border-emerald-400 transition cursor-pointer"
      title={`Open lesson: ${lesson.label}`}
      aria-label={`Start lesson on ${lesson.label}`}
    >
      <Play className="w-2.5 h-2.5 flex-shrink-0" />
      <span>{lesson.label}</span>
      <ArrowRight className="w-2.5 h-2.5 flex-shrink-0 opacity-60" />
    </button>
  );
}

export default function CertificationPage() {
  const { t, lang } = useLang();
  const isRtl = lang === "ar";
  const navigate = useNavigate();
  const [certDataList, setCertDataList] = useState([]);
  const [selectedCertId, setSelectedCertId] = useState("secplus");
  const [activeView, setActiveView] = useState("certs");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [downloadSuccess, setDownloadSuccess] = useState(false);

  const fetchReadiness = () => {
    setLoading(true);
    setError(null);
    axios
      .get("/api/tracks/cert-readiness", { withCredentials: true })
      .then((res) => {
        if (res.data?.ok && Array.isArray(res.data.certifications)) {
          const liveCerts = res.data.certifications;
          const merged = DEFAULT_ORDER.map((id) => {
            const live = liveCerts.find((c) => c.id === id) || {};
            const meta = CERT_STATIC_META[id] || {};
            const learnMap = CERT_LEARNING_MAP[id] || {};
            return {
              id,
              title: live.name || meta.title || id,
              tag: meta.tag || "Certification",
              badgeColor: meta.badgeColor || "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
              description: meta.description || "",
              provider: live.provider || "",
              phdCategory: isRtl ? meta.phdCategory_ar : meta.phdCategory_en,
              phdRoi: isRtl ? meta.phdRoi_ar : meta.phdRoi_en,
              academicTier: meta.academicTier || "Standard",
              // Domains come from the learning map (include real lesson links)
              domains: learnMap.domains || [],
              track_id: learnMap.track,
              track_label: isRtl ? learnMap.track_label_ar : learnMap.track_label_en,
              readiness_pct: typeof live.readiness_pct === "number" ? live.readiness_pct : 0.0,
              covered_skills: Array.isArray(live.covered_skills) ? live.covered_skills : [],
              missing_skills: Array.isArray(live.missing_skills) ? live.missing_skills : [],
              total_skills: typeof live.total_skills === "number" ? live.total_skills : 0,
              disclaimer: isRtl ? live.disclaimer_ar : live.disclaimer_en,
            };
          });
          setCertDataList(merged);
        } else {
          setError("Invalid response received from certification readiness service.");
        }
      })
      .catch((err) => {
        setError(err.response?.data?.error || "Failed to load live certification readiness.");
      })
      .finally(() => {
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchReadiness();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lang]);

  const selectedCert =
    certDataList.find((c) => c.id === selectedCertId) ||
    (certDataList.length > 0 ? certDataList[0] : null);

  const exportDossierSummary = () => {
    const payload = {
      candidate: "Master of Science in Cybersecurity Candidate",
      university: "University of Mohamed Boudiaf – M'Sila",
      platform: "SecuraX (HexaGuard) Intelligent Security Platform",
      generated_at: new Date().toISOString(),
      verified_certifications: certDataList.map((c) => ({
        certification: c.title,
        readiness_pct: c.readiness_pct,
        covered_skills: c.covered_skills,
        academic_tier: c.academicTier,
        phd_alignment: c.phdRoi,
        learning_track: c.track_id,
      })),
      academic_gateways: ACADEMIC_GATEWAYS,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "securax_academic_competence_dossier.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setDownloadSuccess(true);
    setTimeout(() => setDownloadSuccess(false), 2500);
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-900 text-slate-900 dark:text-slate-100 p-6 md:p-8">
      {/* Header */}
      <div className="max-w-6xl mx-auto mb-8">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-violet-100 dark:bg-violet-900/40 text-violet-600 dark:text-violet-300">
                {isRtl ? "تأهيل الشهادات والقبول الأكاديمي" : "Dual-Track Certification Hub"}
              </span>
              <span className="text-xs text-slate-400 font-mono">Academic Gateways & RA Waivers</span>
            </div>
            <h1 className="text-2xl md:text-3xl font-bold tracking-tight">
              {isRtl ? "مركز تأهيل الشهادات والمنح الأكاديمية" : "Cybersecurity Certification & Academic Hub"}
            </h1>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
              {isRtl
                ? "ربط سجل المهارات الفعلي بشهادات الصناعة العالمية ومتطلبات وظائف المساعد البحثي (RA) والمنح للدكتوراه."
                : "Curated industry certification roadmaps mapped to PhD eligibility, Research Assistantship (RA) waivers, and live skill ledger readiness."}
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              id="cert-export-dossier-btn"
              onClick={exportDossierSummary}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white transition shadow-sm"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{downloadSuccess ? (isRtl ? "تم التصدير بنجاح!" : "Dossier Exported!") : (isRtl ? "تصدير بيان الكفاءة الأكاديمي" : "Export Academic Dossier")}</span>
            </button>
            <Link
              to="/tracks"
              id="cert-view-tracks-btn"
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition shadow-sm"
            >
              <Target className="w-3.5 h-3.5" />
              <span>{isRtl ? "مسارات التعلم" : "Learning Tracks"}</span>
            </Link>
            <Link
              to="/phd"
              id="cert-view-phd-btn"
              className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg bg-violet-600 hover:bg-violet-500 text-white transition shadow-sm"
            >
              <GraduationCap className="w-3.5 h-3.5" />
              <span>{isRtl ? "متتبع الدكتوراه" : "PhD Opportunities"}</span>
            </Link>
          </div>
        </div>

        {/* Navigation View Switcher */}
        <div className="flex items-center gap-2 mt-6 p-1 bg-slate-200 dark:bg-slate-800/60 rounded-xl w-fit">
          {[
            { id: "certs",      emoji: "🛡️", label_en: "Certifications & Readiness",   label_ar: "شهادات الصناعة وسجل المهارات" },
            { id: "gateways",   emoji: "🎓", label_en: "Academic Admission Gateways",  label_ar: "بوابات القبول الأكاديمي" },
            { id: "roi_matrix", emoji: "📊", label_en: "Dual ROI Matrix",              label_ar: "مصفوفة العائد المزدوج" },
          ].map(v => (
            <button
              key={v.id}
              id={`cert-tab-${v.id}`}
              onClick={() => setActiveView(v.id)}
              className={`px-4 py-1.5 text-xs font-semibold rounded-lg transition ${
                activeView === v.id
                  ? "bg-white dark:bg-slate-900 text-violet-600 dark:text-violet-400 shadow-sm"
                  : "text-slate-500 hover:text-slate-800 dark:hover:text-slate-200"
              }`}
            >
              {v.emoji} {isRtl ? v.label_ar : v.label_en}
            </button>
          ))}
        </div>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="max-w-6xl mx-auto py-16 flex flex-col items-center justify-center space-y-4">
          <div className="w-8 h-8 border-2 border-violet-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-xs text-slate-400 font-mono">Loading authoritative readiness index...</p>
        </div>
      )}

      {/* Error state */}
      {!loading && error && (
        <div className="max-w-6xl mx-auto mb-8 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
            <p className="text-xs font-medium">{error}</p>
          </div>
          <button
            id="cert-retry-btn"
            onClick={fetchReadiness}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Retry</span>
          </button>
        </div>
      )}

      {/* ── View 1: Certifications & Live Skill Readiness ── */}
      {!loading && !error && activeView === "certs" && selectedCert && (
        <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Certification Cards List */}
          <div className="lg:col-span-1 space-y-4">
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
              {isRtl ? "المسارات المعتمدة" : "Available Study Paths"}
            </h2>
            {certDataList.map((cert) => {
              const isSelected = selectedCert.id === cert.id;
              return (
                <div
                  key={cert.id}
                  id={`cert-card-${cert.id}`}
                  onClick={() => setSelectedCertId(cert.id)}
                  className={`cursor-pointer p-4 rounded-xl border transition-all duration-200 ${
                    isSelected
                      ? "border-violet-500 bg-white dark:bg-slate-800 shadow-md ring-1 ring-violet-500/20"
                      : "border-slate-200 dark:border-slate-800 bg-white/70 dark:bg-slate-800/50 hover:border-slate-300 dark:hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <h3 className="font-semibold text-sm leading-snug">{cert.title}</h3>
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${cert.badgeColor}`}>
                      {cert.tag}
                    </span>
                  </div>
                  <div className="text-[10px] text-amber-500 dark:text-amber-400 font-medium mb-2">
                    🎓 {cert.phdCategory}
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400 line-clamp-2 mb-3">
                    {cert.description}
                  </p>
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span className="font-mono">{cert.covered_skills.length}/{cert.total_skills} Skills</span>
                    <span className="font-bold text-violet-500 font-mono">
                      {cert.readiness_pct}% Ready
                    </span>
                  </div>
                  {/* Quick navigate to track */}
                  {cert.track_id && (
                    <button
                      id={`cert-open-track-${cert.id}`}
                      onClick={(e) => { e.stopPropagation(); navigate("/tracks"); }}
                      className="mt-2 w-full inline-flex items-center justify-center gap-1.5 px-2.5 py-1.5 text-[10px] font-semibold rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition"
                    >
                      <Target className="w-3 h-3" />
                      {isRtl ? cert.track_label : cert.track_label}
                      <ChevronRight className="w-3 h-3" />
                    </button>
                  )}
                </div>
              );
            })}
          </div>

          {/* Selected Certification Detail */}
          <div className="lg:col-span-2">
            <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm">
              <div className="flex items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-700/60 pb-4 mb-6">
                <div>
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${selectedCert.badgeColor}`}>
                      {selectedCert.tag}
                    </span>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-violet-500/10 text-violet-400 border border-violet-500/20">
                      {selectedCert.academicTier}
                    </span>
                  </div>
                  <h2 className="text-xl font-bold mt-1">{selectedCert.title}</h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-xl">
                    {selectedCert.description}
                  </p>
                </div>

                <div className="text-right flex-shrink-0">
                  <span className="text-3xl font-black text-violet-500 font-mono">
                    {selectedCert.readiness_pct}%
                  </span>
                  <p className="text-[10px] text-slate-400 font-medium">Skill Readiness</p>
                </div>
              </div>

              {/* PhD & Research Synergy Banner */}
              <div className="mb-6 p-4 rounded-xl bg-violet-500/10 border border-violet-500/20 text-slate-700 dark:text-slate-200">
                <div className="flex items-center gap-2 mb-1 text-violet-600 dark:text-violet-400 font-bold text-xs uppercase tracking-wider">
                  <Sparkles className="w-4 h-4" />
                  <span>{isRtl ? "الأثر في قبول الدكتوراه ووظائف المساعد البحثي" : "PhD Admission & Research Assistantship Impact"}</span>
                </div>
                <p className="text-xs leading-relaxed">
                  {selectedCert.phdRoi}
                </p>
                {/* Action: open related learning track */}
                {selectedCert.track_id && (
                  <button
                    id={`cert-track-action-${selectedCert.id}`}
                    onClick={() => navigate("/tracks")}
                    className="mt-3 inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-violet-500/20 text-violet-300 hover:bg-violet-500/30 border border-violet-500/30 transition"
                  >
                    <Target className="w-3.5 h-3.5" />
                    {isRtl
                      ? `فتح مسار: ${selectedCert.track_label}`
                      : `Open Track: ${selectedCert.track_label}`}
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>

              {/* Progress Bar */}
              <div className="mb-6 space-y-2">
                <div className="flex justify-between text-xs text-slate-400">
                  <span>Authoritative Readiness Progress</span>
                  <span className="font-mono font-semibold text-slate-200">
                    {selectedCert.covered_skills.length} of {selectedCert.total_skills} required skills practiced
                  </span>
                </div>
                <div className="h-2.5 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
                  <div
                    className="h-full bg-violet-500 rounded-full transition-all duration-500"
                    style={{ width: `${Math.min(100, Math.max(0, selectedCert.readiness_pct))}%` }}
                  />
                </div>
              </div>

              {/* Covered & Missing Skills */}
              <div className="mb-6 space-y-3">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                  Curriculum Skill Coverage
                </h3>
                <div className="flex flex-wrap gap-2">
                  {selectedCert.covered_skills.map((skill) => (
                    <button
                      key={skill}
                      id={`cert-covered-skill-${selectedCert.id}-${skill}`}
                      onClick={() => navigate(`/learn/${skill}`)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-mono
                                 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30
                                 hover:bg-emerald-500/20 hover:border-emerald-400 cursor-pointer transition"
                      title={`Review lesson: ${skill}`}
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>{skill}</span>
                    </button>
                  ))}
                  {selectedCert.missing_skills.map((skill) => (
                    <button
                      key={skill}
                      id={`cert-missing-skill-${selectedCert.id}-${skill}`}
                      onClick={() => navigate(`/learn/${skill}`)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-mono
                                 bg-slate-100 dark:bg-slate-900/60 text-slate-400 border border-slate-300 dark:border-slate-700
                                 hover:bg-cyan-500/10 hover:text-cyan-400 hover:border-cyan-500/30 cursor-pointer transition"
                      title={`Start lesson: ${skill} (not yet practiced)`}
                    >
                      <Play className="w-3 h-3" />
                      <span>{skill}</span>
                    </button>
                  ))}
                </div>
                {selectedCert.missing_skills.length > 0 && (
                  <p className="text-[10px] text-slate-500 italic">
                    {isRtl
                      ? "الزر يفتح الدرس المقابل في مكتبة التعلم."
                      : "Click any skill to open its lesson in the learning library."}
                  </p>
                )}
              </div>

              {/* Domains — LIVE actionable study guides */}
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                    Exam Domains & Study Actions
                  </h3>
                  <Link
                    to="/learn/vulnerabilities"
                    id={`cert-learn-library-${selectedCert.id}`}
                    className="inline-flex items-center gap-1 text-[10px] text-cyan-400 hover:text-cyan-300 transition"
                  >
                    <BookOpen className="w-3 h-3" />
                    {isRtl ? "مكتبة التعلم" : "Learning Library"}
                    <ChevronRight className="w-3 h-3" />
                  </Link>
                </div>

                <div className="space-y-3">
                  {selectedCert.domains.map((dom) => (
                    <div
                      key={dom.code}
                      className="p-3.5 rounded-lg border border-slate-100 dark:border-slate-700/50 bg-slate-50/50 dark:bg-slate-900/30"
                    >
                      <div className="flex items-start justify-between gap-4 mb-2">
                        <div className="flex items-center gap-3">
                          <span className="w-8 h-8 rounded-md bg-violet-100 dark:bg-violet-900/30 text-violet-600 dark:text-violet-300 font-bold text-xs flex items-center justify-center flex-shrink-0 font-mono">
                            {dom.code}
                          </span>
                          <div>
                            <h4 className="text-sm font-semibold">{dom.name}</h4>
                            <span className="text-[11px] text-slate-400">Exam Weight: {dom.weight}</span>
                          </div>
                        </div>
                        {/* Official syllabus link — always opens external authoritative source */}
                        <a
                          href={dom.official_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          id={`cert-official-${selectedCert.id}-${dom.code}`}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300 font-medium hover:bg-slate-300 dark:hover:bg-slate-600 transition flex-shrink-0"
                          title={dom.official_label}
                        >
                          <ExternalLink className="w-2.5 h-2.5" />
                          {isRtl ? "المنهج الرسمي" : "Official Syllabus"}
                        </a>
                      </div>
                      {/* Lesson links — real SecuraX routes */}
                      {dom.internal_lessons && dom.internal_lessons.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 mt-2">
                          {dom.internal_lessons.map((lesson) => (
                            <DomainLesson
                              key={lesson.id}
                              lesson={lesson}
                              navigate={navigate}
                            />
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Quick shortcut: View Skills */}
              <div className="mt-6 grid grid-cols-1 sm:grid-cols-3 gap-3">
                <Link
                  to="/skills"
                  id={`cert-view-skills-${selectedCert.id}`}
                  className="flex items-center gap-2 p-3 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-violet-500/50 bg-slate-50 dark:bg-slate-900/40 transition group"
                >
                  <ShieldCheck className="w-4 h-4 text-violet-400 group-hover:text-violet-300" />
                  <div>
                    <div className="text-xs font-bold">{isRtl ? "سجل المهارات" : "Skill Ledger"}</div>
                    <div className="text-[10px] text-slate-400">{isRtl ? "عرض الإنجازات المثبتة" : "View verified evidence"}</div>
                  </div>
                </Link>
                <Link
                  to="/dojo"
                  id={`cert-view-dojo-${selectedCert.id}`}
                  className="flex items-center gap-2 p-3 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-amber-500/50 bg-slate-50 dark:bg-slate-900/40 transition group"
                >
                  <Zap className="w-4 h-4 text-amber-400 group-hover:text-amber-300" />
                  <div>
                    <div className="text-xs font-bold">{isRtl ? "دوجو يومي" : "Daily Dojo"}</div>
                    <div className="text-[10px] text-slate-400">{isRtl ? "ممارسة يومية سريعة" : "Quick daily practice"}</div>
                  </div>
                </Link>
                <Link
                  to="/phd"
                  id={`cert-view-phd-inline-${selectedCert.id}`}
                  className="flex items-center gap-2 p-3 rounded-lg border border-slate-200 dark:border-slate-700 hover:border-cyan-500/50 bg-slate-50 dark:bg-slate-900/40 transition group"
                >
                  <GraduationCap className="w-4 h-4 text-cyan-400 group-hover:text-cyan-300" />
                  <div>
                    <div className="text-xs font-bold">{isRtl ? "فرص الدكتوراه" : "PhD Opportunities"}</div>
                    <div className="text-[10px] text-slate-400">{isRtl ? "فرص متوافقة مع هذه الشهادة" : "Cert-aligned opportunities"}</div>
                  </div>
                </Link>
              </div>

              {/* Disclaimer */}
              <div className="mt-6 p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-xs text-amber-700 dark:text-amber-300 leading-relaxed">
                <strong>Notice:</strong> {selectedCert.disclaimer || (
                  "HexaGuard / SecuraX provides independent training materials aligned with published objectives. We do not claim official sponsorship, affiliation, or endorsement by CompTIA, INE, or OffSec."
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── View 2: Academic Gateways ── */}
      {!loading && !error && activeView === "gateways" && (
        <div className="max-w-6xl mx-auto space-y-6">
          <div className="p-6 rounded-2xl bg-gradient-to-r from-blue-950/40 via-slate-900 to-violet-950/40 border border-blue-500/30 shadow-xl">
            <h2 className="text-xl font-bold text-white mb-2">
              🎓 {isRtl ? "بوابات القبول واللغة والمعدلات الأكاديمية" : "Academic Admission Gateways & Linguistic Prerequisites"}
            </h2>
            <p className="text-xs text-slate-300 max-w-2xl leading-relaxed">
              {isRtl
                ? "الشهادات التقنية تمنحك الأفضلية في المختبر، لكن البوابات الأكاديمية هي شرط العبور الإداري للمنح والجامعات العالمية."
                : "While technical certifications secure Research Assistantships, academic gateways satisfy mandatory institutional and visa eligibility requirements for doctoral admission."}
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {ACADEMIC_GATEWAYS.map((gw) => (
              <div key={gw.id} className="p-6 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-800/80 shadow-sm flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between gap-2 mb-3">
                    <span className={`text-[10px] font-bold px-2.5 py-0.5 rounded-full border ${gw.badgeColor}`}>
                      {gw.badge}
                    </span>
                    <span className="text-xs font-mono font-semibold text-slate-400">
                      {isRtl ? gw.type_ar : gw.type}
                    </span>
                  </div>
                  <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">
                    {isRtl ? gw.title_ar : gw.title_en}
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed mb-4">
                    {isRtl ? gw.desc_ar : gw.desc_en}
                  </p>
                </div>
                <div className="p-3 rounded-xl bg-slate-100 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-700/60 flex items-center justify-between">
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase tracking-wider block font-bold">
                      {isRtl ? "الإجراء الموصى به" : "Actionable Target"}
                    </span>
                    <span className="text-xs font-bold text-violet-500 font-mono">
                      {isRtl ? gw.action_ar : gw.action_en}
                    </span>
                  </div>
                  <a
                    href={gw.action_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    id={`gateway-action-${gw.id}`}
                    className="inline-flex items-center gap-1 text-[10px] px-2.5 py-1 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold hover:bg-emerald-500/20 transition"
                  >
                    <ExternalLink className="w-3 h-3" />
                    {gw.action_url_label}
                  </a>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── View 3: Dual ROI Matrix ── */}
      {!loading && !error && activeView === "roi_matrix" && (
        <div className="max-w-6xl mx-auto space-y-6">
          <div className="p-6 rounded-2xl bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-800 shadow-sm">
            <h2 className="text-lg font-bold text-slate-900 dark:text-white mb-2">
              📊 {isRtl ? "مصفوفة العائد المزدوج: القيمة المهنية مقابل التأهيل الأكاديمي" : "Dual ROI Matrix: Industry Market Value vs. PhD Funding Leverage"}
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mb-6 max-w-3xl leading-relaxed">
              {isRtl
                ? "يوضح هذا الجدول كيف يتحول كل إنجاز معتمد في SecuraX إلى قوة تفاوضية مضاعفة."
                : "Comparative breakdown mapping each certification track to industry recruitment value and academic doctoral sponsorship leverage."}
            </p>

            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead>
                  <tr className="border-b border-slate-200 dark:border-slate-700 text-slate-400 uppercase tracking-wider text-[10px]">
                    <th className="py-3 px-4">{isRtl ? "المسار / الشهادة" : "Track / Certificate"}</th>
                    <th className="py-3 px-4">{isRtl ? "المستوى الأكاديمي" : "Academic Tier"}</th>
                    <th className="py-3 px-4">{isRtl ? "العائد في سوق العمل" : "Industry Market Role"}</th>
                    <th className="py-3 px-4">{isRtl ? "أثر التمويل وقبول الدكتوراه" : "PhD & RA Fellowship Leverage"}</th>
                    <th className="py-3 px-4">{isRtl ? "إجراء" : "Action"}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                  {[
                    {
                      cert: "OSCP (OffSec)", color: "bg-purple-500", tier: "Tier S", tier_color: "text-violet-400",
                      role_en: "Senior Penetration Tester / Red Teamer", role_ar: "كبير مختبري اختراق / مهندس أمن هجومي",
                      leverage_en: "Instant RA grant qualification & introductory lab waiver",
                      leverage_ar: "إعفاء فوري وتأهيل مباشر لمنح Research Assistantship (RA) مدفوعة",
                      leverage_color: "text-emerald-400", nav: "/learn/certification", nav_cert: "oscp",
                    },
                    {
                      cert: "eJPT (INE)", color: "bg-amber-500", tier: "Tier A", tier_color: "text-amber-400",
                      role_en: "Application Security Analyst", role_ar: "محلل أمان تطبيقي / Junior PenTester",
                      leverage_en: "Evidence of empirical penetration testing capability for research papers",
                      leverage_ar: "إثبات قدرة عملية على إجراء تجارب الاختراق الميدانية في أوراق البحث",
                      leverage_color: "text-slate-300", nav: "/tracks", nav_cert: "ejpt",
                    },
                    {
                      cert: "CompTIA Security+", color: "bg-blue-500", tier: "Tier B", tier_color: "text-blue-400",
                      role_en: "SOC Analyst / Security Auditor", role_ar: "محلل مركز العمليات الأمنية (SOC Analyst)",
                      leverage_en: "Meets baseline compliance for defense-contracted lab projects",
                      leverage_ar: "تلبية المتطلبات الإلزامية للمشاريع الدفاعية والحكومية الممولة",
                      leverage_color: "text-slate-300", nav: "/tracks", nav_cert: "secplus",
                    },
                    {
                      cert: "SecuraX Working Artifact", color: "bg-emerald-500", tier: "Master's Defense", tier_color: "text-emerald-400",
                      role_en: "Security Software Architect", role_ar: "مهندس أمن معماري / باحث برمجيات",
                      leverage_en: "Live working artifact proving full-stack security engineering capabilities",
                      leverage_ar: "حجة دامغة تثبت القدرة على بناء أنظمة كاملة من الصفر (يعادل أوراق بحثية)",
                      leverage_color: "text-emerald-400 font-bold", nav: "/journey", nav_cert: null,
                    },
                  ].map((row) => (
                    <tr key={row.cert} className="hover:bg-slate-50 dark:hover:bg-slate-700/30 transition">
                      <td className="py-4 px-4 font-bold text-white">
                        <div className="flex items-center gap-2">
                          <span className={`w-2 h-2 rounded-full ${row.color}`} />
                          <span>{row.cert}</span>
                        </div>
                      </td>
                      <td className={`py-4 px-4 font-mono font-bold ${row.tier_color}`}>{row.tier}</td>
                      <td className="py-4 px-4 text-slate-400">{isRtl ? row.role_ar : row.role_en}</td>
                      <td className={`py-4 px-4 ${row.leverage_color}`}>{isRtl ? row.leverage_ar : row.leverage_en}</td>
                      <td className="py-4 px-4">
                        <button
                          id={`roi-action-${row.cert.replace(/\s+/g,'-').toLowerCase()}`}
                          onClick={() => navigate(row.nav)}
                          className="inline-flex items-center gap-1 px-2 py-1 text-[10px] rounded bg-violet-500/10 text-violet-400 border border-violet-500/20 hover:bg-violet-500/20 transition"
                        >
                          {isRtl ? "ابدأ" : "Start"}
                          <ChevronRight className="w-3 h-3" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
