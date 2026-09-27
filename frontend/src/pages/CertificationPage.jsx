import React, { useState, useEffect } from "react";
import axios from "axios";
import { useLang } from "../context/LangContext";
import { Link } from "react-router-dom";
import { AlertCircle, RefreshCw, CheckCircle2, ChevronRight, Award } from "lucide-react";

const CERT_STATIC_META = {
  secplus: {
    id: "secplus",
    title: "CompTIA Security+ (SY0-701)",
    tag: "Security Fundamentals",
    badgeColor: "bg-blue-500/10 text-blue-500 border-blue-500/30",
    description:
      "Global baseline cybersecurity certification covering core security principles, threat analysis, architecture, operations, and governance.",
    domains: [
      { code: "1.0", name: "General Security Concepts", weight: "12%" },
      { code: "2.0", name: "Threats, Vulnerabilities & Mitigations", weight: "22%" },
      { code: "3.0", name: "Security Architecture", weight: "18%" },
      { code: "4.0", name: "Security Operations", weight: "28%" },
      { code: "5.0", name: "Security Program Management & Oversight", weight: "20%" },
    ],
  },
  ejpt: {
    id: "ejpt",
    title: "eJPT (Junior Penetration Tester)",
    tag: "Offensive Hands-On",
    badgeColor: "bg-amber-500/10 text-amber-500 border-amber-500/30",
    description:
      "Hands-on entry-level penetration testing certification focusing on real assessment methodology, scanning, and web application exploitation.",
    domains: [
      { code: "1.0", name: "Assessment Methodologies", weight: "25%" },
      { code: "2.0", name: "Host & Network Auditing", weight: "25%" },
      { code: "3.0", name: "Host & Network Penetration Testing", weight: "35%" },
      { code: "4.0", name: "Web Application Penetration Testing", weight: "15%" },
    ],
  },
  oscp: {
    id: "oscp",
    title: "OSCP (OffSec Certified Professional)",
    tag: "Advanced Offensive",
    badgeColor: "bg-purple-500/10 text-purple-500 border-purple-500/30",
    description:
      "Rigorous offensive security certification testing real-world penetration testing methodology, manual vulnerability discovery, exploitation, and reporting.",
    domains: [
      { code: "1.0", name: "Penetration Testing Methodology & Recon", weight: "20%" },
      { code: "2.0", name: "Web Application Attacks & Exploitation", weight: "25%" },
      { code: "3.0", name: "Privilege Escalation & Client-Side Attacks", weight: "25%" },
      { code: "4.0", name: "Tunneling, Pivoting & Reporting", weight: "30%" },
    ],
  },
};

const DEFAULT_ORDER = ["secplus", "ejpt", "oscp"];

export default function CertificationPage() {
  const { t, lang } = useLang();
  const [certDataList, setCertDataList] = useState([]);
  const [selectedCertId, setSelectedCertId] = useState("secplus");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchReadiness = () => {
    setLoading(true);
    setError(null);
    axios
      .get("/api/tracks/cert-readiness", { withCredentials: true })
      .then((res) => {
        if (res.data?.ok && Array.isArray(res.data.certifications)) {
          const liveCerts = res.data.certifications;
          // Merge live backend data with static domain meta
          const merged = DEFAULT_ORDER.map((id) => {
            const live = liveCerts.find((c) => c.id === id) || {};
            const meta = CERT_STATIC_META[id] || {};
            return {
              id,
              title: live.name || meta.title || id,
              tag: meta.tag || "Certification",
              badgeColor: meta.badgeColor || "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
              description: meta.description || "",
              provider: live.provider || "",
              domains: meta.domains || [],
              readiness_pct: typeof live.readiness_pct === "number" ? live.readiness_pct : 0.0,
              covered_skills: Array.isArray(live.covered_skills) ? live.covered_skills : [],
              missing_skills: Array.isArray(live.missing_skills) ? live.missing_skills : [],
              total_skills: typeof live.total_skills === "number" ? live.total_skills : (meta.domains?.length || 0),
              disclaimer: lang === "ar" ? live.disclaimer_ar : live.disclaimer_en,
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
  }, [lang]);

  const selectedCert =
    certDataList.find((c) => c.id === selectedCertId) ||
    (certDataList.length > 0 ? certDataList[0] : null);

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-900 text-slate-900 dark:text-slate-100 p-6 md:p-8">
      {/* Header */}
      <div className="max-w-6xl mx-auto mb-8">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-primary-100 dark:bg-primary-900/40 text-primary-600 dark:text-primary-300">
                {t("certification_prep", "Certification Prep")}
              </span>
              <span className="text-xs text-slate-400 font-mono">Live Skill Ledger Readiness</span>
            </div>
            <h1 className="text-2xl md:text-3xl font-bold tracking-tight">
              {t("certification_prep", "Cybersecurity Certification Hub")}
            </h1>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
              {t(
                "certification_prep_desc",
                "Curated study guides, domain-aligned exercises, and progress tracking for industry security certifications."
              )}
            </p>
          </div>

          <div className="flex items-center gap-3">
            <Link
              to="/tracks"
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 transition"
            >
              <span>{t("learning_tracks", "View Learning Tracks")}</span>
            </Link>
            <Link
              to="/hunt/manual"
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-lg bg-primary-600 text-white hover:bg-primary-700 transition shadow-sm"
            >
              <span>{t("manual_testing", "Manual Web Testing")}</span>
            </Link>
          </div>
        </div>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="max-w-6xl mx-auto py-16 flex flex-col items-center justify-center space-y-4">
          <div className="w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full animate-spin" />
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
            onClick={fetchReadiness}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Retry</span>
          </button>
        </div>
      )}

      {/* Main Content */}
      {!loading && !error && selectedCert && (
        <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Certification Cards List */}
          <div className="lg:col-span-1 space-y-4">
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
              Available Study Paths
            </h2>
            {certDataList.map((cert) => {
              const isSelected = selectedCert.id === cert.id;
              return (
                <div
                  key={cert.id}
                  onClick={() => setSelectedCertId(cert.id)}
                  className={`cursor-pointer p-4 rounded-xl border transition-all duration-200 ${
                    isSelected
                      ? "border-primary-500 bg-white dark:bg-slate-800 shadow-md ring-1 ring-primary-500/20"
                      : "border-slate-200 dark:border-slate-800 bg-white/70 dark:bg-slate-800/50 hover:border-slate-300 dark:hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <h3 className="font-semibold text-sm leading-snug">{cert.title}</h3>
                    <span
                      className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${cert.badgeColor}`}
                    >
                      {cert.tag}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500 dark:text-slate-400 line-clamp-2 mb-3">
                    {cert.description}
                  </p>
                  <div className="flex items-center justify-between text-xs text-slate-400">
                    <span className="font-mono">{cert.covered_skills.length}/{cert.total_skills} Skills</span>
                    <span className="font-bold text-primary-500 font-mono">
                      {cert.readiness_pct}% Ready
                    </span>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Selected Certification Detail */}
          <div className="lg:col-span-2">
            <div className="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm">
              <div className="flex items-center justify-between gap-4 border-b border-slate-100 dark:border-slate-700/60 pb-4 mb-6">
                <div>
                  <span
                    className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${selectedCert.badgeColor}`}
                  >
                    {selectedCert.tag}
                  </span>
                  <h2 className="text-xl font-bold mt-1">{selectedCert.title}</h2>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-xl">
                    {selectedCert.description}
                  </p>
                </div>

                <div className="text-right flex-shrink-0">
                  <span className="text-3xl font-black text-primary-500 font-mono">
                    {selectedCert.readiness_pct}%
                  </span>
                  <p className="text-[10px] text-slate-400 font-medium">Skill Readiness</p>
                </div>
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
                    className="h-full bg-primary-500 rounded-full transition-all duration-500"
                    style={{ width: `${Math.min(100, Math.max(0, selectedCert.readiness_pct))}%` }}
                  />
                </div>
              </div>

              {/* Covered & Missing Skills Chips */}
              <div className="mb-6 space-y-3">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                  Curriculum Skill Coverage
                </h3>
                <div className="flex flex-wrap gap-2">
                  {selectedCert.covered_skills.map((skill) => (
                    <span
                      key={skill}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>{skill}</span>
                    </span>
                  ))}
                  {selectedCert.missing_skills.map((skill) => (
                    <span
                      key={skill}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-mono bg-slate-100 dark:bg-slate-900/60 text-slate-400 border border-slate-300 dark:border-slate-700"
                    >
                      <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
                      <span>{skill}</span>
                    </span>
                  ))}
                </div>
              </div>

              {/* Domains breakdown */}
              <div className="space-y-4">
                <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
                  Exam Domains & Objectives Breakdown
                </h3>

                <div className="space-y-3">
                  {selectedCert.domains.map((dom) => (
                    <div
                      key={dom.code}
                      className="p-3.5 rounded-lg border border-slate-100 dark:border-slate-700/50 bg-slate-50/50 dark:bg-slate-900/30 flex items-center justify-between gap-4"
                    >
                      <div className="flex items-center gap-3">
                        <span className="w-8 h-8 rounded-md bg-primary-100 dark:bg-primary-900/30 text-primary-600 dark:text-primary-300 font-bold text-xs flex items-center justify-center flex-shrink-0 font-mono">
                          {dom.code}
                        </span>
                        <div>
                          <h4 className="text-sm font-semibold">{dom.name}</h4>
                          <span className="text-[11px] text-slate-400">Exam Weight: {dom.weight}</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        <span className="text-xs px-2.5 py-1 rounded bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300 font-medium">
                          Study Guide
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Disclaimer */}
              <div className="mt-8 p-3.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-xs text-amber-700 dark:text-amber-300 leading-relaxed">
                <strong>Notice:</strong> {selectedCert.disclaimer || (
                  "HexaGuard / SecuraX provides independent training materials aligned with published objectives. We do not claim official sponsorship, affiliation, or endorsement by CompTIA or other certification providers."
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
