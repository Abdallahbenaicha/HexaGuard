import React, { useState } from "react";
import { useLang } from "../context/LangContext";
import { Link } from "react-router-dom";

const CERTIFICATIONS = [
  {
    id: "security_plus",
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
    status: "active",
    totalModules: 5,
    completedModules: 0,
  },
  {
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
    status: "coming_soon",
    totalModules: 4,
    completedModules: 0,
  },
  {
    id: "ceh",
    title: "Certified Ethical Hacker (CEH)",
    tag: "Ethical Hacking",
    badgeColor: "bg-purple-500/10 text-purple-500 border-purple-500/30",
    description:
      "Comprehensive knowledge of ethical hacking phases, tools, countermeasures, and vulnerability analysis across enterprise environments.",
    domains: [
      { code: "1.0", name: "Information Security & Ethical Hacking Overview", weight: "6%" },
      { code: "2.0", name: "Reconnaissance & Footprinting Techniques", weight: "21%" },
      { code: "3.0", name: "System Hacking & Malware Threats", weight: "17%" },
      { code: "4.0", name: "Network & Perimeter Attacks", weight: "14%" },
      { code: "5.0", name: "Web Application & Database Attacks", weight: "16%" },
      { code: "6.0", name: "Wireless & Mobile Security", weight: "10%" },
      { code: "7.0", name: "Cloud, IoT & OT Security", weight: "8%" },
      { code: "8.0", name: "Cryptography & PKI", weight: "8%" },
    ],
    status: "coming_soon",
    totalModules: 8,
    completedModules: 0,
  },
];

export default function CertificationPage() {
  const { t } = useLang();
  const [selectedCert, setSelectedCert] = useState(CERTIFICATIONS[0]);

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
              <span className="text-xs text-slate-400">SY0-701 Alignment</span>
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

      {/* Main Content */}
      <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Certification Cards List */}
        <div className="lg:col-span-1 space-y-4">
          <h2 className="text-xs font-bold uppercase tracking-wider text-slate-400 dark:text-slate-500">
            Available Study Paths
          </h2>
          {CERTIFICATIONS.map((cert) => {
            const isSelected = selectedCert.id === cert.id;
            return (
              <div
                key={cert.id}
                onClick={() => setSelectedCert(cert)}
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
                  <span>{cert.totalModules} Domains</span>
                  {cert.status === "active" ? (
                    <span className="text-emerald-500 font-medium">Ready</span>
                  ) : (
                    <span className="text-amber-500 font-medium">In Progress</span>
                  )}
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
                <span className="text-2xl font-black text-primary-500">0%</span>
                <p className="text-[10px] text-slate-400 font-medium">Domain Mastery</p>
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
                      <span className="w-8 h-8 rounded-md bg-primary-100 dark:bg-primary-900/30 text-primary-600 dark:text-primary-300 font-bold text-xs flex items-center justify-center flex-shrink-0">
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
              <strong>Notice:</strong> HexaGuard / SecuraX provides independent training materials
              aligned with published objectives. We do not claim official sponsorship, affiliation, or
              endorsement by CompTIA or other certification providers.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
