import React, { useState, useEffect, useCallback } from "react";
import axios from "axios";
import { Link } from "react-router-dom";
import {
  ShieldAlert, Terminal, Search, CheckCircle2, XCircle, AlertTriangle,
  FileText, ArrowRight, RefreshCw, Send, Lock, ExternalLink, HelpCircle,
  Cpu, Activity, Layers, Award, ChevronRight
} from "lucide-react";
import { useLang } from "../context/LangContext";

export default function CaseFilesPage() {
  const { lang, t } = useLang();
  const isAr = lang === "ar";

  const [cases, setCases] = useState([]);
  const [selectedCaseId, setSelectedCaseId] = useState(null);
  const [activeCase, setActiveCase] = useState(null);
  const [loadingList, setLoadingList] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [logFilter, setLogFilter] = useState("");
  const [evaluationResult, setEvaluationResult] = useState(null);

  // Form inputs
  const [formData, setFormData] = useState({
    attacker_source: "",
    compromised_target: "",
    mitre_technique: "",
    findings_narrative: "",
    containment_plan: "",
  });

  const fetchCases = useCallback(async () => {
    try {
      setLoadingList(true);
      const res = await axios.get("/api/casefiles");
      if (res.data.ok) {
        setCases(res.data.cases || []);
        if (!selectedCaseId && res.data.cases.length > 0) {
          setSelectedCaseId(res.data.cases[0].id);
        }
      }
    } catch (err) {
      console.error("Failed to load case files", err);
    } finally {
      setLoadingList(false);
    }
  }, [selectedCaseId]);

  useEffect(() => {
    fetchCases();
  }, []);

  const fetchCaseDetail = useCallback(async (caseId) => {
    if (!caseId) return;
    try {
      setLoadingDetail(true);
      setEvaluationResult(null);
      const res = await axios.get(`/api/casefiles/${caseId}`);
      if (res.data.ok) {
        setActiveCase(res.data.case);
        if (res.data.case.previous_submission) {
          setEvaluationResult(res.data.case.previous_submission.feedback);
        }
      }
    } catch (err) {
      console.error("Failed to load case detail", err);
    } finally {
      setLoadingDetail(false);
    }
  }, []);

  useEffect(() => {
    if (selectedCaseId) {
      fetchCaseDetail(selectedCaseId);
    }
  }, [selectedCaseId, fetchCaseDetail]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!selectedCaseId) return;
    try {
      setSubmitting(true);
      const res = await axios.post(`/api/casefiles/${selectedCaseId}/submit`, formData);
      if (res.data.ok) {
        setEvaluationResult(res.data.feedback);
        fetchCases(); // refresh status
      }
    } catch (err) {
      console.error("Failed to submit investigation", err);
    } finally {
      setSubmitting(false);
    }
  };

  const solvedCount = cases.filter((c) => c.status?.passed).length;
  const filteredLogs = (activeCase?.evidence_logs || []).filter((line) =>
    logFilter ? line.toLowerCase().includes(logFilter.toLowerCase()) : true
  );

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 p-4 sm:p-6 lg:p-8">
      {/* Header */}
      <div className="max-w-7xl mx-auto mb-8">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-200 dark:border-slate-800 pb-6">
          <div>
            <div className="flex items-center gap-2.5 mb-2">
              <span className="px-2.5 py-0.5 rounded-full text-xs font-bold uppercase tracking-wider bg-cyan-100 text-cyan-800 dark:bg-cyan-950/80 dark:text-cyan-300 border border-cyan-300 dark:border-cyan-800">
                Blue Team / SOC Lab (E-02)
              </span>
              <span className="text-xs text-slate-500 dark:text-slate-400">
                MITRE ATT&CK Mapping
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight">
              {isAr ? "ملفات القضايا الأمنية (SOC Case Files)" : "SOC Incident Case Files"}
            </h1>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-400 max-w-2xl">
              {isAr
                ? "تحقيق جنائي رقمي واقعي: حلل حزم الأدلة وسجلات الخوادم، حدد مصدر الهجوم وتقنية المهاجم، واكتب خطة احتواء فورية."
                : "Hands-on digital forensics & incident triage. Analyze raw evidence logs, uncover threat actors and TTPs, and author structured containment playbooks."}
            </p>
          </div>

          {/* Quick Metrics */}
          <div className="flex items-center gap-3">
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-3.5 px-5 shadow-sm text-center">
              <div className="text-xs text-slate-500 font-medium">
                {isAr ? "القضايا المحلولة" : "Cases Solved"}
              </div>
              <div className="text-xl font-bold text-cyan-600 dark:text-cyan-400 mt-0.5">
                {solvedCount} / {cases.length}
              </div>
            </div>
            <Link
              to="/tracks"
              className="flex items-center gap-2 px-4 py-2.5 bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 text-sm font-semibold rounded-xl transition"
            >
              <Layers className="w-4 h-4" />
              <span>{isAr ? "عرض المسارات" : "Learning Tracks"}</span>
            </Link>
          </div>
        </div>

        {/* Case Cards Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-6">
          {cases.map((c) => {
            const isSelected = c.id === selectedCaseId;
            const isPassed = c.status?.passed;
            return (
              <button
                key={c.id}
                onClick={() => setSelectedCaseId(c.id)}
                className={`text-start p-4 rounded-xl border transition-all duration-200 flex flex-col justify-between ${
                  isSelected
                    ? "bg-cyan-500/10 border-cyan-500 shadow-md ring-1 ring-cyan-500/50"
                    : "bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700"
                }`}
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                      {c.mitre_id}
                    </span>
                    {isPassed ? (
                      <span className="flex items-center gap-1 text-[11px] font-bold text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/60 px-2 py-0.5 rounded-full border border-emerald-200 dark:border-emerald-800">
                        <CheckCircle2 className="w-3 h-3" />
                        {c.status.score}%
                      </span>
                    ) : (
                      <span className="text-[11px] font-medium text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/60 px-2 py-0.5 rounded-full border border-amber-200 dark:border-amber-800">
                        {isAr ? "قيد التحقيق" : "Pending"}
                      </span>
                    )}
                  </div>

                  <h3 className="text-sm font-bold leading-snug line-clamp-2">
                    {isAr ? c.title_ar : c.title_en}
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 line-clamp-2">
                    {isAr ? c.scenario_ar : c.scenario_en}
                  </p>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80 flex items-center justify-between text-xs text-slate-500">
                  <span>{c.incident_name_en}</span>
                  <ChevronRight className="w-3.5 h-3.5 opacity-60" />
                </div>
              </button>
            );
          })}
        </div>

        {/* Main Investigation Workspace */}
        {activeCase && (
          <div className="mt-8 grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left: Evidence & Scenario (7 cols) */}
            <div className="lg:col-span-7 space-y-6">
              {/* Scenario Briefing */}
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-sm">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
                    <h2 className="text-base font-bold">
                      {isAr ? activeCase.title_ar : activeCase.title_en}
                    </h2>
                  </div>
                  <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-900">
                    {activeCase.severity.toUpperCase()}
                  </span>
                </div>

                <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed mb-4">
                  {isAr ? activeCase.scenario_ar : activeCase.scenario_en}
                </p>

                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs bg-slate-50 dark:bg-slate-800/50 p-3 rounded-xl border border-slate-200/60 dark:border-slate-700/60">
                  <div>
                    <span className="text-slate-400 block">{isAr ? "الهدف المتأثر" : "Target System"}</span>
                    <span className="font-semibold">{activeCase.target_system}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">{isAr ? "تكتيك MITRE" : "MITRE Tactic"}</span>
                    <span className="font-semibold">{activeCase.mitre_tactic}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block">{isAr ? "مصادر السجلات" : "Log Sources"}</span>
                    <span className="font-semibold">{activeCase.log_sources?.join(", ") || "Syslog"}</span>
                  </div>
                </div>
              </div>

              {/* Raw Evidence Terminal */}
              <div className="bg-slate-900 text-slate-100 rounded-2xl border border-slate-800 shadow-lg overflow-hidden flex flex-col">
                <div className="px-4 py-3 bg-slate-950 border-b border-slate-800 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    <span className="text-xs font-mono font-bold tracking-wider uppercase text-slate-300">
                      Forensic Evidence Logs ({activeCase.evidence_logs?.length || 0} entries)
                    </span>
                  </div>
                  <div className="relative w-48 sm:w-64">
                    <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-500" />
                    <input
                      type="text"
                      placeholder={isAr ? "تصفية السجلات..." : "Filter logs..."}
                      value={logFilter}
                      onChange={(e) => setLogFilter(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 text-xs text-slate-200 pl-8 pr-2.5 py-1.5 rounded-lg focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>

                <div className="p-4 font-mono text-xs overflow-x-auto max-h-[380px] overflow-y-auto space-y-1.5 leading-relaxed">
                  {filteredLogs.length > 0 ? (
                    filteredLogs.map((line, idx) => (
                      <div key={idx} className="flex items-start gap-3 hover:bg-slate-800/60 px-2 py-0.5 rounded">
                        <span className="text-slate-600 select-none w-6 text-right flex-shrink-0">
                          {idx + 1}
                        </span>
                        <span className="text-slate-300 break-all">{line}</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-8 text-slate-500">
                      {isAr ? "لا توجد نتائج تطابق الفلتر" : "No logs match filter"}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Right: Analyst Submission Report (5 cols) */}
            <div className="lg:col-span-5 space-y-6">
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-sm">
                <div className="flex items-center gap-2 mb-4 pb-3 border-b border-slate-200 dark:border-slate-800">
                  <FileText className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
                  <h2 className="text-base font-bold">
                    {isAr ? "تقرير المحلل الجنائي" : "SOC Analyst Incident Form"}
                  </h2>
                </div>

                <form onSubmit={handleSubmit} className="space-y-4 text-xs">
                  <div>
                    <label className="block font-semibold mb-1 text-slate-700 dark:text-slate-300">
                      {isAr ? "1. عنوان IP أو نطاق المهاجم" : "1. Threat Actor Source (IP / Domain)"}
                    </label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. 198.51.100.42 or malicious.domain.xyz"
                      value={formData.attacker_source}
                      onChange={(e) => setFormData({ ...formData, attacker_source: e.target.value })}
                      className="w-full px-3 py-2 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    />
                  </div>

                  <div>
                    <label className="block font-semibold mb-1 text-slate-700 dark:text-slate-300">
                      {isAr ? "2. الحساب أو الخادم المخترق" : "2. Compromised Account / Host"}
                    </label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. deploy user on bastion or sarah.finance"
                      value={formData.compromised_target}
                      onChange={(e) => setFormData({ ...formData, compromised_target: e.target.value })}
                      className="w-full px-3 py-2 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    />
                  </div>

                  <div>
                    <label className="block font-semibold mb-1 text-slate-700 dark:text-slate-300">
                      {isAr ? "3. تصنيف تقنية MITRE ATT&CK" : "3. MITRE ATT&CK Technique"}
                    </label>
                    <input
                      type="text"
                      required
                      placeholder="e.g. T1110 Brute Force or T1566 Phishing"
                      value={formData.mitre_technique}
                      onChange={(e) => setFormData({ ...formData, mitre_technique: e.target.value })}
                      className="w-full px-3 py-2 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    />
                  </div>

                  <div>
                    <label className="block font-semibold mb-1 text-slate-700 dark:text-slate-300">
                      {isAr ? "4. ملخص النتائج والأدلة التقنية" : "4. Technical Evidence & Root Cause"}
                    </label>
                    <textarea
                      rows={3}
                      required
                      placeholder={isAr ? "اشرح ما تم استخراجه أو الأوامر المنفذة بناءً على السجلات..." : "Explain findings, commands executed, or data exfiltrated from the logs..."}
                      value={formData.findings_narrative}
                      onChange={(e) => setFormData({ ...formData, findings_narrative: e.target.value })}
                      className="w-full px-3 py-2 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    />
                  </div>

                  <div>
                    <label className="block font-semibold mb-1 text-slate-700 dark:text-slate-300">
                      {isAr ? "5. خطة الاحتواء والمعالجة الفورية" : "5. Containment & Remediation Plan"}
                    </label>
                    <textarea
                      rows={3}
                      required
                      placeholder={isAr ? "إجراءات عزل، حظر على جدار الحماية، تدوير كلمات السر والمفاتيح..." : "Containment steps (firewall blocks, credential resets, host isolation)..."}
                      value={formData.containment_plan}
                      onChange={(e) => setFormData({ ...formData, containment_plan: e.target.value })}
                      className="w-full px-3 py-2 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={submitting}
                    className="w-full py-2.5 px-4 bg-cyan-600 hover:bg-cyan-700 disabled:opacity-50 text-white font-bold rounded-xl shadow transition flex items-center justify-center gap-2"
                  >
                    {submitting ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>{isAr ? "جاري التقييم السقراطي..." : "Evaluating..."}</span>
                      </>
                    ) : (
                      <>
                        <Send className="w-4 h-4" />
                        <span>{isAr ? "إرسال التقرير للتقييم" : "Submit Investigation"}</span>
                      </>
                    )}
                  </button>
                </form>
              </div>

              {/* Evaluation Feedback Panel */}
              {evaluationResult && (
                <div className={`p-5 rounded-2xl border shadow-sm ${
                  evaluationResult.passed
                    ? "bg-emerald-500/10 border-emerald-500/40 text-emerald-950 dark:text-emerald-100"
                    : "bg-amber-500/10 border-amber-500/40 text-amber-950 dark:text-amber-100"
                }`}>
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-2">
                      {evaluationResult.passed ? (
                        <CheckCircle2 className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                      ) : (
                        <AlertTriangle className="w-5 h-5 text-amber-600 dark:text-amber-400" />
                      )}
                      <h3 className="text-sm font-bold">
                        {isAr ? "نتيجة تقييم التحقيق" : "Investigation Assessment"}
                      </h3>
                    </div>
                    <span className="text-lg font-extrabold">
                      {evaluationResult.score} / 100
                    </span>
                  </div>

                  <p className="text-xs leading-relaxed mb-4">
                    {evaluationResult.socratic_debrief}
                  </p>

                  <div className="space-y-2 text-xs">
                    {Object.entries(evaluationResult.checks || {}).map(([k, v]) => (
                      <div key={k} className="flex items-start gap-2 bg-white/60 dark:bg-slate-900/60 p-2 rounded-lg">
                        {v.status === "pass" ? (
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400 flex-shrink-0 mt-0.5" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5 text-red-500 flex-shrink-0 mt-0.5" />
                        )}
                        <span className="text-[11px]">{v.msg}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
