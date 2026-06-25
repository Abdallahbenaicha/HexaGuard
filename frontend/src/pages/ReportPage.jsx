import React, { useState, useEffect } from 'react';
import { Link, useParams } from 'react-router-dom';
import axios from 'axios';
import { FileText, Table, Code, ArrowLeft, Download, FileDown, Activity } from 'lucide-react';
import ResultsPanel from '../components/ResultsPanel';
import NetworkReconPanel from '../components/NetworkReconPanel';
import ReportExportBar from '../components/ReportExportBar';
import { REPORT_ENDPOINTS, reportDownloadUrl } from '../utils/reportExport';

const SECONDARY_REPORTS = [
    {
        label: 'Markdown Report',
        desc:  'Full report with executive summary, recon, and remediation',
        icon:  FileText,
        color: 'text-primary-600 bg-primary-100 dark:text-primary-400 dark:bg-primary-500/10 border-primary-200 dark:border-primary-500/20',
        endpoint: REPORT_ENDPOINTS.md,
        filename: 'vulnerability_report.md',
    },
    {
        label: 'CSV Export',
        desc:  'Spreadsheet-ready CSV with all findings',
        icon:  Table,
        color: 'text-green-600 bg-green-100 dark:text-green-400 dark:bg-green-500/10 border-green-200 dark:border-green-500/20',
        endpoint: REPORT_ENDPOINTS.csv,
        filename: 'findings_summary.csv',
    },
    {
        label: 'JSON Export',
        desc:  'Raw JSON data for integration with other tools',
        icon:  Code,
        color: 'text-purple-600 bg-purple-100 dark:text-purple-400 dark:bg-purple-500/10 border-purple-200 dark:border-purple-500/20',
        endpoint: REPORT_ENDPOINTS.json,
        filename: 'findings.json',
    },
];

const ReportPage = () => {
    const { token } = useParams();
    const [downloading, setDownloading]     = useState({});
    const [pdfLang,     setPdfLang]         = useState('en');
    const [inlineData,  setInlineData]      = useState(null);
    const [inlineLoading, setInlineLoading] = useState(false);
    const [inlineError,  setInlineError]    = useState('');

    useEffect(() => {
        if (!token) return;
        setInlineLoading(true);
        setInlineError('');
        axios.get(`/api/reports/${token}`, { withCredentials: true })
            .then(r => setInlineData(r.data))
            .catch(e => setInlineError(e.response?.data?.error || 'Failed to load report.'))
            .finally(() => setInlineLoading(false));
    }, [token]);

    const handlePdfDownload = async () => {
        setDownloading(p => ({ ...p, pdf: true }));
        try {
            const res = await fetch(
                reportDownloadUrl(REPORT_ENDPOINTS.pdf, token, { lang: pdfLang }),
                { credentials: 'include' },
            );
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                alert(err.error || 'No report found. Run a scan first.');
                return;
            }
            const blob    = await res.blob();
            const blobUrl = URL.createObjectURL(blob);
            const a       = document.createElement('a');
            a.href        = blobUrl;
            a.download    = `securax_report_${pdfLang}.pdf`;
            a.click();
            URL.revokeObjectURL(blobUrl);
        } catch {
            alert('Backend offline or no scan run yet.');
        } finally {
            setDownloading(p => ({ ...p, pdf: false }));
        }
    };

    const handleDownload = async (report) => {
        setDownloading(p => ({ ...p, [report.label]: true }));
        try {
            const downloadUrl = reportDownloadUrl(report.endpoint, token);
            const res = await fetch(downloadUrl, { credentials: 'include' });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                alert(err.error || 'No report found. Run a scan first.');
                return;
            }
            const blob    = await res.blob();
            const blobUrl = URL.createObjectURL(blob);
            const a       = document.createElement('a');
            a.href        = blobUrl;
            a.download    = report.filename;
            a.click();
            URL.revokeObjectURL(blobUrl);
        } catch {
            alert('Backend offline or no scan run yet.');
        } finally {
            setDownloading(p => ({ ...p, [report.label]: false }));
        }
    };

    return (
        <div className="animate-in fade-in duration-500 max-w-4xl mx-auto">
            {/* Header */}
            <div className="mb-8 text-center">
                <Link to="/dashboard" className="inline-flex items-center gap-2 text-sm font-medium text-slate-500 hover:text-primary-600 transition-colors mb-4">
                    <ArrowLeft className="w-4 h-4" /> Back to Dashboard
                </Link>
                <h1 className="text-3xl font-bold text-slate-900 dark:text-white flex items-center justify-center gap-3">
                    <Download className="w-8 h-8 text-primary-500" />
                    Export Reports
                </h1>
                <p className="text-slate-500 dark:text-slate-400 mt-2 text-sm max-w-xl mx-auto">
                    Download the results of your most recent security assessment.
                </p>
            </div>

            {/* Inline report viewer */}
            {token && (
                <div className="mb-10">
                    {inlineLoading && (
                        <div className="flex items-center justify-center gap-3 py-12 text-slate-500">
                            <Activity className="w-5 h-5 animate-spin" />
                            <span className="text-sm">Loading report…</span>
                        </div>
                    )}
                    {inlineError && (
                        <div className="p-4 bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 rounded-xl text-red-600 dark:text-red-400 text-sm">
                            {inlineError}
                        </div>
                    )}
                    {inlineData && (
                        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm space-y-6">
                            <div className="flex items-center justify-between">
                                <div>
                                    <h2 className="text-lg font-bold text-slate-900 dark:text-white">
                                        {inlineData.target || 'Security Report'}
                                    </h2>
                                    <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                                        {inlineData.scan_type_label || inlineData.scan_type} ·{' '}
                                        {inlineData.stored_at ? new Date(inlineData.stored_at).toLocaleString() : ''}
                                    </p>
                                </div>
                                <div className="text-right">
                                    <p className="text-2xl font-bold font-mono text-primary-600 dark:text-primary-400">
                                        {Number(inlineData.risk_score || 0).toFixed(1)}
                                        <span className="text-sm text-slate-400">/10</span>
                                    </p>
                                    <p className="text-xs uppercase tracking-wider text-slate-500">
                                        {inlineData.risk_level}
                                    </p>
                                </div>
                            </div>
                            {inlineData.executive_summary && (
                                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                                    {inlineData.executive_summary.replace(/\*\*/g, '')}
                                </div>
                            )}
                            {inlineData.recon && <NetworkReconPanel recon={inlineData.recon} />}
                            <ResultsPanel
                                findings={inlineData.findings || []}
                                total={inlineData.vuln_count || (inlineData.findings || []).length}
                                attackChains={inlineData.attack_chains || []}
                                kevFindings={inlineData.cisa_kev_findings || []}
                                reportToken={token}
                            />
                            <ReportExportBar reportToken={token} />
                        </div>
                    )}
                </div>
            )}

            {/* ── PRIMARY: PDF download ───────────────────────────────────── */}
            <div className="bg-gradient-to-br from-red-50 to-orange-50 dark:from-red-500/10 dark:to-orange-500/5 border-2 border-red-200 dark:border-red-500/30 rounded-2xl p-6 shadow-sm mb-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6">
                    <div className="flex items-center gap-4">
                        <div className="w-14 h-14 flex items-center justify-center rounded-xl bg-red-100 dark:bg-red-500/20 border border-red-200 dark:border-red-500/30 text-red-600 dark:text-red-400">
                            <FileDown className="w-7 h-7" />
                        </div>
                        <div>
                            <div className="flex items-center gap-2 mb-0.5">
                                <h3 className="text-base font-bold text-slate-900 dark:text-white">PDF Report</h3>
                                <span className="text-[10px] font-bold bg-red-600 text-white px-2 py-0.5 rounded-full uppercase tracking-wide">Recommended</span>
                            </div>
                            <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md">
                                Professional SECURAX-branded PDF with severity summary, CVE table, and all findings — exactly like the sample.
                            </p>
                            <div className="flex items-center gap-2 mt-2">
                                <span className="text-[10px] text-slate-500 uppercase tracking-wider">Language:</span>
                                {['en', 'ar'].map(lang => (
                                    <button
                                        key={lang}
                                        onClick={() => setPdfLang(lang)}
                                        className={`px-2.5 py-0.5 rounded text-[11px] font-semibold transition-colors ${
                                            pdfLang === lang
                                                ? 'bg-red-600 text-white'
                                                : 'bg-white dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700 hover:bg-slate-50'
                                        }`}
                                    >
                                        {lang === 'en' ? 'English' : 'العربية'}
                                    </button>
                                ))}
                            </div>
                        </div>
                    </div>
                    <button
                        onClick={handlePdfDownload}
                        disabled={downloading.pdf}
                        className="w-full sm:w-auto px-8 py-3 bg-red-600 hover:bg-red-700 active:bg-red-800 text-white rounded-xl text-sm font-bold shadow-lg shadow-red-500/20 transition-all disabled:opacity-50 flex items-center justify-center gap-2"
                    >
                        {downloading.pdf ? (
                            <>
                                <div className="w-4 h-4 border-2 border-white/40 border-t-white rounded-full animate-spin" />
                                Generating…
                            </>
                        ) : (
                            <><FileDown className="w-4 h-4" /> Download PDF</>
                        )}
                    </button>
                </div>
            </div>

            {/* ── SECONDARY: other formats ────────────────────────────────── */}
            <p className="text-[10px] font-semibold text-slate-400 uppercase tracking-widest px-1 mb-3 mt-6">
                Other formats
            </p>
            <div className="grid gap-3">
                {SECONDARY_REPORTS.map((report) => {
                    const Icon = report.icon;
                    return (
                        <div
                            key={report.label}
                            className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:shadow-md transition-shadow"
                        >
                            <div className="flex items-center gap-3">
                                <div className={`w-10 h-10 flex items-center justify-center rounded-lg border ${report.color}`}>
                                    <Icon className="w-5 h-5" />
                                </div>
                                <div>
                                    <h3 className="text-sm font-semibold text-slate-800 dark:text-white">{report.label}</h3>
                                    <p className="text-xs text-slate-500 dark:text-slate-400">{report.desc}</p>
                                </div>
                            </div>
                            <button
                                onClick={() => handleDownload(report)}
                                disabled={downloading[report.label]}
                                className="w-full sm:w-auto px-5 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg text-sm font-semibold transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
                            >
                                {downloading[report.label] ? (
                                    <div className="w-4 h-4 border-2 border-slate-400 border-t-transparent rounded-full animate-spin" />
                                ) : (
                                    <><Download className="w-4 h-4" /> Download</>
                                )}
                            </button>
                        </div>
                    );
                })}
            </div>

            {/* Quick nav */}
            <div className="mt-12 pt-8 border-t border-slate-200 dark:border-slate-800 text-center">
                <p className="text-slate-500 dark:text-slate-400 text-sm mb-4">No recent reports? Run a new security assessment.</p>
                <div className="flex flex-wrap justify-center gap-3">
                    {[
                        { href: '/scan/web',         label: 'Web Scanner' },
                        { href: '/scan/ssl',          label: 'SSL/TLS Audit' },
                        { href: '/scan/network',      label: 'Network Recon' },
                        { href: '/scan/code',         label: 'Code Analyzer' },
                        { href: '/scan/dast',         label: 'DAST Scanner' },
                        { href: '/scan/apache',       label: 'Config Audit' },
                        { href: '/scan/dependencies', label: 'Dependencies' },
                        { href: '/scan/server-ext',   label: 'Server Audit' },
                    ].map(link => (
                        <Link
                            key={link.href}
                            to={link.href}
                            className="px-4 py-2 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 text-xs font-semibold uppercase tracking-wider rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
                        >
                            {link.label}
                        </Link>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default ReportPage;
