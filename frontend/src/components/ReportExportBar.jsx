import React, { useState } from 'react';
import { Download, FileDown, ChevronDown, FileJson, FileText, Globe } from 'lucide-react';
import { Link } from 'react-router-dom';
import { REPORT_ENDPOINTS, reportDownloadUrl } from '../utils/reportExport';

const ReportExportBar = ({ reportToken, className = '' }) => {
    const [pdfOpen, setPdfOpen] = useState(false);

    if (!reportToken) return null;

    const pdfEnUrl  = reportDownloadUrl(REPORT_ENDPOINTS.pdf,  reportToken);
    const pdfArUrl  = reportDownloadUrl(REPORT_ENDPOINTS.pdf,  reportToken, { lang: 'ar' });
    const mdUrl     = reportDownloadUrl(REPORT_ENDPOINTS.md,   reportToken);
    const jsonUrl   = reportDownloadUrl(REPORT_ENDPOINTS.json, reportToken);
    const viewUrl   = `/reports/${reportToken}`;

    return (
        <div className={`flex flex-wrap items-center gap-3 ${className}`}>
            {/* PDF dropdown */}
            <div className="relative">
                <button
                    onClick={() => setPdfOpen(o => !o)}
                    onBlur={() => setTimeout(() => setPdfOpen(false), 150)}
                    className="px-4 py-2 bg-red-50 hover:bg-red-100 dark:bg-red-500/10 dark:hover:bg-red-500/20 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-500/20 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
                >
                    <FileDown className="w-4 h-4" />
                    PDF Report
                    <ChevronDown className={`w-3.5 h-3.5 transition-transform ${pdfOpen ? 'rotate-180' : ''}`} />
                </button>

                {pdfOpen && (
                    <div className="absolute top-full mt-1 left-0 z-20 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl shadow-lg overflow-hidden min-w-[170px]">
                        <a
                            href={pdfEnUrl}
                            className="flex items-center gap-2.5 px-4 py-2.5 text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                        >
                            <Globe className="w-4 h-4 text-slate-400" />
                            English PDF
                        </a>
                        <a
                            href={pdfArUrl}
                            className="flex items-center gap-2.5 px-4 py-2.5 text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors border-t border-slate-100 dark:border-slate-700"
                            dir="rtl"
                        >
                            <Globe className="w-4 h-4 text-slate-400" />
                            تقرير عربي PDF
                        </a>
                    </div>
                )}
            </div>

            {/* Markdown */}
            <a
                href={mdUrl}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
            >
                <FileText className="w-4 h-4" /> Markdown
            </a>

            {/* JSON */}
            <a
                href={jsonUrl}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
            >
                <FileJson className="w-4 h-4" /> JSON
            </a>

            {/* View full report */}
            <Link
                to={viewUrl}
                className="px-4 py-2 border border-primary-300 dark:border-primary-500/30 text-primary-700 dark:text-primary-400 rounded-lg text-sm font-medium hover:bg-primary-50 dark:hover:bg-primary-500/10 transition-colors flex items-center gap-2"
            >
                <Download className="w-4 h-4" /> View Full Report →
            </Link>
        </div>
    );
};

export default ReportExportBar;
