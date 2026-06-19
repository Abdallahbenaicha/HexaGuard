import React from 'react';
import { Download, FileDown } from 'lucide-react';
import { Link } from 'react-router-dom';
import { REPORT_ENDPOINTS, reportDownloadUrl } from '../utils/reportExport';

/**
 * Export bar shown after any scan — links downloads to the correct report token.
 */
const ReportExportBar = ({ reportToken, className = '' }) => {
    if (!reportToken) return null;

    const pdfUrl  = reportDownloadUrl(REPORT_ENDPOINTS.pdf, reportToken);
    const mdUrl   = reportDownloadUrl(REPORT_ENDPOINTS.md, reportToken);
    const csvUrl  = reportDownloadUrl(REPORT_ENDPOINTS.csv, reportToken);
    const viewUrl = `/reports/${reportToken}`;

    return (
        <div className={`flex flex-wrap items-center gap-3 ${className}`}>
            <a
                href={pdfUrl}
                className="px-4 py-2 bg-red-50 hover:bg-red-100 dark:bg-red-500/10 dark:hover:bg-red-500/20 text-red-700 dark:text-red-400 border border-red-200 dark:border-red-500/20 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
            >
                <FileDown className="w-4 h-4" /> PDF Report
            </a>
            <a
                href={mdUrl}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
            >
                <Download className="w-4 h-4" /> Markdown
            </a>
            <a
                href={csvUrl}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg text-sm font-medium transition-colors flex items-center gap-2"
            >
                <Download className="w-4 h-4" /> CSV
            </a>
            <Link
                to={viewUrl}
                className="px-4 py-2 border border-primary-300 dark:border-primary-500/30 text-primary-700 dark:text-primary-400 rounded-lg text-sm font-medium hover:bg-primary-50 dark:hover:bg-primary-500/10 transition-colors"
            >
                View Full Report →
            </Link>
        </div>
    );
};

export default ReportExportBar;
