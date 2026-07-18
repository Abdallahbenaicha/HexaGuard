import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, CheckCircle, XCircle, Loader, ChevronUp, ExternalLink, Globe, Network, Zap, Lock, Server, X, Trash2 } from 'lucide-react';
import { useScanJobs } from '../context/ScanJobsContext';

const SCAN_ICONS = {
    web:        Globe,
    network:    Network,
    dast:       Zap,
    ssl:        Lock,
    server_ext: Server,
    default:    Activity,
};

const STATUS_RING = {
    queued:  'border-slate-300 dark:border-slate-600',
    running: 'border-cyan-400 dark:border-cyan-500 animate-pulse',
    done:    'border-green-400 dark:border-green-500',
    error:   'border-red-400 dark:border-red-500',
};

function JobRow({ job, onDismiss }) {
    const Icon = SCAN_ICONS[job.scan_type] || SCAN_ICONS.default;
    const isDone      = job.status === 'done';
    const isError     = job.status === 'error';
    const isFinished  = isDone || isError;
    const [expanded, setExpanded] = useState(false);

    return (
        <div className="px-4 py-2.5 hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors">
            <div className="flex items-center gap-3">
                <div className={`flex-shrink-0 w-7 h-7 rounded-full border-2 flex items-center justify-center ${STATUS_RING[job.status]}`}>
                    {job.status === 'running' && <Loader className="w-3.5 h-3.5 text-cyan-500 animate-spin" />}
                    {job.status === 'queued'  && <Loader className="w-3.5 h-3.5 text-slate-400" />}
                    {isDone  && <CheckCircle className="w-3.5 h-3.5 text-green-500" />}
                    {isError && (
                        <button onClick={() => setExpanded(e => !e)} title="Show error details">
                            <XCircle className="w-3.5 h-3.5 text-red-500 hover:text-red-400 transition-colors" />
                        </button>
                    )}
                </div>

                <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                        <Icon className="w-3 h-3 text-slate-400 flex-shrink-0" />
                        <span className="text-xs font-semibold text-slate-700 dark:text-slate-200 uppercase tracking-wide">
                            {job.scan_type}
                        </span>
                    </div>
                    <div className="text-[11px] text-slate-400 truncate max-w-[140px]" title={job.target}>{job.target}</div>
                </div>

                <div className="flex-shrink-0 flex items-center gap-1.5">
                    {job.status === 'running' && (
                        <div className="w-16 h-1.5 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                            <div className="h-full bg-cyan-500 rounded-full transition-all duration-500"
                                 style={{ width: `${job.progress || 20}%` }} />
                        </div>
                    )}
                    {job.status === 'queued' && (
                        <span className="text-[10px] text-slate-400">Queued</span>
                    )}
                    {isDone && job.report_token && (
                        <Link
                            to={`/reports/${job.report_token}`}
                            className="text-[10px] text-primary-600 dark:text-primary-400 flex items-center gap-0.5 hover:underline"
                        >
                            Report <ExternalLink className="w-2.5 h-2.5" />
                        </Link>
                    )}
                    {isError && (
                        <button
                            onClick={() => setExpanded(e => !e)}
                            className="text-[10px] text-red-500 hover:text-red-400 underline"
                        >
                            {expanded ? 'Hide' : 'Details'}
                        </button>
                    )}

                    {/* Dismiss button for finished jobs */}
                    {isFinished && (
                        <button
                            onClick={() => onDismiss(job.job_id)}
                            title="Dismiss"
                            className="ml-1 p-0.5 text-slate-300 hover:text-slate-500 dark:hover:text-slate-200 transition-colors rounded"
                        >
                            <X className="w-3 h-3" />
                        </button>
                    )}
                </div>
            </div>

            {/* Expanded error message */}
            {isError && expanded && (
                <div className="mt-2 ml-10 p-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                    <p className="text-[11px] text-red-700 dark:text-red-300 break-words leading-relaxed">
                        {job.message || job.error || 'Unknown error'}
                    </p>
                </div>
            )}
        </div>
    );
}

export default function GlobalScanProgress() {
    const { jobs, activeCount, errorCount, dismissJob, clearErrors } = useScanJobs();
    const [open, setOpen] = useState(false);

    const recentJobs = [...jobs]
        .sort((a, b) => new Date(b.started_at) - new Date(a.started_at))
        .slice(0, 8);

    if (jobs.length === 0) return null;

    const hasErrors = errorCount > 0;
    const label = activeCount > 0
        ? `${activeCount} scanning…`
        : hasErrors
            ? `${errorCount} error${errorCount !== 1 ? 's' : ''}`
            : `${jobs.length} scan${jobs.length !== 1 ? 's' : ''}`;

    return (
        <div className="fixed bottom-4 right-4 z-[9000]">
            {open && (
                <div className="mb-2 w-80 bg-white dark:bg-slate-900 rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-700 overflow-hidden animate-in slide-in-from-bottom-2 duration-200">
                    <div className="flex items-center justify-between px-4 py-3 border-b border-slate-100 dark:border-slate-800">
                        <div className="flex items-center gap-2">
                            <Activity className="w-4 h-4 text-cyan-500" />
                            <span className="text-sm font-semibold text-slate-800 dark:text-slate-100">Background Scans</span>
                        </div>
                        <div className="flex items-center gap-2">
                            {hasErrors && (
                                <button
                                    onClick={clearErrors}
                                    title="Clear all errors"
                                    className="flex items-center gap-1 text-[11px] text-red-500 hover:text-red-400 transition-colors"
                                >
                                    <Trash2 className="w-3 h-3" />
                                    Clear errors
                                </button>
                            )}
                            <button
                                onClick={() => setOpen(false)}
                                className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors p-0.5 rounded"
                            >
                                <X className="w-4 h-4" />
                            </button>
                        </div>
                    </div>
                    <div className="divide-y divide-slate-100 dark:divide-slate-800 max-h-80 overflow-y-auto">
                        {recentJobs.map(j => (
                            <JobRow key={j.job_id} job={j} onDismiss={dismissJob} />
                        ))}
                    </div>
                </div>
            )}

            <button
                onClick={() => setOpen(o => !o)}
                className={`flex items-center gap-2 px-4 py-2.5 rounded-2xl shadow-lg border font-semibold text-sm transition-all duration-200 ${
                    activeCount > 0
                        ? 'bg-cyan-500 hover:bg-cyan-400 text-white border-cyan-400 shadow-cyan-500/30'
                        : hasErrors
                            ? 'bg-red-50 hover:bg-red-100 dark:bg-red-900/20 dark:hover:bg-red-900/30 text-red-600 dark:text-red-400 border-red-300 dark:border-red-700'
                            : 'bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 border-slate-200 dark:border-slate-700'
                }`}
            >
                {activeCount > 0
                    ? <Loader className="w-4 h-4 animate-spin" />
                    : hasErrors
                        ? <XCircle className="w-4 h-4" />
                        : <Activity className="w-4 h-4" />
                }
                {label}
                <ChevronUp className={`w-3.5 h-3.5 transition-transform ${open ? 'rotate-180' : ''}`} />
            </button>
        </div>
    );
}
