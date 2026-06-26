import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Activity, CheckCircle, XCircle, Loader, ChevronUp, ExternalLink, Globe, Network, Zap, Lock, Server } from 'lucide-react';
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

function JobRow({ job }) {
    const Icon = SCAN_ICONS[job.scan_type] || SCAN_ICONS.default;
    const isDone  = job.status === 'done';
    const isError = job.status === 'error';

    return (
        <div className="flex items-center gap-3 px-4 py-2.5 hover:bg-slate-50 dark:hover:bg-slate-800/60 transition-colors">
            <div className={`flex-shrink-0 w-7 h-7 rounded-full border-2 flex items-center justify-center ${STATUS_RING[job.status]}`}>
                {job.status === 'running' && <Loader className="w-3.5 h-3.5 text-cyan-500 animate-spin" />}
                {job.status === 'queued'  && <Loader className="w-3.5 h-3.5 text-slate-400" />}
                {isDone   && <CheckCircle className="w-3.5 h-3.5 text-green-500" />}
                {isError  && <XCircle     className="w-3.5 h-3.5 text-red-500" />}
            </div>

            <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5">
                    <Icon className="w-3 h-3 text-slate-400 flex-shrink-0" />
                    <span className="text-xs font-semibold text-slate-700 dark:text-slate-200 uppercase tracking-wide">
                        {job.scan_type}
                    </span>
                </div>
                <div className="text-[11px] text-slate-400 truncate max-w-[160px]">{job.target}</div>
            </div>

            <div className="flex-shrink-0 text-right">
                {job.status === 'running' && (
                    <div className="flex items-center gap-1">
                        <div className="w-16 h-1.5 bg-slate-200 dark:bg-slate-700 rounded-full overflow-hidden">
                            <div className="h-full bg-cyan-500 rounded-full transition-all duration-500"
                                 style={{ width: `${job.progress || 20}%` }} />
                        </div>
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
                    <span className="text-[10px] text-red-500">Failed</span>
                )}
            </div>
        </div>
    );
}

export default function GlobalScanProgress() {
    const { jobs, activeCount } = useScanJobs();
    const [open, setOpen] = useState(false);

    const recentJobs = [...jobs]
        .sort((a, b) => new Date(b.started_at) - new Date(a.started_at))
        .slice(0, 6);

    if (jobs.length === 0) return null;

    return (
        <div className="fixed bottom-4 right-4 z-[9000]">
            {open && (
                <div className="mb-2 w-72 bg-white dark:bg-slate-900 rounded-2xl shadow-2xl border border-slate-200 dark:border-slate-700 overflow-hidden animate-in slide-in-from-bottom-2 duration-200">
                    <div className="flex items-center justify-between px-4 py-3 border-b border-slate-100 dark:border-slate-800">
                        <div className="flex items-center gap-2">
                            <Activity className="w-4 h-4 text-cyan-500" />
                            <span className="text-sm font-semibold text-slate-800 dark:text-slate-100">Background Scans</span>
                        </div>
                        <button onClick={() => setOpen(false)} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 text-xs">✕</button>
                    </div>
                    <div className="divide-y divide-slate-100 dark:divide-slate-800 max-h-72 overflow-y-auto">
                        {recentJobs.map(j => <JobRow key={j.job_id} job={j} />)}
                    </div>
                </div>
            )}

            <button
                onClick={() => setOpen(o => !o)}
                className={`flex items-center gap-2 px-4 py-2.5 rounded-2xl shadow-lg border font-semibold text-sm transition-all duration-200 ${
                    activeCount > 0
                        ? 'bg-cyan-500 hover:bg-cyan-400 text-white border-cyan-400 shadow-cyan-500/30'
                        : 'bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 border-slate-200 dark:border-slate-700'
                }`}
            >
                {activeCount > 0
                    ? <Loader className="w-4 h-4 animate-spin" />
                    : <Activity className="w-4 h-4" />
                }
                {activeCount > 0 ? `${activeCount} scanning…` : `${jobs.length} scan${jobs.length !== 1 ? 's' : ''}`}
                <ChevronUp className={`w-3.5 h-3.5 transition-transform ${open ? 'rotate-180' : ''}`} />
            </button>
        </div>
    );
}
