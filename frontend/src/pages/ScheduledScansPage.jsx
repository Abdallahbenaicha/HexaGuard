import { useState, useEffect, useCallback } from 'react';
import { motion } from 'framer-motion';
import axios from 'axios';
import { useLang } from '../context/LangContext';
import {
    Clock, Plus, Trash2, Play, Pause, Globe, Server,
    Zap, Lock, Settings, Package, Layers, AlertTriangle,
} from 'lucide-react';

const SCAN_TYPES = [
    { value: 'web',          label: 'Web',         icon: Globe,    color: 'text-indigo-500' },
    { value: 'network',      label: 'Network',      icon: Server,   color: 'text-blue-500'   },
    { value: 'dast',         label: 'DAST',         icon: Zap,      color: 'text-orange-500' },
    { value: 'ssl',          label: 'SSL/TLS',      icon: Lock,     color: 'text-emerald-500'},
    { value: 'server',       label: 'Server',       icon: Settings, color: 'text-slate-500'  },
    { value: 'sast',         label: 'SAST',         icon: Layers,   color: 'text-purple-500' },
    { value: 'dependencies', label: 'Dependencies', icon: Package,  color: 'text-yellow-500' },
];

const CRONS = [
    { value: 'daily',   label: 'Daily'   },
    { value: 'weekly',  label: 'Weekly'  },
    { value: 'monthly', label: 'Monthly' },
];

const fmtDate = (iso) => {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleDateString(); } catch { return iso; }
};

export default function ScheduledScansPage() {
    const { t } = useLang();
    const [scans, setScans]       = useState([]);
    const [loading, setLoading]   = useState(true);
    const [error, setError]       = useState('');
    const [creating, setCreating] = useState(false);
    const [form, setForm]         = useState({ scan_type: 'web', target: '', cron_expr: 'daily' });
    const [formErr, setFormErr]   = useState('');
    const [msg, setMsg]           = useState('');

    const fetchScans = useCallback(async () => {
        try {
            const { data } = await axios.get('/api/scheduled-scans', { withCredentials: true });
            setScans(data.scheduled || []);
        } catch {
            setError('Failed to load scheduled scans.');
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => { fetchScans(); }, [fetchScans]);

    const handleCreate = async (e) => {
        e.preventDefault();
        setFormErr('');
        setMsg('');
        if (!form.target.trim()) { setFormErr('Target is required.'); return; }
        try {
            await axios.post('/api/scheduled-scans', form, { withCredentials: true });
            setMsg('Scheduled scan created successfully.');
            setForm({ scan_type: 'web', target: '', cron_expr: 'daily' });
            fetchScans();
        } catch (err) {
            setFormErr(err.response?.data?.error || 'Failed to create scheduled scan.');
        }
    };

    const toggle = async (id, current) => {
        try {
            await axios.patch(`/api/scheduled-scans/${id}`, { is_active: !current }, { withCredentials: true });
            fetchScans();
        } catch { /* ignore */ }
    };

    const remove = async (id) => {
        if (!window.confirm('Delete this scheduled scan?')) return;
        try {
            await axios.delete(`/api/scheduled-scans/${id}`, { withCredentials: true });
            fetchScans();
        } catch { /* ignore */ }
    };

    const ScanIcon = ({ type }) => {
        const entry = SCAN_TYPES.find(s => s.value === type);
        if (!entry) return <Clock className="w-4 h-4" />;
        const Icon = entry.icon;
        return <Icon className={`w-4 h-4 ${entry.color}`} />;
    };

    return (
        <div className="space-y-8 animate-in fade-in duration-500">
            {/* Header */}
            <div>
                <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <Clock className="w-6 h-6 text-purple-500" />
                    Scheduled Scans
                </h1>
                <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">
                    Set up recurring scans — daily, weekly, or monthly. Results appear in your Reports.
                </p>
            </div>

            {/* Create form */}
            <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm"
            >
                <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-4 flex items-center gap-2">
                    <Plus className="w-4 h-4" /> New Scheduled Scan
                </h2>

                <form onSubmit={handleCreate} className="grid grid-cols-1 sm:grid-cols-4 gap-3">
                    {/* Scan type */}
                    <select
                        value={form.scan_type}
                        onChange={e => setForm(f => ({ ...f, scan_type: e.target.value }))}
                        className="px-3 py-2.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                        aria-label="Scan type"
                    >
                        {SCAN_TYPES.map(s => (
                            <option key={s.value} value={s.value}>{s.label}</option>
                        ))}
                    </select>

                    {/* Target */}
                    <input
                        type="text"
                        placeholder="Target (e.g. example.com)"
                        value={form.target}
                        onChange={e => setForm(f => ({ ...f, target: e.target.value }))}
                        className="sm:col-span-2 px-3 py-2.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                        aria-label="Scan target"
                    />

                    {/* Frequency */}
                    <select
                        value={form.cron_expr}
                        onChange={e => setForm(f => ({ ...f, cron_expr: e.target.value }))}
                        className="px-3 py-2.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                        aria-label="Frequency"
                    >
                        {CRONS.map(c => (
                            <option key={c.value} value={c.value}>{c.label}</option>
                        ))}
                    </select>

                    <button
                        type="submit"
                        className="sm:col-span-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-white text-sm font-semibold transition-colors flex items-center justify-center gap-2"
                    >
                        <Plus className="w-4 h-4" /> Schedule Scan
                    </button>

                    {formErr && (
                        <p className="sm:col-span-4 text-sm text-red-500 flex items-center gap-1">
                            <AlertTriangle className="w-3.5 h-3.5" /> {formErr}
                        </p>
                    )}
                    {msg && (
                        <p className="sm:col-span-4 text-sm text-green-600 dark:text-green-400">{msg}</p>
                    )}
                </form>
            </motion.div>

            {/* List */}
            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm overflow-hidden">
                {loading ? (
                    <div className="p-12 text-center text-slate-400 text-sm">Loading…</div>
                ) : error ? (
                    <div className="p-8 text-center text-red-500 text-sm">{error}</div>
                ) : scans.length === 0 ? (
                    <div className="p-12 text-center">
                        <Clock className="w-12 h-12 text-slate-300 dark:text-slate-600 mx-auto mb-3" />
                        <p className="text-sm text-slate-500 dark:text-slate-400">No scheduled scans yet.</p>
                        <p className="text-xs text-slate-400 mt-1">Create one above to start monitoring on autopilot.</p>
                    </div>
                ) : (
                    <div className="divide-y divide-slate-100 dark:divide-slate-800">
                        {scans.map((s) => (
                            <div key={s.id} className="flex items-center gap-4 px-6 py-4 hover:bg-slate-50 dark:hover:bg-slate-800/40 transition-colors">
                                <div className={`w-8 h-8 rounded-lg flex items-center justify-center bg-slate-100 dark:bg-slate-800`}>
                                    <ScanIcon type={s.scan_type} />
                                </div>
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm font-semibold text-slate-900 dark:text-white truncate">{s.target}</p>
                                    <p className="text-xs text-slate-400 capitalize">{s.scan_type} · {s.cron_expr}</p>
                                </div>
                                <div className="text-xs text-slate-400 hidden sm:block">
                                    <span>Next: {fmtDate(s.next_run_at)}</span>
                                </div>
                                <span className={`hidden sm:inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                                    s.is_active
                                        ? 'bg-green-100 text-green-700 dark:bg-green-500/10 dark:text-green-400'
                                        : 'bg-slate-100 text-slate-500 dark:bg-slate-700 dark:text-slate-400'
                                }`}>
                                    {s.is_active ? 'Active' : 'Paused'}
                                </span>
                                <div className="flex items-center gap-1">
                                    <button
                                        onClick={() => toggle(s.id, s.is_active)}
                                        title={s.is_active ? 'Pause' : 'Resume'}
                                        className="p-2 rounded-lg text-slate-400 hover:text-cyan-500 hover:bg-cyan-50 dark:hover:bg-cyan-500/10 transition-colors"
                                        aria-label={s.is_active ? 'Pause scan' : 'Resume scan'}
                                    >
                                        {s.is_active ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                                    </button>
                                    <button
                                        onClick={() => remove(s.id)}
                                        title="Delete"
                                        className="p-2 rounded-lg text-slate-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-500/10 transition-colors"
                                        aria-label="Delete scheduled scan"
                                    >
                                        <Trash2 className="w-4 h-4" />
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
