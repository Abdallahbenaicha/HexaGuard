import { useEffect, useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';
import { useLang } from '../context/LangContext';
import {
    Activity, Shield, AlertTriangle, FileText,
    Globe, Server, Code, Settings, ChevronRight,
    Package, Zap, Network, Layers,
    Users, BarChart2, AlertOctagon, ShieldAlert,
    RefreshCw, Calendar, TrendingUp,
    Bug, Clock, UserCheck, Lock, Radar,
    Plus, Command,
} from 'lucide-react';

// ── Security Posture Gauge ─────────────────────────────────────────────────────
const PostureGauge = ({ avgRisk, criticalVulns, totalScans }) => {
    const { t } = useLang();
    const score = totalScans === 0 ? 100
        : Math.max(0, Math.round(100 - (avgRisk * 10) - (criticalVulns * 3)));
    const clamped = Math.min(100, Math.max(0, score));
    const color = clamped >= 80 ? '#22c55e' : clamped >= 60 ? '#eab308' : clamped >= 40 ? '#f97316' : '#ef4444';
    const labelKey = clamped >= 80 ? 'posture_strong' : clamped >= 60 ? 'posture_moderate' : clamped >= 40 ? 'posture_at_risk' : 'posture_critical';
    const r = 54, cx = 60, cy = 60;
    const circ = Math.PI * r;
    const dash = (clamped / 100) * circ;
    return (
        <div className="flex flex-col items-center gap-1">
            <svg width="120" height="70" viewBox="0 0 120 70">
                <path d={`M${cx-r},${cy} A${r},${r} 0 0,1 ${cx+r},${cy}`} fill="none" stroke="currentColor" strokeWidth="10"
                    className="text-slate-200 dark:text-slate-800" strokeLinecap="round"/>
                <path d={`M${cx-r},${cy} A${r},${r} 0 0,1 ${cx+r},${cy}`} fill="none" stroke={color} strokeWidth="10"
                    strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
                    style={{ transition: 'stroke-dasharray 1s ease' }}/>
                <text x="60" y="58" textAnchor="middle" fontSize="20" fontWeight="bold" fill={color} fontFamily="monospace">{clamped}</text>
            </svg>
            <span className="text-xs font-bold uppercase tracking-widest" style={{ color }}>{t(labelKey)}</span>
            <span className="text-[10px] text-slate-400">{t('security_posture')}</span>
        </div>
    );
};

// ── Shared severity / scan-type maps ─────────────────────────────────────────

const SEVERITY_STYLES = {
    critical: 'bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400 border-red-200 dark:border-red-500/20',
    high:     'bg-orange-100 text-orange-700 dark:bg-orange-500/10 dark:text-orange-400 border-orange-200 dark:border-orange-500/20',
    medium:   'bg-yellow-100 text-yellow-700 dark:bg-yellow-500/10 dark:text-yellow-400 border-yellow-200 dark:border-yellow-500/20',
    low:      'bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400 border-blue-200 dark:border-blue-500/20',
    info:     'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-400 border-slate-200 dark:border-slate-700',
};

const SCAN_TYPE_BADGE = {
    web:          { icon: Globe,    color: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-500/10 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-500/20',  labelKey: 'stype_web'   },
    network:      { icon: Server,   color: 'bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400 border border-blue-200 dark:border-blue-500/20',              labelKey: 'stype_netex' },
    network_ext:  { icon: Network,  color: 'bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400 border border-blue-200 dark:border-blue-500/20',              labelKey: 'stype_netex' },
    network_int:  { icon: Network,  color: 'bg-teal-100 text-teal-700 dark:bg-teal-500/10 dark:text-teal-400 border border-teal-200 dark:border-teal-500/20',              labelKey: 'stype_netin' },
    code:         { icon: Code,     color: 'bg-purple-100 text-purple-700 dark:bg-purple-500/10 dark:text-purple-400 border border-purple-200 dark:border-purple-500/20',  labelKey: 'stype_sast'  },
    sast:         { icon: Layers,   color: 'bg-purple-100 text-purple-700 dark:bg-purple-500/10 dark:text-purple-400 border border-purple-200 dark:border-purple-500/20',  labelKey: 'stype_sast'  },
    dast:         { icon: Zap,      color: 'bg-orange-100 text-orange-700 dark:bg-orange-500/10 dark:text-orange-400 border border-orange-200 dark:border-orange-500/20',  labelKey: 'stype_dast'  },
    dependencies: { icon: Package,  color: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-500/10 dark:text-yellow-400 border border-yellow-200 dark:border-yellow-500/20',  labelKey: 'stype_deps'  },
    apache:       { icon: Settings, color: 'bg-slate-100 text-slate-700 dark:bg-slate-500/10 dark:text-slate-400 border border-slate-200 dark:border-slate-500/20',        labelKey: 'stype_srvin' },
    server_ext:   { icon: Server,   color: 'bg-slate-100 text-slate-700 dark:bg-slate-500/10 dark:text-slate-400 border border-slate-200 dark:border-slate-500/20',        labelKey: 'stype_srvex' },
    server_int:   { icon: Settings, color: 'bg-slate-100 text-slate-700 dark:bg-slate-500/10 dark:text-slate-400 border border-slate-200 dark:border-slate-500/20',        labelKey: 'stype_srvin' },
};

const SCAN_TYPE_LABEL_KEYS = {
    web:          'stype_web',
    network_ext:  'stype_netex',
    network_int:  'stype_netin',
    server_ext:   'stype_srvex',
    server_int:   'stype_srvin',
    dependencies: 'stype_deps',
    sast:         'stype_sast',
    dast:         'stype_dast',
};

const ACTION_STYLES = {
    login_success: 'text-green-600 dark:text-green-400',
    login_failed:  'text-red-600 dark:text-red-400',
    scan_started:  'text-blue-600 dark:text-blue-400',
    scan_complete: 'text-primary-600 dark:text-primary-400',
    user_created:  'text-purple-600 dark:text-purple-400',
    user_deleted:  'text-red-600 dark:text-red-400',
    logout:        'text-slate-500 dark:text-slate-400',
};

// ── Helpers ───────────────────────────────────────────────────────────────────

const getLast7Days = () => {
    const days = [];
    for (let i = 6; i >= 0; i--) {
        const d = new Date();
        d.setDate(d.getDate() - i);
        days.push(d.toISOString().slice(0, 10));
    }
    return days;
};

// ── Small reusable cards ──────────────────────────────────────────────────────

const PersonalStatCard = ({ label, value, icon: Icon, colorClass, delay }) => (
    <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay }}
        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 shadow-sm hover:shadow-md transition-shadow"
    >
        <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-medium text-slate-500 dark:text-slate-400">{label}</h3>
            <div className={`p-2 rounded-lg ${colorClass}`}>
                <Icon className="w-5 h-5" />
            </div>
        </div>
        <div className="text-3xl font-bold text-slate-900 dark:text-white font-mono">{value}</div>
    </motion.div>
);

const AdminStatCard = ({ icon: Icon, label, value, sub, color }) => (
    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 shadow-sm flex flex-col gap-3">
        <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{label}</span>
            <div className={`w-9 h-9 rounded-xl flex items-center justify-center ${color}`}>
                <Icon className="w-5 h-5" />
            </div>
        </div>
        <div>
            <div className="text-3xl font-bold text-slate-900 dark:text-white tabular-nums">{value ?? '—'}</div>
            {sub && <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{sub}</div>}
        </div>
    </div>
);

const RiskProgressBar = ({ score }) => {
    const raw = parseFloat(score) || 0;
    const pct = Math.min(100, Math.max(0, raw * 10));
    const color = pct >= 75 ? 'bg-red-500' : pct >= 50 ? 'bg-orange-500' : pct >= 25 ? 'bg-yellow-500' : 'bg-green-500';
    return (
        <div className="w-full flex items-center gap-3">
            <div className="flex-1 h-2 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%`, transition: 'width 1s ease' }} />
            </div>
            <span className="text-xs font-bold font-mono w-8 text-right text-slate-700 dark:text-slate-300">
                {raw.toFixed(1)}
            </span>
        </div>
    );
};

// ── Main component ────────────────────────────────────────────────────────────

const DashboardPage = () => {
    const { user } = useAuth();
    const { t } = useLang();
    const navigate = useNavigate();
    const isAdmin = user?.role === 'admin';

    const [data, setData]             = useState(null);
    const [loadingMe, setLoadingMe]   = useState(true);
    const [errorMe, setErrorMe]       = useState('');

    const [adminStats, setAdminStats]     = useState(null);
    const [topVulns, setTopVulns]         = useState([]);
    const [allReports, setAllReports]     = useState([]);
    const [loadingAdmin, setLoadingAdmin] = useState(false);
    const [errorAdmin, setErrorAdmin]     = useState('');
    const [lastRefresh, setLastRefresh]   = useState(null);
    const [ariaStatus, setAriaStatus]     = useState(null);
    const [clearingAi, setClearingAi]     = useState(false);
    const [aiClearMsg, setAiClearMsg]     = useState('');

    useEffect(() => {
        if (!user) { navigate('/login'); return; }
        axios.get('/api/dashboard', { withCredentials: true })
            .then(r => setData(r.data))
            .catch(() => setErrorMe('Failed to load dashboard data.'))
            .finally(() => setLoadingMe(false));
    }, [user, navigate]);

    const fetchAdmin = useCallback(async () => {
        if (!isAdmin) return;
        setLoadingAdmin(true);
        setErrorAdmin('');
        try {
            const [statsRes, scansRes] = await Promise.all([
                axios.get('/api/admin/stats', { withCredentials: true }),
                axios.get('/api/admin/scans',  { withCredentials: true }),
            ]);
            setAdminStats(statsRes.data.stats);
            setTopVulns(statsRes.data.top_vulns || []);
            setAllReports(scansRes.data.reports || []);
            setLastRefresh(new Date());
        } catch (err) {
            setErrorAdmin(err.response?.data?.error || 'Failed to load admin data');
        } finally {
            setLoadingAdmin(false);
        }
    }, [isAdmin]);

    useEffect(() => { fetchAdmin(); }, [fetchAdmin]);

    useEffect(() => {
        if (!isAdmin) return;
        axios.get('/api/ai/status', { withCredentials: true })
            .then(r => setAriaStatus(r.data))
            .catch(() => {});
    }, [isAdmin]);

    const handleClearAllAi = async () => {
        if (!window.confirm('Clear ALL users\' AI conversation histories? This cannot be undone.')) return;
        setClearingAi(true);
        setAiClearMsg('');
        try {
            const { data: d } = await axios.post('/api/admin/ai/clear-all', {}, { withCredentials: true });
            setAiClearMsg(d.message || 'Done.');
        } catch (err) {
            setAiClearMsg(err.response?.data?.error || 'Failed to clear AI histories.');
        } finally {
            setClearingAi(false);
        }
    };

    if (loadingMe) return (
        <div className="h-64 flex flex-col items-center justify-center space-y-4">
            <Activity className="w-8 h-8 text-primary-500 animate-spin" />
            <p className="text-sm text-slate-500 dark:text-slate-400 font-medium">{t('loading')}</p>
        </div>
    );

    if (errorMe) return (
        <div className="h-64 flex items-center justify-center">
            <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 px-6 py-4 rounded-xl flex items-center gap-3">
                <AlertTriangle className="w-5 h-5" />
                <p className="text-sm font-medium">{errorMe}</p>
            </div>
        </div>
    );

    const stats   = data?.stats   || {};
    const reports = data?.reports || [];

    const days7 = getLast7Days();
    const dailyCounts = days7.map(day => {
        const count = allReports.filter(r => (r.stored_at || '').startsWith(day)).length;
        const label = new Date(day + 'T12:00:00').toLocaleDateString('en', { weekday: 'short' });
        return { day, label, count };
    });
    const maxDay = Math.max(...dailyCounts.map(d => d.count), 1);

    const byType = {};
    allReports.forEach(r => { const tp = r.scan_type || 'unknown'; byType[tp] = (byType[tp] || 0) + 1; });
    const typeEntries = Object.entries(byType).sort((a, b) => b[1] - a[1]);
    const maxTypeCount = Math.max(...typeEntries.map(([, c]) => c), 1);

    const userIdByName = {};
    (adminStats?.users_list || []).forEach(u => { userIdByName[u.username] = u.id; });

    const QUICK_SCANS = [
        { labelKey: 'qs_web',     to: '/scan/web',         icon: Globe,    color: 'hover:border-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-500/10 hover:text-indigo-600 dark:hover:text-indigo-400' },
        { labelKey: 'qs_ssl',     to: '/scan/ssl',          icon: Lock,     color: 'hover:border-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-500/10 hover:text-emerald-600 dark:hover:text-emerald-400' },
        { labelKey: 'qs_network', to: '/scan/network',      icon: Network,  color: 'hover:border-blue-400 hover:bg-blue-50 dark:hover:bg-blue-500/10 hover:text-blue-600 dark:hover:text-blue-400' },
        { labelKey: 'qs_code',    to: '/scan/code',         icon: Code,     color: 'hover:border-purple-400 hover:bg-purple-50 dark:hover:bg-purple-500/10 hover:text-purple-600 dark:hover:text-purple-400' },
        { labelKey: 'qs_config',  to: '/scan/apache',       icon: Settings, color: 'hover:border-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700 hover:text-slate-600 dark:hover:text-slate-300' },
        { labelKey: 'qs_deps',    to: '/scan/dependencies', icon: Package,  color: 'hover:border-yellow-400 hover:bg-yellow-50 dark:hover:bg-yellow-500/10 hover:text-yellow-600 dark:hover:text-yellow-400' },
    ];

    return (
        <div className="space-y-8 animate-in fade-in duration-500">

            {/* ── Personal header + Posture Gauge ──────────────────────── */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6">
                <div>
                    <h1 className="text-2xl font-bold text-slate-900 dark:text-white mb-1">{t('overview')}</h1>
                    <p className="text-slate-500 dark:text-slate-400 text-sm">{t('overview_sub')}</p>
                    <button
                        onClick={() => window.dispatchEvent(new CustomEvent('securax-cmd-palette'))}
                        className="mt-2 inline-flex items-center gap-2 text-xs text-slate-400 hover:text-primary-600 dark:hover:text-primary-400 transition-colors"
                    >
                        <Command className="w-3 h-3" />
                        {t('quick_navigate')} <kbd className="bg-slate-100 dark:bg-slate-800 px-1 rounded text-[10px] font-mono">Ctrl+K</kbd>
                    </button>
                </div>
                <div className="flex-shrink-0">
                    <PostureGauge
                        avgRisk={parseFloat(stats.avg_risk || 0)}
                        criticalVulns={stats.critical_vulns || 0}
                        totalScans={stats.total_scans || 0}
                    />
                </div>
            </div>

            {/* ── Quick Scan Launcher ───────────────────────────────────── */}
            <div>
                <div className="flex items-center justify-between mb-3">
                    <h2 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-2">
                        <Plus className="w-4 h-4" /> {t('quick_scan')}
                    </h2>
                </div>
                <div className="grid grid-cols-3 sm:grid-cols-6 gap-2">
                    {QUICK_SCANS.map(({ labelKey, to, icon: Icon, color }) => (
                        <Link
                            key={to}
                            to={to}
                            className={`flex flex-col items-center gap-1.5 p-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-500 dark:text-slate-400 text-xs font-semibold transition-all duration-150 ${color}`}
                        >
                            <Icon className="w-4 h-4" />
                            {t(labelKey)}
                        </Link>
                    ))}
                </div>
            </div>

            {/* ── Personal stat cards ───────────────────────────────────── */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <PersonalStatCard label={t('stat_total_scans')}  value={stats.total_scans || 0}                       icon={Activity}      colorClass="bg-blue-100 text-blue-600 dark:bg-blue-500/20 dark:text-blue-400"     delay={0}   />
                <PersonalStatCard label={t('stat_vulns_found')}  value={stats.total_vulns || 0}                       icon={AlertTriangle}  colorClass="bg-orange-100 text-orange-600 dark:bg-orange-500/20 dark:text-orange-400" delay={0.1} />
                <PersonalStatCard label={t('stat_critical')}     value={stats.critical_vulns || 0}                    icon={Shield}        colorClass="bg-red-100 text-red-600 dark:bg-red-500/20 dark:text-red-400"           delay={0.2} />
                <PersonalStatCard label={t('stat_avg_risk')}     value={parseFloat(stats.avg_risk || 0).toFixed(1)}   icon={FileText}      colorClass="bg-purple-100 text-purple-600 dark:bg-purple-500/20 dark:text-purple-400" delay={0.3} />
            </div>

            {/* ── Recent operations ─────────────────────────────────────── */}
            <div className="space-y-4">
                <div className="flex items-center justify-between">
                    <h2 className="text-lg font-semibold text-slate-900 dark:text-white">{t('recent_ops')}</h2>
                    <Link to="/reports" className="text-sm font-medium text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300 flex items-center gap-1">
                        {t('view_all')} <ChevronRight className="w-4 h-4" />
                    </Link>
                </div>

                <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl overflow-hidden shadow-sm">
                    {reports.length === 0 ? (
                        <div className="p-12 text-center">
                            <FileText className="w-12 h-12 text-slate-300 dark:text-slate-600 mx-auto mb-4" />
                            <h3 className="text-sm font-semibold text-slate-900 dark:text-white mb-1">{t('no_scan_records')}</h3>
                            <p className="text-sm text-slate-500 dark:text-slate-400">{t('no_scan_launch')}</p>
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="w-full text-left border-collapse">
                                <thead>
                                    <tr className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-800">
                                        <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{t('col_target')}</th>
                                        <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{t('col_type')}</th>
                                        <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{t('col_risk')}</th>
                                        <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{t('col_findings')}</th>
                                        <th className="px-6 py-3 text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">{t('col_date')}</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                                    {reports.slice(0, 8).map((r) => {
                                        const badge = SCAN_TYPE_BADGE[r.scan_type] || SCAN_TYPE_BADGE.web;
                                        const BadgeIcon = badge.icon;
                                        return (
                                            <tr
                                                key={r.token}
                                                onClick={() => navigate(`/reports/${r.token}`)}
                                                className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors cursor-pointer group"
                                            >
                                                <td className="px-6 py-4">
                                                    <span className="text-sm font-medium text-slate-900 dark:text-slate-100 group-hover:text-primary-600 dark:group-hover:text-primary-400 transition-colors font-mono truncate max-w-[200px] block">
                                                        {r.target || 'N/A'}
                                                    </span>
                                                </td>
                                                <td className="px-6 py-4">
                                                    <div className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-medium ${badge.color}`}>
                                                        <BadgeIcon className="w-3.5 h-3.5" />
                                                        {t(badge.labelKey)}
                                                    </div>
                                                </td>
                                                <td className="px-6 py-4 w-40">
                                                    <RiskProgressBar score={r.risk_score} />
                                                </td>
                                                <td className="px-6 py-4">
                                                    <div className="flex items-center gap-2">
                                                        <span className="text-sm font-bold text-slate-700 dark:text-slate-300 font-mono">{r.vuln_count || 0}</span>
                                                        {(r.critical_count > 0 || r.high_count > 0) && (
                                                            <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400 border border-red-200 dark:border-red-500/20">
                                                                {r.critical_count > 0 ? `${r.critical_count} CRIT` : `${r.high_count} HIGH`}
                                                            </span>
                                                        )}
                                                    </div>
                                                </td>
                                                <td className="px-6 py-4 text-sm text-slate-500 dark:text-slate-400 whitespace-nowrap">
                                                    {r.stored_at ? new Date(r.stored_at).toLocaleDateString() : '—'}
                                                </td>
                                            </tr>
                                        );
                                    })}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </div>

            {/* ── Admin Command Center (admin only) ─────────────────────── */}
            {isAdmin && (
                <div className="space-y-6 pt-4 border-t border-slate-200 dark:border-slate-800">

                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                        <div>
                            <h2 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-3">
                                <Shield className="w-7 h-7 text-primary-500" />
                                {t('admin_center')}
                            </h2>
                            <p className="text-slate-500 dark:text-slate-400 mt-1 text-sm">
                                {t('admin_center_sub')}
                                {lastRefresh && (
                                    <span className="ml-2 text-slate-400">· {t('updated_at')} {lastRefresh.toLocaleTimeString()}</span>
                                )}
                            </p>
                        </div>
                        <button
                            onClick={fetchAdmin}
                            disabled={loadingAdmin}
                            className="self-start sm:self-auto flex items-center gap-2 px-4 py-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors shadow-sm disabled:opacity-50"
                        >
                            <RefreshCw className={`w-4 h-4 ${loadingAdmin ? 'animate-spin' : ''}`} /> {t('refresh')}
                        </button>
                    </div>

                    {errorAdmin && (
                        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 p-4 rounded-xl text-sm flex items-center gap-3">
                            <AlertOctagon className="w-5 h-5 flex-shrink-0" />
                            {errorAdmin}
                            <button onClick={fetchAdmin} className="ml-4 underline text-xs">{t('retry')}</button>
                        </div>
                    )}

                    <div className="bg-blue-50 dark:bg-blue-500/10 border border-blue-200 dark:border-blue-500/20 rounded-xl px-5 py-3 flex items-start gap-3">
                        <Lock className="w-5 h-5 text-blue-600 dark:text-blue-400 flex-shrink-0 mt-0.5" />
                        <p className="text-sm text-blue-700 dark:text-blue-300">
                            <span className="font-semibold">{t('authorized_only')}</span>{' '}
                            {t('all_logged')}
                        </p>
                    </div>

                    {adminStats && (
                        <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-4">
                            <AdminStatCard icon={Users}        label={t('stat_users')}         value={adminStats.total_users}    sub={`${adminStats.active_users ?? 0} ${t('sub_active')}`}  color="bg-blue-100 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400" />
                            <AdminStatCard icon={Radar}        label={t('stat_scans_admin')}   value={adminStats.total_scans}    sub={t('sub_all_time')}                                       color="bg-purple-100 dark:bg-purple-500/10 text-purple-600 dark:text-purple-400" />
                            <AdminStatCard icon={Calendar}     label={t('stat_today')}         value={adminStats.today_scans}    sub={t('sub_last24h')}                                        color="bg-cyan-100 dark:bg-cyan-500/10 text-cyan-600 dark:text-cyan-400" />
                            <AdminStatCard icon={Bug}          label={t('stat_vulns_admin')}   value={adminStats.total_vulns}    sub={t('sub_all_scans')}                                      color="bg-amber-100 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400" />
                            <AdminStatCard icon={AlertOctagon} label={t('stat_critical_admin')}value={adminStats.critical_vulns} sub={t('sub_platform')}                                       color="bg-red-100 dark:bg-red-500/10 text-red-600 dark:text-red-400" />
                            <AdminStatCard icon={ShieldAlert}  label={t('stat_failed_logins')} value={adminStats.failed_logins}  sub={t('sub_today')}                                          color="bg-orange-100 dark:bg-orange-500/10 text-orange-600 dark:text-orange-400" />
                        </div>
                    )}

                    {/* Charts */}
                    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                        <div className="lg:col-span-8 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
                            <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider mb-6 flex items-center gap-2">
                                <BarChart2 className="w-4 h-4 text-primary-500" /> {t('chart_7day')}
                            </h3>
                            <div className="flex items-end justify-between gap-2" style={{ height: '144px' }}>
                                {dailyCounts.map(({ day, label, count }) => (
                                    <div key={day} className="flex-1 flex flex-col items-center gap-1.5 group">
                                        <span className="text-[10px] font-bold text-slate-600 dark:text-slate-300 opacity-0 group-hover:opacity-100 transition-opacity tabular-nums min-h-[14px]">
                                            {count > 0 ? count : ''}
                                        </span>
                                        <div className="w-full flex items-end rounded-t-sm overflow-hidden" style={{ height: '96px' }}>
                                            <div
                                                className="w-full rounded-t-md bg-primary-500 dark:bg-primary-600 hover:bg-primary-400 dark:hover:bg-primary-500 transition-all duration-300"
                                                style={{
                                                    height: count > 0 ? `${Math.max(Math.round((count / maxDay) * 100), 8)}%` : '3px',
                                                    opacity: count > 0 ? 1 : 0.25,
                                                }}
                                                title={`${count} scan${count !== 1 ? 's' : ''} on ${day}`}
                                            />
                                        </div>
                                        <span className="text-[10px] text-slate-500 dark:text-slate-400">{label}</span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="lg:col-span-4 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
                            <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider mb-6 flex items-center gap-2">
                                <TrendingUp className="w-4 h-4 text-primary-500" /> {t('chart_types')}
                            </h3>
                            {typeEntries.length === 0 ? (
                                <p className="text-sm text-slate-500 text-center py-8">{t('no_scans_recorded')}</p>
                            ) : (
                                <div className="space-y-3.5">
                                    {typeEntries.map(([type, count]) => (
                                        <div key={type}>
                                            <div className="flex items-center justify-between mb-1">
                                                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">
                                                    {t(SCAN_TYPE_LABEL_KEYS[type]) || type}
                                                </span>
                                                <span className="text-xs font-bold text-slate-500 dark:text-slate-400 tabular-nums">{count}</span>
                                            </div>
                                            <div className="h-1.5 bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden">
                                                <div className="h-full bg-primary-500 rounded-full transition-all duration-500" style={{ width: `${Math.round((count / maxTypeCount) * 100)}%` }} />
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Top vulns + operators + events */}
                    <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                        <div className="lg:col-span-7 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm overflow-hidden">
                            <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/20 flex items-center gap-2">
                                <Bug className="w-4 h-4 text-primary-500" />
                                <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">{t('top_vulns')}</h3>
                            </div>
                            {topVulns.length === 0 ? (
                                <p className="p-8 text-center text-sm text-slate-500">{t('no_vuln_data')}</p>
                            ) : (
                                <div className="divide-y divide-slate-100 dark:divide-slate-800">
                                    {topVulns.slice(0, 8).map((v, i) => (
                                        <div key={i} className="px-6 py-3 flex items-center justify-between gap-4 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                                            <div className="flex items-center gap-3 min-w-0">
                                                <span className="text-xs font-mono text-slate-400 w-5 flex-shrink-0">#{i + 1}</span>
                                                <span className="text-sm text-slate-700 dark:text-slate-300 truncate">{v.title || v.check_name}</span>
                                            </div>
                                            <div className="flex items-center gap-2 flex-shrink-0">
                                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${SEVERITY_STYLES[(v.severity || '').toLowerCase()] || SEVERITY_STYLES.info}`}>
                                                    {v.severity}
                                                </span>
                                                <span className="text-xs font-bold text-slate-500 dark:text-slate-400 tabular-nums w-8 text-right">{v.count}×</span>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>

                        <div className="lg:col-span-5 flex flex-col gap-6">
                            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm overflow-hidden">
                                <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/20 flex items-center gap-2">
                                    <UserCheck className="w-4 h-4 text-primary-500" />
                                    <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">{t('top_ops')}</h3>
                                </div>
                                {!adminStats?.top_scanners?.length ? (
                                    <p className="p-6 text-center text-sm text-slate-500">{t('no_scan_hist')}</p>
                                ) : (
                                    <div className="divide-y divide-slate-100 dark:divide-slate-800">
                                        {adminStats.top_scanners.map((s, i) => {
                                            const uid = userIdByName[s.username];
                                            return (
                                                <div key={s.username} className="px-6 py-3 flex items-center justify-between hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                                                    <div className="flex items-center gap-3">
                                                        <span className="text-xs font-mono text-slate-400 w-5">#{i + 1}</span>
                                                        {uid != null ? (
                                                            <Link to={`/audit?user_id=${uid}`} className="text-sm font-medium text-slate-700 dark:text-slate-300 hover:text-primary-600 dark:hover:text-primary-400 transition-colors">
                                                                {s.username}
                                                            </Link>
                                                        ) : (
                                                            <span className="text-sm font-medium text-slate-700 dark:text-slate-300">{s.username}</span>
                                                        )}
                                                    </div>
                                                    <span className="text-xs font-bold bg-primary-50 dark:bg-primary-500/10 text-primary-700 dark:text-primary-400 border border-primary-200 dark:border-primary-500/20 px-2.5 py-1 rounded-lg tabular-nums">
                                                        {s.count} scan{s.count !== 1 ? 's' : ''}
                                                    </span>
                                                </div>
                                            );
                                        })}
                                    </div>
                                )}
                            </div>

                            <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-sm overflow-hidden flex-1">
                                <div className="px-6 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/20 flex items-center gap-2">
                                    <Clock className="w-4 h-4 text-primary-500" />
                                    <h3 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">{t('recent_events')}</h3>
                                </div>
                                {!adminStats?.recent_events?.length ? (
                                    <p className="p-6 text-center text-sm text-slate-500">{t('no_events')}</p>
                                ) : (
                                    <div className="divide-y divide-slate-100 dark:divide-slate-800">
                                        {adminStats.recent_events.slice(0, 8).map((ev, i) => (
                                            <div key={i} className="px-6 py-3 flex items-start gap-3 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                                                <div className="flex-1 min-w-0">
                                                    <div className="flex items-center gap-2 flex-wrap">
                                                        <span className={`text-xs font-bold ${ACTION_STYLES[ev.action] || 'text-slate-600 dark:text-slate-400'}`}>
                                                            {(ev.action || '').replace(/_/g, ' ')}
                                                        </span>
                                                        {ev.username && <span className="text-xs text-slate-500 dark:text-slate-400">by {ev.username}</span>}
                                                    </div>
                                                    <span className="text-[10px] text-slate-400">
                                                        {ev.created_at ? new Date(ev.created_at).toLocaleString() : ''}
                                                    </span>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>

                    {/* ARIA AI management */}
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                            <div className="flex items-center gap-4">
                                <div className="w-10 h-10 rounded-xl bg-cyan-50 dark:bg-cyan-500/10 flex items-center justify-center text-cyan-600 dark:text-cyan-400 flex-shrink-0">
                                    <Activity className="w-5 h-5" />
                                </div>
                                <div>
                                    <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                                        {t('aria_mgmt')}
                                        {ariaStatus && (
                                            <span className={`inline-flex items-center gap-1 text-[9px] px-2 py-0.5 rounded-full font-mono border ${
                                                ariaStatus.provider === 'gemini'
                                                    ? 'bg-green-50 border-green-200 text-green-700 dark:bg-green-500/10 dark:border-green-500/30 dark:text-green-400'
                                                    : ariaStatus.provider === 'ollama'
                                                    ? 'bg-blue-50 border-blue-200 text-blue-700 dark:bg-blue-500/10 dark:border-blue-500/30 dark:text-blue-400'
                                                    : 'bg-yellow-50 border-yellow-200 text-yellow-700 dark:bg-yellow-500/10 dark:border-yellow-500/30 dark:text-yellow-400'
                                            }`}>
                                                <span className={`w-1.5 h-1.5 rounded-full ${ariaStatus.provider === 'gemini' ? 'bg-green-500' : ariaStatus.provider === 'ollama' ? 'bg-blue-500' : 'bg-yellow-500'}`} />
                                                {ariaStatus.provider === 'gemini' ? 'Gemini Online' : ariaStatus.provider === 'ollama' ? 'Ollama Local' : 'Offline Mode'}
                                            </span>
                                        )}
                                    </h3>
                                    <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5 flex flex-wrap gap-3">
                                        {ariaStatus?.model && <span>{t('aria_model')} <span className="font-mono text-slate-700 dark:text-slate-300">{ariaStatus.model}</span></span>}
                                        <span>{t('aria_per_user')}</span>
                                    </div>
                                    {aiClearMsg && <p className="text-xs mt-1 text-primary-600 dark:text-primary-400">{aiClearMsg}</p>}
                                </div>
                            </div>
                            <button
                                onClick={handleClearAllAi}
                                disabled={clearingAi}
                                className="self-start sm:self-auto flex items-center gap-2 px-4 py-2 text-sm font-semibold text-red-600 dark:text-red-400 border border-red-200 dark:border-red-500/30 rounded-xl hover:bg-red-50 dark:hover:bg-red-500/10 transition-colors disabled:opacity-50"
                            >
                                <RefreshCw className={`w-4 h-4 ${clearingAi ? 'animate-spin' : ''}`} />
                                {clearingAi ? t('aria_clearing') : t('aria_clear')}
                            </button>
                        </div>
                    </div>

                </div>
            )}
        </div>
    );
};

export default DashboardPage;
