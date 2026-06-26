import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link } from 'react-router-dom';
import axios from 'axios';
import {
    Globe, ArrowLeft, CheckCircle,
    AlertTriangle, Info, ShieldAlert, ExternalLink,
    ChevronDown, ChevronUp, Wordpress,
} from 'lucide-react';

// Fallback icon for Wordpress if not available in lucide-react version
const WpIcon = Wordpress || Globe;

const SEV_STYLES = {
    critical: { badge: 'bg-red-500/10 text-red-400 border-red-500/30',     dot: 'bg-red-500',    border: 'border-red-500/20'    },
    high:     { badge: 'bg-orange-500/10 text-orange-400 border-orange-500/30', dot: 'bg-orange-400', border: 'border-orange-500/20' },
    medium:   { badge: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30', dot: 'bg-yellow-400', border: 'border-yellow-500/20' },
    low:      { badge: 'bg-green-500/10 text-green-400 border-green-500/30',   dot: 'bg-green-400',  border: 'border-green-500/20'  },
    info:     { badge: 'bg-blue-500/10 text-blue-400 border-blue-500/30',     dot: 'bg-blue-400',   border: 'border-blue-500/20'   },
};

const SEV_ICON = { critical: ShieldAlert, high: AlertTriangle, medium: AlertTriangle, low: CheckCircle, info: Info };

function RiskBadge({ score }) {
    const color = score >= 7 ? 'text-red-400' : score >= 4 ? 'text-orange-400' : score >= 2 ? 'text-yellow-400' : 'text-green-400';
    return (
        <div className="text-right">
            <div className={`text-3xl font-orbitron font-black ${color}`}>
                {score?.toFixed(1)}<span className="text-slate-600 text-lg">/10</span>
            </div>
        </div>
    );
}

function FindingCard({ finding }) {
    const [open, setOpen] = useState(false);
    const sev  = finding.severity?.toLowerCase() || 'info';
    const st   = SEV_STYLES[sev] || SEV_STYLES.info;
    const Icon = SEV_ICON[sev] || Info;

    return (
        <div className={`rounded-xl border ${st.border} bg-slate-900/60 overflow-hidden`}>
            <button
                onClick={() => setOpen(o => !o)}
                className="w-full flex items-center gap-3 p-4 text-left hover:bg-slate-800/30 transition-colors"
            >
                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${st.dot}`} />
                <div className="flex-1 min-w-0">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wider ${st.badge}`}>{sev}</span>
                    <div className="text-sm font-semibold text-slate-200 mt-1">{finding.title}</div>
                </div>
                <Icon className="w-4 h-4 flex-shrink-0 text-slate-500" />
                {open ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
            </button>
            <AnimatePresence>
                {open && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        className="overflow-hidden"
                    >
                        <div className="px-4 pb-4 space-y-3 border-t border-slate-800">
                            <p className="text-sm text-slate-400 mt-3 leading-relaxed">{finding.description}</p>
                            <div className="bg-slate-800/60 rounded-lg p-3">
                                <div className="text-[10px] text-emerald-400 uppercase tracking-widest font-semibold mb-1">Fix / Recommendation</div>
                                <pre className="text-xs text-slate-300 whitespace-pre-wrap font-mono leading-relaxed">
                                    {finding.recommendation}
                                </pre>
                            </div>
                            {finding.detail && (
                                <div className="bg-slate-800/40 rounded-lg p-3">
                                    <div className="text-[10px] text-slate-500 uppercase tracking-widest mb-1">Detail</div>
                                    <code className="text-xs text-slate-400 font-mono break-all">{finding.detail}</code>
                                </div>
                            )}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}

function CountChip({ label, value, color }) {
    return (
        <div className={`flex flex-col items-center px-4 py-2 rounded-xl border ${color} bg-slate-900/60`}>
            <span className="text-lg font-orbitron font-bold">{value}</span>
            <span className="text-[10px] text-slate-500 uppercase tracking-wider">{label}</span>
        </div>
    );
}

const WordPressScanPage = () => {
    const [target, setTarget]       = useState('');
    const [loading, setLoading]     = useState(false);
    const [results, setResults]     = useState(null);
    const [error, setError]         = useState(null);
    const [permitted, setPermitted] = useState(false);

    const handleScan = async () => {
        const t = target.trim();
        if (!t || !permitted) return;
        setLoading(true);
        setResults(null);
        setError(null);
        try {
            const { data } = await axios.post(
                '/scan_wordpress',
                { target: t },
                { withCredentials: true, timeout: 90000 },
            );
            setResults(data);
        } catch (e) {
            setError(e.response?.data?.error || e.message || 'Scan failed.');
        } finally {
            setLoading(false);
        }
    };

    const meta    = results?.meta    || {};
    const findings= results?.findings || [];
    const counts  = results?.counts  || {};

    return (
        <div className="min-h-screen bg-slate-950 text-slate-100 p-6">
            <div className="max-w-4xl mx-auto space-y-8">

                {/* Header */}
                <div className="flex items-center gap-4">
                    <Link to="/dashboard" className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 transition-colors">
                        <ArrowLeft className="w-4 h-4 text-slate-400" />
                    </Link>
                    <div className="flex items-center gap-3">
                        <div className="p-2.5 rounded-xl bg-emerald-500/10 border border-emerald-500/20">
                            <WpIcon className="w-5 h-5 text-emerald-400" />
                        </div>
                        <div>
                            <h1 className="font-orbitron font-bold text-lg text-white tracking-wider">WordPress Security Scanner</h1>
                            <p className="text-xs text-slate-500">Version · xmlrpc · user enum · debug log · security headers</p>
                        </div>
                    </div>
                </div>

                {/* Input Card */}
                <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-5">
                    <div className="space-y-2">
                        <label className="text-xs font-orbitron text-slate-400 uppercase tracking-widest">WordPress Site URL</label>
                        <div className="relative">
                            <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                            <input
                                value={target}
                                onChange={e => setTarget(e.target.value)}
                                onKeyDown={e => e.key === 'Enter' && handleScan()}
                                placeholder="https://example.com"
                                className="w-full pl-10 pr-4 py-3 bg-slate-800/60 text-slate-200 text-sm rounded-xl border border-slate-700 outline-none focus:border-emerald-500/50 placeholder-slate-600"
                            />
                        </div>
                        <p className="text-[11px] text-slate-600">
                            Only scan WordPress sites you own or have explicit written permission to test.
                        </p>
                    </div>

                    {/* Info boxes */}
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                        {[
                            { icon: CheckCircle, color: 'text-green-400', label: 'Non-destructive', desc: 'Read-only HTTP probing' },
                            { icon: AlertTriangle, color: 'text-yellow-400', label: 'Authorization required', desc: 'Only scan your own sites' },
                            { icon: Info, color: 'text-blue-400', label: 'No login needed', desc: 'Black-box scan only' },
                        ].map(item => {
                            const Icon = item.icon;
                            return (
                                <div key={item.label} className="flex items-start gap-2 p-3 rounded-xl bg-slate-800/40 border border-slate-700/50">
                                    <Icon className={`w-4 h-4 flex-shrink-0 mt-0.5 ${item.color}`} />
                                    <div>
                                        <div className="text-xs font-semibold text-slate-300">{item.label}</div>
                                        <div className="text-[10px] text-slate-500">{item.desc}</div>
                                    </div>
                                </div>
                            );
                        })}
                    </div>

                    <label className="flex items-start gap-3 cursor-pointer group">
                        <input type="checkbox" checked={permitted} onChange={e => setPermitted(e.target.checked)} className="mt-0.5 accent-emerald-500" />
                        <span className="text-xs text-slate-400 leading-relaxed group-hover:text-slate-300 transition-colors">
                            I own this WordPress site or have written authorisation to perform a security audit.
                        </span>
                    </label>

                    <button
                        onClick={handleScan}
                        disabled={loading || !permitted || !target.trim()}
                        className="w-full py-3 rounded-xl font-orbitron text-sm font-bold uppercase tracking-widest transition-all
                            bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500
                            text-white shadow-lg shadow-emerald-500/10
                            disabled:opacity-40 disabled:cursor-not-allowed disabled:shadow-none"
                    >
                        {loading ? 'Scanning WordPress…' : 'Scan WordPress Site'}
                    </button>
                </div>

                {error && (
                    <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400">{error}</div>
                )}

                <AnimatePresence>
                    {results && (
                        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">

                            {!meta.wordpress_detected ? (
                                <div className="rounded-xl border border-yellow-500/20 bg-yellow-500/5 p-6 text-center">
                                    <AlertTriangle className="w-8 h-8 text-yellow-400 mx-auto mb-2" />
                                    <div className="text-sm text-yellow-300 font-semibold">WordPress not detected</div>
                                    <div className="text-xs text-slate-500 mt-1">
                                        This URL does not appear to be a WordPress installation.
                                    </div>
                                </div>
                            ) : (
                                <>
                                    {/* Summary */}
                                    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-5">
                                        <div className="flex items-center justify-between flex-wrap gap-4">
                                            <div>
                                                <div className="text-xs text-slate-500 font-orbitron uppercase tracking-widest mb-1">WordPress Detected</div>
                                                <div className="flex items-center gap-2">
                                                    <WpIcon className="w-4 h-4 text-emerald-400" />
                                                    {meta.wordpress_version ? (
                                                        <span className="text-sm font-mono text-slate-300">
                                                            Version <span className="text-emerald-400">{meta.wordpress_version}</span>
                                                        </span>
                                                    ) : (
                                                        <span className="text-sm text-slate-500">Version hidden (good)</span>
                                                    )}
                                                </div>
                                                {meta.users_found?.length > 0 && (
                                                    <div className="text-xs text-red-400 mt-1">
                                                        Users exposed: {meta.users_found.join(', ')}
                                                    </div>
                                                )}
                                            </div>
                                            <RiskBadge score={results.risk_score} />
                                        </div>

                                        {/* Count breakdown */}
                                        <div className="flex flex-wrap gap-3">
                                            <CountChip label="Critical" value={counts.critical || 0} color="border-red-500/20 text-red-400" />
                                            <CountChip label="High"     value={counts.high     || 0} color="border-orange-500/20 text-orange-400" />
                                            <CountChip label="Medium"   value={counts.medium   || 0} color="border-yellow-500/20 text-yellow-400" />
                                            <CountChip label="Low"      value={counts.low      || 0} color="border-green-500/20 text-green-400" />
                                            <CountChip label="Info"     value={counts.info     || 0} color="border-blue-500/20 text-blue-400" />
                                        </div>

                                        {meta.scan_duration_s && (
                                            <div className="text-[10px] text-slate-600 text-right">
                                                Scan completed in {meta.scan_duration_s}s
                                            </div>
                                        )}
                                    </div>

                                    {results.report_token && (
                                        <Link to={`/reports/${results.report_token}`} className="flex items-center gap-2 text-xs text-emerald-400 hover:text-emerald-300 transition-colors">
                                            <ExternalLink className="w-3.5 h-3.5" /> View full report
                                        </Link>
                                    )}

                                    <div className="space-y-3">
                                        <div className="text-xs font-orbitron text-slate-500 uppercase tracking-widest">
                                            Findings ({findings.length})
                                        </div>
                                        {findings.length === 0 ? (
                                            <div className="rounded-xl border border-green-500/20 bg-green-500/5 p-6 text-center">
                                                <CheckCircle className="w-8 h-8 text-green-400 mx-auto mb-2" />
                                                <div className="text-sm text-green-400 font-semibold">No WordPress security issues found!</div>
                                            </div>
                                        ) : (
                                            findings.map((f, i) => <FindingCard key={i} finding={f} />)
                                        )}
                                    </div>
                                </>
                            )}
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </div>
    );
};

export default WordPressScanPage;
