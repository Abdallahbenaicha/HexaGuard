import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link } from 'react-router-dom';
import axios from 'axios';
import {
    Globe, ArrowLeft, Mail, Shield, CheckCircle,
    AlertTriangle, Info, ShieldAlert, ExternalLink,
    ChevronDown, ChevronUp, Search,
} from 'lucide-react';

const SEV_STYLES = {
    critical: { badge: 'bg-red-500/10 text-red-400 border-red-500/30',    dot: 'bg-red-500',    bar: 'bg-red-500'    },
    high:     { badge: 'bg-orange-500/10 text-orange-400 border-orange-500/30', dot: 'bg-orange-400', bar: 'bg-orange-500' },
    medium:   { badge: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30', dot: 'bg-yellow-400', bar: 'bg-yellow-500' },
    low:      { badge: 'bg-green-500/10 text-green-400 border-green-500/30',  dot: 'bg-green-400',  bar: 'bg-green-500'  },
    info:     { badge: 'bg-blue-500/10 text-blue-400 border-blue-500/30',    dot: 'bg-blue-400',   bar: 'bg-blue-400'   },
};

const SEV_ICON = { critical: ShieldAlert, high: AlertTriangle, medium: AlertTriangle, low: CheckCircle, info: Info };

const META_CHECKS = [
    { key: 'spf',    label: 'SPF',    icon: Mail,   goodTest: m => m?.record != null },
    { key: 'dmarc',  label: 'DMARC',  icon: Shield, goodTest: m => m?.record != null },
    { key: 'dkim',   label: 'DKIM',   icon: Mail,   goodTest: m => m?.selectors_found?.length > 0 },
    { key: 'dnssec', label: 'DNSSEC', icon: Shield, goodTest: m => m?.dnssec_enabled === true },
    { key: 'caa',    label: 'CAA',    icon: Shield, goodTest: m => m?.caa_records?.length > 0 },
    { key: 'zone_transfer', label: 'Zone Transfer', icon: Globe,
      goodTest: m => m?.zone_transfer_attempted && !m?.zone_transfer_possible },
];

function StatusPill({ ok, label }) {
    return (
        <div className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${
            ok  ? 'bg-green-500/10 border-green-500/20 text-green-400'
                : 'bg-red-500/10 border-red-500/20 text-red-400'
        }`}>
            {ok
                ? <CheckCircle className="w-3.5 h-3.5" />
                : <AlertTriangle className="w-3.5 h-3.5" />
            }
            <span className="text-xs font-bold">{label}</span>
        </div>
    );
}

function FindingCard({ finding }) {
    const [open, setOpen] = useState(false);
    const sev  = finding.severity?.toLowerCase() || 'info';
    const st   = SEV_STYLES[sev] || SEV_STYLES.info;
    const Icon = SEV_ICON[sev] || Info;

    return (
        <div className={`rounded-xl border ${st.badge.includes('red') ? 'border-red-500/20' :
            st.badge.includes('orange') ? 'border-orange-500/20' :
            st.badge.includes('yellow') ? 'border-yellow-500/20' :
            st.badge.includes('green') ? 'border-green-500/20' : 'border-blue-500/20'}
            bg-slate-900/60 overflow-hidden`}>
            <button
                onClick={() => setOpen(o => !o)}
                className="w-full flex items-center gap-3 p-4 text-left hover:bg-slate-800/30 transition-colors"
            >
                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${st.dot}`} />
                <div className="flex-1 min-w-0">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wider ${st.badge}`}>
                        {sev}
                    </span>
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
                                <div className="text-[10px] text-cyan-400 uppercase tracking-widest font-semibold mb-1">Recommendation</div>
                                <pre className="text-xs text-slate-300 whitespace-pre-wrap font-mono leading-relaxed">
                                    {finding.recommendation}
                                </pre>
                            </div>
                            {finding.detail && (
                                <div className="bg-slate-800/40 rounded-lg p-3">
                                    <div className="text-[10px] text-slate-500 uppercase tracking-widest mb-1">Record / Detail</div>
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

const DnsScanPage = () => {
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
                '/scan_dns',
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
    const total   = Object.values(counts).reduce((a, b) => a + b, 0);

    return (
        <div className="min-h-screen bg-slate-950 text-slate-100 p-6">
            <div className="max-w-4xl mx-auto space-y-8">

                {/* Header */}
                <div className="flex items-center gap-4">
                    <Link to="/dashboard" className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 transition-colors">
                        <ArrowLeft className="w-4 h-4 text-slate-400" />
                    </Link>
                    <div className="flex items-center gap-3">
                        <div className="p-2.5 rounded-xl bg-purple-500/10 border border-purple-500/20">
                            <Globe className="w-5 h-5 text-purple-400" />
                        </div>
                        <div>
                            <h1 className="font-orbitron font-bold text-lg text-white tracking-wider">DNS & Email Security Scanner</h1>
                            <p className="text-xs text-slate-500">SPF · DMARC · DKIM · DNSSEC · Zone Transfer · CAA</p>
                        </div>
                    </div>
                </div>

                {/* Input Card */}
                <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-5">
                    <div className="space-y-2">
                        <label className="text-xs font-orbitron text-slate-400 uppercase tracking-widest">Domain Name</label>
                        <div className="flex gap-3">
                            <div className="relative flex-1">
                                <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
                                <input
                                    value={target}
                                    onChange={e => setTarget(e.target.value)}
                                    onKeyDown={e => e.key === 'Enter' && handleScan()}
                                    placeholder="example.com"
                                    className="w-full pl-10 pr-4 py-3 bg-slate-800/60 text-slate-200 text-sm rounded-xl border border-slate-700 outline-none focus:border-purple-500/50 placeholder-slate-600"
                                />
                            </div>
                        </div>
                        <p className="text-[11px] text-slate-600">Enter domain only — no https:// prefix needed.</p>
                    </div>

                    <label className="flex items-start gap-3 cursor-pointer group">
                        <input type="checkbox" checked={permitted} onChange={e => setPermitted(e.target.checked)} className="mt-0.5 accent-purple-500" />
                        <span className="text-xs text-slate-400 leading-relaxed group-hover:text-slate-300 transition-colors">
                            I confirm I own this domain or have authorisation to perform a DNS security audit.
                        </span>
                    </label>

                    <button
                        onClick={handleScan}
                        disabled={loading || !permitted || !target.trim()}
                        className="w-full py-3 rounded-xl font-orbitron text-sm font-bold uppercase tracking-widest transition-all
                            bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500
                            text-white shadow-lg shadow-purple-500/10
                            disabled:opacity-40 disabled:cursor-not-allowed disabled:shadow-none"
                    >
                        {loading ? 'Scanning DNS…' : 'Run DNS Audit'}
                    </button>
                </div>

                {error && (
                    <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400">{error}</div>
                )}

                <AnimatePresence>
                    {results && (
                        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">

                            {/* Status grid */}
                            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-5">
                                <div className="flex items-center justify-between flex-wrap gap-4">
                                    <div>
                                        <div className="text-xs text-slate-500 uppercase tracking-widest font-orbitron">Domain</div>
                                        <div className="text-lg font-orbitron font-bold text-white mt-1">{meta.domain}</div>
                                    </div>
                                    <div className="text-right">
                                        <div className={`text-3xl font-orbitron font-black ${
                                            results.risk_score >= 7 ? 'text-red-400' :
                                            results.risk_score >= 4 ? 'text-orange-400' :
                                            results.risk_score >= 2 ? 'text-yellow-400' : 'text-green-400'
                                        }`}>
                                            {results.risk_score?.toFixed(1)}
                                            <span className="text-slate-600 text-lg">/10</span>
                                        </div>
                                        <div className="text-xs text-slate-500 uppercase">{results.risk}</div>
                                    </div>
                                </div>

                                {/* Email security status pills */}
                                <div>
                                    <div className="text-xs text-slate-600 uppercase tracking-widest mb-3">Email Security Status</div>
                                    <div className="flex flex-wrap gap-2">
                                        {META_CHECKS.map(({ key, label, goodTest }) => {
                                            const ok = goodTest(meta[key]);
                                            return <StatusPill key={key} ok={ok} label={label} />;
                                        })}
                                    </div>
                                </div>

                                {/* SPF / DMARC record preview */}
                                {(meta.spf?.record || meta.dmarc?.record) && (
                                    <div className="space-y-2">
                                        {meta.spf?.record && (
                                            <div className="bg-slate-800/60 rounded-lg p-3">
                                                <div className="text-[10px] text-slate-500 mb-1">SPF Record</div>
                                                <code className="text-xs text-slate-300 font-mono break-all">{meta.spf.record}</code>
                                            </div>
                                        )}
                                        {meta.dmarc?.record && (
                                            <div className="bg-slate-800/60 rounded-lg p-3">
                                                <div className="text-[10px] text-slate-500 mb-1">DMARC Record</div>
                                                <code className="text-xs text-slate-300 font-mono break-all">{meta.dmarc.record}</code>
                                            </div>
                                        )}
                                    </div>
                                )}

                                {meta.dkim?.selectors_found?.length > 0 && (
                                    <div className="text-xs text-slate-500">
                                        DKIM selectors found:{' '}
                                        {meta.dkim.selectors_found.map(s => (
                                            <code key={s} className="text-cyan-400 font-mono ml-1">{s}</code>
                                        ))}
                                    </div>
                                )}

                                {meta.scan_duration_s && (
                                    <div className="text-[10px] text-slate-600 text-right">
                                        Scan completed in {meta.scan_duration_s}s
                                    </div>
                                )}
                            </div>

                            {results.report_token && (
                                <Link to={`/reports/${results.report_token}`} className="flex items-center gap-2 text-xs text-purple-400 hover:text-purple-300 transition-colors">
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
                                        <div className="text-sm text-green-400 font-semibold">Excellent DNS configuration!</div>
                                    </div>
                                ) : (
                                    findings.map((f, i) => <FindingCard key={i} finding={f} />)
                                )}
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </div>
    );
};

export default DnsScanPage;
