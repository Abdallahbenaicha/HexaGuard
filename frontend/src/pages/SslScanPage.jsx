import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import { Link } from 'react-router-dom';
import {
    Lock, ShieldCheck, ShieldAlert, ArrowLeft,
    Clock, Server, Key, Globe, AlertTriangle, CheckCircle, Info,
} from 'lucide-react';
import ResultsPanel from '../components/ResultsPanel';

const SEVERITY_COLORS = {
    critical: 'bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400 border-red-200 dark:border-red-500/20',
    high:     'bg-orange-100 text-orange-700 dark:bg-orange-500/10 dark:text-orange-400 border-orange-200 dark:border-orange-500/20',
    medium:   'bg-yellow-100 text-yellow-700 dark:bg-yellow-500/10 dark:text-yellow-400 border-yellow-200 dark:border-yellow-500/20',
    low:      'bg-green-100 text-green-700 dark:bg-green-500/10 dark:text-green-400 border-green-200 dark:border-green-500/20',
    info:     'bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400 border-blue-200 dark:border-blue-500/20',
};

const MetaCard = ({ icon: Icon, label, value, ok }) => (
    <div className="flex items-center gap-3 p-3 rounded-xl bg-slate-800/60 border border-slate-700/50">
        <div className={`p-2 rounded-lg ${ok === true ? 'bg-green-500/10' : ok === false ? 'bg-red-500/10' : 'bg-slate-700/60'}`}>
            <Icon className={`w-4 h-4 ${ok === true ? 'text-green-400' : ok === false ? 'text-red-400' : 'text-slate-400'}`} />
        </div>
        <div className="min-w-0">
            <div className="text-[10px] text-slate-500 uppercase tracking-widest font-orbitron">{label}</div>
            <div className="text-sm text-slate-200 font-mono truncate">{value ?? '—'}</div>
        </div>
        {ok !== undefined && (
            <div className="ml-auto">
                {ok ? <CheckCircle className="w-4 h-4 text-green-400" /> : <AlertTriangle className="w-4 h-4 text-red-400" />}
            </div>
        )}
    </div>
);

const SslScanPage = () => {
    const [target, setTarget]     = useState('');
    const [loading, setLoading]   = useState(false);
    const [results, setResults]   = useState(null);
    const [error, setError]       = useState(null);
    const [permitted, setPermitted] = useState(false);

    const handleScan = async () => {
        if (!target.trim() || !permitted) return;
        setLoading(true);
        setResults(null);
        setError(null);
        try {
            const { data } = await axios.post(
                '/scan_ssl',
                { target: target.trim() },
                { withCredentials: true, timeout: 60000 },
            );
            setResults(data);
        } catch (e) {
            setError(e.response?.data?.error || e.message || 'Scan failed.');
        } finally {
            setLoading(false);
        }
    };

    const meta = results?.meta || {};
    const findings = results?.findings || [];

    const daysLeft = meta.cert_days_remaining;
    const daysColor = daysLeft == null ? 'text-slate-400'
        : daysLeft < 0  ? 'text-red-400'
        : daysLeft < 30 ? 'text-orange-400'
        : daysLeft < 90 ? 'text-yellow-400'
        : 'text-green-400';

    return (
        <div className="min-h-screen bg-slate-950 text-slate-100 p-6">
            <div className="max-w-4xl mx-auto space-y-8">

                {/* Header */}
                <div className="flex items-center gap-4">
                    <Link to="/dashboard" className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 transition-colors">
                        <ArrowLeft className="w-4 h-4 text-slate-400" />
                    </Link>
                    <div className="flex items-center gap-3">
                        <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20">
                            <Lock className="w-5 h-5 text-cyan-400" />
                        </div>
                        <div>
                            <h1 className="font-orbitron font-bold text-lg text-white tracking-wider">SSL/TLS Scanner</h1>
                            <p className="text-xs text-slate-500">Certificate, protocol & cipher analysis</p>
                        </div>
                    </div>
                </div>

                {/* Input card */}
                <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-5">
                    <div className="space-y-2">
                        <label className="text-xs font-orbitron text-slate-400 uppercase tracking-widest">Target Host / URL</label>
                        <div className="flex gap-3">
                            <input
                                value={target}
                                onChange={e => setTarget(e.target.value)}
                                onKeyDown={e => e.key === 'Enter' && handleScan()}
                                placeholder="example.com  or  https://example.com"
                                className="flex-1 bg-slate-800 border border-slate-700 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-cyan-500/60 font-mono"
                            />
                            <motion.button
                                whileTap={{ scale: 0.97 }}
                                onClick={handleScan}
                                disabled={loading || !target.trim() || !permitted}
                                className={`px-6 py-3 rounded-xl font-orbitron text-xs tracking-widest uppercase font-bold transition-all
                                    ${loading || !target.trim() || !permitted
                                        ? 'bg-slate-800 text-slate-600 cursor-not-allowed'
                                        : 'bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-500/20'}`}
                            >
                                {loading ? 'Scanning…' : 'Scan'}
                            </motion.button>
                        </div>
                    </div>

                    {/* Legal consent */}
                    <label className="flex items-start gap-3 cursor-pointer group">
                        <div
                            onClick={() => setPermitted(p => !p)}
                            className={`mt-0.5 w-4 h-4 rounded flex-shrink-0 border-2 transition-all flex items-center justify-center
                                ${permitted ? 'bg-cyan-500 border-cyan-500' : 'border-slate-600 hover:border-cyan-500/60'}`}
                        >
                            {permitted && <CheckCircle className="w-3 h-3 text-white" />}
                        </div>
                        <span className="text-xs text-slate-500 leading-relaxed">
                            I confirm I have authorization to scan this target. SSL scanning sends TLS handshake probes to the target.
                        </span>
                    </label>

                    {/* What we check */}
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 pt-2">
                        {[
                            'Certificate Expiry', 'TLS Version', 'Cipher Suites',
                            'HSTS Header', 'HTTP→HTTPS Redirect', 'Key Strength',
                            'Self-Signed Detection', 'SAN Validation', 'Trust Chain',
                        ].map(c => (
                            <div key={c} className="flex items-center gap-2 text-[11px] text-slate-500">
                                <div className="w-1.5 h-1.5 rounded-full bg-cyan-500/60 flex-shrink-0" />
                                {c}
                            </div>
                        ))}
                    </div>
                </div>

                {/* Loading */}
                <AnimatePresence>
                    {loading && (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="flex flex-col items-center justify-center py-20 gap-4"
                        >
                            <div className="relative">
                                <div className="w-16 h-16 rounded-full border-2 border-cyan-500/20 animate-ping absolute inset-0" />
                                <div className="w-16 h-16 rounded-full border-2 border-cyan-500 animate-spin" style={{ borderTopColor: 'transparent' }} />
                                <Lock className="absolute inset-0 m-auto w-6 h-6 text-cyan-400" />
                            </div>
                            <div className="font-orbitron text-xs text-cyan-400 tracking-widest animate-pulse uppercase">
                                Probing TLS stack…
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>

                {/* Error */}
                {error && !loading && (
                    <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-4 flex items-start gap-3">
                        <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
                        <span className="text-sm text-red-300">{error}</span>
                    </div>
                )}

                {/* Results */}
                <AnimatePresence>
                    {results && !loading && (
                        <motion.div
                            initial={{ opacity: 0, y: 16 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="space-y-6"
                        >
                            {/* Certificate metadata grid */}
                            {meta.host && (
                                <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 space-y-4">
                                    <h2 className="font-orbitron text-xs text-slate-400 uppercase tracking-widest">
                                        Certificate Details
                                    </h2>
                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                        <MetaCard icon={Globe}       label="Host"          value={`${meta.host}:${meta.port}`} />
                                        <MetaCard icon={Server}      label="TLS Version"   value={meta.tls_version}
                                            ok={meta.tls_version === 'TLSv1.3' || meta.tls_version === 'TLSv1.2'} />
                                        <MetaCard icon={Key}         label="Cipher Suite"  value={meta.cipher_suite} />
                                        <MetaCard icon={ShieldCheck} label="Trust Verified" value={meta.trust_verified ? 'Yes' : 'No'} ok={meta.trust_verified} />
                                        <MetaCard icon={Lock}        label="Issuer"        value={meta.cert_issuer || '—'} />
                                        <MetaCard icon={Info}        label="Subject"       value={meta.cert_subject || '—'} />
                                        <MetaCard icon={ShieldCheck} label="HSTS"
                                            value={meta.hsts_enabled ? `max-age=${meta.hsts_max_age}s` : 'Not set'}
                                            ok={meta.hsts_enabled} />
                                        <MetaCard icon={Clock}       label="Days Until Expiry"
                                            value={
                                                daysLeft == null ? '—'
                                                : daysLeft < 0  ? `EXPIRED ${Math.abs(daysLeft)} days ago`
                                                : `${daysLeft} days`
                                            }
                                            ok={daysLeft != null && daysLeft > 30}
                                        />
                                    </div>

                                    {/* Expiry progress bar */}
                                    {daysLeft != null && daysLeft >= 0 && (
                                        <div className="space-y-1">
                                            <div className="flex justify-between text-[10px] text-slate-500">
                                                <span>Cert validity</span>
                                                <span className={daysColor}>{daysLeft} days left</span>
                                            </div>
                                            <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                                                <div
                                                    className={`h-full rounded-full transition-all ${
                                                        daysLeft < 7  ? 'bg-red-500'
                                                        : daysLeft < 30 ? 'bg-orange-500'
                                                        : daysLeft < 90 ? 'bg-yellow-500'
                                                        : 'bg-green-500'
                                                    }`}
                                                    style={{ width: `${Math.min(100, (daysLeft / 365) * 100)}%` }}
                                                />
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Findings */}
                            <ResultsPanel
                                findings={findings}
                                total={findings.length}
                                reportToken={results.report_token}
                            />
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </div>
    );
};

export default SslScanPage;
