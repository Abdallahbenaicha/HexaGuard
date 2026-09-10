import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import { Link } from 'react-router-dom';
import {
    Server, ArrowLeft, ShieldAlert, ShieldCheck,
    AlertTriangle, CheckCircle, Info, Lock, Globe,
    Cpu, Activity, Zap, Terminal, RefreshCw, FileText
} from 'lucide-react';
import AssessmentMethodologyBanner from '../components/AssessmentMethodologyBanner';

const SEVERITY_BADGES = {
    critical: 'bg-red-500/10 text-red-400 border-red-500/30',
    high:     'bg-orange-500/10 text-orange-400 border-orange-500/30',
    medium:   'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
    low:      'bg-blue-500/10 text-blue-400 border-blue-500/30',
    info:     'bg-slate-500/10 text-slate-400 border-slate-500/30',
};

const ServerExtScanPage = () => {
    const [target, setTarget] = useState('');
    const [deep, setDeep] = useState(false);
    const [permitted, setPermitted] = useState(false);
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState(null);

    const handleScan = async () => {
        if (!target.trim() || !permitted || loading) return;
        setLoading(true);
        setResults(null);
        setError(null);

        try {
            const { data } = await axios.post(
                '/scan_server',
                { target: target.trim(), deep },
                { withCredentials: true, timeout: 90000 }
            );
            setResults(data);
        } catch (err) {
            setError(err.response?.data?.error || err.message || 'External server audit failed.');
        } finally {
            setLoading(false);
        }
    };

    const vulns = results?.vulnerabilities || results?.findings || [];
    const serverBanner = results?.server_banner || results?.server_type || 'Unknown';
    const serverVersion = results?.server_version || '';
    const riskScore = results?.risk_score ?? results?.risk ?? 0;
    const methods = results?.methods_allowed || results?.http_methods || [];

    return (
        <div className="min-h-screen bg-slate-950 text-slate-100 p-6">
            <div className="max-w-5xl mx-auto space-y-8">
                {/* Header */}
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        <Link to="/dashboard" className="p-2 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 transition-colors">
                            <ArrowLeft className="w-5 h-5 text-slate-400" />
                        </Link>
                        <div className="flex items-center gap-3">
                            <div className="p-3 rounded-2xl bg-cyan-500/10 border border-cyan-500/20">
                                <Server className="w-6 h-6 text-cyan-400" />
                            </div>
                            <div>
                                <h1 className="font-orbitron font-bold text-xl text-white tracking-wider flex items-center gap-2">
                                    External Server Audit
                                    <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">Black-box</span>
                                </h1>
                                <p className="text-xs text-slate-400">Probe web server banners, HTTP methods, headers, and known CVEs externally</p>
                            </div>
                        </div>
                    </div>
                </div>

                <AssessmentMethodologyBanner compact />

                {/* Scan Configuration Form */}
                <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-6 shadow-xl backdrop-blur-md">
                    <div className="space-y-2">
                        <label className="text-xs font-orbitron text-slate-400 uppercase tracking-widest flex items-center gap-2">
                            <Globe className="w-3.5 h-3.5 text-cyan-400" />
                            Target Server Host / URL / IP
                        </label>
                        <div className="flex flex-col sm:flex-row gap-3">
                            <input
                                type="text"
                                value={target}
                                onChange={e => setTarget(e.target.value)}
                                onKeyDown={e => e.key === 'Enter' && handleScan()}
                                placeholder="e.g. example.com or https://api.example.com"
                                className="flex-1 px-4 py-3 bg-slate-950 border border-slate-800 rounded-xl text-sm font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-colors"
                            />
                            <button
                                onClick={handleScan}
                                disabled={!target.trim() || !permitted || loading}
                                className="px-6 py-3 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:opacity-40 disabled:cursor-not-allowed text-white font-orbitron font-bold text-xs uppercase tracking-widest rounded-xl transition-all shadow-lg shadow-cyan-900/30 flex items-center justify-center gap-2"
                            >
                                {loading ? (
                                    <>
                                        <RefreshCw className="w-4 h-4 animate-spin" />
                                        Auditing...
                                    </>
                                ) : (
                                    <>
                                        <Zap className="w-4 h-4" />
                                        Audit Server
                                    </>
                                )}
                            </button>
                        </div>
                    </div>

                    {/* Scan Options & Legal Consent */}
                    <div className="flex flex-wrap items-center justify-between gap-4 pt-4 border-t border-slate-800/80 text-xs">
                        <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                            <input
                                type="checkbox"
                                checked={deep}
                                onChange={e => setDeep(e.target.checked)}
                                className="rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-cyan-500"
                            />
                            <span>Deep path discovery (/server-status, exposed .git, .env)</span>
                        </label>

                        <label className="flex items-center gap-2 text-slate-300 cursor-pointer">
                            <input
                                type="checkbox"
                                checked={permitted}
                                onChange={e => setPermitted(e.target.checked)}
                                className="rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-cyan-500"
                            />
                            <span className="text-amber-400/90 font-medium">I am authorized to probe this target server</span>
                        </label>
                    </div>

                    {error && (
                        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-xs flex items-center gap-3">
                            <AlertTriangle className="w-5 h-5 flex-shrink-0" />
                            <span>{error}</span>
                        </div>
                    )}
                </div>

                {/* Scan Results Presentation */}
                <AnimatePresence>
                    {results && (
                        <motion.div
                            initial={{ opacity: 0, y: 15 }}
                            animate={{ opacity: 1, y: 0 }}
                            exit={{ opacity: 0 }}
                            className="space-y-6"
                        >
                            {/* Summary Cards */}
                            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
                                <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-1">
                                    <div className="text-[10px] font-orbitron uppercase text-slate-500 tracking-wider">Detected Banner</div>
                                    <div className="text-sm font-mono text-cyan-400 truncate">{serverBanner}</div>
                                </div>
                                <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-1">
                                    <div className="text-[10px] font-orbitron uppercase text-slate-500 tracking-wider">Server Version</div>
                                    <div className="text-sm font-mono text-slate-200">{serverVersion || 'Hidden / Generic'}</div>
                                </div>
                                <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-1">
                                    <div className="text-[10px] font-orbitron uppercase text-slate-500 tracking-wider">Vulnerabilities Found</div>
                                    <div className="text-sm font-orbitron font-bold text-amber-400">{vulns.length} findings</div>
                                </div>
                                <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-1">
                                    <div className="text-[10px] font-orbitron uppercase text-slate-500 tracking-wider">Risk Score</div>
                                    <div className={`text-sm font-orbitron font-black ${riskScore >= 7 ? 'text-red-400' : riskScore >= 4 ? 'text-yellow-400' : 'text-green-400'}`}>
                                        {riskScore} / 10.0
                                    </div>
                                </div>
                            </div>

                            {/* Allowed Methods Banner if available */}
                            {methods.length > 0 && (
                                <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800 flex items-center justify-between text-xs font-mono">
                                    <span className="text-slate-400">Supported HTTP Methods:</span>
                                    <div className="flex flex-wrap gap-1.5">
                                        {methods.map((m, idx) => (
                                            <span
                                                key={idx}
                                                className={`px-2 py-0.5 rounded text-[11px] ${
                                                    ['TRACE', 'TRACK', 'PUT', 'DELETE'].includes(m.toUpperCase())
                                                        ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                                                        : 'bg-slate-800 text-slate-300'
                                                }`}
                                            >
                                                {m}
                                            </span>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Findings List */}
                            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-4">
                                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                                    <h2 className="font-orbitron font-bold text-sm text-white uppercase tracking-wider flex items-center gap-2">
                                        <Terminal className="w-4 h-4 text-cyan-400" />
                                        Audit Findings ({vulns.length})
                                    </h2>
                                    {results?.report_token && (
                                        <Link
                                            to={`/reports/${results.report_token}`}
                                            className="text-xs font-orbitron text-cyan-400 hover:text-cyan-300 flex items-center gap-1.5 transition-colors"
                                        >
                                            <FileText className="w-3.5 h-3.5" />
                                            Full Report
                                        </Link>
                                    )}
                                </div>

                                {vulns.length === 0 ? (
                                    <div className="py-12 text-center text-slate-500 space-y-2">
                                        <CheckCircle className="w-8 h-8 text-green-500 mx-auto" />
                                        <p className="text-sm font-medium text-slate-300">No external server misconfigurations detected.</p>
                                        <p className="text-xs">Server banners are suppressed and no dangerous HTTP methods were accepted.</p>
                                    </div>
                                ) : (
                                    <div className="space-y-3">
                                        {vulns.map((v, i) => {
                                            const sev = (v.severity || 'low').toLowerCase();
                                            const badgeClass = SEVERITY_BADGES[sev] || SEVERITY_BADGES.low;
                                            return (
                                                <div
                                                    key={i}
                                                    className="p-4 rounded-xl bg-slate-950 border border-slate-800/80 hover:border-slate-700 transition-colors space-y-2"
                                                >
                                                    <div className="flex items-start justify-between gap-3">
                                                        <div className="flex items-center gap-2">
                                                            <span className={`px-2 py-0.5 rounded text-[10px] font-orbitron font-bold uppercase border ${badgeClass}`}>
                                                                {sev}
                                                            </span>
                                                            <h3 className="text-sm font-medium text-slate-200">{v.title || v.name}</h3>
                                                        </div>
                                                        {v.cve_ids && v.cve_ids.length > 0 && (
                                                            <div className="flex gap-1">
                                                                {v.cve_ids.map((cve, cidx) => (
                                                                    <span key={cidx} className="px-1.5 py-0.5 text-[10px] font-mono bg-purple-500/10 text-purple-300 rounded border border-purple-500/20">
                                                                        {cve}
                                                                    </span>
                                                                ))}
                                                            </div>
                                                        )}
                                                    </div>
                                                    <p className="text-xs text-slate-400 font-inter">{v.description}</p>
                                                    {v.remediation && (
                                                        <div className="pt-2 text-xs text-slate-300 bg-slate-900/60 p-2.5 rounded-lg font-mono border border-slate-800/50">
                                                            <span className="text-cyan-400 font-semibold">Remediation: </span>
                                                            {v.remediation}
                                                        </div>
                                                    )}
                                                </div>
                                            );
                                        })}
                                    </div>
                                )}
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </div>
    );
};

export default ServerExtScanPage;
