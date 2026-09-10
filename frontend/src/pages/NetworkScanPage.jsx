import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import axios from 'axios';
import { Link } from 'react-router-dom';
import {
    Activity, ArrowLeft, Server, Shield,
    AlertTriangle, Terminal, ChevronRight, Wifi
} from 'lucide-react';
import ResultsPanel from '../components/ResultsPanel';
import NetworkReconPanel from '../components/NetworkReconPanel';
import ReportExportBar from '../components/ReportExportBar';
import AssessmentMethodologyBanner from '../components/AssessmentMethodologyBanner';

const NetworkScanPage = () => {
    const [target, setTarget] = useState('');
    const [scanMode, setScanMode] = useState('full');
    const [loading, setLoading] = useState(false);
    const [results, setResults] = useState(null);
    const [error, setError] = useState(null);
    const [permissionGranted, setPermissionGranted] = useState(false);
    const [ariaAnalysis, setAriaAnalysis] = useState('');
    const [analyzing, setAnalyzing] = useState(false);
    const abortControllerRef = React.useRef(null);

    const handleStopScan = () => {
        if (abortControllerRef.current) {
            abortControllerRef.current.abort();
            abortControllerRef.current = null;
        }
        setLoading(false);
        setError('Scan cancelled by user.');
    };

    const scanModes = [
        { id: 'full',      label: 'Deep Infiltration',   desc: 'Comprehensive scan (Ports + Services + OS)',  icon: Server },
        { id: 'ports',     label: 'Port Discovery',       desc: 'Identify all active entry points',            icon: Activity },
        { id: 'quick',     label: 'Surveillance Mode',    desc: 'Rapid scan of top 100 ports (fastest)',       icon: Terminal },
        { id: 'discover',  label: 'Discover All Devices', desc: 'Ping-sweep subnet — e.g. 192.168.1.0/24',    icon: Wifi }
    ];

    const isPrivateIP = (t) => /^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)/.test(t);
    const showInternalBadge = isPrivateIP(target.trim());

    const handleExecuteScan = async () => {
        if (!target.trim() || !permissionGranted) return;
        let scanTarget = target.trim().replace(/^https?:\/\//, '').split(':')[0];

        // Discover mode: auto-append /24 if the user entered a plain IP (no CIDR already)
        if (scanMode === 'discover' && !scanTarget.includes('/')) {
            const parts = scanTarget.split('.');
            if (parts.length === 4) {
                scanTarget = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
            }
        } else if (scanMode !== 'discover') {
            scanTarget = scanTarget.split('/')[0]; // strip CIDR for non-discovery modes
        }

        setLoading(true);
        setResults(null);
        setError(null);
        setAriaAnalysis('');

        abortControllerRef.current = new AbortController();

        try {
            const { data } = await axios.post(
                '/scan_network',
                { target: scanTarget, mode: scanMode === 'discover' ? 'quick' : scanMode },
                { withCredentials: true, timeout: 480000, signal: abortControllerRef.current.signal }
            );
            // Show results if we have findings OR if nmap found live hosts/open ports
            const hasFindings = data.findings?.length > 0;
            const hasHosts    = data.recon?.hosts_up > 0 || data.recon?.open_port_list?.length > 0;
            if (hasFindings || hasHosts) setResults(data);
            else setError('No services or vulnerabilities discovered on target. Try: scanme.nmap.org or your router IP (192.168.1.1)');
        } catch (e) {
            if (axios.isCancel(e) || e.name === 'CanceledError') { /* user cancelled */ }
            else if (e.response?.status === 502) setError('Backend is offline or crashing. Check Flask logs.');
            else if (e.code === 'ECONNABORTED') setError('Scan Timeout — try "Surveillance Mode" for faster results.');
            else setError(`Error: ${e.response?.data?.error || e.message}`);
        } finally {
            abortControllerRef.current = null;
            setLoading(false);
        }
    };

    const analyzeWithAria = async () => {
        if (!results?.findings?.length) return;
        setAnalyzing(true);
        setAriaAnalysis('');
        try {
            const payload = results.report_token
                ? { token: results.report_token, scan_type: 'network', target: target.trim() }
                : { findings: results.findings, scan_type: 'network', target: target.trim() };
            const { data } = await axios.post('/api/ai/analyze', payload, { withCredentials: true });
            const a = data.analysis || {};
            const text = typeof a === 'string'
                ? a
                : [a.attack_chain, a.remediation_md].filter(Boolean).join('\n\n---\n\n');
            setAriaAnalysis(text || data.response || 'No analysis returned.');
        } catch (e) {
            setAriaAnalysis('ARIA analysis unavailable: ' + (e.response?.data?.error || e.message));
        } finally {
            setAnalyzing(false);
        }
    };

    const getSeverityCount = (sev) => results?.findings?.filter(f => f.severity === sev).length || 0;

    return (
        <div className="animate-in fade-in duration-500">
            <div className="mb-8 flex items-center gap-3">
                <Link to="/dashboard" className="inline-flex items-center gap-2 px-3 py-1.5 text-sm font-medium text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 rounded-lg transition-all hover:scale-[1.02] active:scale-[0.98]">
                    <ArrowLeft className="w-4 h-4" /> Back
                </Link>
                <h1 className="text-2xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
                    <Server className="w-6 h-6 text-primary-500" />
                    Scan Network
                </h1>
            </div>

            <div className="mb-6">
                <AssessmentMethodologyBanner compact />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                <div className="lg:col-span-4 space-y-6">
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 shadow-sm">

                        <div className="space-y-1.5 mb-6">
                            <div className="flex items-center justify-between">
                                <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Target Hostname / IP</label>
                                {showInternalBadge && (
                                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-blue-100 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400 border border-blue-200 dark:border-blue-500/30">
                                        🔒 Internal Network
                                    </span>
                                )}
                            </div>
                            <input
                                value={target}
                                onChange={e => setTarget(e.target.value)}
                                onKeyDown={e => e.key === 'Enter' && handleExecuteScan()}
                                placeholder="e.g. 192.168.1.1 or scanme.nmap.org"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-lg px-4 py-3 text-slate-900 dark:text-white placeholder-slate-400 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 transition-shadow"
                            />
                            {showInternalBadge && (
                                <p className="text-[11px] text-blue-500 dark:text-blue-400 mt-1">
                                    💡 IP داخلي — سيُفحص كشبكة LAN تلقائياً
                                </p>
                            )}
                        </div>

                        <div className="space-y-3 mb-6">
                            <label className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Operational Mode</label>
                            {scanModes.map(mode => {
                                const Icon = mode.icon;
                                return (
                                    <button
                                        key={mode.id}
                                        onClick={() => setScanMode(mode.id)}
                                        className={`w-full p-4 rounded-xl border text-left transition-all duration-200 flex items-start gap-4 ${
                                            scanMode === mode.id
                                                ? 'border-primary-500 bg-primary-50 dark:bg-primary-500/10 ring-1 ring-primary-500'
                                                : 'border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                                        }`}
                                    >
                                        <Icon className={`w-5 h-5 mt-0.5 ${scanMode === mode.id ? 'text-primary-600 dark:text-primary-400' : 'text-slate-400'}`} />
                                        <div>
                                            <div className={`text-sm font-semibold mb-0.5 ${scanMode === mode.id ? 'text-primary-700 dark:text-primary-300' : 'text-slate-700 dark:text-slate-300'}`}>
                                                {mode.label}
                                            </div>
                                            <div className="text-xs text-slate-500 dark:text-slate-400">{mode.desc}</div>
                                        </div>
                                    </button>
                                );
                            })}
                        </div>

                        <div className={`mb-6 p-4 rounded-xl border transition-colors ${
                            permissionGranted
                                ? 'bg-green-50 dark:bg-green-500/10 border-green-300 dark:border-green-500/30'
                                : 'bg-amber-50 dark:bg-amber-500/10 border-amber-200 dark:border-amber-500/30'
                        }`}>
                            <label className="flex items-start gap-3 cursor-pointer select-none" dir="rtl">
                                <input
                                    type="checkbox"
                                    checked={permissionGranted}
                                    onChange={e => setPermissionGranted(e.target.checked)}
                                    className="mt-1 w-4 h-4 text-primary-600 rounded border-slate-300 focus:ring-primary-500 dark:border-slate-600 dark:bg-slate-900 flex-shrink-0"
                                />
                                <span className={`text-sm font-semibold leading-relaxed ${
                                    permissionGranted
                                        ? 'text-green-700 dark:text-green-400'
                                        : 'text-amber-700 dark:text-amber-400'
                                }`}>
                                    أتعهد بشرفي أنني مُخوَّل بإجراء هذا الفحص الأمني على الهدف المحدد لغرض أخلاقي على موقعي
                                </span>
                            </label>
                            {!permissionGranted && (
                                <p className="text-[10px] text-amber-600 dark:text-amber-400 mt-2 text-right">
                                    يجب الموافقة على التعهد قبل بدء الفحص
                                </p>
                            )}
                        </div>

                        <div className="flex gap-2">
                            <button
                                onClick={handleExecuteScan}
                                disabled={loading || !target.trim() || !permissionGranted}
                                className={`flex-1 py-3.5 px-4 rounded-xl text-sm font-bold uppercase tracking-wider transition-all flex items-center justify-center gap-2 ${
                                    loading || !target.trim() || !permissionGranted
                                        ? 'bg-slate-100 dark:bg-slate-800 text-slate-400 cursor-not-allowed'
                                        : 'bg-primary-600 hover:bg-primary-700 text-white shadow-md shadow-primary-500/20'
                                }`}
                            >
                                {loading ? (
                                    <>
                                        <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                                        Scanning...
                                    </>
                                ) : (
                                    <>Start Reconnaissance <ChevronRight className="w-4 h-4" /></>
                                )}
                            </button>
                            {loading && (
                                <button
                                    onClick={handleStopScan}
                                    className="px-4 py-3.5 rounded-xl text-sm font-bold bg-red-500 hover:bg-red-600 text-white transition-all shadow-md shadow-red-500/20 flex items-center gap-1"
                                    title="Cancel scan"
                                >
                                    ✕ Stop
                                </button>
                            )}
                        </div>
                    </div>
                </div>

                <div className="lg:col-span-8">
                    {error && (
                        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 text-red-600 dark:text-red-400 p-4 rounded-xl text-sm font-medium flex items-center gap-3 mb-6">
                            <AlertTriangle className="w-5 h-5 flex-shrink-0" />
                            <span>{error}</span>
                        </div>
                    )}

                    <AnimatePresence mode="wait">
                        {results ? (
                            <motion.div initial={{ opacity:0, y:10 }} animate={{ opacity:1, y:0 }} className="space-y-6">
                                {/* Risk banner */}
                                <div className="bg-gradient-to-r from-slate-900 to-slate-800 dark:from-slate-950 dark:to-slate-900 border border-slate-700 rounded-2xl p-6 text-white">
                                    <div className="flex flex-wrap items-center justify-between gap-4">
                                        <div>
                                            <p className="text-xs uppercase tracking-widest text-slate-400 mb-1">Risk Assessment</p>
                                            <p className="text-2xl font-bold font-mono">
                                                {results.risk_score?.toFixed?.(1) ?? results.risk_score ?? '—'}
                                                <span className="text-sm text-slate-400 font-normal"> / 10</span>
                                            </p>
                                            <p className="text-sm text-primary-400 mt-1 uppercase tracking-wider">
                                                {results.risk || '—'}
                                            </p>
                                        </div>
                                        {results.executive_summary && (
                                            <p className="text-sm text-slate-300 max-w-xl leading-relaxed">
                                                {results.executive_summary.replace(/\*\*/g, '')}
                                            </p>
                                        )}
                                    </div>
                                </div>

                                <NetworkReconPanel recon={results.recon} history={results.history} />

                                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                                    {[
                                        { l: 'CRITICAL', c: 'red',    v: getSeverityCount('CRITICAL') },
                                        { l: 'HIGH',     c: 'orange', v: getSeverityCount('HIGH') },
                                        { l: 'MEDIUM',   c: 'yellow', v: getSeverityCount('MEDIUM') },
                                        { l: 'LOW',      c: 'green',  v: getSeverityCount('LOW') },
                                        { l: 'INFO',     c: 'blue',   v: getSeverityCount('INFO') },
                                    ].map(s => (
                                        <div key={s.l} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 text-center shadow-sm">
                                            <div className={`text-2xl font-bold font-mono text-${s.c}-600 dark:text-${s.c}-400 mb-1`}>{s.v}</div>
                                            <div className="text-[10px] font-semibold text-slate-500 tracking-wider uppercase">{s.l}</div>
                                        </div>
                                    ))}
                                </div>

                                {/* ARIA Analysis Card */}
                                <div className="bg-purple-50 dark:bg-purple-500/5 border border-purple-200 dark:border-purple-500/20 rounded-xl p-6 shadow-sm">
                                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
                                        <div>
                                            <h3 className="text-sm font-bold text-purple-700 dark:text-purple-400 flex items-center gap-2">
                                                <Terminal className="w-4 h-4" /> Analyze with ARIA
                                            </h3>
                                            <p className="text-xs text-purple-600/80 dark:text-purple-400/80 mt-1">Expert AI interpretation of infrastructure risk.</p>
                                        </div>
                                        <button
                                            onClick={analyzeWithAria}
                                            disabled={analyzing}
                                            className="px-4 py-2 bg-purple-100 dark:bg-purple-500/20 text-purple-700 dark:text-purple-300 rounded-lg text-xs font-semibold hover:bg-purple-200 dark:hover:bg-purple-500/30 transition-colors disabled:opacity-50 whitespace-nowrap"
                                        >
                                            {analyzing ? 'Analyzing...' : 'Analyze with ARIA'}
                                        </button>
                                    </div>
                                    {ariaAnalysis && (
                                        <div className="bg-white dark:bg-slate-950 border border-purple-100 dark:border-purple-500/10 rounded-lg p-4">
                                            <pre className="text-xs text-slate-700 dark:text-slate-300 font-mono leading-relaxed whitespace-pre-wrap max-h-64 overflow-y-auto">
                                                {ariaAnalysis}
                                            </pre>
                                        </div>
                                    )}
                                </div>



                                <ResultsPanel
                                    findings={results.findings}
                                    total={results.findings.length}
                                    attackChains={results.attack_chains || []}
                                    reportToken={results.report_token}
                                />

                                <div className="pt-6 border-t border-slate-200 dark:border-slate-800">
                                    <ReportExportBar reportToken={results.report_token} />
                                </div>
                            </motion.div>
                        ) : loading ? (
                            <motion.div initial={{ opacity:0 }} animate={{ opacity:1 }} className="h-96 flex flex-col items-center justify-center border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-2xl bg-white/50 dark:bg-slate-900/50">
                                <Activity className="w-12 h-12 text-primary-500 animate-pulse mb-6" />
                                <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">Synchronizing Recon Data</h3>
                                <p className="text-sm text-slate-500 text-center max-w-sm px-4">Intercepting network packets and mapping target surface.</p>
                            </motion.div>
                        ) : (
                            <div className="h-96 flex flex-col items-center justify-center border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-2xl bg-white dark:bg-slate-900">
                                <Server className="w-16 h-16 text-slate-200 dark:text-slate-700 mb-6" />
                                <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">Awaiting Target</h3>
                                <p className="text-sm text-slate-500 text-center max-w-xs">Input a target hostname or IP to begin automated reconnaissance.</p>
                            </div>
                        )}
                    </AnimatePresence>
                </div>
            </div>
        </div>
    );
};

export default NetworkScanPage;
