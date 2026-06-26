import { useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Link } from 'react-router-dom';
import axios from 'axios';
import {
    Container, ArrowLeft, Upload, FileText,
    AlertTriangle, CheckCircle, Info, ShieldAlert,
    ChevronDown, ChevronUp, ExternalLink,
} from 'lucide-react';

const SEV_STYLES = {
    critical: {
        badge: 'bg-red-500/10 text-red-400 border-red-500/30',
        bar:   'bg-red-500',
        dot:   'bg-red-500',
        border: 'border-red-500/30',
    },
    high: {
        badge: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
        bar:   'bg-orange-500',
        dot:   'bg-orange-400',
        border: 'border-orange-500/30',
    },
    medium: {
        badge: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
        bar:   'bg-yellow-500',
        dot:   'bg-yellow-400',
        border: 'border-yellow-500/30',
    },
    low: {
        badge: 'bg-green-500/10 text-green-400 border-green-500/30',
        bar:   'bg-green-500',
        dot:   'bg-green-400',
        border: 'border-green-500/30',
    },
    info: {
        badge: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
        bar:   'bg-blue-400',
        dot:   'bg-blue-400',
        border: 'border-blue-500/30',
    },
};

const SEV_ICON = {
    critical: ShieldAlert,
    high:     AlertTriangle,
    medium:   AlertTriangle,
    low:      CheckCircle,
    info:     Info,
};

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
                    <div className="flex items-center gap-2 flex-wrap">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wider ${st.badge}`}>
                            {sev}
                        </span>
                        {finding.line && (
                            <span className="text-[10px] text-slate-500 font-mono">Line {finding.line}</span>
                        )}
                    </div>
                    <div className="text-sm font-semibold text-slate-200 mt-1">{finding.title}</div>
                </div>
                <Icon className={`w-4 h-4 flex-shrink-0 text-slate-500`} />
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
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}

function SeverityBar({ counts }) {
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    if (total === 0) return null;
    const sevs  = ['critical', 'high', 'medium', 'low', 'info'];
    return (
        <div className="space-y-2">
            {sevs.map(s => {
                const n   = counts[s] || 0;
                const pct = total > 0 ? (n / total) * 100 : 0;
                const st  = SEV_STYLES[s];
                return (
                    <div key={s} className="flex items-center gap-3">
                        <span className="text-[10px] w-14 text-right text-slate-500 uppercase font-semibold">{s}</span>
                        <div className="flex-1 bg-slate-800 rounded-full h-1.5">
                            <div className={`h-1.5 rounded-full ${st.bar}`} style={{ width: `${pct}%` }} />
                        </div>
                        <span className="text-[11px] text-slate-400 w-4 text-right">{n}</span>
                    </div>
                );
            })}
        </div>
    );
}

const DockerScanPage = () => {
    const fileRef              = useRef(null);
    const [file, setFile]      = useState(null);
    const [content, setContent]= useState('');
    const [inputMode, setMode] = useState('upload'); // 'upload' | 'paste'
    const [loading, setLoading]= useState(false);
    const [results, setResults]= useState(null);
    const [error, setError]    = useState(null);
    const [permitted, setPermitted] = useState(false);

    const handleFile = (f) => {
        if (!f) return;
        setFile(f);
        setError(null);
        const reader = new FileReader();
        reader.onload = e => setContent(e.target.result);
        reader.readAsText(f);
    };

    const handleDrop = (e) => {
        e.preventDefault();
        const f = e.dataTransfer.files?.[0];
        if (f) handleFile(f);
    };

    const handleScan = async () => {
        const body = inputMode === 'upload' ? file : content.trim();
        if (!body || !permitted) return;

        setLoading(true);
        setResults(null);
        setError(null);

        try {
            let data;
            if (inputMode === 'upload' && file) {
                const form = new FormData();
                form.append('file', file);
                const res = await axios.post('/scan_docker', form, {
                    withCredentials: true,
                    timeout: 60000,
                    headers: { 'Content-Type': 'multipart/form-data' },
                });
                data = res.data;
            } else {
                const res = await axios.post('/scan_docker',
                    { content, filename: 'Dockerfile' },
                    { withCredentials: true, timeout: 60000 },
                );
                data = res.data;
            }
            setResults(data);
        } catch (e) {
            setError(e.response?.data?.error || e.message || 'Scan failed.');
        } finally {
            setLoading(false);
        }
    };

    const counts  = results?.counts  || {};
    const findings= results?.findings || [];
    const meta    = results?.meta    || {};
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
                        <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20">
                            <Container className="w-5 h-5 text-cyan-400" />
                        </div>
                        <div>
                            <h1 className="font-orbitron font-bold text-lg text-white tracking-wider">Docker Security Scanner</h1>
                            <p className="text-xs text-slate-500">Dockerfile & docker-compose.yml security analysis</p>
                        </div>
                    </div>
                </div>

                {/* Input Card */}
                <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-5">

                    {/* Mode toggle */}
                    <div className="flex gap-2">
                        {['upload', 'paste'].map(m => (
                            <button
                                key={m}
                                onClick={() => setMode(m)}
                                className={`px-4 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                                    inputMode === m
                                        ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                                        : 'bg-slate-800 text-slate-500 hover:text-slate-300'
                                }`}
                            >
                                {m === 'upload' ? 'Upload File' : 'Paste Content'}
                            </button>
                        ))}
                    </div>

                    {inputMode === 'upload' ? (
                        <div
                            onDrop={handleDrop}
                            onDragOver={e => e.preventDefault()}
                            onClick={() => fileRef.current?.click()}
                            className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors ${
                                file
                                    ? 'border-cyan-500/50 bg-cyan-500/5'
                                    : 'border-slate-700 hover:border-slate-600 hover:bg-slate-800/30'
                            }`}
                        >
                            <input
                                ref={fileRef}
                                type="file"
                                className="hidden"
                                accept=".dockerfile,.yml,.yaml,.txt,.conf"
                                onChange={e => handleFile(e.target.files?.[0])}
                            />
                            {file ? (
                                <div className="space-y-2">
                                    <FileText className="w-8 h-8 text-cyan-400 mx-auto" />
                                    <div className="text-sm text-cyan-300 font-semibold">{file.name}</div>
                                    <div className="text-xs text-slate-500">{(file.size / 1024).toFixed(1)} KB</div>
                                </div>
                            ) : (
                                <div className="space-y-2">
                                    <Upload className="w-8 h-8 text-slate-600 mx-auto" />
                                    <div className="text-sm text-slate-400">
                                        Drop your <span className="text-cyan-400">Dockerfile</span> or{' '}
                                        <span className="text-cyan-400">docker-compose.yml</span> here
                                    </div>
                                    <div className="text-xs text-slate-600">or click to browse</div>
                                </div>
                            )}
                        </div>
                    ) : (
                        <textarea
                            value={content}
                            onChange={e => setContent(e.target.value)}
                            placeholder={'# Paste Dockerfile or docker-compose.yml content here\nFROM node:18\n...'}
                            rows={10}
                            className="w-full bg-slate-800/60 text-slate-200 text-sm font-mono rounded-xl border border-slate-700 p-4 resize-y outline-none focus:border-cyan-500/50 placeholder-slate-600"
                        />
                    )}

                    {/* Legal disclaimer */}
                    <label className="flex items-start gap-3 cursor-pointer group">
                        <input
                            type="checkbox"
                            checked={permitted}
                            onChange={e => setPermitted(e.target.checked)}
                            className="mt-0.5 accent-cyan-500"
                        />
                        <span className="text-xs text-slate-400 leading-relaxed group-hover:text-slate-300 transition-colors">
                            I confirm this Dockerfile/configuration belongs to me or I have authorisation to audit it.
                        </span>
                    </label>

                    <button
                        onClick={handleScan}
                        disabled={loading || !permitted || (inputMode === 'upload' ? !file : !content.trim())}
                        className="w-full py-3 rounded-xl font-orbitron text-sm font-bold uppercase tracking-widest transition-all
                            bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500
                            text-white shadow-lg shadow-cyan-500/10
                            disabled:opacity-40 disabled:cursor-not-allowed disabled:shadow-none"
                    >
                        {loading ? 'Analyzing…' : 'Analyze Security'}
                    </button>
                </div>

                {/* Error */}
                {error && (
                    <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400">
                        {error}
                    </div>
                )}

                {/* Results */}
                <AnimatePresence>
                    {results && (
                        <motion.div
                            initial={{ opacity: 0, y: 20 }}
                            animate={{ opacity: 1, y: 0 }}
                            className="space-y-6"
                        >
                            {/* Summary */}
                            <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-5">
                                <div className="flex items-center justify-between flex-wrap gap-4">
                                    <div>
                                        <div className="text-xs text-slate-500 uppercase tracking-widest font-orbitron mb-1">Risk Score</div>
                                        <div className={`text-3xl font-orbitron font-black ${
                                            results.risk_score >= 7 ? 'text-red-400' :
                                            results.risk_score >= 4 ? 'text-orange-400' :
                                            results.risk_score >= 2 ? 'text-yellow-400' : 'text-green-400'
                                        }`}>
                                            {results.risk_score?.toFixed(1)}
                                            <span className="text-slate-600 text-lg">/10</span>
                                        </div>
                                        <div className="text-xs font-semibold mt-1 uppercase tracking-wider text-slate-400">{results.risk}</div>
                                    </div>
                                    <div className="text-right">
                                        <div className="text-2xl font-orbitron font-bold text-slate-200">{total}</div>
                                        <div className="text-xs text-slate-500">issues found</div>
                                        {meta.file_type && (
                                            <div className="text-[10px] text-cyan-400 mt-1 font-mono">{meta.file_type}</div>
                                        )}
                                    </div>
                                </div>

                                <SeverityBar counts={counts} />

                                {meta.base_image && (
                                    <div className="flex items-center gap-2 text-xs text-slate-500">
                                        <span className="text-slate-600">Base image:</span>
                                        <code className="text-cyan-400 font-mono">{meta.base_image}</code>
                                    </div>
                                )}
                            </div>

                            {/* Report link */}
                            {results.report_token && (
                                <Link
                                    to={`/reports/${results.report_token}`}
                                    className="flex items-center gap-2 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
                                >
                                    <ExternalLink className="w-3.5 h-3.5" />
                                    View full report
                                </Link>
                            )}

                            {/* Findings */}
                            <div className="space-y-3">
                                <div className="text-xs font-orbitron text-slate-500 uppercase tracking-widest">
                                    Findings ({findings.length})
                                </div>
                                {findings.length === 0 ? (
                                    <div className="rounded-xl border border-green-500/20 bg-green-500/5 p-6 text-center">
                                        <CheckCircle className="w-8 h-8 text-green-400 mx-auto mb-2" />
                                        <div className="text-sm text-green-400 font-semibold">No issues found — great job!</div>
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

export default DockerScanPage;
