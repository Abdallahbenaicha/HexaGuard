import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import {
    Crosshair, ArrowLeft, ShieldAlert, Globe,
    Terminal, Copy, Check, ExternalLink, BookOpen,
    AlertTriangle, Sparkles, Filter, ChevronRight
} from 'lucide-react';
import {
    ASSET_TYPE_META,
    METHODOLOGY,
    HUNT_PHASES,
    VULN_RESOURCES,
    TOOLS_BY_PHASE
} from '../utils/huntGuideData';

const isPrivateTarget = (str) => {
    const s = str.trim().toLowerCase();
    if (s.includes('localhost') || s.includes('127.0.0.1') || s.includes('0.0.0.0')) return true;
    if (s.startsWith('10.') || s.startsWith('192.168.') || s.startsWith('169.254.')) return true;
    if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(s)) return true;
    return false;
};

const ManualHuntPage = () => {
    const [assetType, setAssetType] = useState('URL');
    const [target, setTarget] = useState('');
    const [activePhase, setActivePhase] = useState('recon');
    const [authorized, setAuthorized] = useState(false);
    const [copiedIndex, setCopiedIndex] = useState(null);

    const methodology = METHODOLOGY[assetType] || METHODOLOGY.URL;
    const currentPhaseData = methodology.phases.find(p => p.phase === activePhase) || methodology.phases[0];

    const copyCommand = (cmd, idx) => {
        const rendered = target.trim()
            ? cmd.replace(/<target>/g, target.trim())
                 .replace(/<domain>/g, target.trim().replace(/^https?:\/\//, '').split('/')[0])
                 .replace(/<target_cidr>/g, target.trim())
                 .replace(/<target_ip>/g, target.trim())
            : cmd;
        navigator.clipboard.writeText(rendered);
        setCopiedIndex(idx);
        setTimeout(() => setCopiedIndex(null), 2000);
    };

    const ssrfError = target.trim() && isPrivateTarget(target);

    return (
        <div className="min-h-screen bg-slate-950 text-slate-100 p-6">
            <div className="max-w-6xl mx-auto space-y-8">
                {/* Header */}
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        <Link to="/dashboard" className="p-2 rounded-xl bg-slate-900 border border-slate-800 hover:bg-slate-800 transition-colors">
                            <ArrowLeft className="w-5 h-5 text-slate-400" />
                        </Link>
                        <div>
                            <h1 className="font-orbitron font-bold text-xl text-white tracking-wider flex items-center gap-2">
                                <Crosshair className="w-5 h-5 text-cyan-400" />
                                Manual Bug Bounty Hunting Guide
                            </h1>
                            <p className="text-xs text-slate-400">Step-by-step methodology and command generation for all in-scope asset types</p>
                        </div>
                    </div>
                    <Link
                        to="/learn/vulnerabilities"
                        className="px-4 py-2 rounded-xl bg-purple-500/10 border border-purple-500/20 hover:bg-purple-500/20 text-purple-300 text-xs font-orbitron flex items-center gap-2 transition-all"
                    >
                        <BookOpen className="w-4 h-4 text-purple-400" />
                        Vulnerability Encyclopedia
                    </Link>
                </div>

                {/* Legal Disclaimer Banner */}
                <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-5 space-y-3">
                    <div className="flex items-center gap-2 font-orbitron font-bold text-sm text-amber-400">
                        <ShieldAlert className="w-4 h-4 text-amber-400 flex-shrink-0" />
                        <span>Rules of Engagement & Legal Disclaimer</span>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed">
                        Bug bounty testing must remain strictly within the target organization's authorized scope and program policies.
                        Never perform testing without explicit authorization. Do not execute destructive payloads, access private user data beyond minimal proof, or cause service denial.
                    </p>
                    <label className="flex items-center gap-2 text-xs text-amber-300 font-medium cursor-pointer pt-1">
                        <input
                            type="checkbox"
                            checked={authorized}
                            onChange={e => setAuthorized(e.target.checked)}
                            className="rounded border-amber-500 bg-slate-900 text-amber-500 focus:ring-amber-500"
                        />
                        <span>I understand and certify that my activities strictly follow the target's authorized bug bounty policy.</span>
                    </label>
                </div>

                {/* Asset Type Selector */}
                <div className="space-y-3">
                    <label className="text-xs font-orbitron uppercase text-slate-400 tracking-wider">Select In-Scope Asset Type</label>
                    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
                        {Object.entries(ASSET_TYPE_META).map(([typeKey, meta]) => (
                            <button
                                key={typeKey}
                                onClick={() => setAssetType(typeKey)}
                                className={`p-3 rounded-xl border text-left transition-all flex flex-col justify-between space-y-2 ${
                                    assetType === typeKey
                                        ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-200 shadow-lg shadow-cyan-950/40'
                                        : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:bg-slate-850 hover:text-slate-200'
                                }`}
                            >
                                <div className="text-xl">{meta.icon}</div>
                                <div>
                                    <div className="font-orbitron font-semibold text-xs text-white">{meta.label}</div>
                                    <div className="text-[10px] text-slate-500 leading-tight">{meta.desc}</div>
                                </div>
                            </button>
                        ))}
                    </div>
                </div>

                {/* Target Host Form */}
                <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
                    <label className="text-xs font-orbitron uppercase text-slate-400 tracking-wider flex items-center gap-2">
                        <Globe className="w-4 h-4 text-cyan-400" />
                        Target Identifier (replaces &lt;target&gt; in commands)
                    </label>
                    <input
                        type="text"
                        value={target}
                        onChange={e => setTarget(e.target.value)}
                        placeholder="e.g. example.com or 192.0.2.1 or api.example.com"
                        className="w-full px-4 py-3 rounded-xl bg-slate-950 border border-slate-800 text-sm font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 transition-colors"
                    />
                    {ssrfError && (
                        <div className="flex items-center gap-2 text-xs text-red-400">
                            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                            <span>Warning: Target resolves to a local/private loopback range. SSRF guards prohibit internal testing.</span>
                        </div>
                    )}
                </div>

                {/* Phase Tabs */}
                <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
                    {Object.values(HUNT_PHASES).map(ph => (
                        <button
                            key={ph.id}
                            onClick={() => setActivePhase(ph.id)}
                            className={`px-4 py-2 rounded-xl text-xs font-orbitron font-semibold transition-all flex items-center gap-2 ${
                                activePhase === ph.id
                                    ? `${ph.bg} ${ph.color} border ${ph.border} shadow-md`
                                    : 'text-slate-400 hover:text-slate-200'
                            }`}
                        >
                            <span>{ph.label}</span>
                        </button>
                    ))}
                </div>

                {/* Steps and Commands */}
                <div className="space-y-4">
                    <div className="text-xs text-slate-400 font-inter">
                        {methodology.summary}
                    </div>

                    <div className="space-y-4">
                        {currentPhaseData?.steps?.map((step, idx) => {
                            const renderedCmd = target.trim()
                                ? step.cmd.replace(/<target>/g, target.trim())
                                          .replace(/<domain>/g, target.trim().replace(/^https?:\/\//, '').split('/')[0])
                                          .replace(/<target_cidr>/g, target.trim())
                                          .replace(/<target_ip>/g, target.trim())
                                : step.cmd;

                            return (
                                <div key={idx} className="p-5 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-3">
                                    <div className="flex items-center justify-between">
                                        <h3 className="font-orbitron font-semibold text-sm text-slate-200 flex items-center gap-2">
                                            <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-400 text-xs flex items-center justify-center font-mono">
                                                {idx + 1}
                                            </span>
                                            {step.title}
                                        </h3>
                                        {step.vuln && VULN_RESOURCES[step.vuln] && (
                                            <Link
                                                to="/learn/vulnerabilities"
                                                className="text-[11px] font-mono text-purple-400 hover:text-purple-300 flex items-center gap-1 transition-colors"
                                            >
                                                Learn in Encyclopedia
                                                <ExternalLink className="w-3 h-3" />
                                            </Link>
                                        )}
                                    </div>
                                    <p className="text-xs text-slate-400">{step.desc}</p>
                                    <div className="relative group">
                                        <pre className="p-4 rounded-xl bg-slate-950 border border-slate-850 font-mono text-xs text-cyan-300 overflow-x-auto whitespace-pre-wrap">
                                            {renderedCmd}
                                        </pre>
                                        <button
                                            onClick={() => copyCommand(step.cmd, idx)}
                                            className="absolute top-2 right-2 p-2 rounded-lg bg-slate-850 hover:bg-slate-800 text-slate-400 hover:text-white transition-colors border border-slate-700/50"
                                            title="Copy Command"
                                        >
                                            {copiedIndex === idx ? (
                                                <Check className="w-3.5 h-3.5 text-green-400" />
                                            ) : (
                                                <Copy className="w-3.5 h-3.5" />
                                            )}
                                        </button>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>

                {/* Methodology Tips */}
                {methodology.tips && methodology.tips.length > 0 && (
                    <div className="p-5 rounded-2xl bg-slate-900/40 border border-slate-800 space-y-2">
                        <h4 className="font-orbitron font-semibold text-xs text-cyan-400 uppercase tracking-wider flex items-center gap-2">
                            <Sparkles className="w-4 h-4 text-cyan-400" />
                            Pro Tips for {ASSET_TYPE_META[assetType]?.label || assetType}
                        </h4>
                        <ul className="list-disc list-inside space-y-1 text-xs text-slate-400">
                            {methodology.tips.map((tip, tidx) => (
                                <li key={tidx}>{tip}</li>
                            ))}
                        </ul>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ManualHuntPage;
