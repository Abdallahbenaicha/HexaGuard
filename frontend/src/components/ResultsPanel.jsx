import React, { useState } from 'react';
import axios from 'axios';
import { Zap, Terminal, Copy, Check, AlertTriangle, ShieldCheck, Tag } from 'lucide-react';
import { SEVERITY_STYLES, sortBySeverity, formatFinding } from '../utils/logicProtection';
import { REPORT_ENDPOINTS, reportDownloadUrl } from '../utils/reportExport';
import SeverityBadge from './SeverityBadge';
import AttackChainPanel from './AttackChainPanel';

const TRIAGE_CONFIG = {
    New:            { label: 'New',            bg: 'bg-blue-500/10',   text: 'text-blue-400',   border: 'border-blue-500/30' },
    Reviewing:      { label: 'Reviewing',      bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
    Reported:       { label: 'Reported',       bg: 'bg-purple-500/10', text: 'text-purple-400', border: 'border-purple-500/30' },
    Duplicate:      { label: 'Duplicate',      bg: 'bg-slate-500/10',  text: 'text-slate-400',  border: 'border-slate-500/30' },
    'False Positive': { label: 'False Positive', bg: 'bg-red-500/10',    text: 'text-red-400',    border: 'border-red-500/30' },
};

const ResultsPanel = ({ findings = [], total, attackChains = [], kevFindings = [], reportToken = null }) => {
    const [triageStates, setTriageStates] = useState({});
    const [copiedIndex, setCopiedIndex] = useState(null);
    const [triageUpdating, setTriageUpdating] = useState({});

    const sorted = sortBySeverity(findings);
    const kevSet = new Set((kevFindings || []).map(s => s.toUpperCase()));

    const counts = sorted.reduce((acc, f) => {
        const sev = (f.severity || '').toLowerCase();
        acc[sev] = (acc[sev] || 0) + 1;
        return acc;
    }, {});

    const risk = ['critical', 'high', 'medium', 'low'].find(s => counts[s]) || 'info';

    const handleTriageChange = async (vulnId, newStatus, index) => {
        if (!vulnId) return;
        setTriageUpdating(prev => ({ ...prev, [vulnId]: true }));
        try {
            await axios.patch(`/api/reports/vulnerabilities/${vulnId}/triage`, {
                triage_status: newStatus,
            }, { withCredentials: true });
            setTriageStates(prev => ({ ...prev, [vulnId]: newStatus }));
        } catch (err) {
            alert('Failed to update triage status.');
        } finally {
            setTriageUpdating(prev => ({ ...prev, [vulnId]: false }));
        }
    };

    const handleCopyPoc = (pocText, index) => {
        navigator.clipboard.writeText(pocText);
        setCopiedIndex(index);
        setTimeout(() => setCopiedIndex(null), 2000);
    };

    return (
        <div className="mt-10 space-y-4">

            {/* Attack chain panel — full-featured with MITRE ATT&CK badges */}
            <AttackChainPanel attackChains={attackChains} kevFindings={kevFindings} />

            {/* Summary bar */}
            <div className="flex flex-wrap items-center justify-between gap-4 p-5 scanner-glass rounded-2xl mb-6">
                <div className="flex items-center gap-3">
                    <span className="font-orbitron text-xs text-gray-500 tracking-widest uppercase">
                        Overall Risk:
                    </span>
                    <SeverityBadge severity={risk} />
                    <span className="font-orbitron text-xs text-gray-500">
                        {total} finding{total !== 1 ? 's' : ''}
                    </span>
                </div>

                <div className="flex items-center gap-4 text-xs font-orbitron tracking-wider">
                    {['critical', 'high', 'medium', 'low'].map(s =>
                        counts[s] ? (
                            <span key={s} style={{ color: SEVERITY_STYLES[s].text }}>
                                {s.toUpperCase()}: {counts[s]}
                            </span>
                        ) : null
                    )}
                </div>

                <a
                    href={reportDownloadUrl(REPORT_ENDPOINTS.pdf, reportToken)}
                    className="font-orbitron text-[10px] tracking-[0.2em] uppercase px-4 py-2 border border-cyan-500/40 text-cyan-400 hover:bg-cyan-500 hover:text-black transition-all duration-300 rounded-sm"
                >
                    Export Report →
                </a>
            </div>

            {/* Finding cards */}
            {sorted.map((f, i) => {
                const style = SEVERITY_STYLES[(f.severity || '').toLowerCase()] || SEVERITY_STYLES.low;
                const cveId = (f.cve_id || f.cve || '').toUpperCase();
                const isKev = cveId && kevSet.has(cveId);
                const currentTriage = triageStates[f.id] || f.triage_status || 'New';
                const triageMeta = TRIAGE_CONFIG[currentTriage] || TRIAGE_CONFIG.New;

                return (
                    <div
                        key={f.id || i}
                        className="rounded-xl p-5 fade-in-up space-y-4"
                        style={{
                            background:     style.bg,
                            borderLeft:     `3px solid ${style.border}`,
                            animationDelay: `${i * 0.05}s`,
                        }}
                    >
                        {/* Card Header Row */}
                        <div className="flex items-center gap-3 flex-wrap">
                            <SeverityBadge severity={f.severity} />
                            <span className="font-orbitron text-xs font-bold text-white/90 tracking-wider">
                                {f.code || f.title}
                            </span>
                            {isKev && (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold bg-red-600 text-white">
                                    <Zap className="w-3 h-3" />
                                    ACTIVELY EXPLOITED
                                </span>
                            )}
                            {cveId && (
                                <span className="text-[11px] text-gray-500 font-mono">{cveId}</span>
                            )}

                            {/* Triage Status Selector (P2.2) */}
                            {f.id && (
                                <div className="inline-flex items-center gap-1.5 ml-auto">
                                    <Tag className="w-3 h-3 text-slate-500" />
                                    <select
                                        value={currentTriage}
                                        disabled={triageUpdating[f.id]}
                                        onChange={(e) => handleTriageChange(f.id, e.target.value, i)}
                                        className={`text-[11px] font-bold px-2 py-0.5 rounded border transition-colors cursor-pointer outline-none ${triageMeta.bg} ${triageMeta.text} ${triageMeta.border} bg-slate-900/80`}
                                        title="Change finding triage workflow status"
                                    >
                                        <option value="New" className="bg-slate-900 text-blue-400">New</option>
                                        <option value="Reviewing" className="bg-slate-900 text-yellow-400">Reviewing</option>
                                        <option value="Reported" className="bg-slate-900 text-purple-400">Reported</option>
                                        <option value="Duplicate" className="bg-slate-900 text-slate-400">Duplicate</option>
                                        <option value="False Positive" className="bg-slate-900 text-red-400">False Positive</option>
                                    </select>
                                </div>
                            )}

                            {f.file && (
                                <span className="text-[11px] text-gray-500 truncate max-w-[200px]" title={f.file}>
                                    {f.file}
                                </span>
                            )}
                        </div>

                        {/* Program Cap Warning Banner (P2.3) */}
                        {f.exceeds_program_cap && f.program_cap_warning && (
                            <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 text-xs text-amber-300 flex items-center gap-2">
                                <AlertTriangle className="w-4 h-4 flex-shrink-0 text-amber-400" />
                                <span>{f.program_cap_warning}</span>
                            </div>
                        )}

                        {/* Finding Message / Description */}
                        <div
                            className="text-gray-400 text-sm leading-relaxed font-inter whitespace-pre-wrap"
                            dangerouslySetInnerHTML={{
                                __html: formatFinding(f)
                                    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
                                    .replace(/`([^`]+)`/g, '<code class="text-cyan-400/80">$1</code>')
                                    .replace(/\n/g, '<br/>'),
                            }}
                        />

                        {/* Reproduction PoC (P2.3) */}
                        {f.poc_curl && (
                            <div className="mt-3 bg-slate-950/80 border border-slate-800 rounded-lg p-3">
                                <div className="flex items-center justify-between gap-2 mb-1.5">
                                    <div className="flex items-center gap-1.5 text-[10px] font-mono text-cyan-400 uppercase tracking-wider">
                                        <Terminal className="w-3.5 h-3.5" />
                                        <span>Reproduction PoC (curl)</span>
                                    </div>
                                    <button
                                        onClick={() => handleCopyPoc(f.poc_curl, i)}
                                        className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                                    >
                                        {copiedIndex === i ? (
                                            <>
                                                <Check className="w-3 h-3 text-green-400" />
                                                <span className="text-green-400">Copied</span>
                                            </>
                                        ) : (
                                            <>
                                                <Copy className="w-3 h-3" />
                                                <span>Copy curl</span>
                                            </>
                                        )}
                                    </button>
                                </div>
                                <pre className="text-[11px] font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap break-all p-1 bg-black/40 rounded">
                                    {f.poc_curl}
                                </pre>
                            </div>
                        )}
                    </div>
                );
            })}
        </div>
    );
};

export default ResultsPanel;
