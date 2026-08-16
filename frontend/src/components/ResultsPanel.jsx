import React from 'react';
import { Zap } from 'lucide-react';
import { SEVERITY_STYLES, sortBySeverity, formatFinding } from '../utils/logicProtection';
import { REPORT_ENDPOINTS, reportDownloadUrl } from '../utils/reportExport';
import SeverityBadge from './SeverityBadge';
import AttackChainPanel from './AttackChainPanel';

const ResultsPanel = ({ findings, total, attackChains = [], kevFindings = [], reportToken = null }) => {
    const sorted = sortBySeverity(findings);
    const kevSet = new Set((kevFindings || []).map(s => s.toUpperCase()));

    const counts = sorted.reduce((acc, f) => {
        const sev = (f.severity || '').toLowerCase();
        acc[sev] = (acc[sev] || 0) + 1;
        return acc;
    }, {});

    const risk = ['critical', 'high', 'medium', 'low'].find(s => counts[s]) || 'info';

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
                return (
                    <div
                        key={i}
                        className="rounded-xl p-5 fade-in-up"
                        style={{
                            background:     style.bg,
                            borderLeft:     `3px solid ${style.border}`,
                            animationDelay: `${i * 0.05}s`
                        }}
                    >
                        <div className="flex items-center gap-3 mb-3 flex-wrap">
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
                            {f.file && (
                                <span className="ml-auto text-[11px] text-gray-600 truncate max-w-[200px]">
                                    {f.file}
                                </span>
                            )}
                        </div>
                        <div
                            className="text-gray-400 text-sm leading-relaxed font-inter whitespace-pre-wrap"
                            dangerouslySetInnerHTML={{
                                __html: formatFinding(f)
                                    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
                                    .replace(/`([^`]+)`/g, '<code class="text-cyan-400/80">$1</code>')
                                    .replace(/\n/g, '<br/>'),
                            }}
                        />
                    </div>
                );
            })}
        </div>
    );
};

export default ResultsPanel;
