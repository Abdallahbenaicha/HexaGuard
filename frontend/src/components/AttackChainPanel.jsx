import React, { useState } from 'react';
import {
    ShieldAlert, AlertTriangle, ChevronDown, ChevronRight,
    ExternalLink, Zap, Link2, Eye,
} from 'lucide-react';

// ── MITRE ATT&CK technique mappings ──────────────────────────────────────────
// Maps attack chain keyword patterns to ATT&CK technique IDs and names.
// Source: https://attack.mitre.org (MITRE ATT&CK Enterprise Framework v14)
const ATTACK_TECHNIQUE_MAP = {
    // Keyword fragments → { tactic, technique, id, url }
    'xss':              { tactic: 'Collection', technique: 'Input Capture', id: 'T1056', url: 'https://attack.mitre.org/techniques/T1056/' },
    'cross-site':       { tactic: 'Execution',  technique: 'Scripting',     id: 'T1059', url: 'https://attack.mitre.org/techniques/T1059/' },
    'sql':              { tactic: 'Exfiltration', technique: 'Exfiltration Over Web Service', id: 'T1567', url: 'https://attack.mitre.org/techniques/T1567/' },
    'sql injection':    { tactic: 'Collection', technique: 'Data from Local System', id: 'T1005', url: 'https://attack.mitre.org/techniques/T1005/' },
    'rce':              { tactic: 'Execution',  technique: 'Command and Scripting Interpreter', id: 'T1059', url: 'https://attack.mitre.org/techniques/T1059/' },
    'remote code':      { tactic: 'Execution',  technique: 'Remote Services', id: 'T1021', url: 'https://attack.mitre.org/techniques/T1021/' },
    'command injection':{ tactic: 'Execution',  technique: 'Command and Scripting Interpreter', id: 'T1059', url: 'https://attack.mitre.org/techniques/T1059/' },
    'ssrf':             { tactic: 'Discovery',  technique: 'Cloud Infrastructure Discovery', id: 'T1580', url: 'https://attack.mitre.org/techniques/T1580/' },
    'csrf':             { tactic: 'Impact',     technique: 'Account Manipulation', id: 'T1098', url: 'https://attack.mitre.org/techniques/T1098/' },
    'path traversal':   { tactic: 'Collection', technique: 'Data from Local System', id: 'T1005', url: 'https://attack.mitre.org/techniques/T1005/' },
    'directory traversal':{ tactic: 'Collection','technique': 'Data from Local System', id: 'T1005', url: 'https://attack.mitre.org/techniques/T1005/' },
    'deserialization':  { tactic: 'Execution',  technique: 'Exploitation for Client Execution', id: 'T1203', url: 'https://attack.mitre.org/techniques/T1203/' },
    'xxe':              { tactic: 'Collection', technique: 'Data from Local System', id: 'T1005', url: 'https://attack.mitre.org/techniques/T1005/' },
    'auth bypass':      { tactic: 'Defense Evasion', technique: 'Valid Accounts', id: 'T1078', url: 'https://attack.mitre.org/techniques/T1078/' },
    'authentication bypass': { tactic: 'Defense Evasion', technique: 'Valid Accounts', id: 'T1078', url: 'https://attack.mitre.org/techniques/T1078/' },
    'hardcoded':        { tactic: 'Credential Access', technique: 'Credentials in Files', id: 'T1552', url: 'https://attack.mitre.org/techniques/T1552/' },
    'credential':       { tactic: 'Credential Access', technique: 'Credentials from Password Stores', id: 'T1555', url: 'https://attack.mitre.org/techniques/T1555/' },
    'open redirect':    { tactic: 'Initial Access', technique: 'Phishing', id: 'T1566', url: 'https://attack.mitre.org/techniques/T1566/' },
    'lateral':          { tactic: 'Lateral Movement', technique: 'Internal Spearphishing', id: 'T1534', url: 'https://attack.mitre.org/techniques/T1534/' },
    'session hijack':   { tactic: 'Credential Access', technique: 'Steal Web Session Cookie', id: 'T1539', url: 'https://attack.mitre.org/techniques/T1539/' },
    'csp':              { tactic: 'Defense Evasion', technique: 'Reflective Code Loading', id: 'T1620', url: 'https://attack.mitre.org/techniques/T1620/' },
    'kev':              { tactic: 'Initial Access', technique: 'Exploit Public-Facing Application', id: 'T1190', url: 'https://attack.mitre.org/techniques/T1190/' },
    'known exploit':    { tactic: 'Initial Access', technique: 'Exploit Public-Facing Application', id: 'T1190', url: 'https://attack.mitre.org/techniques/T1190/' },
    'internet':         { tactic: 'Reconnaissance', technique: 'Active Scanning', id: 'T1595', url: 'https://attack.mitre.org/techniques/T1595/' },
    'exposed port':     { tactic: 'Discovery', technique: 'Network Service Discovery', id: 'T1046', url: 'https://attack.mitre.org/techniques/T1046/' },
    'smb':              { tactic: 'Lateral Movement', technique: 'Remote Services: SMB/Windows Admin Shares', id: 'T1021.002', url: 'https://attack.mitre.org/techniques/T1021/002/' },
};

// Tactic → colour scheme
const TACTIC_COLORS = {
    'Reconnaissance':    { bg: '#1e3a5f', border: '#3b82f6', text: '#93c5fd', label: 'Recon' },
    'Initial Access':    { bg: '#3b1f1f', border: '#ef4444', text: '#fca5a5', label: 'Init' },
    'Execution':         { bg: '#4a2100', border: '#f97316', text: '#fdba74', label: 'Exec' },
    'Defense Evasion':   { bg: '#2d1b5e', border: '#8b5cf6', text: '#c4b5fd', label: 'Evasion' },
    'Credential Access': { bg: '#1a1a3e', border: '#6366f1', text: '#a5b4fc', label: 'CredAccess' },
    'Discovery':         { bg: '#1b3a2d', border: '#10b981', text: '#6ee7b7', label: 'Discovery' },
    'Lateral Movement':  { bg: '#3b2a00', border: '#f59e0b', text: '#fcd34d', label: 'Lateral' },
    'Collection':        { bg: '#1a3b3b', border: '#06b6d4', text: '#67e8f9', label: 'Collect' },
    'Exfiltration':      { bg: '#3b1a1a', border: '#dc2626', text: '#fca5a5', label: 'Exfil' },
    'Impact':            { bg: '#3b0000', border: '#b91c1c', text: '#f87171', label: 'Impact' },
};

// ── Derive MITRE techniques from a chain description string ──────────────────
function deriveTechniques(chainText) {
    const lower = chainText.toLowerCase();
    const found = [];
    const seen = new Set();
    for (const [keyword, info] of Object.entries(ATTACK_TECHNIQUE_MAP)) {
        if (lower.includes(keyword) && !seen.has(info.id)) {
            found.push(info);
            seen.add(info.id);
        }
    }
    return found;
}

// ── Parse a chain string into steps ─────────────────────────────────────────
function parseChainSteps(chainText) {
    // Split on →, ->, +, then, leading to, allows, combined with
    const separators = /\s*(?:→|->|\+|combined with|then|leading to|allows)\s*/i;
    const parts = chainText.split(separators).map(s => s.trim()).filter(Boolean);
    return parts.length >= 2 ? parts : [chainText];
}

// ── MITRE ATT&CK Badge ───────────────────────────────────────────────────────
const MitreBadge = ({ technique }) => {
    const colorScheme = TACTIC_COLORS[technique.tactic] || {
        bg: '#1a1a2e', border: '#374151', text: '#9ca3af', label: technique.tactic,
    };

    return (
        <a
            href={technique.url}
            target="_blank"
            rel="noopener noreferrer"
            title={`${technique.tactic}: ${technique.technique} (${technique.id})`}
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold 
                       transition-all duration-200 hover:brightness-125 hover:scale-105"
            style={{
                background:   colorScheme.bg,
                border:       `1px solid ${colorScheme.border}`,
                color:        colorScheme.text,
            }}
        >
            <span className="opacity-60 text-[9px]">[ATT&CK]</span>
            {technique.id}
            <ExternalLink className="w-2.5 h-2.5 opacity-50" />
        </a>
    );
};

// ── Attack chain node ────────────────────────────────────────────────────────
const ChainStep = ({ step, index, total }) => (
    <div className="flex items-center gap-2">
        <div
            className="flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center 
                       text-[10px] font-bold font-mono"
            style={{
                background: index === 0
                    ? 'rgba(239,68,68,0.2)'
                    : index === total - 1
                    ? 'rgba(249,115,22,0.3)'
                    : 'rgba(251,191,36,0.15)',
                border: `1px solid ${index === 0 ? '#ef4444' : index === total - 1 ? '#f97316' : '#fbbf24'}`,
                color:  index === 0 ? '#f87171' : index === total - 1 ? '#fb923c' : '#fcd34d',
            }}
        >
            {index + 1}
        </div>
        <span className="text-sm text-gray-300 font-inter">{step}</span>
        {index < total - 1 && (
            <span className="text-orange-500 font-bold text-base mx-1">→</span>
        )}
    </div>
);

// ── Single expanded attack chain card ───────────────────────────────────────
const AttackChainCard = ({ chain, index }) => {
    const [expanded, setExpanded] = useState(false);
    const steps      = parseChainSteps(chain);
    const techniques = deriveTechniques(chain);
    const hasDetail  = steps.length > 1 || techniques.length > 0;

    return (
        <div
            className="rounded-xl overflow-hidden transition-all duration-300"
            style={{
                background: 'rgba(251,146,60,0.04)',
                border:     '1px solid rgba(251,146,60,0.25)',
            }}
        >
            {/* Header */}
            <button
                className="w-full flex items-start gap-3 p-4 text-left hover:bg-orange-500/5 
                           transition-colors duration-200"
                onClick={() => setExpanded(v => !v)}
                aria-expanded={expanded}
                id={`attack-chain-${index}`}
            >
                <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0 text-orange-400" />
                <div className="flex-1 min-w-0">
                    <p className="text-sm text-orange-200 font-inter leading-relaxed">{chain}</p>
                    {techniques.length > 0 && (
                        <div className="flex flex-wrap gap-1.5 mt-2">
                            {techniques.slice(0, 3).map((t, i) => (
                                <MitreBadge key={i} technique={t} />
                            ))}
                            {techniques.length > 3 && (
                                <span className="text-[10px] text-gray-500 self-center">
                                    +{techniques.length - 3} more
                                </span>
                            )}
                        </div>
                    )}
                </div>
                {hasDetail && (
                    <div className="flex-shrink-0 text-orange-400 mt-0.5">
                        {expanded
                            ? <ChevronDown className="w-4 h-4" />
                            : <ChevronRight className="w-4 h-4" />
                        }
                    </div>
                )}
            </button>

            {/* Expanded detail */}
            {expanded && hasDetail && (
                <div
                    className="px-4 pb-4 space-y-4 border-t border-orange-500/10"
                    role="region"
                    aria-labelledby={`attack-chain-${index}`}
                >
                    {/* Step-by-step flow */}
                    {steps.length > 1 && (
                        <div className="pt-3">
                            <p className="text-[10px] font-mono text-orange-400/60 uppercase tracking-widest mb-3">
                                Exploitation Path
                            </p>
                            <div className="flex flex-wrap items-center gap-1">
                                {steps.map((step, i) => (
                                    <ChainStep key={i} step={step} index={i} total={steps.length} />
                                ))}
                            </div>
                        </div>
                    )}

                    {/* MITRE ATT&CK techniques */}
                    {techniques.length > 0 && (
                        <div>
                            <p className="text-[10px] font-mono text-orange-400/60 uppercase tracking-widest mb-2">
                                MITRE ATT&CK Techniques
                            </p>
                            <div className="space-y-1.5">
                                {techniques.map((t, i) => (
                                    <a
                                        key={i}
                                        href={t.url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="flex items-center gap-3 p-2 rounded-lg text-xs 
                                                   hover:bg-orange-500/10 transition-colors duration-150"
                                        style={{
                                            background: TACTIC_COLORS[t.tactic]
                                                ? TACTIC_COLORS[t.tactic].bg
                                                : 'rgba(31,41,55,0.4)',
                                        }}
                                    >
                                        <span
                                            className="font-mono font-bold text-[10px] px-1.5 py-0.5 rounded"
                                            style={{
                                                color:  TACTIC_COLORS[t.tactic]?.text || '#9ca3af',
                                                border: `1px solid ${TACTIC_COLORS[t.tactic]?.border || '#374151'}`,
                                            }}
                                        >
                                            {t.id}
                                        </span>
                                        <span className="text-gray-300">{t.technique}</span>
                                        <span className="text-gray-600 ml-auto">{t.tactic}</span>
                                        <ExternalLink className="w-3 h-3 text-gray-600 flex-shrink-0" />
                                    </a>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

// ── Main AttackChainPanel component ─────────────────────────────────────────
const AttackChainPanel = ({ attackChains = [], kevFindings = [] }) => {
    const [collapsed, setCollapsed] = useState(false);

    if (!attackChains.length && !kevFindings.length) return null;

    const totalTechniques = attackChains.reduce(
        (sum, chain) => sum + deriveTechniques(chain).length, 0
    );

    return (
        <div
            className="rounded-2xl overflow-hidden mb-4"
            style={{
                background: 'linear-gradient(135deg, rgba(251,146,60,0.06) 0%, rgba(239,68,68,0.04) 100%)',
                border:     '1px solid rgba(249,115,22,0.35)',
                boxShadow:  '0 0 30px rgba(249,115,22,0.08)',
            }}
            role="region"
            aria-label="Attack chain risk panel"
        >
            {/* Panel header */}
            <button
                className="w-full flex items-center gap-3 px-5 py-4 hover:bg-orange-500/5 
                           transition-colors duration-200"
                onClick={() => setCollapsed(v => !v)}
                aria-expanded={!collapsed}
                id="attack-chain-panel-header"
            >
                <ShieldAlert className="w-5 h-5 text-orange-400 shrink-0" />
                <div className="flex-1 text-left">
                    <div className="flex items-center gap-3 flex-wrap">
                        <span className="font-orbitron text-xs text-orange-400 tracking-widest uppercase font-bold">
                            Attack Chain Risk Detected
                        </span>
                        {/* Chain count badge */}
                        {attackChains.length > 0 && (
                            <span
                                className="px-2 py-0.5 rounded-full text-[10px] font-bold"
                                style={{ background: 'rgba(249,115,22,0.2)', color: '#fb923c', border: '1px solid rgba(249,115,22,0.4)' }}
                            >
                                {attackChains.length} chain{attackChains.length !== 1 ? 's' : ''}
                            </span>
                        )}
                        {/* KEV badge */}
                        {kevFindings.length > 0 && (
                            <span
                                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-bold"
                                style={{ background: 'rgba(239,68,68,0.2)', color: '#f87171', border: '1px solid rgba(239,68,68,0.4)' }}
                            >
                                <Zap className="w-2.5 h-2.5" />
                                {kevFindings.length} KEV
                            </span>
                        )}
                        {/* MITRE technique count */}
                        {totalTechniques > 0 && (
                            <span className="text-[10px] text-gray-500 flex items-center gap-1">
                                <Link2 className="w-3 h-3" />
                                {totalTechniques} ATT&CK technique{totalTechniques !== 1 ? 's' : ''}
                            </span>
                        )}
                    </div>
                </div>
                <div className="flex-shrink-0 text-orange-400">
                    {collapsed
                        ? <ChevronRight className="w-4 h-4" />
                        : <ChevronDown className="w-4 h-4" />
                    }
                </div>
            </button>

            {/* Expanded body */}
            {!collapsed && (
                <div className="px-5 pb-5 space-y-3" role="region" aria-labelledby="attack-chain-panel-header">

                    {/* KEV alert */}
                    {kevFindings.length > 0 && (
                        <div
                            className="flex items-start gap-3 p-3 rounded-lg"
                            style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)' }}
                        >
                            <Zap className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                            <div className="text-xs text-red-300 font-inter">
                                <span className="font-bold text-red-400">CISA KEV Match: </span>
                                {kevFindings.join(', ')} — these CVEs are actively exploited in the wild.
                                Patch immediately.
                            </div>
                        </div>
                    )}

                    {/* Chain cards */}
                    {attackChains.map((chain, i) => (
                        <AttackChainCard key={i} chain={chain} index={i} />
                    ))}

                    {/* Footer: ATT&CK link */}
                    <div className="flex items-center justify-end pt-1">
                        <a
                            href="https://attack.mitre.org"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-1 text-[10px] text-gray-600 hover:text-gray-400 
                                       transition-colors duration-150 font-mono"
                        >
                            <Eye className="w-3 h-3" />
                            MITRE ATT&CK Framework
                            <ExternalLink className="w-2.5 h-2.5" />
                        </a>
                    </div>
                </div>
            )}
        </div>
    );
};

export default AttackChainPanel;
