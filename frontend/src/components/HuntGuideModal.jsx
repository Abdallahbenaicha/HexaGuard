import { useState, useEffect, useCallback } from 'react';
import {
  X, Target, BookOpen, Wrench, ExternalLink, ChevronDown,
  ChevronUp, Copy, Check, Shield, Globe, Layers,
  Maximize2, Minimize2, PanelRight, Monitor,
  Youtube, FileText, AlertTriangle, Zap, CheckCircle, Clock,
} from 'lucide-react';
import {
  METHODOLOGY, VULN_RESOURCES, TOOLS_BY_PHASE, HUNT_PHASES,
  PLATFORM_META, SEVERITY_CONFIG, ASSET_TYPE_META,
} from '../utils/huntGuideData';

// ─── Copy-to-clipboard mini hook ──────────────────────────────────────────────
function useCopy(text) {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(() => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    });
  }, [text]);
  return [copied, copy];
}

// ─── Code block with copy button ─────────────────────────────────────────────
const CodeBlock = ({ code, target }) => {
  const filled = code.replace(/<target>/g, target || '<target>').replace(/<domain>/g, target?.replace(/^https?:\/\//, '') || '<domain>');
  const [copied, copy] = useCopy(filled);
  return (
    <div className="relative group mt-2">
      <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs text-green-300 font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed">
        {filled}
      </pre>
      <button
        onClick={copy}
        className="absolute top-2 right-2 p-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors opacity-0 group-hover:opacity-100"
        title="Copy"
      >
        {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
      </button>
    </div>
  );
};

// ─── Phase step card ──────────────────────────────────────────────────────────
const StepCard = ({ step, phaseConfig, target, vulnResources }) => {
  const [expanded, setExpanded] = useState(false);
  const vuln = step.vuln ? vulnResources[step.vuln] : null;

  return (
    <div className={`rounded-xl border ${phaseConfig.border} ${phaseConfig.bg} overflow-hidden`}>
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left"
        onClick={() => setExpanded(v => !v)}
      >
        <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${phaseConfig.color.replace('text-', 'bg-')}`} />
        <span className="font-semibold text-sm text-white flex-1">{step.title}</span>
        {step.vuln && (
          <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30">
            {vuln?.label ?? step.vuln}
          </span>
        )}
        {expanded ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
      </button>

      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-slate-800">
          <p className="text-sm text-slate-300 mt-3">{step.desc}</p>
          {step.cmd && <CodeBlock code={step.cmd} target={target?.asset} />}
          {vuln && (
            <div className="flex flex-wrap gap-2 pt-1">
              <a href={vuln.portswigger} target="_blank" rel="noopener noreferrer"
                 className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-orange-500/10 text-orange-300 border border-orange-500/30 hover:bg-orange-500/20 transition-colors">
                <Shield className="w-3 h-3" /> PortSwigger
              </a>
              <a href={vuln.hacktricks} target="_blank" rel="noopener noreferrer"
                 className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-500/10 text-blue-300 border border-blue-500/30 hover:bg-blue-500/20 transition-colors">
                <BookOpen className="w-3 h-3" /> HackTricks
              </a>
              {vuln.youtube?.map((yt, i) => (
                <a key={i} href={yt.url} target="_blank" rel="noopener noreferrer"
                   className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-500/10 text-red-300 border border-red-500/30 hover:bg-red-500/20 transition-colors">
                  <Youtube className="w-3 h-3" /> {yt.title}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// ─── Tab: Overview ────────────────────────────────────────────────────────────
const TabOverview = ({ target, methodology }) => {
  const assetMeta = ASSET_TYPE_META[target.asset_type] ?? { icon: '📄', label: target.asset_type };
  const platMeta  = PLATFORM_META[target.platform] ?? { label: target.platform, icon: '●' };
  const sevCfg    = SEVERITY_CONFIG[target.max_severity?.toLowerCase()] ?? SEVERITY_CONFIG.low;

  return (
    <div className="space-y-6">
      {/* Target info grid */}
      <div className="grid grid-cols-2 gap-3">
        {[
          { label: 'Platform',     value: `${platMeta.icon} ${platMeta.label}` },
          { label: 'Asset Type',   value: `${assetMeta.icon} ${assetMeta.label}` },
          { label: 'Max Severity', value: target.max_severity ?? '—', badge: sevCfg.color },
          { label: 'Bounty',       value: target.eligible_bounty ? '💰 Yes' : '🚫 No (VDP)' },
          { label: 'Auto-scan',    value: target.auto_scan_ok ? '✅ Allowed' : '⚠️ Check Policy' },
          { label: 'Program',      value: target.program_name },
        ].map(({ label, value, badge }) => (
          <div key={label} className="bg-slate-800/60 rounded-xl p-3">
            <div className="text-xs text-slate-500 mb-1">{label}</div>
            {badge ? (
              <span className={`text-xs font-semibold px-2 py-0.5 rounded-md border ${badge}`}>{value}</span>
            ) : (
              <div className="text-sm font-semibold text-white">{value}</div>
            )}
          </div>
        ))}
      </div>

      {/* Asset */}
      <div className="bg-slate-800/60 rounded-xl p-4">
        <div className="text-xs text-slate-500 mb-1.5">Target Asset</div>
        <code className="text-cyan-400 text-base font-mono break-all">{target.asset}</code>
        {target.website && target.website !== target.asset && (
          <div className="text-xs text-slate-500 mt-1">Program site: <a href={target.website} target="_blank" rel="noopener noreferrer" className="text-cyan-400 hover:underline">{target.website}</a></div>
        )}
      </div>

      {/* Instruction / policy note */}
      {target.instruction && (
        <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-xl p-4 flex gap-3">
          <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
          <div>
            <div className="text-xs font-semibold text-yellow-400 mb-1">Program Instructions / Restrictions</div>
            <p className="text-sm text-yellow-200">{target.instruction}</p>
          </div>
        </div>
      )}

      {/* Methodology summary */}
      <div className="bg-slate-800/60 rounded-xl p-4">
        <div className="text-xs text-slate-500 mb-2">Testing Approach</div>
        <p className="text-sm text-slate-300">{methodology.summary}</p>
      </div>

      {/* View program */}
      <a
        href={target.program_url}
        target="_blank"
        rel="noopener noreferrer"
        className="flex items-center justify-center gap-2 w-full py-3 rounded-xl bg-gradient-to-r from-purple-600/20 to-indigo-600/20 border border-purple-500/30 text-purple-300 hover:text-white hover:from-purple-600/30 hover:to-indigo-600/30 transition-all text-sm font-semibold"
      >
        <ExternalLink className="w-4 h-4" /> View Full Scope & Program Rules
      </a>
    </div>
  );
};

// ─── Tab: Methodology ─────────────────────────────────────────────────────────
const TabMethodology = ({ target, methodology }) => {
  const [activePhase, setActivePhase] = useState('recon');

  const currentPhase = methodology.phases.find(p => p.phase === activePhase);
  const phaseConfig  = HUNT_PHASES[activePhase];

  return (
    <div className="space-y-4">
      {/* Phase selector */}
      <div className="grid grid-cols-4 gap-2">
        {Object.values(HUNT_PHASES).map(ph => {
          const phaseData = methodology.phases.find(p => p.phase === ph.id);
          const count = phaseData?.steps?.length ?? 0;
          return (
            <button
              key={ph.id}
              onClick={() => setActivePhase(ph.id)}
              className={`p-3 rounded-xl text-left transition-all border ${
                activePhase === ph.id
                  ? `${ph.bg} ${ph.border} ${ph.color}`
                  : 'bg-slate-800/60 border-slate-700 text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              <div className="text-[10px] font-bold uppercase tracking-wider mb-1 truncate">{ph.label.split('—')[0].trim()}</div>
              <div className="text-lg font-black">{count}</div>
              <div className="text-[10px] opacity-70">steps</div>
            </button>
          );
        })}
      </div>

      {/* Phase label */}
      <div className={`text-sm font-bold ${phaseConfig?.color ?? 'text-white'}`}>
        {phaseConfig?.label}
      </div>

      {/* Steps */}
      <div className="space-y-2">
        {currentPhase?.steps?.map((step, i) => (
          <StepCard
            key={i}
            step={step}
            phaseConfig={phaseConfig ?? { bg: 'bg-slate-800/40', border: 'border-slate-700', color: 'text-slate-400' }}
            target={target}
            vulnResources={VULN_RESOURCES}
          />
        ))}
      </div>

      {/* Tips */}
      {activePhase === 'recon' && methodology.tips && (
        <div className="bg-cyan-500/5 border border-cyan-500/20 rounded-xl p-4 space-y-2">
          <div className="text-xs font-bold text-cyan-400 uppercase tracking-wider mb-2">💡 Pro Tips</div>
          {methodology.tips.map((tip, i) => (
            <div key={i} className="flex gap-2 text-sm text-slate-300">
              <CheckCircle className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0 mt-0.5" />
              {tip}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ─── Tab: Resources ───────────────────────────────────────────────────────────
const TabResources = ({ target }) => {
  const methodology = METHODOLOGY[target.asset_type] ?? METHODOLOGY.URL;
  // collect unique vulns from all steps
  const vulnKeys = [...new Set(
    methodology.phases.flatMap(ph => ph.steps.filter(s => s.vuln).map(s => s.vuln))
  )];

  return (
    <div className="space-y-4">
      {vulnKeys.length === 0 && (
        <p className="text-slate-400 text-sm">No vulnerability-specific resources for this asset type.</p>
      )}
      {vulnKeys.map(key => {
        const res = VULN_RESOURCES[key];
        if (!res) return null;
        return (
          <div key={key} className="bg-slate-800/60 rounded-xl p-4 space-y-3">
            <div className="font-bold text-white text-sm">{res.label}</div>
            <div className="space-y-2">
              {/* PortSwigger */}
              <a href={res.portswigger} target="_blank" rel="noopener noreferrer"
                 className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-orange-500/5 border border-orange-500/20 hover:bg-orange-500/15 transition-colors">
                <div className="w-8 h-8 rounded-lg bg-orange-500/20 flex items-center justify-center flex-shrink-0">
                  <Shield className="w-4 h-4 text-orange-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-bold text-orange-300">PortSwigger Web Academy</div>
                  <div className="text-[11px] text-slate-500 truncate">{res.portswigger}</div>
                </div>
                <ExternalLink className="w-3.5 h-3.5 text-slate-500" />
              </a>
              {/* HackTricks */}
              <a href={res.hacktricks} target="_blank" rel="noopener noreferrer"
                 className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-blue-500/5 border border-blue-500/20 hover:bg-blue-500/15 transition-colors">
                <div className="w-8 h-8 rounded-lg bg-blue-500/20 flex items-center justify-center flex-shrink-0">
                  <BookOpen className="w-4 h-4 text-blue-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-bold text-blue-300">HackTricks</div>
                  <div className="text-[11px] text-slate-500 truncate">{res.hacktricks}</div>
                </div>
                <ExternalLink className="w-3.5 h-3.5 text-slate-500" />
              </a>
              {/* OWASP */}
              <a href={res.owasp} target="_blank" rel="noopener noreferrer"
                 className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-green-500/5 border border-green-500/20 hover:bg-green-500/15 transition-colors">
                <div className="w-8 h-8 rounded-lg bg-green-500/20 flex items-center justify-center flex-shrink-0">
                  <FileText className="w-4 h-4 text-green-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-bold text-green-300">OWASP</div>
                  <div className="text-[11px] text-slate-500 truncate">{res.owasp}</div>
                </div>
                <ExternalLink className="w-3.5 h-3.5 text-slate-500" />
              </a>
              {/* YouTube */}
              {res.youtube?.map((yt, i) => (
                <a key={i} href={yt.url} target="_blank" rel="noopener noreferrer"
                   className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-red-500/5 border border-red-500/20 hover:bg-red-500/15 transition-colors">
                  <div className="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center flex-shrink-0">
                    <Youtube className="w-4 h-4 text-red-400" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-bold text-red-300">{yt.title}</div>
                    <div className="text-[11px] text-slate-500">YouTube Search</div>
                  </div>
                  <ExternalLink className="w-3.5 h-3.5 text-slate-500" />
                </a>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
};

// ─── Tab: Tools ───────────────────────────────────────────────────────────────
const TOOL_PHASE_LABELS = {
  recon:  { label: 'Recon Tools', color: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/20' },
  enum:   { label: 'Enum Tools',  color: 'text-purple-400', bg: 'bg-purple-500/10', border: 'border-purple-500/20' },
  test:   { label: 'Testing Tools', color: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20' },
  report: { label: 'Report Tools', color: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/20' },
};

const CATEGORY_ICONS = {
  subdomain: '🔍', urls: '🌐', osint: '🕵️', fuzz: '💥', params: '🔢',
  probe: '📡', screenshot: '📸', proxy: '🔀', scanner: '⚡', sqli: '💉',
  xss: '📜', ssrf: '🔗', takeover: '🏳️', cors: '🌍', scoring: '📊',
  oob: '📡', presentation: '🎨', browser: '🖥️',
};

const TabTools = () => (
  <div className="space-y-5">
    {Object.entries(TOOLS_BY_PHASE).map(([phase, tools]) => {
      const cfg = TOOL_PHASE_LABELS[phase];
      return (
        <div key={phase}>
          <div className={`text-xs font-bold uppercase tracking-wider ${cfg.color} mb-2`}>{cfg.label}</div>
          <div className="space-y-2">
            {tools.map(tool => (
              <a
                key={tool.name}
                href={tool.url}
                target="_blank"
                rel="noopener noreferrer"
                className={`flex items-center gap-3 px-3 py-2.5 rounded-xl ${cfg.bg} border ${cfg.border} hover:opacity-80 transition-opacity`}
              >
                <span className="text-lg">{CATEGORY_ICONS[tool.category] ?? '🔧'}</span>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-bold text-white">{tool.name}</div>
                  <div className="text-xs text-slate-400">{tool.desc}</div>
                </div>
                <ExternalLink className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
              </a>
            ))}
          </div>
        </div>
      );
    })}
  </div>
);

// ─── View mode toggle ─────────────────────────────────────────────────────────
// 'modal' | 'drawer' | 'page'
const VIEW_MODES = [
  { id: 'modal',  icon: Monitor,     label: 'Modal' },
  { id: 'drawer', icon: PanelRight,  label: 'Drawer' },
  { id: 'page',   icon: Maximize2,   label: 'Full Page' },
];

// ═══════════════════════════════════════════════════════════════════════════════
//  MAIN HUNT GUIDE MODAL COMPONENT
// ═══════════════════════════════════════════════════════════════════════════════
export default function HuntGuideModal({ target, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [viewMode,  setViewMode]  = useState('modal');   // 'modal' | 'drawer' | 'page'

  const methodology = METHODOLOGY[target.asset_type] ?? METHODOLOGY.URL;

  // Close on Escape
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  const TABS = [
    { id: 'overview',     label: 'Overview',     icon: Globe },
    { id: 'methodology',  label: 'Methodology',  icon: Target },
    { id: 'resources',    label: 'Resources',    icon: BookOpen },
    { id: 'tools',        label: 'Tools',        icon: Wrench },
  ];

  const tabContent = {
    overview:    <TabOverview target={target} methodology={methodology} />,
    methodology: <TabMethodology target={target} methodology={methodology} />,
    resources:   <TabResources target={target} />,
    tools:       <TabTools />,
  };

  // ── Modal layout ────────────────────────────────────────────────────────────
  if (viewMode === 'modal') {
    return (
      <div className="fixed inset-0 z-[9500] bg-black/80 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}>
        <div
          className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl"
          onClick={e => e.stopPropagation()}
        >
          <ModalHeader target={target} viewMode={viewMode} onViewMode={setViewMode} onClose={onClose} />
          <TabBar tabs={TABS} activeTab={activeTab} onTab={setActiveTab} />
          <div className="flex-1 overflow-y-auto p-5 space-y-4">{tabContent[activeTab]}</div>
        </div>
      </div>
    );
  }

  // ── Drawer layout ───────────────────────────────────────────────────────────
  if (viewMode === 'drawer') {
    return (
      <div className="fixed inset-0 z-[9500] flex" onClick={onClose}>
        <div className="flex-1 bg-black/60 backdrop-blur-sm" />
        <div
          className="bg-slate-900 border-l border-slate-700 w-full max-w-xl h-full flex flex-col shadow-2xl overflow-hidden"
          onClick={e => e.stopPropagation()}
        >
          <ModalHeader target={target} viewMode={viewMode} onViewMode={setViewMode} onClose={onClose} />
          <TabBar tabs={TABS} activeTab={activeTab} onTab={setActiveTab} />
          <div className="flex-1 overflow-y-auto p-5 space-y-4">{tabContent[activeTab]}</div>
        </div>
      </div>
    );
  }

  // ── Full page layout ────────────────────────────────────────────────────────
  return (
    <div className="fixed inset-0 z-[9500] bg-slate-950 flex flex-col overflow-hidden">
      <ModalHeader target={target} viewMode={viewMode} onViewMode={setViewMode} onClose={onClose} />
      <TabBar tabs={TABS} activeTab={activeTab} onTab={setActiveTab} />
      <div className="flex-1 overflow-y-auto p-6 max-w-4xl mx-auto w-full space-y-4">{tabContent[activeTab]}</div>
    </div>
  );
}

// ─── Shared sub-components ────────────────────────────────────────────────────
const ModalHeader = ({ target, viewMode, onViewMode, onClose }) => {
  const assetMeta = ASSET_TYPE_META[target.asset_type] ?? { icon: '📄' };
  return (
    <div className="flex items-center gap-3 px-5 py-4 border-b border-slate-800 flex-shrink-0">
      <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center flex-shrink-0">
        <Target className="w-4.5 h-4.5 text-white" />
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-sm font-bold text-white truncate">Hunt Guide — {target.program_name}</div>
        <div className="flex items-center gap-1.5">
          <span className="text-sm">{assetMeta.icon}</span>
          <code className="text-cyan-400 text-xs font-mono truncate">{target.asset}</code>
        </div>
      </div>
      {/* View mode toggles */}
      <div className="flex items-center gap-1 bg-slate-800 rounded-xl p-1">
        {VIEW_MODES.map(({ id, icon: Icon, label }) => (
          <button
            key={id}
            onClick={() => onViewMode(id)}
            title={label}
            className={`p-1.5 rounded-lg transition-colors ${
              viewMode === id ? 'bg-slate-600 text-white' : 'text-slate-500 hover:text-white'
            }`}
          >
            <Icon className="w-3.5 h-3.5" />
          </button>
        ))}
      </div>
      <button onClick={onClose} className="p-1.5 rounded-lg text-slate-500 hover:text-white hover:bg-slate-800 transition-colors">
        <X className="w-4 h-4" />
      </button>
    </div>
  );
};

const TabBar = ({ tabs, activeTab, onTab }) => (
  <div className="flex border-b border-slate-800 flex-shrink-0 overflow-x-auto">
    {tabs.map(({ id, label, icon: Icon }) => (
      <button
        key={id}
        onClick={() => onTab(id)}
        className={`flex items-center gap-1.5 px-4 py-3 text-sm font-semibold whitespace-nowrap border-b-2 transition-colors ${
          activeTab === id
            ? 'border-purple-500 text-white'
            : 'border-transparent text-slate-400 hover:text-white'
        }`}
      >
        <Icon className="w-3.5 h-3.5" /> {label}
      </button>
    ))}
  </div>
);
