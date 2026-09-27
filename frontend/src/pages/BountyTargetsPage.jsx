import { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import {
  Target, RefreshCw, Search, ExternalLink,
  BookmarkPlus, BookmarkCheck, Zap, Clock, ChevronLeft,
  ChevronRight, Shield, AlertTriangle, CheckCircle,
  XCircle, Crosshair, Calendar, Info, Star,
  HelpCircle, Lock, Unlock, ChevronDown, ChevronUp,
  Globe, Sliders, GraduationCap, ShieldAlert,
} from 'lucide-react';
import {
  PLATFORM_META, SEVERITY_CONFIG, ASSET_TYPE_META, METHODOLOGY,
} from '../utils/huntGuideData';
import HuntGuideModal from '../components/HuntGuideModal';

// ─── localStorage bookmark helpers ────────────────────────────────────────────
const BOOKMARK_KEY = 'hexaguard_bb_bookmarks';
const getBookmarks = () => {
  try { return JSON.parse(localStorage.getItem(BOOKMARK_KEY) || '[]'); } catch { return []; }
};
const setBookmarks = (arr) => localStorage.setItem(BOOKMARK_KEY, JSON.stringify(arr));
const makeTargetId = (t) => `${t.platform}::${t.program_handle}::${t.asset}`;

// ─── Stat mini-card ────────────────────────────────────────────────────────────
const MiniStat = ({ label, value, icon: Icon, color }) => (
  <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex items-center gap-3">
    <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${color}`}>
      <Icon className="w-5 h-5" />
    </div>
    <div>
      <div className="text-2xl font-bold text-white tabular-nums">{value ?? '—'}</div>
      <div className="text-xs text-slate-400 mt-0.5">{label}</div>
    </div>
  </div>
);

// ─── Platform badge ────────────────────────────────────────────────────────────
const PlatformBadge = ({ platform }) => {
  const meta = PLATFORM_META[platform] ?? { label: platform, color: 'bg-slate-500/20 text-slate-300 border-slate-500/30', icon: '●' };
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold border ${meta.color}`}>
      {meta.icon} {meta.label}
    </span>
  );
};

// ─── Severity badge ────────────────────────────────────────────────────────────
const SeverityBadge = ({ sev }) => {
  const s = sev?.toLowerCase();
  const cfg = SEVERITY_CONFIG[s] ?? SEVERITY_CONFIG.low;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-semibold border ${cfg.color}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
};

// ─── Policy & Tier Badge ──────────────────────────────────────────────────────
// Maps 3-tier model and 5-bucket classification statuses to UI config.
const POLICY_CFG = {
  // Mandatory Part B Tiers
  VERIFIED_AUTOMATED_ALLOWED:        { icon: CheckCircle, label: 'Verified Automated Allowed (Tier 1)', cls: 'text-green-400',  bg: 'bg-green-500/10 border-green-500/30' },
  MANUAL_VERIFICATION_REQUIRED:      { icon: ShieldAlert, label: 'Manual Verification Required (Tier 0)', cls: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30' },
  OUT_OF_SCOPE:                      { icon: Lock,        label: 'Out of Scope / Prohibited',           cls: 'text-red-400',    bg: 'bg-red-500/10 border-red-500/30' },

  // Five-bucket status constants
  AUTHORIZED_FOR_AUTOMATED_SCANNING: { icon: CheckCircle, label: 'Auto Scan Authorized (Tier 1)',      cls: 'text-green-400',  bg: 'bg-green-500/10 border-green-500/30' },
  AUTHORIZED_FOR_MANUAL_REVIEW:      { icon: Unlock,       label: 'Manual Review OK (Tier 0)',           cls: 'text-blue-400',   bg: 'bg-blue-500/10  border-blue-500/30' },
  UNKNOWN_AUTHORIZATION:             { icon: HelpCircle,   label: 'Manual Verification Required (Tier 0)', cls: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30' },

  // Legacy aliases
  ALLOWED:    { icon: CheckCircle, label: 'Scan Allowed',   cls: 'text-green-400',  bg: 'bg-green-500/10 border-green-500/30' },
  RESTRICTED: { icon: Lock,        label: 'Restricted',     cls: 'text-red-400',    bg: 'bg-red-500/10 border-red-500/30' },
  UNKNOWN:    { icon: HelpCircle,  label: 'Policy Unknown', cls: 'text-slate-400',  bg: 'bg-slate-500/10 border-slate-500/30' },
};
const DEFAULT_POLICY_CFG = { icon: HelpCircle, label: 'Manual Verification Required (Tier 0)', cls: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30' };

const PolicyBadge = ({ policy, tier, expanded, onToggle }) => {
  const s   = tier ?? policy?.status ?? 'MANUAL_VERIFICATION_REQUIRED';
  const cfg = POLICY_CFG[s] ?? DEFAULT_POLICY_CFG;
  const Icon = cfg.icon;
  const conf = policy?.confidence ?? 0;
  return (
    <div className="space-y-1.5">
      <button
        onClick={onToggle}
        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-semibold border transition-colors ${cfg.cls} ${cfg.bg}`}
      >
        <Icon className="w-3 h-3" />
        {cfg.label}
        {conf > 0 && <span className="opacity-60">{conf}%</span>}
        {policy?.signals?.length > 0 && (
          expanded ? <ChevronUp className="w-2.5 h-2.5 ml-0.5" /> : <ChevronDown className="w-2.5 h-2.5 ml-0.5" />
        )}
      </button>
      {expanded && policy?.signals?.length > 0 && (
        <div className="ml-1 space-y-0.5">
          {policy.signals.map((sig, i) => (
            <div key={i} className="text-[10px] text-slate-400 font-mono flex gap-1">
              <span className={
                sig.startsWith('+') ? 'text-green-400' :
                sig.startsWith('-') ? 'text-red-400' : 'text-yellow-400'
              }>{sig.charAt(0)}</span>
              <span>{sig.slice(2)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// ─── Target card ──────────────────────────────────────────────────────────────
const TargetCard = ({ target, bookmarked, onToggleBookmark, onHuntGuide, onLaunchScan, onSchedule, onRecon, onHistory }) => {
  const assetMeta      = ASSET_TYPE_META[target.asset_type] ?? { icon: '📄', label: target.asset_type };
  const hasMethodology = !!METHODOLOGY[target.asset_type];
  const policy         = target.scan_policy ?? { status: 'UNKNOWN', confidence: 0, signals: [] };
  const [policyExpanded, setPolicyExpanded] = useState(false);

  return (
    <div className="group bg-slate-900 border border-slate-800 hover:border-slate-600 rounded-2xl p-5 transition-all duration-200 hover:shadow-lg hover:shadow-black/40 flex flex-col gap-3">
      {/* Header row */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 flex-wrap">
          <PlatformBadge platform={target.platform} />
          {target.eligible_bounty && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold border bg-yellow-500/10 text-yellow-300 border-yellow-500/30">
              <Star className="w-3 h-3" /> Bounty
            </span>
          )}
          {target.managed && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold border bg-purple-500/10 text-purple-300 border-purple-500/30">
              Managed
            </span>
          )}
        </div>
        <button
          onClick={() => onToggleBookmark(target)}
          title={bookmarked ? 'Remove bookmark' : 'Bookmark this target'}
          className={`p-1.5 rounded-lg transition-colors flex-shrink-0 ${
            bookmarked
              ? 'text-cyan-400 bg-cyan-500/10'
              : 'text-slate-500 hover:text-cyan-400 hover:bg-cyan-500/10'
          }`}
        >
          {bookmarked ? <BookmarkCheck className="w-4 h-4" /> : <BookmarkPlus className="w-4 h-4" />}
        </button>
      </div>

      {/* Program name */}
      <div>
        <div className="text-sm font-bold text-white leading-tight">{target.program_name}</div>
        <div className="flex items-center gap-1.5 mt-1">
          <span className="text-lg">{assetMeta.icon}</span>
          <code className="text-cyan-400 text-sm font-mono break-all">{target.asset}</code>
        </div>
      </div>

      {/* Meta row */}
      <div className="flex items-center gap-2 flex-wrap">
        <SeverityBadge sev={target.max_severity} />
        <span className="text-xs text-slate-500">{assetMeta.label}</span>
        {target.avg_response_h && (
          <span className="text-xs text-slate-500 flex items-center gap-1">
            <Clock className="w-3 h-3" /> ~{Math.round(target.avg_response_h)}h response
          </span>
        )}

        {/* Safe Harbor Badge (P3.1) */}
        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold border ${
          target.has_safe_harbor
            ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
            : 'bg-slate-800 text-slate-400 border-slate-700'
        }`}>
          <Shield className="w-3 h-3 text-emerald-400" />
          {target.has_safe_harbor ? 'Safe Harbor' : 'No Safe Harbor'}
        </span>

        {/* Expected ROI Score (P3.3) */}
        {target.expected_value_score !== undefined && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold border bg-indigo-500/10 text-indigo-300 border-indigo-500/30" title="Expected ROI / Value Score">
            <Zap className="w-3 h-3 text-indigo-400" /> ROI: {target.expected_value_score}/100
          </span>
        )}

        {/* Learn & Earn Score (Part 4) */}
        {target.learn_earn_score !== undefined && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold border bg-purple-500/10 text-purple-300 border-purple-500/30" title="Learn & Earn Rank Score">
            <GraduationCap className="w-3 h-3 text-purple-400" /> Learn+Earn: {target.learn_earn_score}
          </span>
        )}
      </div>

      {/* Policy & Tier badge — expandable signals */}
      <PolicyBadge
        policy={policy}
        tier={target.authorization_tier}
        expanded={policyExpanded}
        onToggle={() => setPolicyExpanded(v => !v)}
      />

      {/* Suggested Training Labs / Lessons */}
      {target.suggested_lessons?.length > 0 && (
        <div className="flex items-center gap-1.5 flex-wrap pt-0.5">
          <span className="text-[11px] text-slate-400 flex items-center gap-1 font-medium">
            <GraduationCap className="w-3 h-3 text-purple-400" /> Prep Labs:
          </span>
          {target.suggested_lessons.slice(0, 4).map((les) => (
            <a
              key={les}
              href={`/learn/${les}`}
              className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/25 hover:bg-purple-500/20 hover:text-white transition-colors"
              title={`Practice ${les} in HexaGuard Encyclopedia`}
            >
              {les}
            </a>
          ))}
        </div>
      )}

      {/* Instruction warning */}
      {target.instruction && (
        <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-lg px-3 py-2 text-xs text-yellow-300 flex gap-2">
          <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
          <span className="line-clamp-2">{target.instruction}</span>
        </div>
      )}

      {/* Action buttons */}
      <div className="flex items-center gap-2 flex-wrap pt-1 border-t border-slate-800">
        {/* View scope */}
        <a
          href={target.program_url}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 transition-colors"
        >
          <ExternalLink className="w-3 h-3" /> View Scope
        </a>

        {/* Hunt Guide */}
        <button
          onClick={() => onHuntGuide(target)}
          disabled={!hasMethodology}
          title={hasMethodology ? 'Open Hunt Guide' : 'No methodology for this asset type'}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 transition-all disabled:opacity-40 disabled:cursor-not-allowed shadow-sm shadow-purple-500/20"
        >
          <Target className="w-3 h-3" /> Hunt Guide
        </button>

        {/* Wildcard Recon (P1.2) */}
        {(target.asset?.startsWith('*.') || target.asset_type === 'WILDCARD') && (
          <button
            onClick={() => onRecon(target)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-cyan-300 bg-cyan-950/70 hover:bg-cyan-900 border border-cyan-800 hover:border-cyan-500 transition-all shadow-sm"
            title="Discover and probe subdomains"
          >
            <Globe className="w-3 h-3" /> Recon
          </button>
        )}

        {/* History & Diff (P2.1) */}
        <button
          onClick={() => onHistory(target)}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 transition-colors"
          title="Scan history & differential analysis"
        >
          <Clock className="w-3 h-3 text-indigo-400" /> History
        </button>

        {/* Launch Scan / Policy Review */}
        <button
          onClick={() => onLaunchScan(target)}
          title={target.auto_scan_ok ? 'Launch automated scan' : 'Review target policy before testing'}
          className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all shadow-sm ${
            target.auto_scan_ok
              ? 'text-white bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 shadow-emerald-500/20'
              : target.authorization_tier === 'OUT_OF_SCOPE'
              ? 'text-red-400 bg-red-950/40 border border-red-900/50'
              : 'text-amber-300 bg-amber-950/40 hover:bg-amber-900/50 border border-amber-800/60'
          }`}
        >
          {target.auto_scan_ok ? <Zap className="w-3 h-3" /> : target.authorization_tier === 'OUT_OF_SCOPE' ? <Lock className="w-3 h-3" /> : <ShieldAlert className="w-3 h-3" />}
          {target.auto_scan_ok ? 'Scan Now' : target.authorization_tier === 'OUT_OF_SCOPE' ? 'Prohibited' : 'Policy / Gate'}
        </button>

        {/* Schedule */}
        <button
          onClick={() => onSchedule(target)}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 hover:border-slate-600 transition-colors"
        >
          <Calendar className="w-3 h-3" /> Schedule
        </button>
      </div>
    </div>
  );
};

// ─── Policy Gate Modal (Tier-aware with Engine & Rate Controls) ────────────────
const PolicyGateModal = ({ target, onClose, onConfirm }) => {
  const policy    = target?.scan_policy ?? { status: 'UNKNOWN', confidence: 0, signals: [] };
  const status    = policy.status;
  const tier      = target?.authorization_tier ?? 'MANUAL_VERIFICATION_REQUIRED';
  const asset     = target?.asset?.replace(/^\*\./, '') ?? '';
  const [checked, setChecked] = useState(false);

  const isTier1    = tier === 'VERIFIED_AUTOMATED_ALLOWED';
  const isBlocked  = tier === 'OUT_OF_SCOPE' || status === 'OUT_OF_SCOPE';
  const isTier0    = !isTier1 && !isBlocked;

  // P1.1: Engine selection and rate limits
  const [rateLimit, setRateLimit] = useState(isBlocked ? 5 : 50);
  const [threads, setThreads] = useState(isBlocked ? 1 : 3);
  const [engineNuclei, setEngineNuclei] = useState(true);
  const [engineZap, setEngineZap] = useState(true);
  const [engineNikto, setEngineNikto] = useState(true);
  const [customAttribution, setCustomAttribution] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const hasEngines   = engineNuclei || engineZap || engineNikto;
  // Safety Boundary B7: Automated scanning is ONLY enabled for Tier 1 verified affirmative targets.
  const canProceed   = isTier1 && hasEngines;

  const statusConfig = {
    VERIFIED_AUTOMATED_ALLOWED:   { icon: CheckCircle, title: 'Tier 1: Verified Automated Allowed',   color: 'text-green-400',  bg: 'bg-green-500/10 border-green-500/30',   msg: 'Affirmative written authorization for automated testing has been verified for this program.' },
    MANUAL_VERIFICATION_REQUIRED: { icon: ShieldAlert, title: 'Tier 0: Manual Verification Required',  color: 'text-amber-400',  bg: 'bg-amber-500/10 border-amber-500/30',   msg: 'SecuraX cannot prove affirmative automated authorization from this data source. Automated scanning is locked. Only manual testing following program rules is permitted.' },
    OUT_OF_SCOPE:                 { icon: Lock,        title: 'Out of Scope / Prohibited',            color: 'text-red-400',    bg: 'bg-red-500/10 border-red-500/30',       msg: 'This target is explicitly OUT OF SCOPE or prohibits automated scanning. Testing is prohibited.' },
  };
  const sc = statusConfig[tier] ?? statusConfig.MANUAL_VERIFICATION_REQUIRED;
  const Ico = sc.icon;

  const handleProceed = () => {
    const enabledEngines = [];
    if (engineNuclei) enabledEngines.push('nuclei');
    if (engineZap)    enabledEngines.push('zap');
    if (engineNikto)  enabledEngines.push('nikto');

    onConfirm(target, {
      rateLimit,
      threads,
      enabledEngines: enabledEngines.length > 0 ? enabledEngines : ['nuclei'],
      attributionHeader: customAttribution.trim() || undefined,
    });
  };

  return (
    <div className="fixed inset-0 z-[9200] bg-black/80 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-lg shadow-2xl max-h-[90vh] flex flex-col" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className={`flex items-center gap-3 px-6 pt-6 pb-4 rounded-t-2xl border-b border-slate-800`}>
          <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${sc.bg}`}>
            <Ico className={`w-5 h-5 ${sc.color}`} />
          </div>
          <div>
            <div className={`font-bold text-sm ${sc.color}`}>{sc.title}</div>
            <div className="text-xs text-slate-400 mt-0.5">Confidence: {policy.confidence}%</div>
          </div>
        </div>

        <div className="px-6 py-5 space-y-4 overflow-y-auto flex-1">
          {/* Target */}
          <div className="bg-slate-800 rounded-xl px-4 py-3">
            <div className="text-xs text-slate-500 mb-1">Target</div>
            <code className="text-cyan-400 text-sm font-mono">{asset}</code>
            <div className="text-xs text-slate-500 mt-1">{target?.program_name}</div>
          </div>

          {/* Policy message */}
          <p className="text-sm text-slate-300">{sc.msg}</p>

          {/* Signals */}
          {policy.signals?.length > 0 && (
            <div className="bg-slate-800/60 rounded-xl p-4 space-y-1.5">
              <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Policy Signals</div>
              {policy.signals.map((sig, i) => (
                <div key={i} className="flex gap-2 text-xs font-mono">
                  <span className={
                    sig.startsWith('+') ? 'text-green-400' :
                    sig.startsWith('-') ? 'text-red-400' : 'text-yellow-400'
                  }>{sig.charAt(0)}</span>
                  <span className="text-slate-300">{sig.slice(2)}</span>
                </div>
              ))}
            </div>
          )}

          {/* Open program policy */}
          <a
            href={target?.program_url}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 text-xs text-cyan-400 hover:underline"
          >
            <ExternalLink className="w-3 h-3" /> Open full program policy
          </a>

          {/* P1.1 Engine & Rate Controls */}
          <div className="bg-slate-800/80 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <div className="flex items-center justify-between">
              <div className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                <Sliders className="w-3.5 h-3.5 text-cyan-400" />
                Engines & Rate Limits (P1.1)
              </div>
              <button
                type="button"
                onClick={() => setShowAdvanced(s => !s)}
                className="text-[11px] text-cyan-400 hover:underline font-semibold"
              >
                {showAdvanced ? 'Simple View' : 'Adjust Sliders'}
              </button>
            </div>

            {/* Active engines checkboxes */}
            <div className="flex items-center gap-4 text-xs text-slate-300">
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={engineNuclei}
                  onChange={e => setEngineNuclei(e.target.checked)}
                  className="accent-cyan-400 rounded"
                />
                <span>Nuclei</span>
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={engineZap}
                  onChange={e => setEngineZap(e.target.checked)}
                  className="accent-cyan-400 rounded"
                />
                <span>ZAP</span>
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={engineNikto}
                  onChange={e => setEngineNikto(e.target.checked)}
                  className="accent-cyan-400 rounded"
                />
                <span>Nikto</span>
              </label>
            </div>

            {showAdvanced && (
              <div className="pt-2 space-y-3 border-t border-slate-700/50">
                {/* Rate limit slider */}
                <div>
                  <div className="flex justify-between text-xs text-slate-400 mb-1">
                    <span>Scan Rate</span>
                    <span className="font-mono text-cyan-400 font-bold">{rateLimit} req/s</span>
                  </div>
                  <input
                    type="range"
                    min="1"
                    max="150"
                    value={rateLimit}
                    onChange={e => setRateLimit(Number(e.target.value))}
                    className="w-full h-1.5 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-cyan-400"
                  />
                </div>

                {/* Threads slider */}
                <div>
                  <div className="flex justify-between text-xs text-slate-400 mb-1">
                    <span>Concurrency</span>
                    <span className="font-mono text-cyan-400 font-bold">{threads} worker(s)</span>
                  </div>
                  <input
                    type="range"
                    min="1"
                    max="5"
                    value={threads}
                    onChange={e => setThreads(Number(e.target.value))}
                    className="w-full h-1.5 bg-slate-700 rounded-lg appearance-none cursor-pointer accent-cyan-400"
                  />
                </div>

                {/* Attribution Header input */}
                <div>
                  <div className="text-xs text-slate-400 mb-1">Researcher Attribution Header (P1.3)</div>
                  <input
                    type="text"
                    value={customAttribution}
                    onChange={e => setCustomAttribution(e.target.value)}
                    placeholder="Default: SecuraX-Bounty-Scanner/1.0 (+user: <you>)"
                    className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>
            )}
          </div>

          {/* Tier 0 / Out of Scope Safety Notice */}
          {!isTier1 && (
            <div className={`rounded-xl p-4 border text-xs leading-relaxed flex gap-3 ${
              isBlocked
                ? 'bg-red-500/10 border-red-500/30 text-red-300'
                : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
            }`}>
              <ShieldAlert className="w-5 h-5 flex-shrink-0 mt-0.5" />
              <div>
                <strong>{isBlocked ? 'Automated Scanning Prohibited' : 'Tier 0: Automated Scanning Locked'}</strong>
                <p className="mt-1 text-slate-300">
                  {isBlocked
                    ? 'This target prohibits automated testing or is out of scope. Automated scanning cannot be launched.'
                    : 'SecuraX cannot verify affirmative written authorization for automated scanning on this target. Automated scanners are locked by default. Always verify target policy on the official program page before manual testing.'}
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="flex gap-3 px-6 pb-6 pt-3 border-t border-slate-800">
          <button
            onClick={onClose}
            className="flex-1 py-2.5 rounded-xl border border-slate-700 text-slate-300 text-sm font-semibold hover:bg-slate-800 transition-colors"
          >
            Close
          </button>
          {isTier1 ? (
            <button
              onClick={handleProceed}
              disabled={!canProceed}
              className="flex-1 py-2.5 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-sm font-semibold transition-all shadow-sm disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Zap className="w-3.5 h-3.5 inline mr-1.5" />
              Launch Scan
            </button>
          ) : (
            <a
              href={target?.program_url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex-1 py-2.5 rounded-xl text-center inline-flex items-center justify-center gap-1.5 bg-gradient-to-r from-slate-800 to-slate-700 hover:from-slate-700 hover:to-slate-600 border border-slate-600 text-white text-sm font-semibold transition-all shadow-sm"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              Open Program Scope
            </a>
          )}
        </div>
      </div>
    </div>
  );
};

// ─── Wildcard Reconnaissance Modal (P1.2) ──────────────────────────────────────
const WildcardReconModal = ({ target, onClose, onSelectSubdomain }) => {
  const isRestricted = target?.scan_policy?.status === 'RESTRICTED' || target?.scan_policy?.status === 'UNKNOWN';
  const [probeAlive, setProbeAlive] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [loading, setLoading] = useState(false);
  const [subdomains, setSubdomains] = useState([]);
  const [error, setError] = useState('');
  const [ranProbe, setRanProbe] = useState(false);

  const fetchSubdomains = async (withProbe) => {
    setLoading(true);
    setError('');
    try {
      const payload = {
        domain: target.asset,
        bounty_context: {
          asset: target.asset,
          platform: target.platform,
          program_handle: target.program_handle,
          scan_policy: target.scan_policy,
          acknowledged: Boolean(withProbe ? acknowledged : false),
        },
        probe_alive: Boolean(withProbe),
      };
      const { data } = await axios.post('/api/bounty/recon/subdomains', payload, { withCredentials: true });
      setSubdomains(data.results || []);
      setRanProbe(Boolean(withProbe));
    } catch (err) {
      setError(err.response?.data?.error || err.message || 'Failed to discover subdomains');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // Initial passive discovery (safe: zero target packets)
    fetchSubdomains(false);
  }, [target]);

  return (
    <div className="fixed inset-0 z-[9300] bg-black/80 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
              <Globe className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h3 className="font-bold text-sm text-white flex items-center gap-2">
                Subdomain Recon: <span className="font-mono text-cyan-400">{target.asset}</span>
              </h3>
              <p className="text-xs text-slate-400">{target.program_name} ({target.platform})</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white p-1 rounded-lg">
            ✕
          </button>
        </div>

        {/* Content */}
        <div className="px-6 py-4 overflow-y-auto flex-1 space-y-4">
          {/* Controls Bar */}
          <div className="bg-slate-800/80 rounded-xl p-4 border border-slate-700/60 space-y-3">
            <div className="flex items-center justify-between">
              <div className="text-xs font-semibold text-slate-300">
                Discovery Mode:
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-xs ${!probeAlive ? 'text-cyan-400 font-bold' : 'text-slate-400'}`}>Passive (CT logs)</span>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={probeAlive}
                    onChange={e => setProbeAlive(e.target.checked)}
                    className="sr-only peer"
                  />
                  <div className="w-9 h-5 bg-slate-700 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-cyan-600"></div>
                </label>
                <span className={`text-xs ${probeAlive ? 'text-cyan-400 font-bold' : 'text-slate-400'}`}>Active (HEAD probe)</span>
              </div>
            </div>

            {probeAlive && isRestricted && (
              <label className="flex items-start gap-2.5 cursor-pointer bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3">
                <input
                  type="checkbox"
                  checked={acknowledged}
                  onChange={e => setAcknowledged(e.target.checked)}
                  className="w-4 h-4 mt-0.5 accent-yellow-400 flex-shrink-0"
                />
                <span className="text-xs text-yellow-200">
                  Target policy is {target.scan_policy?.status}. I confirm I am authorized to send HTTP probes to discovered subdomains.
                </span>
              </label>
            )}

            <div className="flex justify-end">
              <button
                onClick={() => fetchSubdomains(probeAlive)}
                disabled={loading || (probeAlive && isRestricted && !acknowledged)}
                className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1.5 transition-colors"
              >
                <RefreshCw className={`w-3 h-3 ${loading ? 'animate-spin' : ''}`} />
                {probeAlive ? 'Run Active Alive-Check' : 'Refresh Passive CT Logs'}
              </button>
            </div>
          </div>

          {error && (
            <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-300">
              {error}
            </div>
          )}

          {/* Results List */}
          <div>
            <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
              <span>Discovered Subdomains ({subdomains.length})</span>
              {ranProbe && <span className="text-green-400">Alive: {subdomains.filter(s => s.alive).length}</span>}
            </div>

            {loading ? (
              <div className="py-12 flex flex-col items-center justify-center gap-2 text-slate-400">
                <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
                <span className="text-xs">Querying Certificate Transparency & Probing...</span>
              </div>
            ) : subdomains.length === 0 ? (
              <div className="py-12 text-center text-xs text-slate-500">
                No subdomains found yet. Try refreshing or checking the base domain.
              </div>
            ) : (
              <div className="space-y-2">
                {subdomains.map((item, i) => (
                  <div key={i} className="flex items-center justify-between p-3 rounded-xl bg-slate-800/50 border border-slate-700/50 hover:border-slate-600 transition-colors">
                    <div className="min-w-0 flex items-center gap-2.5">
                      <span className={`w-2 h-2 rounded-full flex-shrink-0 ${item.alive === true ? 'bg-green-400' : item.alive === false ? 'bg-red-400' : 'bg-slate-500'}`} />
                      <div className="truncate">
                        <div className="text-xs font-mono font-semibold text-slate-200 truncate">{item.subdomain}</div>
                        <div className="text-[10px] text-slate-500 flex items-center gap-2 mt-0.5">
                          {item.ip && <span>IP: {item.ip}</span>}
                          {item.server && <span>Server: {item.server}</span>}
                          {item.status_code && <span>Status: {item.status_code}</span>}
                          {item.duplicate_fingerprint && <span className="text-yellow-400">duplicate IP</span>}
                          {item.status === 'unprobed' && <span className="italic">Unprobed (passive)</span>}
                        </div>
                      </div>
                    </div>
                    <button
                      onClick={() => onSelectSubdomain(item.subdomain)}
                      className="px-3 py-1 rounded-lg text-xs font-semibold text-white bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 transition-all ml-3 flex-shrink-0"
                    >
                      Scan Subdomain
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// ─── Schedule Modal ────────────────────────────────────────────────────────────
const ScheduleModal = ({ target, onClose, onConfirm }) => {
  const [mode, setMode]         = useState('now');   // 'now' | 'scheduled'
  const [scanType, setScanType] = useState('web');
  const [cronExpr, setCronExpr] = useState('daily');
  const [policyAck, setPolicyAck] = useState(false);

  const asset  = target?.asset?.replace(/^\*\./, '') ?? '';
  const policy = target?.scan_policy ?? { status: 'UNKNOWN' };
  const needsAck = policy.status !== 'ALLOWED';

  return (
    <div className="fixed inset-0 z-[9000] bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-md p-6 shadow-2xl" onClick={e => e.stopPropagation()}>
        <h3 className="text-lg font-bold text-white mb-1 flex items-center gap-2">
          <Calendar className="w-5 h-5 text-cyan-400" /> Schedule / Run Scan
        </h3>
        <p className="text-sm text-slate-400 mb-5">
          Target: <code className="text-cyan-400">{asset}</code>
        </p>

        {/* Mode select */}
        <div className="flex rounded-xl overflow-hidden border border-slate-700 mb-5">
          {[{ id: 'now', label: '⚡ Run Now' }, { id: 'scheduled', label: '🗓 Schedule' }].map(m => (
            <button
              key={m.id}
              onClick={() => setMode(m.id)}
              className={`flex-1 py-2 text-sm font-semibold transition-colors ${
                mode === m.id ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-white hover:bg-slate-800'
              }`}
            >
              {m.label}
            </button>
          ))}
        </div>

        {/* Scan type */}
        <label className="block text-xs text-slate-400 mb-1.5 font-semibold uppercase tracking-wider">Scan Type</label>
        <select
          value={scanType}
          onChange={e => setScanType(e.target.value)}
          className="w-full bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white mb-4 focus:outline-none focus:border-cyan-500"
        >
          <option value="web">Web Scan</option>
          <option value="dast">DAST</option>
          <option value="ssl">SSL/TLS</option>
          <option value="network">Network</option>
          <option value="dns">DNS</option>
        </select>

        {/* Cron (only if scheduled) */}
        {mode === 'scheduled' && (
          <>
            <label className="block text-xs text-slate-400 mb-1.5 font-semibold uppercase tracking-wider">Frequency</label>
            <select
              value={cronExpr}
              onChange={e => setCronExpr(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white mb-4 focus:outline-none focus:border-cyan-500"
            >
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </select>
            {/* Schedule policy warning */}
            <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-xl p-3 text-xs text-yellow-300 flex gap-2 mb-4">
              <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
              <span>Scheduled scans will verify the target is still in scope before each run. Scans on out-of-scope targets are automatically cancelled.</span>
            </div>
          </>
        )}

        {/* Policy ack for non-ALLOWED */}
        {needsAck && (
          <label className="flex items-start gap-3 cursor-pointer bg-yellow-500/5 border border-yellow-500/20 rounded-xl p-3 mb-4">
            <input
              type="checkbox"
              checked={policyAck}
              onChange={e => setPolicyAck(e.target.checked)}
              className="w-4 h-4 mt-0.5 accent-yellow-400 flex-shrink-0"
            />
            <span className="text-xs text-yellow-200">I have verified this target's policy (status: <strong>{policy.status}</strong>) and accept responsibility.</span>
          </label>
        )}

        <div className="flex gap-3">
          <button
            onClick={onClose}
            className="flex-1 py-2.5 rounded-xl border border-slate-700 text-slate-300 text-sm font-semibold hover:bg-slate-800 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={() => onConfirm({ mode, scanType, cronExpr, target: asset })}
            disabled={needsAck && !policyAck}
            className="flex-1 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-sm font-semibold transition-all shadow-sm disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {mode === 'now' ? '⚡ Launch' : '🗓 Schedule'}
          </button>
        </div>
      </div>
    </div>
  );
};

// ─── Target Scan History & Differential Analysis Modal (P2.1) ─────────────────
const TargetHistoryModal = ({ target, onClose }) => {
  const [historyData, setHistoryData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!target) return;
    setLoading(true);
    axios.get('/api/bounty/targets/history', {
      params: { asset: target.asset, platform: target.platform },
      withCredentials: true,
    })
      .then(res => setHistoryData(res.data))
      .catch(err => setError(err.response?.data?.error || 'Failed to load target history.'))
      .finally(() => setLoading(false));
  }, [target]);

  if (!target) return null;

  const diff = historyData?.differential || {};

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center">
              <Clock className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <h3 className="font-bold text-sm text-white flex items-center gap-2">
                Scan History & Differential Analysis
              </h3>
              <p className="text-xs text-slate-400 font-mono">{target.asset}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white p-1 rounded-lg">✕</button>
        </div>

        <div className="px-6 py-4 overflow-y-auto flex-1 space-y-5">
          {loading && (
            <div className="py-12 text-center text-slate-400 text-sm flex items-center justify-center gap-2">
              <RefreshCw className="w-4 h-4 animate-spin text-indigo-400" /> Loading scan history…
            </div>
          )}

          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl text-red-400 text-xs">{error}</div>
          )}

          {!loading && !error && historyData && (
            <>
              {/* Stats summary row */}
              <div className="grid grid-cols-3 gap-3">
                <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl p-3 text-center">
                  <div className="text-xs text-slate-400">Total Scans</div>
                  <div className="text-xl font-bold text-white mt-0.5">{historyData.total_scans}</div>
                </div>
                <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-3 text-center">
                  <div className="text-xs text-emerald-400">New Findings (Diff)</div>
                  <div className="text-xl font-bold text-emerald-300 mt-0.5">+{diff.new_count || 0}</div>
                </div>
                <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-3 text-center">
                  <div className="text-xs text-blue-400">Resolved (Diff)</div>
                  <div className="text-xl font-bold text-blue-300 mt-0.5">✓ {diff.resolved_count || 0}</div>
                </div>
              </div>

              {/* New and Resolved Findings details */}
              {(diff.new_findings?.length > 0 || diff.resolved_findings?.length > 0) && (
                <div className="space-y-3">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Differential Insights</h4>
                  {diff.new_findings?.map((f, idx) => (
                    <div key={`new-${idx}`} className="flex items-center justify-between p-2.5 rounded-lg bg-emerald-950/30 border border-emerald-500/30 text-xs">
                      <div className="flex items-center gap-2">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-500 text-black uppercase">+ NEW</span>
                        <span className="text-white font-medium">{f.title || f.check}</span>
                      </div>
                      <span className="text-slate-400 uppercase text-[10px]">{f.severity}</span>
                    </div>
                  ))}
                  {diff.resolved_findings?.map((f, idx) => (
                    <div key={`res-${idx}`} className="flex items-center justify-between p-2.5 rounded-lg bg-blue-950/30 border border-blue-500/30 text-xs">
                      <div className="flex items-center gap-2">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-blue-500 text-white uppercase">✓ RESOLVED</span>
                        <span className="text-slate-300 line-through">{f.title || f.check}</span>
                      </div>
                      <span className="text-slate-500 uppercase text-[10px]">{f.severity}</span>
                    </div>
                  ))}
                </div>
              )}

              {/* Historical scans list */}
              <div className="space-y-2">
                <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Previous Scans ({historyData.scans?.length || 0})</h4>
                {historyData.scans?.length === 0 ? (
                  <div className="p-6 text-center text-slate-500 text-xs bg-slate-800/40 rounded-xl border border-slate-700/40">
                    No scan records found for this asset yet. Launch a scan to start tracking history!
                  </div>
                ) : (
                  historyData.scans.map((sc, idx) => (
                    <div key={idx} className="flex items-center justify-between p-3 rounded-xl bg-slate-800/60 border border-slate-700/60 hover:border-slate-600 transition-colors text-xs">
                      <div>
                        <div className="text-white font-semibold flex items-center gap-2">
                          <span>{sc.scan_type?.toUpperCase() || 'SCAN'}</span>
                          <span className="text-slate-400 font-normal">· {new Date(sc.stored_at).toLocaleString()}</span>
                        </div>
                        <div className="text-slate-400 mt-0.5">
                          Risk: <span className="text-cyan-400 font-mono">{Number(sc.risk_score || 0).toFixed(1)}/10</span> · Vulns: <span className="text-white">{sc.vuln_count}</span> (Critical: {sc.critical_count}, High: {sc.high_count})
                        </div>
                      </div>
                      <a
                        href={`/report/${sc.token}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white transition-colors"
                      >
                        View Report →
                      </a>
                    </div>
                  ))
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════════════════
//  MAIN PAGE
// ═══════════════════════════════════════════════════════════════════════════════
export default function BountyTargetsPage() {
  const navigate = useNavigate();

  // ─ Data state ──────────────────────────────────────────────────────────────
  const [targets, setTargets]     = useState([]);
  const [total, setTotal]         = useState(0);
  const [pages, setPages]         = useState(1);
  const [cacheInfo, setCacheInfo] = useState({});
  const [diagnostics, setDiagnostics] = useState(null);
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState('');
  const [stats, setStats]         = useState(null);

  // ─ Filter state ────────────────────────────────────────────────────────────
  const [platform,   setPlatform]   = useState('all');
  const [assetType,  setAssetType]  = useState('ALL');
  const [bountyOnly,   setBountyOnly]   = useState(false);
  const [policyFilter, setPolicyFilter] = useState('ALL');
  const [safeHarborOnly, setSafeHarborOnly] = useState(false);
  const [sortBy,       setSortBy]       = useState('default');
  const [search,       setSearch]       = useState('');
  const [page,       setPage]       = useState(1);
  const PER_PAGE = 24;

  // ─ UI state ────────────────────────────────────────────────────────────────
  const [bookmarks,       setBookmarkState]  = useState(getBookmarks);
  const [huntTarget,      setHuntTarget]     = useState(null);  // HuntGuideModal
  const [scheduleTarget,  setScheduleTarget] = useState(null);  // ScheduleModal
  const [policyGateTarget,setPolicyGateTarget] = useState(null); // PolicyGateModal
  const [reconTarget,     setReconTarget]     = useState(null); // WildcardReconModal (P1.2)
  const [historyTarget,   setHistoryTarget]   = useState(null); // TargetHistoryModal (P2.1)
  const [showBookmarked,  setShowBookmarked] = useState(false);
  const [refreshing,      setRefreshing]     = useState(false);
  const searchRef = useRef(null);

  // ─ Fetch targets ───────────────────────────────────────────────────────────
  const fetchTargets = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const params = {
        platform,
        asset_type:  assetType,
        bounty:      bountyOnly ? 1 : 0,
        policy:      policyFilter,  // ALLOWED | RESTRICTED | UNKNOWN | ALL
        safe_harbor: safeHarborOnly ? 1 : 0,
        sort:        sortBy,
        search,
        page,
        per_page:    PER_PAGE,
      };
      const { data } = await axios.get('/api/admin/bounty-targets', { params, withCredentials: true });
      setTargets(data.targets ?? []);
      setTotal(data.total ?? 0);
      setPages(data.pages ?? 1);
      setCacheInfo(data.cache_info ?? {});
      setDiagnostics(data.diagnostics ?? null);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to load bug bounty targets.');
    } finally {
      setLoading(false);
    }
  }, [platform, assetType, bountyOnly, policyFilter, safeHarborOnly, sortBy, search, page]);

  const fetchStats = useCallback(async () => {
    try {
      const { data } = await axios.get('/api/admin/bounty-targets/stats', { withCredentials: true });
      setStats(data.stats);
    } catch { /* ignore stats error */ }
  }, []);

  useEffect(() => { fetchTargets(); }, [fetchTargets]);
  useEffect(() => { fetchStats(); }, [fetchStats]);

  // Reset to page 1 when filters change
  useEffect(() => { setPage(1); }, [platform, assetType, bountyOnly, policyFilter, safeHarborOnly, sortBy, search]);

  // ─ Bookmark helpers ────────────────────────────────────────────────────────
  const isBookmarked = (t) => bookmarks.some(b => b.id === makeTargetId(t));
  const toggleBookmark = (t) => {
    const id = makeTargetId(t);
    const updated = isBookmarked(t)
      ? bookmarks.filter(b => b.id !== id)
      : [...bookmarks, { id, ...t }];
    setBookmarks(updated);
    setBookmarkState(updated);
  };

  // ─ Launch Scan → Policy Gate first (or Recon for wildcards) ───────────────
  const handleLaunchScan = (t) => {
    if (t.asset?.startsWith('*.') || t.asset_type === 'WILDCARD') {
      setReconTarget(t);
    } else {
      setPolicyGateTarget(t);
    }
  };

  // ─ Confirmed through Policy Gate → navigate to WebScanPage ─────────────────
  const handlePolicyGateConfirm = (t, config = {}) => {
    setPolicyGateTarget(null);
    const target = t.asset.replace(/^\*\./, '');
    const bountyContext = {
      asset: target,
      platform: t.platform,
      program_handle: t.program_handle,
      program_name: t.program_name,
      program_url: t.program_url,
      scan_policy: t.scan_policy || { status: 'UNKNOWN', confidence: 0, signals: [] },
      instruction: t.instruction || '',
      acknowledged: true,
      rate_limit: config.rateLimit,
      threads: config.threads,
      enabled_engines: config.enabledEngines,
      attribution_header: config.attributionHeader,
    };
    try {
      sessionStorage.setItem('hexaguard_bounty_context', JSON.stringify(bountyContext));
    } catch { /* ignore */ }
    navigate(`/scan/web?target=${encodeURIComponent(target)}`, { state: { bountyContext } });
  };

  // ─ Schedule confirm ────────────────────────────────────────────────────────
  const handleScheduleConfirm = async ({ mode, scanType, cronExpr, target }) => {
    const bountyContext = scheduleTarget ? {
      asset: target,
      platform: scheduleTarget.platform,
      program_handle: scheduleTarget.program_handle,
      program_name: scheduleTarget.program_name,
      program_url: scheduleTarget.program_url,
      scan_policy: scheduleTarget.scan_policy || { status: 'UNKNOWN', confidence: 0, signals: [] },
      instruction: scheduleTarget.instruction || '',
      acknowledged: true,
    } : null;
    if (bountyContext) {
      try {
        sessionStorage.setItem('hexaguard_bounty_context', JSON.stringify(bountyContext));
      } catch { /* ignore */ }
    }
    if (mode === 'now') {
      navigate(`/scan/${scanType}?target=${encodeURIComponent(target)}`, { state: { bountyContext } });
    } else {
      try {
        await axios.post('/api/scheduled-scans',
          { scan_type: scanType, target, cron_expr: cronExpr, bounty_context: bountyContext },
          { withCredentials: true }
        );
        setScheduleTarget(null);
        navigate('/scheduled');
      } catch (err) {
        alert(err.response?.data?.error || 'Failed to create scheduled scan.');
      }
    }
  };

  // ─ Force cache refresh ──────────────────────────────────────────────────────
  const handleRefresh = async () => {
    setRefreshing(true);
    try {
      await axios.post('/api/admin/bounty-targets/refresh', {}, { withCredentials: true });
      await fetchTargets();
      await fetchStats();
    } catch { /* ignore */ } finally {
      setRefreshing(false);
    }
  };

  // ─ Displayed list (bookmarks mode) ─────────────────────────────────────────
  const displayedTargets = showBookmarked ? bookmarks : targets;
  const displayedTotal   = showBookmarked ? bookmarks.length : total;

  // ─ Cache age label ─────────────────────────────────────────────────────────
  const cacheAge = Object.values(cacheInfo).find(v => v.age_seconds != null)?.age_seconds;
  const cacheLabel = cacheAge == null ? 'Not loaded'
    : cacheAge < 60 ? 'Just now'
    : `${Math.round(cacheAge / 60)}m ago`;

  // ─ Total stats breakdown ───────────────────────────────────────────────────
  const totalAutoScan   = stats ? Object.values(stats).reduce((s, p) => s + (p.authorized_for_automated_scanning ?? p.allowed ?? p.auto_ok ?? 0), 0) : null;
  const totalManualOk   = stats ? Object.values(stats).reduce((s, p) => s + (p.authorized_for_manual_review ?? 0), 0) : null;
  const totalUnknown    = stats ? Object.values(stats).reduce((s, p) => s + (p.unknown_authorization ?? p.unknown ?? 0), 0) : null;
  const totalBounty     = stats ? Object.values(stats).reduce((s, p) => s + (p.with_bounty ?? 0), 0) : null;


  return (
    <div className="min-h-screen bg-slate-950 text-white p-6 space-y-6">
      {/* ── Header ── */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-purple-500/20">
              <Crosshair className="w-5 h-5 text-white" />
            </div>
            <h1 className="text-2xl font-black text-white">Bug Bounty Targets</h1>
          </div>
          <p className="text-slate-400 text-sm ml-13 pl-13">
            Live from{' '}
            <a href="https://github.com/arkadiyt/bounty-targets-data" target="_blank" rel="noopener noreferrer"
               className="text-cyan-400 hover:underline">arkadiyt/bounty-targets-data</a>
            {' '}— updated hourly. Cache: <span className="text-slate-300">{cacheLabel}</span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowBookmarked(v => !v)}
            className={`inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-semibold border transition-all ${
              showBookmarked
                ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                : 'bg-slate-800 text-slate-400 border-slate-700 hover:text-white hover:border-slate-600'
            }`}
          >
            <BookmarkCheck className="w-4 h-4" />
            Bookmarks ({bookmarks.length})
          </button>
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-xl text-sm font-semibold bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700 hover:text-white transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh Cache
          </button>
        </div>
      </div>

      {/* -- Stats Row -- */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <MiniStat
            label="Tier 1 (Auto Scan OK)"
            value={Object.values(stats).reduce((s, p) => s + (p.verified_automated_allowed ?? p.authorized_for_automated_scanning ?? 0), 0)}
            icon={CheckCircle}
            color="bg-green-500/10 text-green-400"
          />
          <MiniStat
            label="Tier 0 (Manual Verification)"
            value={Object.values(stats).reduce((s, p) => s + (p.manual_verification_required ?? (p.authorized_for_manual_review + p.unknown_authorization) ?? 0), 0)}
            icon={ShieldAlert}
            color="bg-amber-500/10 text-amber-400"
          />
          <MiniStat
            label="Out of Scope / Blocked"
            value={Object.values(stats).reduce((s, p) => s + (p.out_of_scope ?? p.restricted ?? 0), 0)}
            icon={Lock}
            color="bg-red-500/10 text-red-400"
          />
          <MiniStat
            label="With Bounty Reward"
            value={totalBounty}
            icon={Star}
            color="bg-orange-500/10 text-orange-400"
          />
        </div>
      )}

      {/* ── Partial results diagnostics banner ── */}
      {diagnostics?.failed_platforms?.length > 0 && (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-xl p-3.5 text-amber-300 text-xs flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 flex-shrink-0 text-amber-400" />
          <span>
            <strong>Partial Results:</strong> Could not connect to {diagnostics.failed_platforms.map(f => f.platform).join(', ')}.
            Displaying targets from accessible platforms ({diagnostics.successful_platforms.join(', ')}).
          </span>
        </div>
      )}

      {/* ── Filters Bar ── */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-4 flex flex-wrap gap-3 items-center">
        {/* Search */}
        <div className="relative flex-1 min-w-[180px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
          <input
            ref={searchRef}
            type="text"
            placeholder="Search programs or assets…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full bg-slate-800 border border-slate-700 rounded-xl pl-9 pr-4 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
          />
        </div>

        {/* Platform */}
        <select
          value={platform}
          onChange={e => setPlatform(e.target.value)}
          className="bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
        >
          <option value="all">All Platforms</option>
          <option value="hackerone">HackerOne</option>
          <option value="bugcrowd">Bugcrowd</option>
          <option value="yeswehack">YesWeHack</option>
          <option value="intigriti">Intigriti</option>
          <option value="federacy">Federacy</option>
        </select>

        {/* Asset type */}
        <select
          value={assetType}
          onChange={e => setAssetType(e.target.value)}
          className="bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
        >
          <option value="ALL">All Asset Types</option>
          <option value="URL">URL (Web App)</option>
          <option value="WILDCARD">Wildcard Domain</option>
          <option value="DOMAIN">Domain</option>
        </select>

        {/* Policy filter -- Tier 1 / Tier 0 / Out of Scope */}
        <select
          value={policyFilter}
          onChange={e => setPolicyFilter(e.target.value)}
          className="bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
        >
          <option value="ALL">All Targets (Discovered)</option>
          <option value="VERIFIED_AUTOMATED_ALLOWED">Tier 1: Verified Auto Scan</option>
          <option value="MANUAL_VERIFICATION_REQUIRED">Tier 0: Manual Verification Required</option>
          <option value="AUTHORIZED_FOR_MANUAL_REVIEW">Tier 0: Manual Review OK</option>
          <option value="UNKNOWN_AUTHORIZATION">Tier 0: Unknown Policy</option>
          <option value="OUT_OF_SCOPE">Out of Scope / Prohibited</option>
        </select>

        {/* Bounty toggle */}
        <label className="inline-flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={bountyOnly}
            onChange={e => setBountyOnly(e.target.checked)}
            className="w-4 h-4 accent-yellow-400"
          />
          <span className="text-sm text-slate-300">Bounty only</span>
        </label>

        {/* Safe Harbor toggle (P3.1) */}
        <label className="inline-flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={safeHarborOnly}
            onChange={e => setSafeHarborOnly(e.target.checked)}
            className="w-4 h-4 accent-emerald-500"
          />
          <span className="text-sm text-emerald-400 font-medium">Safe Harbor</span>
        </label>

        {/* Sort selector (P3.3 & Part 4) */}
        <select
          value={sortBy}
          onChange={e => setSortBy(e.target.value)}
          className="bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
        >
          <option value="default">Default Sorting</option>
          <option value="learn_earn">🎯 Learn & Earn (الأنسب للتعلم+الربح)</option>
          <option value="roi">Highest Expected ROI</option>
          <option value="response_time">Fastest Response</option>
        </select>

        <div className="text-xs text-slate-500 ml-auto">
          {displayedTotal.toLocaleString()} results
        </div>
      </div>

      {/* ── Error ── */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-red-400 text-sm flex items-center gap-2">
          <XCircle className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      )}

      {/* ── Loading skeleton ── */}
      {loading && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="bg-slate-900 border border-slate-800 rounded-2xl p-5 animate-pulse space-y-3">
              <div className="h-4 bg-slate-800 rounded w-1/2" />
              <div className="h-6 bg-slate-800 rounded w-3/4" />
              <div className="h-3 bg-slate-800 rounded w-full" />
              <div className="flex gap-2">
                <div className="h-8 bg-slate-800 rounded-lg w-24" />
                <div className="h-8 bg-slate-800 rounded-lg w-28" />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ── Targets Grid ── */}
      {!loading && displayedTargets.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {displayedTargets.map((t, i) => (
            <TargetCard
              key={`${t.platform}-${t.program_handle}-${t.asset}-${i}`}
              target={t}
              bookmarked={isBookmarked(t)}
              onToggleBookmark={toggleBookmark}
              onHuntGuide={setHuntTarget}
              onLaunchScan={handleLaunchScan}
              onSchedule={setScheduleTarget}
              onRecon={setReconTarget}
              onHistory={setHistoryTarget}
            />
          ))}
        </div>
      )}

      {/* ── Empty state ── */}
      {!loading && displayedTargets.length === 0 && (
        <div className="text-center py-20 bg-slate-900/40 border border-slate-800/80 rounded-2xl p-8 max-w-2xl mx-auto my-8">
          <div className="text-6xl mb-4">🎯</div>
          <div className="text-xl font-bold text-white mb-2">
            {showBookmarked
              ? 'No bookmarks yet'
              : (policyFilter === 'VERIFIED_AUTOMATED_ALLOWED' || policyFilter === 'AUTHORIZED_FOR_AUTOMATED_SCANNING')
              ? '0 Verified Tier 1 Targets'
              : 'No targets found'}
          </div>
          <p className="text-slate-400 text-sm leading-relaxed">
            {showBookmarked
              ? 'Bookmark targets to save them here for quick access.'
              : (policyFilter === 'VERIFIED_AUTOMATED_ALLOWED' || policyFilter === 'AUTHORIZED_FOR_AUTOMATED_SCANNING')
              ? 'Currently, no targets have verified affirmative written authorization for automated scanning (Tier 1). HexaGuard enforces strict evidence-based safety rules. Switch to "All Targets" or "Tier 0" to explore all discovered targets.'
              : 'Try adjusting your filters or search keywords.'}
          </p>
        </div>
      )}

      {/* ── Pagination ── */}
      {!showBookmarked && pages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button
            disabled={page <= 1}
            onClick={() => setPage(p => p - 1)}
            className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <span className="text-sm text-slate-400 px-3">
            Page <strong className="text-white">{page}</strong> of <strong className="text-white">{pages}</strong>
          </span>
          <button
            disabled={page >= pages}
            onClick={() => setPage(p => p + 1)}
            className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-400 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* ── Legal disclaimer ── */}
      <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-xl p-4 text-yellow-300 text-xs flex gap-3">
        <Info className="w-4 h-4 flex-shrink-0 mt-0.5" />
        <div>
          <strong>Legal Notice:</strong> These targets are from public bug bounty programs. Always read each program's
          full scope and policy before testing. Automated scanning may be restricted on certain programs.
          You are solely responsible for your testing activities.
        </div>
      </div>

      {/* -- Modals -- */}
      {huntTarget && (
        <HuntGuideModal target={huntTarget} onClose={() => setHuntTarget(null)} />
      )}
      {scheduleTarget && (
        <ScheduleModal
          target={scheduleTarget}
          onClose={() => setScheduleTarget(null)}
          onConfirm={handleScheduleConfirm}
        />
      )}
      {policyGateTarget && (
        <PolicyGateModal
          target={policyGateTarget}
          onClose={() => setPolicyGateTarget(null)}
          onConfirm={handlePolicyGateConfirm}
        />
      )}
      {reconTarget && (
        <WildcardReconModal
          target={reconTarget}
          onClose={() => setReconTarget(null)}
          onSelectSubdomain={(sub) => {
            const base = reconTarget;
            setReconTarget(null);
            setPolicyGateTarget({
              ...base,
              asset: sub,
              original_wildcard: base.asset,
            });
          }}
        />
      )}
      {historyTarget && (
        <TargetHistoryModal
          target={historyTarget}
          onClose={() => setHistoryTarget(null)}
        />
      )}
    </div>
  );
}

