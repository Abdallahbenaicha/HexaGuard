import { useState, useEffect, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import {
  Target, RefreshCw, Search, ExternalLink,
  BookmarkPlus, BookmarkCheck, Zap, Clock, ChevronLeft,
  ChevronRight, Shield, AlertTriangle, CheckCircle,
  XCircle, Crosshair, Calendar, Info, Star,
  HelpCircle, Lock, Unlock, ChevronDown, ChevronUp,
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

// ─── Policy Badge ──────────────────────────────────────────────────────────────
const POLICY_CFG = {
  ALLOWED:    { icon: CheckCircle, label: 'Scan Allowed',    cls: 'text-green-400',  bg: 'bg-green-500/8  border-green-500/25' },
  RESTRICTED: { icon: Lock,        label: 'Restricted',      cls: 'text-yellow-400', bg: 'bg-yellow-500/8 border-yellow-500/25' },
  UNKNOWN:    { icon: HelpCircle,  label: 'Policy Unknown',  cls: 'text-slate-400',  bg: 'bg-slate-500/8  border-slate-500/25' },
};

const PolicyBadge = ({ policy, expanded, onToggle }) => {
  const s   = policy?.status ?? 'UNKNOWN';
  const cfg = POLICY_CFG[s] ?? POLICY_CFG.UNKNOWN;
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
const TargetCard = ({ target, bookmarked, onToggleBookmark, onHuntGuide, onLaunchScan, onSchedule }) => {
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
      <div className="flex items-center gap-3 flex-wrap">
        <SeverityBadge sev={target.max_severity} />
        <span className="text-xs text-slate-500">{assetMeta.label}</span>
        {target.avg_response_h && (
          <span className="text-xs text-slate-500 flex items-center gap-1">
            <Clock className="w-3 h-3" /> ~{Math.round(target.avg_response_h)}h response
          </span>
        )}
      </div>

      {/* Policy badge — expandable signals */}
      <PolicyBadge
        policy={policy}
        expanded={policyExpanded}
        onToggle={() => setPolicyExpanded(v => !v)}
      />

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

        {/* Launch Scan — always clickable, gate handled in modal */}
        <button
          onClick={() => onLaunchScan(target)}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold text-white bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 transition-all shadow-sm shadow-cyan-500/20"
        >
          <Zap className="w-3 h-3" /> Scan Now
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

// ─── Policy Gate Modal (Fix 5) ────────────────────────────────────────────────
// Shows before every scan launch; blocks on RESTRICTED/UNKNOWN unless user
// explicitly acknowledges the policy risk.
const PolicyGateModal = ({ target, onClose, onConfirm }) => {
  const policy    = target?.scan_policy ?? { status: 'UNKNOWN', confidence: 0, signals: [] };
  const status    = policy.status;
  const asset     = target?.asset?.replace(/^\*\./, '') ?? '';
  const [checked, setChecked] = useState(false);

  const isAllowed    = status === 'ALLOWED';
  const isRestricted = status === 'RESTRICTED';
  const isUnknown    = status === 'UNKNOWN';

  // ALLOWED + high confidence → auto-proceed (no modal needed, but we still show briefly)
  const needsCheck   = isRestricted || isUnknown;
  const canProceed   = isAllowed || checked;

  const statusConfig = {
    ALLOWED:    { icon: CheckCircle, title: 'Scan Policy: Allowed',    color: 'text-green-400',  bg: 'bg-green-500/10 border-green-500/30',   msg: 'Automated scanning is explicitly allowed by this program.' },
    RESTRICTED: { icon: Lock,        title: 'Scan Policy: Restricted',  color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/30', msg: 'This program has restrictions. Review them before scanning.' },
    UNKNOWN:    { icon: HelpCircle,  title: 'Scan Policy: Unknown',     color: 'text-slate-400',  bg: 'bg-slate-500/10 border-slate-500/30',   msg: 'No clear automation policy found. Manual review is required.' },
  };
  const sc = statusConfig[status] ?? statusConfig.UNKNOWN;
  const Ico = sc.icon;

  return (
    <div className="fixed inset-0 z-[9200] bg-black/80 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-slate-900 border border-slate-700 rounded-2xl w-full max-w-md shadow-2xl" onClick={e => e.stopPropagation()}>
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

        <div className="px-6 py-5 space-y-4">
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

          {/* Acknowledgement checkbox for non-ALLOWED */}
          {needsCheck && (
            <label className="flex items-start gap-3 cursor-pointer bg-yellow-500/5 border border-yellow-500/20 rounded-xl p-4">
              <input
                type="checkbox"
                checked={checked}
                onChange={e => setChecked(e.target.checked)}
                className="w-4 h-4 mt-0.5 accent-yellow-400 flex-shrink-0"
              />
              <span className="text-xs text-yellow-200 leading-relaxed">
                I have manually reviewed the program policy and confirm I am authorized to run automated scans on this target. I accept full responsibility.
              </span>
            </label>
          )}
        </div>

        {/* Actions */}
        <div className="flex gap-3 px-6 pb-6">
          <button
            onClick={onClose}
            className="flex-1 py-2.5 rounded-xl border border-slate-700 text-slate-300 text-sm font-semibold hover:bg-slate-800 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={() => canProceed && onConfirm(target)}
            disabled={!canProceed}
            className="flex-1 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-sm font-semibold transition-all shadow-sm disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Zap className="w-3.5 h-3.5 inline mr-1.5" />
            {isAllowed ? 'Launch Scan' : 'Proceed Anyway'}
          </button>
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
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState('');
  const [stats, setStats]         = useState(null);

  // ─ Filter state ────────────────────────────────────────────────────────────
  const [platform,   setPlatform]   = useState('all');
  const [assetType,  setAssetType]  = useState('ALL');
  const [bountyOnly, setBountyOnly] = useState(false);
  const [autoOnly,   setAutoOnly]   = useState(true);
  const [search,     setSearch]     = useState('');
  const [page,       setPage]       = useState(1);
  const PER_PAGE = 24;

  // ─ UI state ────────────────────────────────────────────────────────────────
  const [bookmarks,       setBookmarkState]  = useState(getBookmarks);
  const [huntTarget,      setHuntTarget]     = useState(null);  // HuntGuideModal
  const [scheduleTarget,  setScheduleTarget] = useState(null);  // ScheduleModal
  const [policyGateTarget,setPolicyGateTarget] = useState(null); // PolicyGateModal
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
        policy:      policyFilter,  // new param — ALLOWED | RESTRICTED | UNKNOWN | ALL
        search,
        page,
        per_page:    PER_PAGE,
      };
      const { data } = await axios.get('/api/admin/bounty-targets', { params, withCredentials: true });
      setTargets(data.targets ?? []);
      setTotal(data.total ?? 0);
      setPages(data.pages ?? 1);
      setCacheInfo(data.cache_info ?? {});
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to load bug bounty targets.');
    } finally {
      setLoading(false);
    }
  }, [platform, assetType, bountyOnly, policyFilter, search, page]);

  const fetchStats = useCallback(async () => {
    try {
      const { data } = await axios.get('/api/admin/bounty-targets/stats', { withCredentials: true });
      setStats(data.stats);
    } catch { /* ignore stats error */ }
  }, []);

  useEffect(() => { fetchTargets(); }, [fetchTargets]);
  useEffect(() => { fetchStats(); }, [fetchStats]);

  // Reset to page 1 when filters change
  useEffect(() => { setPage(1); }, [platform, assetType, bountyOnly, policyFilter, search]);

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

  // ─ Launch Scan → Policy Gate first ─────────────────────────────────────────
  const handleLaunchScan = (t) => {
    // Always show policy gate — even ALLOWED targets get a brief confirmation
    setPolicyGateTarget(t);
  };

  // ─ Confirmed through Policy Gate → navigate to WebScanPage ─────────────────
  const handlePolicyGateConfirm = (t) => {
    setPolicyGateTarget(null);
    const target = t.asset.replace(/^\*\./, '');
    navigate(`/scan/web?target=${encodeURIComponent(target)}`);
  };

  // ─ Schedule confirm ────────────────────────────────────────────────────────
  const handleScheduleConfirm = async ({ mode, scanType, cronExpr, target }) => {
    if (mode === 'now') {
      navigate(`/scan/${scanType}?target=${encodeURIComponent(target)}`);
    } else {
      try {
        await axios.post('/api/scheduled-scans',
          { scan_type: scanType, target, cron_expr: cronExpr },
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
  const totalAllowed     = stats ? Object.values(stats).reduce((s, p) => s + (p.allowed ?? p.auto_ok ?? 0), 0) : null;
  const totalRestricted  = stats ? Object.values(stats).reduce((s, p) => s + (p.restricted ?? 0), 0) : null;
  const totalUnknown     = stats ? Object.values(stats).reduce((s, p) => s + (p.unknown ?? 0), 0) : null;
  const totalBounty      = stats ? Object.values(stats).reduce((s, p) => s + p.with_bounty, 0) : null;

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
          <MiniStat label="Scan Allowed"  value={totalAllowed}    icon={CheckCircle}  color="bg-green-500/10 text-green-400" />
          <MiniStat label="Restricted"    value={totalRestricted} icon={Lock}         color="bg-yellow-500/10 text-yellow-400" />
          <MiniStat label="Policy Unknown" value={totalUnknown}   icon={HelpCircle}   color="bg-slate-500/10 text-slate-400" />
          <MiniStat label="Bounty + Allowed" value={totalBounty} icon={Star}          color="bg-orange-500/10 text-orange-400" />
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

        {/* Policy filter -- replaces binary auto-scan checkbox */}
        <select
          value={policyFilter}
          onChange={e => setPolicyFilter(e.target.value)}
          className="bg-slate-800 border border-slate-700 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
        >
          <option value="ALLOWED">Scan Allowed only</option>
          <option value="RESTRICTED">Restricted only</option>
          <option value="UNKNOWN">Policy Unknown</option>
          <option value="ALL">All policies</option>
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
            />
          ))}
        </div>
      )}

      {/* ── Empty state ── */}
      {!loading && displayedTargets.length === 0 && (
        <div className="text-center py-20">
          <div className="text-6xl mb-4">🎯</div>
          <div className="text-xl font-bold text-white mb-2">
            {showBookmarked ? 'No bookmarks yet' : 'No targets found'}
          </div>
          <p className="text-slate-400 text-sm">
            {showBookmarked
              ? 'Bookmark targets to save them here for quick access.'
              : 'Try adjusting your filters or refreshing the cache.'}
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
    </div>
  );
}

