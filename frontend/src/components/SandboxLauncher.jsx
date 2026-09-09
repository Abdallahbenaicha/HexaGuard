import React, { useState, useEffect } from 'react';
import {
  Box, Play, Square, CheckCircle2, ShieldAlert,
  ExternalLink, Clock, Key, AlertTriangle, RefreshCw,
  Sparkles, Check
} from 'lucide-react';
import axios from 'axios';

export default function SandboxLauncher({ targetVulnType, onVerified }) {
  const [catalog, setCatalog] = useState([]);
  const [activeSandboxes, setActiveSandboxes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [flagInputs, setFlagInputs] = useState({});
  const [errorMsg, setErrorMsg] = useState('');
  const [successMsg, setSuccessMsg] = useState('');
  const [isLocalMode, setIsLocalMode] = useState(true);

  const fetchState = async () => {
    try {
      setLoading(true);
      setErrorMsg('');

      // Check deployment mode
      const modeRes = await axios.get('/api/config/deployment-mode').catch(() => ({ data: { is_local: true } }));
      if (modeRes.data && modeRes.data.is_local === false) {
        setIsLocalMode(false);
        setLoading(false);
        return;
      }

      const [catRes, actRes] = await Promise.all([
        axios.get('/api/sandbox/catalog').catch(() => ({ data: { challenges: [] } })),
        axios.get('/api/sandbox/active').catch(() => ({ data: { active: [] } })),
      ]);

      setCatalog(catRes.data?.challenges || []);
      setActiveSandboxes(actRes.data?.active || []);
    } catch (err) {
      if (err.response?.status === 404) {
        setIsLocalMode(false);
      } else {
        setErrorMsg('فشل في جلب حالة بيئة التدريب المحلية.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchState();
    const interval = setInterval(() => {
      if (activeSandboxes.length > 0) {
        fetchState();
      }
    }, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleLaunch = async (vulnType) => {
    setActionLoading(true);
    setErrorMsg('');
    setSuccessMsg('');
    try {
      const res = await axios.post('/api/sandbox/launch', { vuln_type: vulnType });
      if (res.data?.ok) {
        setSuccessMsg(`تم تشغيل بيئة التدريب لـ ${vulnType} بنجاح على المضيف المحلي!`);
        fetchState();
      }
    } catch (err) {
      setErrorMsg(err.response?.data?.error || 'فشل في تشغيل الحاوية.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleComplete = async (sandboxId) => {
    const flag = flagInputs[sandboxId] || '';
    if (!flag.trim()) {
      setErrorMsg('الرجاء إدخال علم/دليل الإنجاز (Proof Flag) أولاً.');
      return;
    }
    setActionLoading(true);
    setErrorMsg('');
    try {
      const res = await axios.post(`/api/sandbox/${sandboxId}/complete`, { flag });
      if (res.data?.ok && res.data?.verified) {
        setSuccessMsg('تهانينا! تم التحقق من العلم بنجاح، وترقية حالتك في سجل المهارة إلى مُتحقَّق آلياً (Verified)!');
        fetchState();
        if (onVerified) onVerified(res.data.skill);
      }
    } catch (err) {
      setErrorMsg(err.response?.data?.error || 'علم غير صحيح. تحقق من حمولة الاستغلال وأعد المحاولة.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleStop = async (sandboxId) => {
    setActionLoading(true);
    try {
      await axios.delete(`/api/sandbox/${sandboxId}`);
      fetchState();
    } catch (err) {
      setErrorMsg(err.response?.data?.error || 'فشل في إيقاف الحاوية.');
    } finally {
      setActionLoading(false);
    }
  };

  if (!isLocalMode) {
    return (
      <div className="p-4 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs flex items-center gap-3">
        <AlertTriangle className="w-5 h-5 flex-shrink-0 text-amber-400" />
        <div>
          <p className="font-semibold">بيئة التدريب المحلية (Adversarial Twin) محظورة في النشر السحابي</p>
          <p className="text-slate-400 mt-0.5">تشغيل حاويات التدريب متاح حصرياً في بيئة التشغيل المحلي (DEPLOYMENT_MODE=local) لضمان أمان الخوادم.</p>
        </div>
      </div>
    );
  }

  const displayedCatalog = targetVulnType
    ? catalog.filter((c) => c.vuln_type === targetVulnType)
    : catalog;

  return (
    <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-blue-500/10 text-blue-400 border border-blue-500/30 rounded-xl">
            <Box className="w-6 h-6" />
          </div>
          <div>
            <h3 className="font-orbitron font-bold text-white text-base">
              التوأم العدائي — Adversarial Twin Sandbox
            </h3>
            <p className="text-slate-400 text-xs mt-0.5">
              بيئة حاويات معزولة على جهازك المحلي (127.0.0.1) للتدريب العملي واستخراج أعلام الإثبات (Proof Flags).
            </p>
          </div>
        </div>

        <button
          onClick={fetchState}
          disabled={loading || actionLoading}
          className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          title="تحديث الحالة"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Notifications */}
      {errorMsg && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}
      {successMsg && (
        <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Active Running Sandboxes */}
      {activeSandboxes.length > 0 && (
        <div className="space-y-3">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-emerald-400 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            الحاويات النشطة حالياً ({activeSandboxes.length} / 2)
          </h4>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {activeSandboxes.map((sb) => (
              <div
                key={sb.id}
                className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/40 space-y-4 shadow-lg shadow-emerald-950/20"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-emerald-300 font-semibold uppercase">
                    {sb.vuln_type}
                  </span>
                  <span className="text-[11px] font-mono text-slate-400">
                    منفذ: {sb.host_port}
                  </span>
                </div>

                <div>
                  <h5 className="text-white text-sm font-semibold">{sb.name}</h5>
                  <div className="flex items-center gap-2 mt-2">
                    <a
                      href={sb.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all shadow-sm"
                    >
                      <span>فتح في المتصفح</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </a>
                    <button
                      onClick={() => handleStop(sb.id)}
                      disabled={actionLoading}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-750 text-slate-300 hover:text-rose-400 rounded-lg text-xs font-semibold transition-colors flex items-center gap-1"
                    >
                      <Square className="w-3 h-3" />
                      <span>إيقاف الحاوية</span>
                    </button>
                  </div>
                </div>

                {/* Flag Submission */}
                <div className="pt-3 border-t border-emerald-500/20 space-y-2">
                  <label className="text-[11px] font-medium text-slate-300 flex items-center gap-1">
                    <Key className="w-3 h-3 text-amber-400" />
                    <span>تقديم علم الإنجاز (Proof Flag):</span>
                  </label>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      placeholder="FLAG{...}"
                      value={flagInputs[sb.id] || ''}
                      onChange={(e) =>
                        setFlagInputs((prev) => ({ ...prev, [sb.id]: e.target.value }))
                      }
                      className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-emerald-400 font-mono"
                    />
                    <button
                      onClick={() => handleComplete(sb.id)}
                      disabled={actionLoading}
                      className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1 transition-all"
                    >
                      <Check className="w-3 h-3" />
                      <span>تحقق</span>
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Available Challenges Catalog */}
      <div className="space-y-3">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          تحديات التدريب المتاحة
        </h4>

        {displayedCatalog.length === 0 ? (
          <p className="text-xs text-slate-500 py-3">لا توجد تحديات ساندبوكس متاحة لهذه الفئة حالياً.</p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {displayedCatalog.map((chal) => {
              const isRunning = activeSandboxes.some((a) => a.vuln_type === chal.vuln_type);

              return (
                <div
                  key={chal.vuln_type}
                  className="p-4 rounded-xl bg-slate-850/60 border border-slate-750 flex flex-col justify-between gap-3 hover:border-slate-650 transition-all"
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-[10px] uppercase px-2 py-0.5 rounded bg-slate-800 text-cyan-400">
                        {chal.vuln_type}
                      </span>
                      <span className="text-[10px] text-slate-500 flex items-center gap-1">
                        <Clock className="w-3 h-3" /> ساعتان حد أقصى
                      </span>
                    </div>
                    <h5 className="text-white font-semibold text-xs leading-snug">{chal.name}</h5>
                    <p className="text-slate-400 text-[11px] line-clamp-2 leading-relaxed">
                      {chal.description}
                    </p>
                  </div>

                  <button
                    onClick={() => handleLaunch(chal.vuln_type)}
                    disabled={isRunning || actionLoading || activeSandboxes.length >= 2}
                    className={`w-full py-2 rounded-xl text-xs font-semibold flex items-center justify-center gap-1.5 transition-all ${
                      isRunning
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 cursor-default'
                        : 'bg-blue-600 hover:bg-blue-500 text-white shadow-md shadow-blue-900/20'
                    }`}
                  >
                    {isRunning ? (
                      <>
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>قيد التشغيل</span>
                      </>
                    ) : (
                      <>
                        <Play className="w-3.5 h-3.5" />
                        <span>إطلاق الحاوية</span>
                      </>
                    )}
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
