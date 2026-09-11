import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Shield, CheckCircle2, Award, Zap, HelpCircle, Star, AlertCircle,
  Eye, Terminal, FileText, Check, Lock
} from 'lucide-react';

const CAPABILITY_DEFINITIONS = [
  { key: 'knowledge', labelEn: 'Knowledge', labelAr: 'المعرفة النظرية', icon: HelpCircle, desc: 'Conceptual mechanics & vulnerability causes' },
  { key: 'recognition', labelEn: 'Recognition', labelAr: 'التعرّف والرصد', icon: Eye, desc: 'Identifying in code and scanner output' },
  { key: 'manual_detection', labelEn: 'Manual Detection', labelAr: 'الاستكشاف اليدوي', icon: Terminal, desc: 'Hands-on target exploration' },
  { key: 'validation', labelEn: 'Validation', labelAr: 'التحقق والإثبات', icon: CheckCircle2, desc: 'Proving true positive vs false alarm' },
  { key: 'lab_exploitation', labelEn: 'Lab Exploitation', labelAr: 'الاستغلال المعملي', icon: Zap, desc: 'Cryptographic sandbox proof flag capture' },
  { key: 'impact_analysis', labelEn: 'Impact Analysis', labelAr: 'تحليل الأثر', icon: Shield, desc: 'Articulating business & technical impact' },
  { key: 'remediation', labelEn: 'Remediation', labelAr: 'المعالجة وسد الثغرة', icon: Check, desc: 'Applying and verifying the patch fix' },
  { key: 'reporting', labelEn: 'Reporting', labelAr: 'التوثيق وإعداد التقارير', icon: FileText, desc: 'Producing structured audit reports' },
];

const STATE_CONFIG = {
  NOT_STARTED: {
    labelAr: 'لم تبدأ',
    labelEn: 'Not Started',
    badgeClass: 'bg-slate-800/60 text-slate-400 border-slate-700/60',
    dotClass: 'bg-slate-600',
    glow: '',
  },
  INTRODUCED: {
    labelAr: 'مُستَهلّة',
    labelEn: 'Introduced',
    badgeClass: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
    dotClass: 'bg-cyan-400 animate-pulse',
    glow: 'shadow-[0_0_8px_rgba(6,182,212,0.2)]',
  },
  PRACTICED: {
    labelAr: 'مُمارَسَة',
    labelEn: 'Practiced',
    badgeClass: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
    dotClass: 'bg-amber-400',
    glow: 'shadow-[0_0_8px_rgba(245,158,11,0.2)]',
  },
  DEMONSTRATED: {
    labelAr: 'مُثبَتَة',
    labelEn: 'Demonstrated',
    badgeClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
    dotClass: 'bg-emerald-400',
    glow: 'shadow-[0_0_8px_rgba(16,185,129,0.25)]',
  },
  MASTERED: {
    labelAr: 'مُتقَنَة',
    labelEn: 'Mastered',
    badgeClass: 'bg-purple-500/15 text-purple-300 border-purple-500/40',
    dotClass: 'bg-purple-400',
    glow: 'shadow-[0_0_12px_rgba(168,85,247,0.35)]',
  },
};

export default function MasteryMatrix({ vulnType, initialMatrix = null }) {
  const [matrix, setMatrix] = useState(initialMatrix);
  const [loading, setLoading] = useState(!initialMatrix);
  const [error, setError] = useState('');

  useEffect(() => {
    if (initialMatrix) {
      setMatrix(initialMatrix);
      return;
    }
    if (!vulnType) return;

    let mounted = true;
    const fetchMatrix = async () => {
      try {
        setLoading(true);
        const res = await axios.get(`/api/learning/mastery/${vulnType}`);
        if (mounted && res.data?.ok) {
          setMatrix(res.data.matrix);
        }
      } catch (err) {
        if (mounted) {
          setError(err.response?.data?.error || 'Failed to load mastery matrix.');
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };

    fetchMatrix();
    return () => { mounted = false; };
  }, [vulnType, initialMatrix]);

  if (loading) {
    return (
      <div className="p-4 bg-slate-900/40 rounded-xl border border-slate-800 animate-pulse flex items-center justify-center gap-3 text-slate-500 text-xs">
        <div className="w-4 h-4 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        <span>جاري تحميل مصفوفة الكفاءات الثمانية...</span>
      </div>
    );
  }

  if (error || !matrix) {
    return null;
  }

  const capabilities = matrix.capabilities || {};
  const skillLevel = matrix.skill_level || 'NOT_STARTED';
  const cfgSkill = STATE_CONFIG[skillLevel] || STATE_CONFIG.NOT_STARTED;

  return (
    <div className="p-4 bg-slate-950/80 rounded-2xl border border-slate-800/80 backdrop-blur-sm space-y-4">
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/60 pb-3">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <h4 className="text-xs font-orbitron font-semibold uppercase tracking-wider text-slate-300">
            مصفوفة الكفاءات القائمة على الأدلة (8-Capability Matrix)
          </h4>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-slate-400">مستوى المهارة الإجمالي:</span>
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold font-mono border ${cfgSkill.badgeClass} ${cfgSkill.glow}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${cfgSkill.dotClass}`} />
            {cfgSkill.labelAr} ({cfgSkill.labelEn})
          </span>
        </div>
      </div>

      {/* 8-Capability Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
        {CAPABILITY_DEFINITIONS.map((def) => {
          const capData = capabilities[def.key] || { state: 'NOT_STARTED' };
          const stateKey = capData.state || 'NOT_STARTED';
          const cfg = STATE_CONFIG[stateKey] || STATE_CONFIG.NOT_STARTED;
          const Icon = def.icon;

          return (
            <div
              key={def.key}
              className={`p-2.5 rounded-xl border bg-slate-900/50 transition-all duration-200 hover:border-slate-700 hover:bg-slate-900/80 ${
                stateKey === 'MASTERED' ? 'border-purple-500/30' :
                stateKey === 'DEMONSTRATED' ? 'border-emerald-500/30' :
                stateKey === 'PRACTICED' ? 'border-amber-500/30' :
                stateKey === 'INTRODUCED' ? 'border-cyan-500/20' : 'border-slate-800/60'
              }`}
              title={def.desc}
            >
              <div className="flex items-center justify-between gap-1 mb-1.5">
                <div className="flex items-center gap-1.5">
                  <Icon className="w-3.5 h-3.5 text-slate-400" />
                  <span className="text-xs font-medium text-slate-200 truncate">
                    {def.labelAr}
                  </span>
                </div>
              </div>

              <div className="flex items-center justify-between mt-2">
                <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium border ${cfg.badgeClass}`}>
                  <span className={`w-1 h-1 rounded-full ${cfg.dotClass}`} />
                  {cfg.labelAr}
                </span>

                {capData.verified_evidence_count > 0 && (
                  <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-0.5" title="إثبات آلي مُتحقَّق">
                    <CheckCircle2 className="w-3 h-3" />
                  </span>
                )}
                {capData.latest_score !== null && capData.latest_score !== undefined && (
                  <span className="text-[10px] font-mono text-slate-400">
                    {Math.round(capData.latest_score * 100)}%
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
