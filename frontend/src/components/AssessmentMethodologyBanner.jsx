import React from 'react';
import { Compass, ArrowRight, ShieldCheck } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function AssessmentMethodologyBanner({ compact = false }) {
  if (compact) {
    return (
      <div className="flex items-center justify-between gap-3 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-950/40 to-indigo-950/40 border border-cyan-500/20 text-xs">
        <div className="flex items-center gap-2 text-slate-300">
          <Compass className="w-4 h-4 text-cyan-400 flex-shrink-0 animate-spin-slow" />
          <span>
            Not sure how to structure this assessment? Review the universal workflow.
          </span>
        </div>
        <Link
          to="/learn/start"
          className="inline-flex items-center gap-1 font-semibold text-cyan-400 hover:text-cyan-300 transition-colors whitespace-nowrap"
        >
          <span>Module 0 Primer</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </Link>
      </div>
    );
  }

  return (
    <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-cyan-950/30 to-indigo-950/40 border border-cyan-500/30 p-5 shadow-lg shadow-black/20">
      <div className="absolute top-0 right-0 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
      <div className="relative flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-start gap-3.5">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex-shrink-0">
            <Compass className="w-6 h-6 animate-spin-slow" />
          </div>
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-[11px] font-bold uppercase tracking-wider text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded-full border border-cyan-500/30">
                Methodology Primer
              </span>
              <span className="text-xs text-slate-400">Universal 7-Phase Workflow</span>
            </div>
            <h3 className="text-base font-bold text-white leading-snug">
              Module 0: How to Run an Assessment
            </h3>
            <p className="text-xs text-slate-300 max-w-2xl mt-0.5 leading-relaxed">
              Unsure what to search for or which engine to run first? Learn the end-to-end methodology:
              from scope definition and passive OSINT, to engine selection, EPSS triage, and verified reporting.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 flex-shrink-0">
          <Link
            to="/learn/start"
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-bold rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-white shadow-md shadow-cyan-500/20 transition-all hover:scale-105"
          >
            <span>Start Module 0</span>
            <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </div>
    </div>
  );
}
