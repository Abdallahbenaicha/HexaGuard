import { useState, useEffect } from 'react';
import axios from 'axios';
import {
  BookOpen, Terminal, CheckCircle2, XCircle, AlertCircle,
  Play, Send, RefreshCw, FileCode, Shield, Award, Sparkles,
  ChevronRight, Check, AlertTriangle, Info
} from 'lucide-react';

const CAPABILITY_LABELS = {
  knowledge: { label: 'Knowledge & Concepts', color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30' },
  recognition: { label: 'Pattern Recognition', color: 'text-amber-400 bg-amber-500/10 border-amber-500/30' },
  manual_detection: { label: 'Manual Detection / CLI', color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30' },
  validation: { label: 'Payload & Validation', color: 'text-rose-400 bg-rose-500/10 border-rose-500/30' },
  impact_analysis: { label: 'Impact & CVSS Scoring', color: 'text-purple-400 bg-purple-500/10 border-purple-500/30' },
  remediation: { label: 'Defensive Remediation', color: 'text-blue-400 bg-blue-500/10 border-blue-500/30' },
  reporting: { label: 'Vulnerability Reporting', color: 'text-teal-400 bg-teal-500/10 border-teal-500/30' },
  lab_exploitation: { label: 'Sandbox Lab', color: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/30' },
};

export default function ExerciseWorkspace({ vulnType, onAttemptCompleted }) {
  const [exercises, setExercises] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedExId, setSelectedExId] = useState(null);

  // Active attempt state
  const [activeAttempt, setActiveAttempt] = useState(null);
  const [startingAttempt, setStartingAttempt] = useState(false);

  // Submission inputs
  const [submissionText, setSubmissionText] = useState('');
  const [cliCommand, setCliCommand] = useState('');
  const [cliOutput, setCliOutput] = useState('');
  const [flagInput, setFlagInput] = useState('');
  const [activeSandboxes, setActiveSandboxes] = useState([]);
  const [selectedSandboxId, setSelectedSandboxId] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Authoritative server-side evaluation result
  // CRITICAL SECURITY INVARIANT: No score or evaluation status is ever calculated client-side.
  // Results are derived strictly from the server's response to POST /api/learning/attempt/complete.
  const [evaluationResult, setEvaluationResult] = useState(null);

  useEffect(() => {
    if (!vulnType) return;
    loadExercises();
    axios.get('/api/sandbox/active')
      .then(res => {
        const active = res.data?.active || [];
        const matching = active.filter(sb => sb.vuln_type === vulnType);
        setActiveSandboxes(matching);
        if (matching.length > 0) {
          setSelectedSandboxId(matching[0].id);
        }
      })
      .catch(() => {});
  }, [vulnType]);

  async function loadExercises() {
    setLoading(true);
    setError(null);
    try {
      const res = await axios.get(`/api/learning/exercises/${vulnType}`);
      if (res.data?.ok) {
        const allExs = res.data.exercises || [];
        setExercises(allExs);
        if (allExs.length > 0) {
          setSelectedExId(allExs[0].id);
        }
      } else {
        setError(res.data?.error || 'Failed to load exercises.');
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to connect to exercise engine.');
    } finally {
      setLoading(false);
    }
  }

  const currentExercise = exercises.find(ex => ex.id === selectedExId) || null;

  async function handleStartAttempt(exerciseId) {
    setStartingAttempt(true);
    setError(null);
    setEvaluationResult(null);
    setSubmissionText('');
    setCliCommand('');
    setCliOutput('');
    setFlagInput('');
    try {
      const res = await axios.post('/api/learning/attempt/start', { exercise_id: exerciseId });
      if (res.data?.ok && res.data?.attempt) {
        setActiveAttempt(res.data.attempt);
      } else {
        setError(res.data?.error || 'Could not start exercise attempt.');
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to start attempt on server.');
    } finally {
      setStartingAttempt(false);
    }
  }

  async function handleSubmitAttempt(e) {
    e.preventDefault();
    if (!activeAttempt) return;

    // Compose submission payload based on modality
    let finalSubmission = submissionText.trim();
    let metadata = undefined;

    if (currentExercise?.exercise_type === 'lab' || currentExercise?.capability === 'lab_exploitation') {
      const flag = flagInput.trim() || submissionText.trim();
      finalSubmission = flag;
      metadata = {
        sandbox_id: selectedSandboxId || undefined,
        flag: flag,
      };
    } else if (currentExercise?.exercise_type === 'cli_detection' || currentExercise?.exercise_type === 'safe_lab') {
      const cmd = cliCommand.trim();
      const out = cliOutput.trim();
      finalSubmission = `Command:\n${cmd}\n\nOutput:\n${out}`;
    }

    if (!finalSubmission) {
      setError('Please provide your submission before requesting evaluation.');
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      // POST strictly to authoritative server-side evaluator
      const res = await axios.post('/api/learning/attempt/complete', {
        attempt_id: activeAttempt.id,
        submission_text: finalSubmission,
        metadata: metadata,
      });

      if (res.data?.ok) {
        setEvaluationResult(res.data);
        if (onAttemptCompleted) {
          onAttemptCompleted(res.data);
        }
      } else {
        setError(res.data?.error || 'Server evaluation returned an unexpected status.');
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Evaluation failed on server.');
    } finally {
      setSubmitting(false);
    }
  }

  // Word count utility for textual modalities
  const wordCount = submissionText.trim() ? submissionText.trim().split(/\s+/).length : 0;
  const contentConfig = currentExercise?.content || {};
  const minWordsRequired = contentConfig.min_words || 0;

  if (loading) {
    return (
      <div className="p-8 rounded-2xl bg-slate-900/60 border border-slate-800 text-center space-y-3">
        <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto" />
        <p className="text-xs text-slate-400">Loading interactive capability exercises...</p>
      </div>
    );
  }

  if (exercises.length === 0) {
    return (
      <div className="p-6 rounded-2xl bg-slate-900/40 border border-slate-800 text-slate-400 text-xs text-center">
        No analytical or non-containerized exercises found for this topic.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Exercise Selector Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-3">
        {exercises.map((ex) => {
          const isSelected = ex.id === selectedExId;
          const capInfo = CAPABILITY_LABELS[ex.capability] || { label: ex.capability, color: 'text-slate-400' };
          return (
            <button
              key={ex.id}
              onClick={() => {
                setSelectedExId(ex.id);
                setActiveAttempt(null);
                setEvaluationResult(null);
                setError(null);
              }}
              className={`px-3 py-2 rounded-xl text-xs font-semibold transition-all flex items-center gap-2 border ${
                isSelected
                  ? 'bg-slate-800 text-cyan-300 border-cyan-500/50 shadow-lg shadow-cyan-950/40'
                  : 'bg-slate-900/60 text-slate-400 border-slate-800 hover:text-slate-200 hover:border-slate-700'
              }`}
            >
              <span className={`w-2 h-2 rounded-full ${isSelected ? 'bg-cyan-400 ring-2 ring-cyan-400/30' : 'bg-slate-600'}`} />
              <span className="truncate max-w-[200px]">{ex.title_en}</span>
              <span className={`text-[10px] px-1.5 py-0.5 rounded border ${capInfo.color}`}>
                {ex.capability}
              </span>
            </button>
          );
        })}
      </div>

      {currentExercise && (
        <div className="rounded-2xl bg-slate-900/90 border border-slate-800 p-6 space-y-6 shadow-xl relative overflow-hidden">
          {/* Header & Meta */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
            <div className="space-y-1.5">
              <div className="flex items-center gap-2.5">
                <span className={`text-xs font-bold uppercase tracking-wider px-2.5 py-1 rounded-lg border ${CAPABILITY_LABELS[currentExercise.capability]?.color || 'text-cyan-400'}`}>
                  {CAPABILITY_LABELS[currentExercise.capability]?.label || currentExercise.capability}
                </span>
                <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 font-mono">
                  {currentExercise.exercise_type}
                </span>
                <span className={`text-xs px-2 py-0.5 rounded font-semibold capitalize ${
                  currentExercise.difficulty === 'hard' ? 'text-rose-400 bg-rose-500/10' :
                  currentExercise.difficulty === 'medium' ? 'text-amber-400 bg-amber-500/10' :
                  'text-emerald-400 bg-emerald-500/10'
                }`}>
                  {currentExercise.difficulty}
                </span>
              </div>
              <h3 className="text-base font-bold text-white tracking-tight">
                {currentExercise.title_en}
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed max-w-3xl">
                {currentExercise.description_en}
              </p>
            </div>

            {/* Start / Attempt State Action */}
            <div className="flex-shrink-0">
              {!activeAttempt ? (
                <button
                  onClick={() => handleStartAttempt(currentExercise.id)}
                  disabled={startingAttempt}
                  className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-50"
                >
                  {startingAttempt ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4 fill-current" />}
                  <span>Start Attempt (Introduced)</span>
                </button>
              ) : (
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-cyan-950/40 border border-cyan-500/30 text-xs text-cyan-300 font-mono">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                  <span>Attempt #{activeAttempt.attempt_number} (Active)</span>
                </div>
              )}
            </div>
          </div>

          {/* Cert hint & Guidance */}
          {currentExercise.cert_hint && (
            <div className="flex items-center gap-2.5 px-3.5 py-2 rounded-xl bg-slate-950/60 border border-slate-800/80 text-xs text-slate-400">
              <Sparkles className="w-4 h-4 text-amber-400 flex-shrink-0" />
              <span><strong>Certification Relevance:</strong> {currentExercise.cert_hint}</span>
            </div>
          )}

          {/* Error Alert */}
          {error && (
            <div className="flex items-start gap-3 p-4 rounded-xl bg-rose-950/50 border border-rose-500/40 text-xs text-rose-200">
              <AlertCircle className="w-4 h-4 text-rose-400 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* Active Attempt Interaction Workspace */}
          {activeAttempt && !evaluationResult && (
            <form onSubmit={handleSubmitAttempt} className="space-y-4 pt-2">
              {/* Dynamic Modality Input Rendering */}
              {currentExercise.exercise_type === 'cli_detection' || currentExercise.exercise_type === 'safe_lab' ? (
                <div className="space-y-3">
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-slate-300 flex items-center gap-2">
                      <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                      <span>CLI Command Executed</span>
                    </label>
                    <input
                      type="text"
                      value={cliCommand}
                      onChange={(e) => setCliCommand(e.target.value)}
                      placeholder="e.g. curl -I -X OPTIONS https://target.local/api/v1"
                      className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-emerald-300 font-mono focus:outline-none focus:border-emerald-500/50 transition-all"
                      required
                    />
                  </div>
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-slate-300 flex items-center gap-2">
                      <FileCode className="w-3.5 h-3.5 text-slate-400" />
                      <span>Terminal Output & Response Headers</span>
                    </label>
                    <textarea
                      rows={5}
                      value={cliOutput}
                      onChange={(e) => setCliOutput(e.target.value)}
                      placeholder="Paste raw terminal response headers or status output here..."
                      className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500/50 transition-all leading-relaxed"
                      required
                    />
                  </div>
                </div>
              ) : currentExercise.exercise_type === 'lab' || currentExercise.capability === 'lab_exploitation' ? (
                <div className="space-y-3">
                  <div className="p-3.5 rounded-xl bg-indigo-950/30 border border-indigo-500/30 text-xs text-indigo-300 space-y-1.5">
                    <div className="flex items-center gap-2 font-bold">
                      <Sparkles className="w-4 h-4 text-indigo-400" />
                      <span>Adversarial Twin Sandbox Lab Proof</span>
                    </div>
                    <p className="text-slate-400 leading-relaxed">
                      Launch the sandbox challenge container in the panel above, exploit the vulnerability, and submit the authentic proof flag (e.g. <code>FLAG&#123;...&#125;</code>) captured from the live target.
                    </p>
                  </div>
                  {activeSandboxes.length > 0 && (
                    <div className="space-y-1.5">
                      <label className="text-xs font-semibold text-slate-300">Target Sandbox Container</label>
                      <select
                        value={selectedSandboxId}
                        onChange={(e) => setSelectedSandboxId(e.target.value)}
                        className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-cyan-300 font-mono focus:outline-none focus:border-cyan-500/50"
                      >
                        {activeSandboxes.map((sb) => (
                          <option key={sb.id} value={sb.id}>
                            {sb.name || sb.vuln_type} (Port: {sb.port || '3000'}) — ID: {sb.id.slice(0, 8)}...
                          </option>
                        ))}
                      </select>
                    </div>
                  )}
                  <div className="space-y-1.5">
                    <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                      <span className="flex items-center gap-2">
                        <Award className="w-3.5 h-3.5 text-indigo-400" />
                        <span>Proof Flag</span>
                      </span>
                      <span className="text-[11px] text-slate-400 font-mono">
                        Authoritative Server-Verified Proof
                      </span>
                    </label>
                    <input
                      type="text"
                      value={flagInput}
                      onChange={(e) => setFlagInput(e.target.value)}
                      placeholder="FLAG{...}"
                      className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-indigo-300 font-mono focus:outline-none focus:border-indigo-500/50 transition-all"
                      required
                    />
                  </div>
                </div>
              ) : currentExercise.exercise_type === 'payload_validation' ? (
                <div className="space-y-2">
                  <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                    <span className="flex items-center gap-2">
                      <FileCode className="w-3.5 h-3.5 text-rose-400" />
                      <span>Exploit Payload & Verification Proof</span>
                    </span>
                    <span className="text-[11px] text-slate-400">
                      Include breakout markers, canary tokens, or response reflections
                    </span>
                  </label>
                  <textarea
                    rows={6}
                    value={submissionText}
                    onChange={(e) => setSubmissionText(e.target.value)}
                    placeholder="Enter the crafted payload and technical breakout proof..."
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-rose-200 font-mono focus:outline-none focus:border-rose-500/50 transition-all leading-relaxed"
                    required
                  />
                </div>
              ) : currentExercise.exercise_type === 'remediation_review' ? (
                <div className="space-y-2">
                  <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
                    <span className="flex items-center gap-2">
                      <Shield className="w-3.5 h-3.5 text-blue-400" />
                      <span>Defensive Configuration / Patch Snippet</span>
                    </span>
                    <span className="text-[11px] text-slate-400">
                      Provide safe policy directives (e.g. Nginx, Apache, or security.txt)
                    </span>
                  </label>
                  <textarea
                    rows={6}
                    value={submissionText}
                    onChange={(e) => setSubmissionText(e.target.value)}
                    placeholder="Enter hardened configuration directive or secure implementation code..."
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-blue-200 font-mono focus:outline-none focus:border-blue-500/50 transition-all leading-relaxed"
                    required
                  />
                </div>
              ) : (
                /* Textual Assessment, Pattern Recognition, Impact Analysis, Reporting */
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-semibold text-slate-300 flex items-center gap-2">
                      <BookOpen className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Technical Analysis & Justification</span>
                    </label>
                    <div className="flex items-center gap-2 text-xs">
                      {minWordsRequired > 0 && (
                        <span className={`px-2 py-0.5 rounded text-[11px] font-mono border ${
                          wordCount >= minWordsRequired
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                            : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                        }`}>
                          Words: {wordCount} / {minWordsRequired} min
                        </span>
                      )}
                    </div>
                  </div>
                  <textarea
                    rows={6}
                    value={submissionText}
                    onChange={(e) => setSubmissionText(e.target.value)}
                    placeholder="Write your technical explanation, vulnerability analysis, or CVSS breakdown here..."
                    className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500/50 transition-all leading-relaxed"
                    required
                  />
                </div>
              )}

              {/* Action Bar */}
              <div className="flex items-center justify-between pt-2">
                <span className="text-[11px] text-slate-500 flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-cyan-500" />
                  <span>Authoritative Server-side Evaluator • Zero Client Trust</span>
                </span>

                <button
                  type="submit"
                  disabled={submitting || (minWordsRequired > 0 && wordCount < minWordsRequired)}
                  className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-lg shadow-cyan-500/20 transition-all disabled:opacity-40"
                >
                  {submitting ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Evaluating Server-side...</span>
                    </>
                  ) : (
                    <>
                      <Send className="w-4 h-4" />
                      <span>Submit for Evaluation</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          )}

          {/* Post-Submission Authoritative Results Card */}
          {evaluationResult && (
            <div className={`p-5 rounded-2xl border transition-all ${
              evaluationResult.result === 'passed'
                ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-200'
                : 'bg-rose-950/30 border-rose-500/40 text-rose-200'
            }`}>
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3">
                  {evaluationResult.result === 'passed' ? (
                    <div className="p-2 rounded-xl bg-emerald-500/20 border border-emerald-500/30 text-emerald-400">
                      <CheckCircle2 className="w-6 h-6" />
                    </div>
                  ) : (
                    <div className="p-2 rounded-xl bg-rose-500/20 border border-rose-500/30 text-rose-400">
                      <XCircle className="w-6 h-6" />
                    </div>
                  )}
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <h4 className="text-sm font-bold text-white capitalize">
                        Evaluation Result: {evaluationResult.result}
                      </h4>
                      <span className="text-xs px-2 py-0.5 rounded font-mono font-bold bg-slate-900 border border-slate-700 text-cyan-300">
                        Score: {Math.round((evaluationResult.score || 0) * 100)}%
                      </span>
                    </div>
                    <p className="text-xs text-slate-300 leading-relaxed pt-1">
                      {evaluationResult.notes || 'No evaluator feedback provided.'}
                    </p>
                  </div>
                </div>

                <button
                  onClick={() => handleStartAttempt(currentExercise.id)}
                  className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold transition-all flex items-center gap-1.5 flex-shrink-0"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Retry Attempt</span>
                </button>
              </div>
            </div>
          )}

          {/* Prompt to start when idle */}
          {!activeAttempt && !evaluationResult && (
            <div className="p-5 rounded-xl bg-slate-950/40 border border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
              <span>Click <strong>Start Attempt</strong> above to initialize your attempt session and unlock submission.</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
