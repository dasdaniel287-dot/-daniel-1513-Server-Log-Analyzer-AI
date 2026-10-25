import React, { useState } from 'react';
import { AiInvestigationResponse, CorrelatedIncident, SecurityAlert } from '../types/log';
import { Sparkles, ShieldCheck, AlertCircle, FileSearch, CheckSquare, RefreshCw, Lock } from 'lucide-react';

interface AiAssistantProps {
  alerts: SecurityAlert[];
  incidents: CorrelatedIncident[];
  selectedAlert?: SecurityAlert | null;
  selectedIncident?: CorrelatedIncident | null;
}

export const AiAssistant: React.FC<AiAssistantProps> = ({
  alerts,
  incidents,
  selectedAlert,
  selectedIncident,
}) => {
  const [selectedTarget, setSelectedTarget] = useState<string>(
    selectedAlert?.id || selectedIncident?.id || (alerts[0]?.id ?? incidents[0]?.id ?? '')
  );
  const [consentGranted, setConsentGranted] = useState<boolean>(true);
  const [loading, setLoading] = useState<boolean>(false);
  const [result, setResult] = useState<AiInvestigationResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Find target item
  const activeAlert = alerts.find((a) => a.id === selectedTarget);
  const activeIncident = !activeAlert ? incidents.find((i) => i.id === selectedTarget) : undefined;

  const handleRunInvestigation = async () => {
    if (!consentGranted) {
      setErrorMsg('Administrator consent for defensive privacy-preserving log analysis must be confirmed.');
      return;
    }

    setLoading(true);
    setErrorMsg(null);

    try {
      const payload = activeAlert
        ? {
            incidentTitle: activeAlert.title,
            severity: activeAlert.severity,
            category: activeAlert.category,
            evidence: activeAlert.evidence,
            ruleExplanation: activeAlert.ruleExplanation,
          }
        : activeIncident
        ? {
            incidentTitle: activeIncident.title,
            severity: activeIncident.severity,
            category: 'Incident Correlation',
            evidence: activeIncident.indicators,
            ruleExplanation: activeIncident.rationale,
            logExcerpts: activeIncident.sampleEvents.map((e) => e.sanitized),
          }
        : {
            incidentTitle: 'System Security & Operational Health Review',
            severity: 'Informational',
            category: 'Overview',
            evidence: alerts.slice(0, 3).map((a) => a.title),
          };

      const res = await fetch('/api/ai/investigate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        throw new Error(`Server returned status ${res.status}`);
      }

      const data = await res.json();
      setResult(data);
    } catch (err: unknown) {
      console.error('AI investigation error:', err);
      setErrorMsg(err instanceof Error ? err.message : 'Failed to query investigation endpoint');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Banner */}
      <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              AI Incident Assistant & Root Cause Engine
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Generates safe root-cause hypotheses, non-destructive troubleshooting steps, and executive summaries.
            All findings are strictly labeled as analytical assessments.
          </p>
        </div>

        {/* Privacy Safeguard Badge */}
        <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-emerald-400">
          <Lock className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
          <span>Local PII & Token Redactor Active</span>
        </div>
      </div>

      {/* Target Selector & Consent Card */}
      <div className="p-4 bg-slate-900/50 border border-slate-800 rounded-xl space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-xs font-medium text-slate-300 block mb-1.5">
              Select Incident or Security Alert to Investigate:
            </label>
            <select
              value={selectedTarget}
              onChange={(e) => {
                setSelectedTarget(e.target.value);
                setResult(null);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <optgroup label="Active Security Alerts">
                {alerts.map((a) => (
                  <option key={a.id} value={a.id}>
                    [{a.id}] {a.title} ({a.severity})
                  </option>
                ))}
              </optgroup>
              <optgroup label="Correlated Multi-Source Incidents">
                {incidents.map((inc) => (
                  <option key={inc.id} value={inc.id}>
                    [{inc.id}] {inc.title}
                  </option>
                ))}
              </optgroup>
            </select>
          </div>

          <div className="flex flex-col justify-end">
            <label className="flex items-start gap-2.5 cursor-pointer text-xs text-slate-300 select-none">
              <input
                type="checkbox"
                checked={consentGranted}
                onChange={(e) => setConsentGranted(e.target.checked)}
                className="mt-0.5 rounded border-slate-700 text-cyan-500 focus:ring-0"
              />
              <span>
                <strong>Administrator Privacy & Safety Consent:</strong> I authorize automated redaction and
                analysis of this incident. No unredacted passwords, session tokens, or raw secrets will be transmitted.
              </span>
            </label>
          </div>
        </div>

        {/* Selected Context Preview */}
        {(activeAlert || activeIncident) && (
          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs space-y-2">
            <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Target Finding Summary:
            </div>
            <div className="font-semibold text-slate-200">
              {activeAlert?.title || activeIncident?.title}
            </div>
            <div className="text-slate-400 text-[11px]">
              {activeAlert?.ruleExplanation || activeIncident?.rationale}
            </div>
          </div>
        )}

        {/* Action Button */}
        <div className="flex items-center justify-between pt-2">
          <span className="text-[11px] text-slate-500">
            Powered by Gemini 3.8 Flash (with automatic Local Rule-Based Engine fallback).
          </span>
          <button
            disabled={loading || !consentGranted}
            onClick={handleRunInvestigation}
            className="px-4 py-2 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 disabled:cursor-not-allowed text-slate-950 font-semibold rounded-lg text-xs transition-colors flex items-center gap-2"
          >
            {loading ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Synthesizing Assessment...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-3.5 h-3.5" />
                <span>Run Investigation Assessment</span>
              </>
            )}
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="p-3 bg-rose-950/40 border border-rose-900 rounded-xl text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Results View */}
      {result && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden space-y-4 p-5">
          {/* Assessment Notice Banner */}
          <div className="p-3 bg-amber-950/30 border border-amber-900/60 rounded-lg flex items-center justify-between text-xs text-amber-300">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-amber-400 shrink-0" />
              <span>
                <strong>DEFENSIVE ASSESSMENT NOTICE:</strong> Generated conclusions represent technical
                hypotheses and assessments rather than verified empirical facts. Confirm with server telemetry.
              </span>
            </div>
            <span className="text-[10px] font-mono text-slate-400">
              Provider: {result.provider}
            </span>
          </div>

          {/* Executive Summary */}
          <div>
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
              Executive Briefing
            </h4>
            <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 leading-relaxed">
              {result.executiveSummary}
            </div>
          </div>

          {/* Root Cause Hypothesis & Assessment Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                Technical Assessment & Context
              </h4>
              <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 leading-relaxed min-h-[120px]">
                {result.assessment}
              </div>
            </div>

            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
                Probable Root Cause
              </h4>
              <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-cyan-300 leading-relaxed min-h-[120px]">
                {result.rootCauseAnalysis}
              </div>
            </div>
          </div>

          {/* Safe Remediation Steps */}
          <div>
            <h4 className="text-xs font-semibold text-emerald-400 uppercase tracking-wider mb-1.5">
              Safe, Non-Destructive Remediation Recommendations
            </h4>
            <div className="space-y-1.5">
              {result.safeRemediationSteps.map((step, idx) => (
                <div
                  key={idx}
                  className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 flex items-start gap-2.5"
                >
                  <CheckSquare className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{step}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Additional Logs to Corroborate */}
          <div>
            <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1.5">
              Recommended Additional Log Sources to Inspect
            </h4>
            <div className="flex flex-wrap gap-2">
              {result.additionalLogsToReview.map((src, idx) => (
                <div
                  key={idx}
                  className="px-3 py-1.5 bg-slate-950 border border-slate-850 rounded-lg text-xs font-mono text-slate-300 flex items-center gap-2"
                >
                  <FileSearch className="w-3.5 h-3.5 text-cyan-400" />
                  <span>{src}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
