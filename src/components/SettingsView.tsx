import React from 'react';
import { DetectionRuleConfig } from '../types/log';
import { Sliders, Shield, RotateCcw, Check, Power } from 'lucide-react';

interface SettingsViewProps {
  rules: DetectionRuleConfig[];
  onUpdateRule: (updatedRule: DetectionRuleConfig) => void;
  onResetRules: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({ rules, onUpdateRule, onResetRules }) => {
  return (
    <div className="space-y-4">
      {/* Top Banner */}
      <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              Detection Rules & Analytical Thresholds
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Configure sensitivity parameters and sliding time windows for authentication brute-force, web path probing, and application error cascades.
          </p>
        </div>

        <button
          onClick={onResetRules}
          className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Reset Default Thresholds</span>
        </button>
      </div>

      {/* Rules List */}
      <div className="space-y-3">
        {rules.map((rule) => {
          return (
            <div
              key={rule.id}
              className={`p-4 bg-slate-900/80 border rounded-xl transition-all ${
                rule.enabled ? 'border-slate-800' : 'border-slate-850 opacity-60'
              }`}
            >
              <div className="flex flex-wrap items-start justify-between gap-3 mb-2">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-xs text-slate-500 font-bold">{rule.id}</span>
                    <span className="text-xs text-slate-600">·</span>
                    <span className="text-xs text-cyan-400 font-semibold">{rule.category}</span>
                  </div>
                  <h4 className="text-sm font-semibold text-slate-100">{rule.name}</h4>
                  <p className="text-xs text-slate-400 mt-0.5">{rule.description}</p>
                </div>

                {/* Enable / Disable Toggle */}
                <button
                  onClick={() => onUpdateRule({ ...rule, enabled: !rule.enabled })}
                  className={`px-3 py-1 text-xs font-semibold rounded-lg flex items-center gap-1.5 transition-colors ${
                    rule.enabled
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/80'
                      : 'bg-slate-800 text-slate-400 border border-slate-700'
                  }`}
                >
                  <Power className="w-3 h-3" />
                  <span>{rule.enabled ? 'Rule Active' : 'Rule Disabled'}</span>
                </button>
              </div>

              {/* Threshold & Window Controls */}
              {rule.enabled && (
                <div className="mt-3 pt-3 border-t border-slate-800/80 flex flex-wrap items-center gap-6 text-xs">
                  <div className="flex items-center gap-2">
                    <label className="text-slate-400 font-medium">Trigger Threshold:</label>
                    <input
                      type="number"
                      min={1}
                      max={100}
                      value={rule.threshold}
                      onChange={(e) =>
                        onUpdateRule({
                          ...rule,
                          threshold: Math.max(1, parseInt(e.target.value, 10) || 1),
                        })
                      }
                      className="w-16 bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-100 font-mono text-xs focus:outline-none focus:border-cyan-500 text-center"
                    />
                    <span className="text-slate-500 text-[11px]">events</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <label className="text-slate-400 font-medium">Sliding Window:</label>
                    <input
                      type="number"
                      min={1}
                      max={1440}
                      value={rule.windowMinutes}
                      onChange={(e) =>
                        onUpdateRule({
                          ...rule,
                          windowMinutes: Math.max(1, parseInt(e.target.value, 10) || 1),
                        })
                      }
                      className="w-16 bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-100 font-mono text-xs focus:outline-none focus:border-cyan-500 text-center"
                    />
                    <span className="text-slate-500 text-[11px]">minutes</span>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Security Architecture Reference */}
      <div className="p-4 bg-slate-900/50 border border-slate-800 rounded-xl space-y-2">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-emerald-400" />
          <h4 className="text-xs font-semibold text-slate-200">
            Defensive Architecture & Privacy Invariants
          </h4>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">
          The Server Log Analyzer platform processes log data strictly within isolated execution boundaries.
          Ingress records are sanitized using deterministic regular expressions that redact Authorization Bearer
          tokens, passwords, database credentials, and email addresses prior to display or optional AI assessment.
        </p>
      </div>
    </div>
  );
};
