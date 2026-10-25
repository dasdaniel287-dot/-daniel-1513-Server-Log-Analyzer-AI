import React, { useState } from 'react';
import { AlertSeverity, AlertStatus, SecurityAlert } from '../types/log';
import { ShieldAlert, AlertTriangle, CheckCircle, Info, ChevronRight, ChevronDown, Check } from 'lucide-react';

interface AlertsManagerProps {
  alerts: SecurityAlert[];
  onUpdateAlertStatus: (alertId: string, status: AlertStatus) => void;
  onInvestigateWithAi?: (alert: SecurityAlert) => void;
}

export const AlertsManager: React.FC<AlertsManagerProps> = ({
  alerts,
  onUpdateAlertStatus,
  onInvestigateWithAi,
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);

  const filtered = alerts.filter((a) => {
    if (severityFilter !== 'ALL' && a.severity !== severityFilter) return false;
    if (statusFilter !== 'ALL' && a.status !== statusFilter) return false;
    return true;
  });

  const getSeverityStyle = (sev: AlertSeverity) => {
    switch (sev) {
      case 'Critical':
        return { text: 'text-red-400', border: 'border-red-900/60 bg-red-950/20', icon: ShieldAlert };
      case 'High':
        return { text: 'text-orange-400', border: 'border-orange-900/60 bg-orange-950/20', icon: AlertTriangle };
      case 'Medium':
        return { text: 'text-amber-400', border: 'border-amber-900/60 bg-amber-950/20', icon: AlertTriangle };
      default:
        return { text: 'text-cyan-400', border: 'border-cyan-900/60 bg-cyan-950/20', icon: Info };
    }
  };

  const getStatusBadge = (status: AlertStatus) => {
    switch (status) {
      case 'New':
        return 'text-red-400 font-semibold';
      case 'Investigating':
        return 'text-amber-400 font-medium';
      case 'Resolved':
        return 'text-emerald-400 font-medium';
      case 'False Positive':
        return 'text-slate-500 line-through';
    }
  };

  return (
    <div className="space-y-4">
      {/* Filters Bar */}
      <div className="p-3 bg-slate-900/70 border border-slate-800 rounded-xl flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-3">
          <span className="text-slate-400 font-medium">Filter Severity:</span>
          <div className="flex items-center gap-1">
            {['ALL', 'Critical', 'High', 'Medium', 'Low'].map((s) => (
              <button
                key={s}
                onClick={() => setSeverityFilter(s)}
                className={`px-2.5 py-1 rounded text-xs transition-colors ${
                  severityFilter === s
                    ? 'bg-slate-800 text-white font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-850'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-slate-400 font-medium">Filter Status:</span>
          <div className="flex items-center gap-1">
            {['ALL', 'New', 'Investigating', 'Resolved', 'False Positive'].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1 rounded text-xs transition-colors ${
                  statusFilter === st
                    ? 'bg-slate-800 text-white font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
          <span className="text-slate-500 font-mono text-[11px] tabular-nums ml-2">
            {filtered.length} alerts
          </span>
        </div>
      </div>

      {/* Alerts List */}
      {filtered.length === 0 ? (
        <div className="p-12 text-center bg-slate-900/40 border border-slate-800 rounded-xl">
          <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
          <h4 className="text-sm font-semibold text-slate-200">No Matching Security Alerts</h4>
          <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1">
            No indicators matched the selected severity or status filters under current detection parameters.
          </p>
        </div>
      ) : (
        <div className="space-y-2.5">
          {filtered.map((alert) => {
            const isExpanded = expandedAlertId === alert.id;
            const style = getSeverityStyle(alert.severity);
            const Icon = style.icon;

            return (
              <div
                key={alert.id}
                className={`border rounded-xl transition-all ${style.border} overflow-hidden`}
              >
                {/* Header row */}
                <div
                  onClick={() => setExpandedAlertId(isExpanded ? null : alert.id)}
                  className="p-3.5 flex items-start justify-between gap-4 cursor-pointer hover:bg-slate-800/30 transition-colors"
                >
                  <div className="flex items-start gap-3 min-w-0">
                    <Icon className={`w-4 h-4 ${style.text} shrink-0 mt-0.5`} />
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className="font-mono text-xs text-slate-400 font-bold">{alert.id}</span>
                        <span className="text-xs text-slate-500">·</span>
                        <span className={`text-xs uppercase tracking-wider font-semibold ${style.text}`}>
                          {alert.severity}
                        </span>
                        <span className="text-xs text-slate-500">·</span>
                        <span className="text-xs text-slate-400">{alert.category}</span>
                        <span className="text-xs text-slate-500">·</span>
                        <span className="text-xs text-slate-500 font-mono">
                          {alert.timestamp.replace('T', ' ').slice(0, 19)}
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-slate-100 truncate">{alert.title}</h4>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    {/* Status Dropdown */}
                    <div onClick={(e) => e.stopPropagation()}>
                      <select
                        value={alert.status}
                        onChange={(e) => onUpdateAlertStatus(alert.id, e.target.value as AlertStatus)}
                        className={`bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs focus:outline-none focus:border-cyan-500 cursor-pointer ${getStatusBadge(
                          alert.status
                        )}`}
                      >
                        <option value="New">New</option>
                        <option value="Investigating">Investigating</option>
                        <option value="Resolved">Resolved</option>
                        <option value="False Positive">False Positive</option>
                      </select>
                    </div>

                    {isExpanded ? (
                      <ChevronDown className="w-4 h-4 text-slate-400" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-slate-400" />
                    )}
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="p-4 bg-slate-950/70 border-t border-slate-800/80 text-xs space-y-4">
                    {/* Detection Rule Explanation */}
                    <div>
                      <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">
                        Detection Logic & Evidence Rationale
                      </div>
                      <p className="text-slate-300 bg-slate-900/60 p-2.5 rounded border border-slate-800">
                        {alert.ruleExplanation}
                      </p>
                    </div>

                    {/* Evidence Points */}
                    <div>
                      <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">
                        Supporting Log Evidence (Sanitized)
                      </div>
                      <ul className="space-y-1 bg-slate-900/60 p-2.5 rounded border border-slate-800 font-mono text-[11px] text-slate-200">
                        {alert.evidence.map((ev, i) => (
                          <li key={i} className="flex items-start gap-1.5">
                            <span className="text-cyan-400 shrink-0">›</span>
                            <span>{ev}</span>
                          </li>
                        ))}
                      </ul>
                      {alert.lineReferences.length > 0 && (
                        <div className="text-[10px] text-slate-500 mt-1 font-mono">
                          Source log lines referenced: #{alert.lineReferences.join(', #')}
                        </div>
                      )}
                    </div>

                    {/* Recommended Investigation Steps */}
                    <div>
                      <div className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider mb-1">
                        Defensive Remediation & Investigation Steps
                      </div>
                      <div className="space-y-1.5">
                        {alert.recommendedSteps.map((step, idx) => (
                          <div
                            key={idx}
                            className="flex items-start gap-2 text-slate-300 bg-slate-900/40 p-2 rounded border border-slate-800/60"
                          >
                            <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                            <span>{step}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Bottom CTA Bar */}
                    <div className="flex items-center justify-between pt-2 border-t border-slate-800">
                      <span className="text-[11px] text-slate-500">
                        Confidence: <strong>{alert.confidence}</strong> · Observed Occurrences:{' '}
                        <strong>{alert.occurrences}</strong>
                      </span>
                      {onInvestigateWithAi && (
                        <button
                          onClick={() => onInvestigateWithAi(alert)}
                          className="px-3 py-1.5 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800/60 rounded-lg font-medium transition-colors"
                        >
                          Investigate Alert in AI Assistant →
                        </button>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
