import React from 'react';
import { AnalysisSummary } from '../types/log';
import { Database, CheckCircle2, AlertOctagon, AlertTriangle, Crosshair, Flame } from 'lucide-react';

interface MetricCardsProps {
  summary: AnalysisSummary;
  criticalAlertCount: number;
}

export const MetricCards: React.FC<MetricCardsProps> = ({ summary, criticalAlertCount }) => {
  const cards = [
    {
      label: 'Total Log Entries',
      value: summary.totalLines.toLocaleString(),
      subtext: `${summary.timeRange.durationMinutes} min timeline span`,
      icon: Database,
      color: 'text-slate-200',
      border: 'border-slate-800',
    },
    {
      label: 'Parsed Records',
      value: summary.parsedRecords.toLocaleString(),
      subtext: `${summary.malformedRecords} malformed/skipped`,
      icon: CheckCircle2,
      color: 'text-emerald-400',
      border: 'border-slate-800',
    },
    {
      label: 'Error Events',
      value: summary.errorCount.toLocaleString(),
      subtext: `${summary.criticalCount} fatal/critical`,
      icon: AlertOctagon,
      color: summary.errorCount > 0 ? 'text-rose-400' : 'text-slate-400',
      border: summary.errorCount > 0 ? 'border-rose-950/60' : 'border-slate-800',
    },
    {
      label: 'Warning Events',
      value: summary.warnCount.toLocaleString(),
      subtext: 'Resource & auth notices',
      icon: AlertTriangle,
      color: summary.warnCount > 0 ? 'text-amber-400' : 'text-slate-400',
      border: 'border-slate-800',
    },
    {
      label: 'Suspicious Patterns',
      value: summary.suspiciousPatternsCount.toLocaleString(),
      subtext: 'Rules & anomalies triggered',
      icon: Crosshair,
      color: summary.suspiciousPatternsCount > 0 ? 'text-orange-400' : 'text-slate-400',
      border: summary.suspiciousPatternsCount > 0 ? 'border-orange-950/60' : 'border-slate-800',
    },
    {
      label: 'Critical Alerts',
      value: criticalAlertCount.toLocaleString(),
      subtext: criticalAlertCount > 0 ? 'Requires immediate triage' : 'Nominal posture',
      icon: Flame,
      color: criticalAlertCount > 0 ? 'text-red-400' : 'text-emerald-400',
      border: criticalAlertCount > 0 ? 'border-red-900/80 bg-red-950/10' : 'border-slate-800',
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map((c) => {
        const Icon = c.icon;
        return (
          <div
            key={c.label}
            className={`p-3.5 bg-slate-900/70 border ${c.border} rounded-xl transition-all hover:border-slate-700`}
          >
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-[11px] font-medium tracking-tight truncate">{c.label}</span>
              <Icon className={`w-3.5 h-3.5 ${c.color} shrink-0`} />
            </div>
            <div className={`text-2xl font-bold font-mono tabular-nums tracking-tight ${c.color}`}>
              {c.value}
            </div>
            <div className="text-[10px] text-slate-500 mt-1 truncate">
              {c.subtext}
            </div>
          </div>
        );
      })}
    </div>
  );
};
