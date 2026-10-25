import React, { useState } from 'react';
import { CorrelatedIncident, LogEntry } from '../types/log';
import { GitMerge, Clock, ChevronDown, ChevronRight, Server, Shield, AlertOctagon } from 'lucide-react';

interface CorrelationViewProps {
  incidents: CorrelatedIncident[];
  onInspectEvent?: (event: LogEntry) => void;
}

export const CorrelationView: React.FC<CorrelationViewProps> = ({ incidents, onInspectEvent }) => {
  const [expandedIncId, setExpandedIncId] = useState<string | null>(null);

  return (
    <div className="space-y-4">
      {/* Overview Banner */}
      <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <GitMerge className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              Correlated Multi-Source Incidents ({incidents.length})
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Correlates related log events by temporal proximity, shared source IP, target account, and service error cascades. 
            Avoids speculative links by requiring concrete log evidence.
          </p>
        </div>
      </div>

      {/* Incident List */}
      {incidents.length === 0 ? (
        <div className="p-12 text-center bg-slate-900/40 border border-slate-800 rounded-xl">
          <Server className="w-8 h-8 text-slate-500 mx-auto mb-2" />
          <h4 className="text-sm font-semibold text-slate-200">No Correlated Incidents Formed</h4>
          <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1">
            Current log dataset does not exhibit sufficient density or cross-event indicators to trigger an incident cluster.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {incidents.map((inc) => {
            const isExpanded = expandedIncId === inc.id;
            return (
              <div
                key={inc.id}
                className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden transition-all hover:border-slate-700"
              >
                {/* Header */}
                <div
                  onClick={() => setExpandedIncId(isExpanded ? null : inc.id)}
                  className="p-4 flex items-start justify-between gap-4 cursor-pointer hover:bg-slate-850/40 transition-colors"
                >
                  <div className="flex items-start gap-3 min-w-0">
                    <div className="w-7 h-7 rounded bg-slate-800 border border-slate-700 flex items-center justify-center shrink-0 mt-0.5">
                      {inc.correlationType === 'IP_ADDRESS' ? (
                        <Shield className="w-3.5 h-3.5 text-cyan-400" />
                      ) : (
                        <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
                      )}
                    </div>

                    <div className="min-w-0">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className="font-mono text-xs text-slate-400 font-bold">{inc.id}</span>
                        <span className="text-xs text-slate-500">·</span>
                        <span
                          className={`text-xs uppercase tracking-wider font-semibold ${
                            inc.severity === 'Critical' ? 'text-rose-400' : 'text-orange-400'
                          }`}
                        >
                          {inc.severity}
                        </span>
                        <span className="text-xs text-slate-500">·</span>
                        <span className="text-xs text-slate-400 font-mono">{inc.correlationKey}</span>
                        <span className="text-xs text-slate-500">·</span>
                        <span className="text-xs text-slate-400 font-mono">
                          {inc.eventCount} correlated events
                        </span>
                      </div>
                      <h4 className="text-sm font-semibold text-slate-100">{inc.title}</h4>
                      <p className="text-xs text-slate-400 mt-1 line-clamp-1">{inc.rationale}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0">
                    <div className="text-right hidden sm:block text-[11px] font-mono text-slate-500">
                      <div>Start: {inc.firstSeen.slice(11, 19)}</div>
                      <div>End: {inc.lastSeen.slice(11, 19)}</div>
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
                    {/* Rationale Box */}
                    <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
                      <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">
                        Correlation Engine Rationale
                      </div>
                      <p className="text-slate-300">{inc.rationale}</p>
                    </div>

                    {/* Observable Indicators */}
                    <div>
                      <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1">
                        Empirical Indicators
                      </div>
                      <div className="flex flex-wrap gap-2 font-mono text-[11px]">
                        {inc.indicators.map((ind, i) => (
                          <span
                            key={i}
                            className="px-2.5 py-1 bg-slate-900 border border-slate-850 rounded text-cyan-300"
                          >
                            {ind}
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* Chronological Supporting Events */}
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                          Sample Supporting Log Records ({inc.sampleEvents.length} shown)
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono">
                          Chronologically Ordered
                        </span>
                      </div>

                      <div className="space-y-1.5 font-mono text-[11px]">
                        {inc.sampleEvents.map((e) => (
                          <div
                            key={e.id}
                            onClick={() => onInspectEvent?.(e)}
                            className="p-2 bg-slate-900 border border-slate-850 rounded flex items-start justify-between gap-3 hover:bg-slate-850/60 transition-colors cursor-pointer"
                          >
                            <div className="min-w-0">
                              <span className="text-slate-500 mr-2">Line {e.lineNumber}</span>
                              <span className="text-slate-400 mr-2">{e.timestamp.slice(11, 19)}</span>
                              <span
                                className={`mr-2 font-semibold ${
                                  e.level === 'CRITICAL' || e.level === 'ERROR'
                                    ? 'text-rose-400'
                                    : 'text-amber-400'
                                }`}
                              >
                                [{e.level}]
                              </span>
                              <span className="text-slate-200">{e.sanitized}</span>
                            </div>
                            <span className="text-cyan-400 text-[10px] shrink-0">Inspect →</span>
                          </div>
                        ))}
                      </div>
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
