import React, { useState } from 'react';
import { TimelineBucket } from '../types/log';
import { BarChart3, Filter } from 'lucide-react';

interface TimelineChartProps {
  timeline: TimelineBucket[];
  onSelectBucket?: (bucket: TimelineBucket) => void;
}

export const TimelineChart: React.FC<TimelineChartProps> = ({ timeline, onSelectBucket }) => {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null);

  if (!timeline || timeline.length === 0) {
    return (
      <div className="h-44 bg-slate-900/50 border border-slate-800 rounded-xl flex items-center justify-center text-slate-500 text-xs">
        No chronological timeline data available for current dataset.
      </div>
    );
  }

  const maxTotal = Math.max(...timeline.map((t) => t.total), 1);
  const activeBucket = hoveredIdx !== null ? timeline[hoveredIdx] : null;

  return (
    <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <BarChart3 className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-semibold text-slate-200 tracking-tight">
            Event Frequency & Anomaly Timeline
          </h3>
          <span className="text-[11px] text-slate-500">· {timeline.length} time windows</span>
        </div>

        {/* Legend */}
        <div className="flex items-center gap-4 text-[11px] text-slate-400">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-cyan-500/80 inline-block" />
            <span>Normal Traffic</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-amber-500/90 inline-block" />
            <span>Auth Failures</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-rose-500 inline-block" />
            <span>Errors / Crashes</span>
          </div>
        </div>
      </div>

      {/* Bar Chart Canvas */}
      <div className="h-28 flex items-end gap-1.5 pt-4 pb-1">
        {timeline.map((b, idx) => {
          const heightPercent = Math.max(8, (b.total / maxTotal) * 100);
          const errorRatio = b.total > 0 ? (b.errors / b.total) : 0;
          const authRatio = b.total > 0 ? (b.authFailures / b.total) : 0;

          let barBg = 'bg-cyan-600/60 hover:bg-cyan-400';
          if (b.errors > 0) {
            barBg = 'bg-rose-600/80 hover:bg-rose-500';
          } else if (b.authFailures > 0) {
            barBg = 'bg-amber-600/80 hover:bg-amber-400';
          }

          const isHovered = hoveredIdx === idx;

          return (
            <div
              key={b.bucket + idx}
              className="flex-1 h-full flex flex-col justify-end items-center group relative cursor-pointer"
              onMouseEnter={() => setHoveredIdx(idx)}
              onMouseLeave={() => setHoveredIdx(null)}
              onClick={() => onSelectBucket?.(b)}
            >
              <div
                className={`w-full rounded-t-sm transition-all duration-150 ${barBg} ${
                  isHovered ? 'ring-1 ring-white/80 shadow-lg' : ''
                }`}
                style={{ height: `${heightPercent}%` }}
              />
            </div>
          );
        })}
      </div>

      {/* X-axis labels */}
      <div className="flex justify-between text-[10px] text-slate-500 font-mono pt-1 border-t border-slate-800">
        <span>{timeline[0]?.bucket}</span>
        <span>{timeline[Math.floor(timeline.length / 2)]?.bucket}</span>
        <span>{timeline[timeline.length - 1]?.bucket}</span>
      </div>

      {/* Hover Inspection Drawer */}
      {activeBucket && (
        <div className="mt-3 p-2.5 bg-slate-950/80 border border-slate-800 rounded-lg flex flex-wrap items-center justify-between text-xs font-mono text-slate-300">
          <div className="flex items-center gap-3">
            <span className="text-cyan-400 font-semibold">{activeBucket.bucket}</span>
            <span>Total: <strong>{activeBucket.total}</strong></span>
            <span className="text-rose-400">Errors: <strong>{activeBucket.errors}</strong></span>
            <span className="text-amber-400">Auth Fails: <strong>{activeBucket.authFailures}</strong></span>
            <span>HTTP 4xx/5xx: <strong>{activeBucket.http4xx + activeBucket.http5xx}</strong></span>
          </div>
          {onSelectBucket && (
            <button
              onClick={() => onSelectBucket(activeBucket)}
              className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
            >
              <Filter className="w-3 h-3" />
              <span>Filter logs to this window</span>
            </button>
          )}
        </div>
      )}
    </div>
  );
};
