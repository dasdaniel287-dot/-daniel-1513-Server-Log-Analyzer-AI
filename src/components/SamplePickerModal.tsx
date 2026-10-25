import React from 'react';
import { SAMPLE_LOGS, SampleLogDefinition } from '../data/sampleLogs';
import { FileText, X, ArrowRight, ShieldCheck } from 'lucide-react';

interface SamplePickerModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectSample: (sample: SampleLogDefinition) => void;
}

export const SamplePickerModal: React.FC<SamplePickerModalProps> = ({
  isOpen,
  onClose,
  onSelectSample,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              Select Synthetic Test Log Dataset
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-slate-200 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* List of Samples */}
        <div className="p-5 overflow-y-auto space-y-3">
          <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-slate-400 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>
              All sample datasets are synthetic, sanitized, and contain zero confidential production telemetry, credentials, or private IPs.
            </span>
          </div>

          <div className="space-y-2.5">
            {SAMPLE_LOGS.map((s) => (
              <div
                key={s.id}
                onClick={() => {
                  onSelectSample(s);
                  onClose();
                }}
                className="p-3.5 bg-slate-950/60 border border-slate-800 hover:border-cyan-500/60 rounded-xl cursor-pointer transition-all hover:bg-slate-900 group"
              >
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider">
                      {s.category}
                    </span>
                    <span className="text-xs text-slate-600">·</span>
                    <span className="text-xs font-semibold text-slate-100 group-hover:text-cyan-300 transition-colors">
                      {s.name}
                    </span>
                  </div>
                  <ArrowRight className="w-4 h-4 text-slate-600 group-hover:text-cyan-400 group-hover:translate-x-0.5 transition-all" />
                </div>
                <p className="text-xs text-slate-400 leading-relaxed mb-2">
                  {s.description}
                </p>
                <div className="text-[10px] font-mono text-slate-600 truncate bg-slate-900 p-1.5 rounded border border-slate-850">
                  {s.content.split('\n')[0]}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
