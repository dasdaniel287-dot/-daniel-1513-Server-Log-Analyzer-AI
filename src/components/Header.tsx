import React from 'react';
import { Shield, Upload, FileText, Activity } from 'lucide-react';

export type ActiveTab = 
  | 'overview' 
  | 'live' 
  | 'logs' 
  | 'alerts' 
  | 'auth' 
  | 'http' 
  | 'correlation' 
  | 'ai' 
  | 'reports' 
  | 'settings';

interface HeaderProps {
  activeTab: ActiveTab;
  onTabChange: (tab: ActiveTab) => void;
  onOpenUpload: () => void;
  onOpenSamples: () => void;
  totalRecords: number;
  criticalAlerts: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  onTabChange,
  onOpenUpload,
  onOpenSamples,
  totalRecords,
  criticalAlerts,
}) => {
  const navItems: { id: ActiveTab; label: string; count?: number }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'live', label: 'Live Monitor' },
    { id: 'logs', label: 'Log Explorer' },
    { id: 'alerts', label: 'Alerts', count: criticalAlerts > 0 ? criticalAlerts : undefined },
    { id: 'auth', label: 'Auth Analysis' },
    { id: 'http', label: 'HTTP Traffic' },
    { id: 'correlation', label: 'Incidents' },
    { id: 'ai', label: 'AI Assistant' },
    { id: 'reports', label: 'Reports' },
    { id: 'settings', label: 'Rules & Config' },
  ];

  return (
    <header className="sticky top-0 z-40 bg-slate-900/90 backdrop-blur-md border-b border-slate-800 text-slate-100">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between gap-8 h-16">
          {/* Zone 1: Single text wordmark with domain badge */}
          <div className="flex items-center gap-3 shrink-0">
            <div className="w-8 h-8 rounded-lg bg-cyan-950 border border-cyan-800/60 flex items-center justify-center text-cyan-400">
              <Shield className="w-4 h-4" />
            </div>
            <a 
              href="#overview" 
              onClick={(e) => { e.preventDefault(); onTabChange('overview'); }}
              className="text-base font-bold tracking-tight text-white whitespace-nowrap hover:text-cyan-300 transition-colors"
            >
              Server Log Analyzer AI
            </a>
          </div>

          {/* Zone 2: Single-line clean navigation links */}
          <nav className="hidden xl:flex items-center gap-1 overflow-x-auto py-2">
            {navItems.map((item) => {
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onTabChange(item.id)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md whitespace-nowrap transition-colors flex items-center gap-1.5 ${
                    isActive
                      ? 'bg-slate-800 text-cyan-400 shadow-inner border border-slate-700/80 font-semibold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  }`}
                >
                  <span>{item.label}</span>
                  {item.count !== undefined && (
                    <span className="px-1.5 py-0.2 text-[10px] rounded bg-red-950 text-red-300 border border-red-800/60 tabular-nums">
                      {item.count}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Zone 3: Primary Actions */}
          <div className="flex items-center gap-2.5 shrink-0">
            <button
              onClick={onOpenSamples}
              className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors flex items-center gap-1.5 whitespace-nowrap"
              title="Load realistic synthetic server logs"
            >
              <FileText className="w-3.5 h-3.5 text-slate-400" />
              <span>Sample Logs</span>
            </button>
            <button
              onClick={onOpenUpload}
              className="px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-all shadow-sm flex items-center gap-1.5 whitespace-nowrap"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Upload / Ingest</span>
            </button>
          </div>
        </div>

        {/* Secondary Mobile/Tablet Navigation Bar */}
        <div className="xl:hidden flex items-center gap-1 overflow-x-auto py-2 border-t border-slate-800/80 no-scrollbar">
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                className={`px-2.5 py-1 text-xs rounded whitespace-nowrap ${
                  isActive
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/60 font-medium'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};
