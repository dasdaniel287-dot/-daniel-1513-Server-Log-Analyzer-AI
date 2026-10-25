import React from 'react';
import { HttpStatistics } from '../types/log';
import { Globe, AlertCircle, Bot, ServerCrash, ExternalLink } from 'lucide-react';

interface HttpViewProps {
  httpStats: HttpStatistics;
  onFilterPath?: (path: string) => void;
  onFilterIp?: (ip: string) => void;
}

export const HttpView: React.FC<HttpViewProps> = ({ httpStats, onFilterPath, onFilterIp }) => {
  return (
    <div className="space-y-4">
      {/* Overview Stat Ribbon */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-3.5 bg-slate-900/70 border border-slate-800 rounded-xl">
          <div className="text-[11px] text-slate-400 font-medium">Total HTTP Requests</div>
          <div className="text-xl font-bold font-mono text-slate-100 tabular-nums mt-1">
            {httpStats.totalRequests.toLocaleString()}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Ingress access records</div>
        </div>

        <div className="p-3.5 bg-slate-900/70 border border-slate-800 rounded-xl">
          <div className="text-[11px] text-slate-400 font-medium">Probed 4xx Endpoints</div>
          <div className="text-xl font-bold font-mono text-amber-400 tabular-nums mt-1">
            {httpStats.top4xxPaths.length}
          </div>
          <div className="text-[10px] text-amber-400/80 mt-0.5">404/403 missing resources</div>
        </div>

        <div className="p-3.5 bg-slate-900/70 border border-slate-800 rounded-xl">
          <div className="text-[11px] text-slate-400 font-medium">Server 5xx Failures</div>
          <div className="text-xl font-bold font-mono text-rose-400 tabular-nums mt-1">
            {httpStats.top5xxErrors.reduce((a, b) => a + b.count, 0)}
          </div>
          <div className="text-[10px] text-rose-400/80 mt-0.5">Internal errors & timeouts</div>
        </div>

        <div className="p-3.5 bg-slate-900/70 border border-slate-800 rounded-xl">
          <div className="text-[11px] text-slate-400 font-medium">Scanner Signatures</div>
          <div className="text-xl font-bold font-mono text-cyan-400 tabular-nums mt-1">
            {httpStats.scannerUserAgents.length}
          </div>
          <div className="text-[10px] text-cyan-400/80 mt-0.5">Known tool user-agents</div>
        </div>
      </div>

      {/* HTTP Status Code Distribution */}
      <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl">
        <h4 className="text-xs font-semibold text-slate-200 mb-3">HTTP Response Status Distribution</h4>
        <div className="flex flex-wrap gap-2">
          {Object.entries(httpStats.statusDistribution).length === 0 ? (
            <span className="text-xs text-slate-500">No HTTP status data present in current logs.</span>
          ) : (
            Object.entries(httpStats.statusDistribution).map(([code, count]) => {
              const num = parseInt(code, 10);
              let badgeColor = 'bg-cyan-950/60 text-cyan-300 border-cyan-800/60';
              if (num >= 500) badgeColor = 'bg-rose-950/60 text-rose-300 border-rose-800/80';
              else if (num >= 400) badgeColor = 'bg-amber-950/60 text-amber-300 border-amber-800/80';
              else if (num >= 300) badgeColor = 'bg-blue-950/60 text-blue-300 border-blue-800/60';
              else if (num >= 200) badgeColor = 'bg-emerald-950/60 text-emerald-300 border-emerald-800/60';

              return (
                <div
                  key={code}
                  className={`px-3 py-1.5 rounded-lg border flex items-center gap-2 text-xs font-mono ${badgeColor}`}
                >
                  <span className="font-bold">{code}</span>
                  <span className="text-slate-400 text-[11px]">({count.toLocaleString()})</span>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Grid: 4xx Probed Paths & Known Scanner Tools */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Top 4xx Probed Endpoints */}
        <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <AlertCircle className="w-4 h-4 text-amber-400" />
              <h4 className="text-xs font-semibold text-slate-200">Sensitive & Probed 4xx Paths</h4>
            </div>
            <span className="text-[11px] text-slate-500">Hits / Unique IPs</span>
          </div>

          {httpStats.top4xxPaths.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-500">No 4xx probing activity recorded.</div>
          ) : (
            <div className="divide-y divide-slate-800/80 font-mono text-xs">
              {httpStats.top4xxPaths.map((item) => (
                <div
                  key={item.path}
                  onClick={() => onFilterPath?.(item.path)}
                  className="py-2.5 flex items-center justify-between hover:bg-slate-800/40 px-2 rounded cursor-pointer transition-colors"
                >
                  <div className="min-w-0 pr-2">
                    <span className="text-amber-300 font-semibold truncate block max-w-sm">{item.path}</span>
                    <span className="text-[10px] text-slate-500">
                      IPs: {item.ips.slice(0, 2).join(', ')}
                      {item.ips.length > 2 ? ` (+${item.ips.length - 2})` : ''}
                    </span>
                  </div>
                  <span className="text-slate-200 font-bold tabular-nums shrink-0">
                    {item.count} hits
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Known Automated Security Scanners */}
        <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Bot className="w-4 h-4 text-rose-400" />
              <h4 className="text-xs font-semibold text-slate-200">Security Scanners & Tools</h4>
            </div>
            <span className="text-[11px] text-slate-500">Identified Signatures</span>
          </div>

          {httpStats.scannerUserAgents.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-500">No known scanner signatures identified.</div>
          ) : (
            <div className="divide-y divide-slate-800/80 font-mono text-xs">
              {httpStats.scannerUserAgents.map((item) => (
                <div
                  key={item.userAgent}
                  className="py-2.5 flex items-center justify-between hover:bg-slate-800/40 px-2 rounded transition-colors"
                >
                  <div className="min-w-0 pr-2">
                    <span className="text-rose-400 font-semibold truncate block max-w-sm">{item.userAgent}</span>
                    <span className="text-[10px] text-slate-500">
                      From: {item.ips.join(', ')}
                    </span>
                  </div>
                  <span className="text-rose-300 font-bold tabular-nums shrink-0">
                    {item.count} reqs
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
