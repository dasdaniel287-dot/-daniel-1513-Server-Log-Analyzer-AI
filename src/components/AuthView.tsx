import React from 'react';
import { AuthStatistics } from '../types/log';
import { KeyRound, ShieldAlert, CheckCircle2, UserCheck, AlertOctagon } from 'lucide-react';

interface AuthViewProps {
  authStats: AuthStatistics;
  onFilterUser?: (user: string) => void;
  onFilterIp?: (ip: string) => void;
}

export const AuthView: React.FC<AuthViewProps> = ({ authStats, onFilterUser, onFilterIp }) => {
  return (
    <div className="space-y-4">
      {/* KPI Ribbon */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-3.5 bg-slate-900/70 border border-slate-800 rounded-xl">
          <div className="text-[11px] text-slate-400 font-medium">Total Auth Attempts</div>
          <div className="text-xl font-bold font-mono text-slate-100 tabular-nums mt-1">
            {authStats.totalAttempts.toLocaleString()}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">SSH & PAM events</div>
        </div>

        <div className="p-3.5 bg-slate-900/70 border border-slate-800 rounded-xl">
          <div className="text-[11px] text-slate-400 font-medium">Failed Authentications</div>
          <div className="text-xl font-bold font-mono text-rose-400 tabular-nums mt-1">
            {authStats.failedAttempts.toLocaleString()}
          </div>
          <div className="text-[10px] text-rose-400/80 mt-0.5">
            {authStats.failureRate}% failure rate
          </div>
        </div>

        <div className="p-3.5 bg-slate-900/70 border border-slate-800 rounded-xl">
          <div className="text-[11px] text-slate-400 font-medium">Successful Logins</div>
          <div className="text-xl font-bold font-mono text-emerald-400 tabular-nums mt-1">
            {authStats.successfulLogins.toLocaleString()}
          </div>
          <div className="text-[10px] text-emerald-400/80 mt-0.5">Authorized access</div>
        </div>

        <div className="p-3.5 bg-slate-900/70 border border-slate-800 rounded-xl">
          <div className="text-[11px] text-slate-400 font-medium">Suspicious Sequences</div>
          <div className="text-xl font-bold font-mono text-amber-400 tabular-nums mt-1">
            {authStats.suspiciousSequences.length}
          </div>
          <div className="text-[10px] text-amber-400/80 mt-0.5">Failures followed by success</div>
        </div>
      </div>

      {/* Critical Compromise Indicator: Success After Failures */}
      {authStats.suspiciousSequences.length > 0 && (
        <div className="p-4 bg-red-950/30 border border-red-900/80 rounded-xl">
          <div className="flex items-center gap-2 mb-2">
            <AlertOctagon className="w-4 h-4 text-rose-400" />
            <h4 className="text-xs font-semibold uppercase tracking-wider text-rose-300">
              High Priority Warning: Successful Authentications Following Repeated Failures
            </h4>
          </div>
          <p className="text-xs text-slate-300 mb-3">
            The following hosts experienced repeated authentication failures before a valid credential was supplied. This pattern warrants urgent verification:
          </p>
          <div className="space-y-2">
            {authStats.suspiciousSequences.map((seq, idx) => (
              <div
                key={idx}
                className="p-2.5 bg-slate-950/70 border border-red-900/50 rounded-lg flex flex-wrap items-center justify-between gap-3 text-xs font-mono"
              >
                <div>
                  <span className="text-cyan-400 font-bold">{seq.ip}</span>
                  <span className="text-slate-500 mx-2">→</span>
                  <span className="text-amber-400 font-bold">User: {seq.user}</span>
                  <span className="text-slate-500 mx-2">·</span>
                  <span className="text-rose-400">{seq.failedBeforeSuccess} prior failed attempts</span>
                </div>
                <div className="text-slate-400 text-[11px]">
                  Success Timestamp: {seq.timestamp.replace('T', ' ').slice(0, 19)}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Grid: Top Targeted Users & Top Failed IPs */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Top Targeted Users */}
        <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-amber-400" />
              <h4 className="text-xs font-semibold text-slate-200">Top Targeted User Accounts</h4>
            </div>
            <span className="text-[11px] text-slate-500">Failures / Successes</span>
          </div>

          {authStats.topTargetedUsers.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-500">No account targeting recorded.</div>
          ) : (
            <div className="divide-y divide-slate-800/80 font-mono text-xs">
              {authStats.topTargetedUsers.map((u) => (
                <div
                  key={u.user}
                  onClick={() => onFilterUser?.(u.user)}
                  className="py-2.5 flex items-center justify-between hover:bg-slate-800/40 px-2 rounded cursor-pointer transition-colors"
                >
                  <div className="flex items-center gap-2">
                    <UserCheck className="w-3.5 h-3.5 text-slate-500" />
                    <span className="text-slate-200 font-semibold">{u.user}</span>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-rose-400 font-semibold tabular-nums">
                      {u.failures} fails
                    </span>
                    <span className="text-slate-600">/</span>
                    <span className="text-emerald-400 tabular-nums">{u.successes} ok</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top Failed Source IPs */}
        <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              <h4 className="text-xs font-semibold text-slate-200">Top Failed Source IP Addresses</h4>
            </div>
            <span className="text-[11px] text-slate-500">Attempts / Targets</span>
          </div>

          {authStats.topFailedIps.length === 0 ? (
            <div className="py-8 text-center text-xs text-slate-500">No failed IP activity detected.</div>
          ) : (
            <div className="divide-y divide-slate-800/80 font-mono text-xs">
              {authStats.topFailedIps.map((item) => (
                <div
                  key={item.ip}
                  onClick={() => onFilterIp?.(item.ip)}
                  className="py-2.5 flex items-center justify-between hover:bg-slate-800/40 px-2 rounded cursor-pointer transition-colors"
                >
                  <div>
                    <span className="text-cyan-400 font-semibold block">{item.ip}</span>
                    <span className="text-[10px] text-slate-500">
                      Targets: {item.targets.slice(0, 3).join(', ')}
                      {item.targets.length > 3 ? ` (+${item.targets.length - 3})` : ''}
                    </span>
                  </div>
                  <span className="text-rose-400 font-bold tabular-nums">
                    {item.count} attempts
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
