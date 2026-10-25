import React, { useState, useMemo } from 'react';
import { LogEntry, LogLevel, LogSource } from '../types/log';
import { Search, ChevronDown, ChevronRight, Copy, Check, FilterX } from 'lucide-react';

interface LogTableProps {
  entries: LogEntry[];
  initialSearch?: string;
}

export const LogTable: React.FC<LogTableProps> = ({ entries, initialSearch = '' }) => {
  const [search, setSearch] = useState(initialSearch);
  const [levelFilter, setLevelFilter] = useState<string>('ALL');
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');
  const [expandedRowId, setExpandedRowId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 40;

  // Filtered entries
  const filtered = useMemo(() => {
    let result = entries;

    if (levelFilter !== 'ALL') {
      result = result.filter((e) => e.level === levelFilter);
    }

    if (sourceFilter !== 'ALL') {
      result = result.filter((e) => e.source === sourceFilter);
    }

    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(
        (e) =>
          e.sanitized.toLowerCase().includes(q) ||
          e.message.toLowerCase().includes(q) ||
          (e.ip && e.ip.toLowerCase().includes(q)) ||
          (e.service && e.service.toLowerCase().includes(q)) ||
          (e.http?.path && e.http.path.toLowerCase().includes(q)) ||
          (e.auth?.user && e.auth.user.toLowerCase().includes(q))
      );
    }

    return result;
  }, [entries, search, levelFilter, sourceFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const paginated = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filtered.slice(start, start + pageSize);
  }, [filtered, currentPage, pageSize]);

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getLevelBadgeClass = (level: LogLevel) => {
    switch (level) {
      case 'CRITICAL':
        return 'text-rose-400 font-bold';
      case 'ERROR':
        return 'text-rose-400 font-semibold';
      case 'WARN':
        return 'text-amber-400 font-medium';
      case 'DEBUG':
        return 'text-slate-500';
      default:
        return 'text-cyan-400 font-normal';
    }
  };

  return (
    <div className="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden flex flex-col">
      {/* Controls Bar */}
      <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-950/40">
        <div className="flex items-center gap-2 flex-1 min-w-[240px]">
          <div className="relative w-full max-w-md">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setCurrentPage(1);
              }}
              placeholder="Search keyword, IP address, path, user, service..."
              className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>

          {(search || levelFilter !== 'ALL' || sourceFilter !== 'ALL') && (
            <button
              onClick={() => {
                setSearch('');
                setLevelFilter('ALL');
                setSourceFilter('ALL');
                setCurrentPage(1);
              }}
              className="px-2.5 py-1.5 text-xs text-slate-400 hover:text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors flex items-center gap-1 shrink-0"
              title="Reset search & filters"
            >
              <FilterX className="w-3 h-3" />
              <span>Reset</span>
            </button>
          )}
        </div>

        {/* Filters */}
        <div className="flex items-center gap-2 shrink-0">
          {/* Level Filter */}
          <select
            value={levelFilter}
            onChange={(e) => {
              setLevelFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Levels</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="ERROR">ERROR</option>
            <option value="WARN">WARN</option>
            <option value="INFO">INFO</option>
            <option value="DEBUG">DEBUG</option>
          </select>

          {/* Source Filter */}
          <select
            value={sourceFilter}
            onChange={(e) => {
              setSourceFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="bg-slate-900 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Sources</option>
            <option value="auth">SSH / Auth</option>
            <option value="nginx_access">Nginx Access</option>
            <option value="nginx_error">Nginx Error</option>
            <option value="apache_access">Apache Access</option>
            <option value="python_app">Python Application</option>
            <option value="syslog">Syslog / Kernel</option>
            <option value="json">JSON Logs</option>
            <option value="custom">Generic / Custom</option>
          </select>

          <span className="text-[11px] text-slate-500 font-mono tabular-nums px-2">
            {filtered.length} / {entries.length} rows
          </span>
        </div>
      </div>

      {/* High-Density Log Table */}
      <div className="overflow-x-auto min-h-[420px]">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="bg-slate-950/70 border-b border-slate-800 text-[11px] text-slate-400 font-medium tracking-tight">
              <th className="py-2 px-3 w-10 text-center">#</th>
              <th className="py-2 px-3 w-40">Timestamp</th>
              <th className="py-2 px-3 w-20">Level</th>
              <th className="py-2 px-3 w-28">Source / Svc</th>
              <th className="py-2 px-3 w-36">Host / IP</th>
              <th className="py-2 px-3">Sanitized Event Message</th>
              <th className="py-2 px-3 w-12 text-center">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {paginated.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-12 text-center text-slate-500">
                  No log entries matched the active filter criteria.
                </td>
              </tr>
            ) : (
              paginated.map((e) => {
                const isExpanded = expandedRowId === e.id;
                return (
                  <React.Fragment key={e.id}>
                    <tr
                      onClick={() => setExpandedRowId(isExpanded ? null : e.id)}
                      className={`hover:bg-slate-800/40 transition-colors cursor-pointer text-[11px] ${
                        isExpanded ? 'bg-slate-800/30' : ''
                      }`}
                    >
                      <td className="py-2 px-3 text-slate-600 text-center tabular-nums">
                        {e.lineNumber}
                      </td>
                      <td className="py-2 px-3 text-slate-400 tabular-nums whitespace-nowrap">
                        {e.timestamp.replace('T', ' ').slice(0, 19)}
                      </td>
                      <td className={`py-2 px-3 ${getLevelBadgeClass(e.level)}`}>
                        {e.level}
                      </td>
                      <td className="py-2 px-3 text-slate-300 truncate max-w-[120px]">
                        {e.service || e.source}
                      </td>
                      <td className="py-2 px-3 text-cyan-300 truncate max-w-[140px]">
                        {e.ip || e.hostname || '—'}
                      </td>
                      <td className="py-2 px-3 text-slate-200 font-sans truncate max-w-xl">
                        {e.sanitized}
                      </td>
                      <td className="py-2 px-3 text-center">
                        {isExpanded ? (
                          <ChevronDown className="w-3.5 h-3.5 text-slate-400 inline" />
                        ) : (
                          <ChevronRight className="w-3.5 h-3.5 text-slate-500 inline" />
                        )}
                      </td>
                    </tr>

                    {/* Expandable Inspection Drawer */}
                    {isExpanded && (
                      <tr className="bg-slate-950/90 border-b border-slate-800">
                        <td colSpan={7} className="p-4 text-xs font-mono">
                          <div className="space-y-3">
                            <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                              <div className="text-[11px] text-slate-400">
                                <strong>Log Entry Reference:</strong> Line {e.lineNumber} · Source: {e.source}
                              </div>
                              <button
                                onClick={(ev) => {
                                  ev.stopPropagation();
                                  handleCopy(e.id, e.raw);
                                }}
                                className="px-2.5 py-1 text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-300 rounded flex items-center gap-1.5 transition-colors"
                              >
                                {copiedId === e.id ? (
                                  <>
                                    <Check className="w-3 h-3 text-emerald-400" />
                                    <span>Copied</span>
                                  </>
                                ) : (
                                  <>
                                    <Copy className="w-3 h-3" />
                                    <span>Copy Raw</span>
                                  </>
                                )}
                              </button>
                            </div>

                            {/* Raw & Sanitized Comparison */}
                            <div>
                              <div className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold mb-1">
                                Sanitized Display (PII & Secrets Protected)
                              </div>
                              <div className="p-2.5 bg-slate-900 border border-slate-800 rounded text-slate-200 break-all select-all">
                                {e.sanitized}
                              </div>
                            </div>

                            {/* Structured Context Grid */}
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px]">
                              {e.ip && (
                                <div className="p-2 bg-slate-900/60 border border-slate-800 rounded">
                                  <span className="text-slate-500 block">Client IP</span>
                                  <span className="text-cyan-400 font-semibold">{e.ip}</span>
                                </div>
                              )}
                              {e.http && (
                                <>
                                  <div className="p-2 bg-slate-900/60 border border-slate-800 rounded">
                                    <span className="text-slate-500 block">HTTP Request</span>
                                    <span className="text-emerald-400">{e.http.method} {e.http.path}</span>
                                  </div>
                                  <div className="p-2 bg-slate-900/60 border border-slate-800 rounded">
                                    <span className="text-slate-500 block">HTTP Status</span>
                                    <span className={e.http.status >= 400 ? 'text-rose-400 font-bold' : 'text-slate-200'}>
                                      {e.http.status}
                                    </span>
                                  </div>
                                </>
                              )}
                              {e.auth && (
                                <>
                                  <div className="p-2 bg-slate-900/60 border border-slate-800 rounded">
                                    <span className="text-slate-500 block">Target Account</span>
                                    <span className="text-amber-400">{e.auth.user || 'N/A'}</span>
                                  </div>
                                  <div className="p-2 bg-slate-900/60 border border-slate-800 rounded">
                                    <span className="text-slate-500 block">Auth Outcome</span>
                                    <span className={e.auth.status === 'FAILURE' ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                                      {e.auth.status}
                                    </span>
                                  </div>
                                </>
                              )}
                              {e.exceptionClass && (
                                <div className="p-2 bg-slate-900/60 border border-slate-800 rounded">
                                  <span className="text-slate-500 block">Exception</span>
                                  <span className="text-rose-400">{e.exceptionClass}</span>
                                </div>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Bar */}
      <div className="p-3 border-t border-slate-800 bg-slate-950/50 flex items-center justify-between text-xs text-slate-400">
        <div>
          Showing page <strong>{currentPage}</strong> of <strong>{totalPages}</strong>
        </div>
        <div className="flex items-center gap-1.5">
          <button
            disabled={currentPage === 1}
            onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
            className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-700 transition-colors"
          >
            Previous
          </button>
          <button
            disabled={currentPage === totalPages}
            onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
            className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-slate-700 transition-colors"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
};
