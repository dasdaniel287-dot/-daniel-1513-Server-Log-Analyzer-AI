import React, { useState, useEffect, useRef } from 'react';
import { LogEntry } from '../types/log';
import { parseLogLine } from '../engine/parsers';
import { Play, Pause, RotateCcw, PlusCircle, Terminal, Radio } from 'lucide-react';

interface LiveMonitorProps {
  onAppendEntry?: (entry: LogEntry) => void;
}

const STREAM_TEMPLATES = [
  '2026-10-25 14:40:01,112 [INFO] [app.worker] Heartbeat check completed in 12ms',
  '198.51.100.22 - - [25/Oct/2026:14:40:02 +0000] "GET /api/v1/health HTTP/1.1" 200 42 "-" "kube-probe/1.28"',
  'Oct 25 14:40:05 bastion sshd[31201]: Failed password for invalid user admin from 198.51.100.99 port 51234 ssh2',
  '198.51.100.80 - - [25/Oct/2026:14:40:07 +0000] "GET /.env HTTP/1.1" 404 162 "-" "Mozilla/5.0"',
  '2026-10-25 14:40:09,340 [WARN] [app.cache] Redis pool response latency elevated: 890ms',
  '198.51.100.22 - - [25/Oct/2026:14:40:11 +0000] "GET /api/v1/users/me HTTP/1.1" 200 1204 "-" "Mozilla/5.0"',
  '2026-10-25 14:40:14,402 [ERROR] [app.db] OperationalError: server closed connection unexpectedly',
  '198.51.100.99 - - [25/Oct/2026:14:40:18 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Nikto/2.1.6"',
  'Oct 25 14:40:22 bastion sshd[31205]: Accepted publickey for s_chen from 192.168.1.105 port 42100 ssh2: RSA',
];

export const LiveMonitor: React.FC<LiveMonitorProps> = ({ onAppendEntry }) => {
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [speed, setSpeed] = useState<number>(1500); // ms per event
  const [streamEntries, setStreamEntries] = useState<LogEntry[]>([]);
  const [totalStreamed, setTotalStreamed] = useState<number>(0);
  const [errorCount, setErrorCount] = useState<number>(0);
  const terminalEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (!isRunning) return;

    const interval = setInterval(() => {
      const template = STREAM_TEMPLATES[Math.floor(Math.random() * STREAM_TEMPLATES.length)];
      const entry = parseLogLine(template, totalStreamed + 1);

      setStreamEntries((prev) => [...prev.slice(-100), entry]);
      setTotalStreamed((c) => c + 1);
      if (entry.level === 'ERROR' || entry.level === 'CRITICAL') {
        setErrorCount((e) => e + 1);
      }
      onAppendEntry?.(entry);
    }, speed);

    return () => clearInterval(interval);
  }, [isRunning, speed, totalStreamed, onAppendEntry]);

  // Auto-scroll terminal
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [streamEntries]);

  const handleInjectAttack = (type: 'ssh_burst' | 'http_502' | 'scanner_probe') => {
    let lines: string[] = [];
    if (type === 'ssh_burst') {
      lines = [
        'Oct 25 14:41:01 bastion sshd[32001]: Failed password for invalid user root from 203.0.113.77 port 48110 ssh2',
        'Oct 25 14:41:03 bastion sshd[32002]: Failed password for invalid user admin from 203.0.113.77 port 48114 ssh2',
        'Oct 25 14:41:05 bastion sshd[32003]: Failed password for invalid user oracle from 203.0.113.77 port 48118 ssh2',
        'Oct 25 14:41:07 bastion sshd[32004]: Failed password for invalid user postgres from 203.0.113.77 port 48122 ssh2',
      ];
    } else if (type === 'http_502') {
      lines = [
        '2026/10/25 14:41:10 [error] 1402#0: *82 connect() failed (111: Connection refused) while connecting to upstream, client: 198.51.100.5',
        '198.51.100.5 - - [25/Oct/2026:14:41:10 +0000] "POST /api/v1/checkout HTTP/1.1" 502 173 "-" "Mozilla/5.0"',
      ];
    } else {
      lines = [
        '198.51.100.44 - - [25/Oct/2026:14:41:15 +0000] "GET /actuator/health HTTP/1.1" 404 162 "-" "sqlmap/1.7#stable"',
        '198.51.100.44 - - [25/Oct/2026:14:41:16 +0000] "GET /actuator/env HTTP/1.1" 404 162 "-" "sqlmap/1.7#stable"',
      ];
    }

    const newEntries = lines.map((l, i) => parseLogLine(l, totalStreamed + i + 1));
    setStreamEntries((prev) => [...prev.slice(-100), ...newEntries]);
    setTotalStreamed((c) => c + newEntries.length);
    newEntries.forEach((e) => {
      if (e.level === 'ERROR' || e.level === 'CRITICAL') setErrorCount((cnt) => cnt + 1);
      onAppendEntry?.(e);
    });
  };

  return (
    <div className="space-y-4">
      {/* Control Banner */}
      <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Radio className={`w-4 h-4 ${isRunning ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`} />
            <h3 className="text-sm font-semibold text-slate-100">
              Live Incremental Log Receiver & Monitoring Console
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Simulates real-time syslog/nginx streaming ingest with auto-sanitization and on-the-fly parsing.
          </p>
        </div>

        {/* Live Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => setIsRunning(!isRunning)}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors ${
              isRunning
                ? 'bg-amber-500 hover:bg-amber-400 text-slate-950'
                : 'bg-emerald-500 hover:bg-emerald-400 text-slate-950'
            }`}
          >
            {isRunning ? (
              <>
                <Pause className="w-3.5 h-3.5" />
                <span>Pause Stream</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Start Stream</span>
              </>
            )}
          </button>

          <select
            value={speed}
            onChange={(e) => setSpeed(parseInt(e.target.value, 10))}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 font-mono"
          >
            <option value={3000}>Speed: 0.5x (Slow)</option>
            <option value={1500}>Speed: 1.0x (Normal)</option>
            <option value={600}>Speed: 2.5x (Fast)</option>
          </select>

          <button
            onClick={() => {
              setStreamEntries([]);
              setTotalStreamed(0);
              setErrorCount(0);
            }}
            className="p-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg text-slate-300 transition-colors"
            title="Clear Stream"
          >
            <RotateCcw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Telemetry Counter Strip */}
      <div className="grid grid-cols-3 gap-3">
        <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
          <span className="text-[11px] text-slate-400 block">Stream Status</span>
          <span className={`text-sm font-semibold font-mono ${isRunning ? 'text-emerald-400' : 'text-slate-400'}`}>
            {isRunning ? '● ACTIVE STREAMING' : '○ PAUSED / IDLE'}
          </span>
        </div>
        <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
          <span className="text-[11px] text-slate-400 block">Streamed Records</span>
          <span className="text-sm font-bold font-mono text-cyan-400 tabular-nums">
            {totalStreamed.toLocaleString()}
          </span>
        </div>
        <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
          <span className="text-[11px] text-slate-400 block">Stream Errors</span>
          <span className="text-sm font-bold font-mono text-rose-400 tabular-nums">
            {errorCount.toLocaleString()}
          </span>
        </div>
      </div>

      {/* Synthetic Incident Injectors */}
      <div className="p-3 bg-slate-900/40 border border-slate-800/80 rounded-lg flex flex-wrap items-center justify-between gap-2">
        <span className="text-xs text-slate-400 flex items-center gap-1.5 font-medium">
          <PlusCircle className="w-3.5 h-3.5 text-cyan-400" />
          <span>Simulate Synthetic Pattern Ingestion:</span>
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={() => handleInjectAttack('ssh_burst')}
            className="px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-amber-300 rounded border border-slate-700 transition-colors"
          >
            + SSH Brute-Force Burst
          </button>
          <button
            onClick={() => handleInjectAttack('http_502')}
            className="px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-rose-300 rounded border border-slate-700 transition-colors"
          >
            + Upstream 502 Crash
          </button>
          <button
            onClick={() => handleInjectAttack('scanner_probe')}
            className="px-2.5 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded border border-slate-700 transition-colors"
          >
            + Web Scanner Probe
          </button>
        </div>
      </div>

      {/* Terminal Viewport */}
      <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs overflow-hidden">
        <div className="flex items-center justify-between pb-2 mb-2 border-b border-slate-800/80 text-[11px] text-slate-500">
          <div className="flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5 text-slate-400" />
            <span>live-log-tail --follow --sanitize</span>
          </div>
          <span>Showing latest {streamEntries.length} lines</span>
        </div>

        <div className="h-80 overflow-y-auto space-y-1 pr-2 no-scrollbar">
          {streamEntries.length === 0 ? (
            <div className="h-full flex items-center justify-center text-slate-600">
              Click &quot;Start Stream&quot; or inject synthetic events to begin streaming live logs.
            </div>
          ) : (
            streamEntries.map((e, idx) => {
              let color = 'text-slate-300';
              if (e.level === 'CRITICAL' || e.level === 'ERROR') color = 'text-rose-400 font-semibold';
              else if (e.level === 'WARN') color = 'text-amber-300';

              return (
                <div key={idx} className="flex items-start gap-2 hover:bg-slate-900/60 px-1 rounded">
                  <span className="text-slate-600 select-none tabular-nums w-8 shrink-0">
                    {idx + 1}
                  </span>
                  <span className="text-slate-500 select-none shrink-0">
                    {e.timestamp.slice(11, 19)}
                  </span>
                  <span
                    className={`shrink-0 text-[10px] uppercase font-bold w-12 ${
                      e.level === 'CRITICAL' || e.level === 'ERROR'
                        ? 'text-rose-400'
                        : e.level === 'WARN'
                        ? 'text-amber-400'
                        : 'text-cyan-400'
                    }`}
                  >
                    [{e.level.slice(0, 4)}]
                  </span>
                  <span className={`break-all ${color}`}>{e.sanitized}</span>
                </div>
              );
            })
          )}
          <div ref={terminalEndRef} />
        </div>
      </div>
    </div>
  );
};
