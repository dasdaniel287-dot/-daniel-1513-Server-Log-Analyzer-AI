import React, { useState } from 'react';
import { AnalysisResult } from '../types/log';
import { generateCsvExport, generateHtmlReport, generateJsonExport } from '../engine/reports';
import { Download, Printer, Cpu, FileSpreadsheet, FileCode, CheckCircle, RefreshCw } from 'lucide-react';

interface ReportsViewProps {
  analysis: AnalysisResult;
}

interface BenchmarkResult {
  targetLines: number;
  parsedRecords: number;
  durationMs: number;
  throughputLinesPerSec: number;
  memoryDeltaMb: number;
  alertsDetected: number;
  errorGroupsCount: number;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ analysis }) => {
  const [analystNotes, setAnalystNotes] = useState<string>(
    'Incident investigation conducted pursuant to defensive security audit. Empirical findings reviewed against perimeter baselines.'
  );
  const [benchmarkLoading, setBenchmarkLoading] = useState<boolean>(false);
  const [benchmarkData, setBenchmarkData] = useState<BenchmarkResult | null>(null);
  const [benchmarkSize, setBenchmarkSize] = useState<number>(10000);

  const downloadFile = (content: string, filename: string, type: string) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDownloadCsv = () => {
    const csv = generateCsvExport(analysis);
    downloadFile(csv, `server-log-analysis-${Date.now()}.csv`, 'text/csv;charset=utf-8;');
  };

  const handleDownloadJson = () => {
    const jsonStr = generateJsonExport(analysis);
    downloadFile(jsonStr, `server-log-analysis-${Date.now()}.json`, 'application/json');
  };

  const handlePrintHtml = () => {
    const html = generateHtmlReport(analysis, analystNotes);
    const printWindow = window.open('', '_blank');
    if (printWindow) {
      printWindow.document.write(html);
      printWindow.document.close();
      printWindow.focus();
      setTimeout(() => {
        printWindow.print();
      }, 350);
    }
  };

  const handleRunBenchmark = async () => {
    setBenchmarkLoading(true);
    try {
      const res = await fetch('/api/benchmarks', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ lineCount: benchmarkSize }),
      });
      const data = await res.json();
      if (data.success) {
        setBenchmarkData(data.benchmark);
      }
    } catch (err) {
      console.error('Benchmark execution error:', err);
    } finally {
      setBenchmarkLoading(false);
    }
  };

  return (
    <div className="space-y-5">
      {/* Top Banner */}
      <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-100">
            Report Generation & Diagnostic Audit Center
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Export structured security incident dossiers in CSV (with formula injection defense), JSON, or self-contained HTML.
          </p>
        </div>

        {/* Quick Action Buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadCsv}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={handleDownloadJson}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 rounded-lg text-xs font-medium flex items-center gap-1.5 transition-colors"
          >
            <FileCode className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={handlePrintHtml}
            className="px-3.5 py-1.5 bg-cyan-400 hover:bg-cyan-300 text-slate-950 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Printable HTML / PDF</span>
          </button>
        </div>
      </div>

      {/* Analyst Annotations Card */}
      <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2">
        <label className="text-xs font-semibold text-slate-300 block">
          Incident Investigation Notes & Remediation Summary (Included in Exported Reports):
        </label>
        <textarea
          rows={3}
          value={analystNotes}
          onChange={(e) => setAnalystNotes(e.target.value)}
          placeholder="Add manual verification notes, forensic findings, or ticket references..."
          className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-sans"
        />
      </div>

      {/* Report Structure & Scope Preview */}
      <div className="p-4 bg-slate-900/50 border border-slate-800 rounded-xl">
        <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider mb-3">
          Current Analysis Scope & Data Boundaries
        </h4>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div className="p-2.5 bg-slate-950/60 border border-slate-800/80 rounded">
            <span className="text-slate-500 block text-[10px]">Processing Timeline</span>
            <span className="text-slate-200 font-mono font-medium">
              {analysis.summary.timeRange.start.slice(0, 19)} → {analysis.summary.timeRange.end.slice(11, 19)}
            </span>
          </div>
          <div className="p-2.5 bg-slate-950/60 border border-slate-800/80 rounded">
            <span className="text-slate-500 block text-[10px]">Records Processed</span>
            <span className="text-slate-200 font-mono font-medium">
              {analysis.summary.totalLines} lines ({analysis.summary.parsedRecords} valid)
            </span>
          </div>
          <div className="p-2.5 bg-slate-950/60 border border-slate-800/80 rounded">
            <span className="text-slate-500 block text-[10px]">Unique Source IPs</span>
            <span className="text-cyan-400 font-mono font-medium">
              {analysis.summary.uniqueIps} observed hosts
            </span>
          </div>
          <div className="p-2.5 bg-slate-950/60 border border-slate-800/80 rounded">
            <span className="text-slate-500 block text-[10px]">Active Alerts</span>
            <span className="text-rose-400 font-mono font-medium">
              {analysis.alerts.length} security alerts
            </span>
          </div>
        </div>
      </div>

      {/* Reproducible Performance Benchmarks Engine */}
      <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h4 className="text-xs font-semibold text-slate-200">
              Reproducible Ingestion & Parsing Benchmarks
            </h4>
          </div>

          <div className="flex items-center gap-2">
            <select
              value={benchmarkSize}
              onChange={(e) => setBenchmarkSize(parseInt(e.target.value, 10))}
              className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-xs text-slate-300 font-mono"
            >
              <option value={1000}>1,000 records</option>
              <option value={10000}>10,000 records</option>
              <option value={50000}>50,000 records</option>
            </select>

            <button
              disabled={benchmarkLoading}
              onClick={handleRunBenchmark}
              className="px-3 py-1 bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-800/60 rounded text-xs font-medium flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              {benchmarkLoading ? (
                <>
                  <RefreshCw className="w-3 h-3 animate-spin" />
                  <span>Measuring...</span>
                </>
              ) : (
                <>
                  <Cpu className="w-3 h-3" />
                  <span>Execute Benchmark</span>
                </>
              )}
            </button>
          </div>
        </div>

        {benchmarkData && (
          <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
              <div>
                <span className="text-slate-500 block text-[10px]">Parsed Dataset</span>
                <span className="text-slate-200 font-bold tabular-nums">
                  {benchmarkData.targetLines.toLocaleString()} records
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Total Elapsed Duration</span>
                <span className="text-cyan-400 font-bold tabular-nums">
                  {benchmarkData.durationMs} ms
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Actual Throughput</span>
                <span className="text-emerald-400 font-bold tabular-nums">
                  {benchmarkData.throughputLinesPerSec.toLocaleString()} lines/sec
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px]">Memory Allocated</span>
                <span className="text-amber-400 font-bold tabular-nums">
                  +{benchmarkData.memoryDeltaMb} MB RAM
                </span>
              </div>
            </div>
            <div className="text-[10px] text-slate-500 mt-2">
              Benchmark measured using in-memory synthetic multi-format server logs on Node.js / V8 runtime.
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
