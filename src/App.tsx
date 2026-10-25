/**
 * Server Log Analyzer AI - Core Application Entry Point
 * Intelligent Log Monitoring, Anomaly Detection & Defensive Security Analysis Platform
 */

import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { AnalysisResult, AlertStatus, DetectionRuleConfig, LogEntry, SecurityAlert, CorrelatedIncident, TimelineBucket } from './types/log';
import { analyzeLogs, DEFAULT_DETECTION_RULES } from './engine/analyzer';
import { SAMPLE_LOGS, SampleLogDefinition } from './data/sampleLogs';

import { Header, ActiveTab } from './components/Header';
import { MetricCards } from './components/MetricCards';
import { TimelineChart } from './components/TimelineChart';
import { LogTable } from './components/LogTable';
import { AlertsManager } from './components/AlertsManager';
import { AuthView } from './components/AuthView';
import { HttpView } from './components/HttpView';
import { CorrelationView } from './components/CorrelationView';
import { AiAssistant } from './components/AiAssistant';
import { LiveMonitor } from './components/LiveMonitor';
import { ReportsView } from './components/ReportsView';
import { SettingsView } from './components/SettingsView';
import { UploadModal } from './components/UploadModal';
import { SamplePickerModal } from './components/SamplePickerModal';

import { 
  ShieldAlert, 
  Layers, 
  Activity, 
  AlertTriangle, 
  CheckCircle2, 
  ArrowRight,
  Server,
  Zap
} from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('overview');
  const [rules, setRules] = useState<DetectionRuleConfig[]>(DEFAULT_DETECTION_RULES);
  
  // Combine first 3 sample logs for rich initial state
  const initialLogPayload = useMemo(() => {
    return [
      SAMPLE_LOGS[0].content,
      SAMPLE_LOGS[1].content,
      SAMPLE_LOGS[2].content,
    ].join('\n');
  }, []);

  const [rawLogs, setRawLogs] = useState<string>(initialLogPayload);
  const [analysis, setAnalysis] = useState<AnalysisResult>(() => analyzeLogs(initialLogPayload, DEFAULT_DETECTION_RULES));

  // Modals & Navigation state
  const [isUploadOpen, setIsUploadOpen] = useState<boolean>(false);
  const [isSamplesOpen, setIsSamplesOpen] = useState<boolean>(false);
  const [tableSearchFilter, setTableSearchFilter] = useState<string>('');
  const [selectedAlertForAi, setSelectedAlertForAi] = useState<SecurityAlert | null>(null);
  const [selectedIncidentForAi, setSelectedIncidentForAi] = useState<CorrelatedIncident | null>(null);

  // Re-run analysis if rules change
  const reanalyze = useCallback((content: string, customRules: DetectionRuleConfig[]) => {
    const res = analyzeLogs(content, customRules);
    setAnalysis(res);
  }, []);

  const handleUpdateRule = (updated: DetectionRuleConfig) => {
    const nextRules = rules.map((r) => (r.id === updated.id ? updated : r));
    setRules(nextRules);
    reanalyze(rawLogs, nextRules);
  };

  const handleResetRules = () => {
    setRules(DEFAULT_DETECTION_RULES);
    reanalyze(rawLogs, DEFAULT_DETECTION_RULES);
  };

  const handleNewLogIngestion = (newRawText: string) => {
    setRawLogs(newRawText);
    reanalyze(newRawText, rules);
    setTableSearchFilter('');
    setActiveTab('overview');
  };

  const handleSelectSample = (sample: SampleLogDefinition) => {
    handleNewLogIngestion(sample.content);
  };

  const handleUpdateAlertStatus = (alertId: string, status: AlertStatus) => {
    setAnalysis((prev) => ({
      ...prev,
      alerts: prev.alerts.map((a) => (a.id === alertId ? { ...a, status } : a)),
    }));
  };

  // Live monitor append entry handler
  const handleAppendEntry = (newEntry: LogEntry) => {
    setAnalysis((prev) => {
      const updatedEntries = [...prev.entries, newEntry];
      return {
        ...prev,
        entries: updatedEntries,
        summary: {
          ...prev.summary,
          totalLines: prev.summary.totalLines + 1,
          parsedRecords: prev.summary.parsedRecords + 1,
          errorCount: newEntry.level === 'ERROR' ? prev.summary.errorCount + 1 : prev.summary.errorCount,
          warnCount: newEntry.level === 'WARN' ? prev.summary.warnCount + 1 : prev.summary.warnCount,
          criticalCount: newEntry.level === 'CRITICAL' ? prev.summary.criticalCount + 1 : prev.summary.criticalCount,
        },
      };
    });
  };

  // Jump helpers
  const handleJumpToLogsWithQuery = (query: string) => {
    setTableSearchFilter(query);
    setActiveTab('logs');
  };

  const handleJumpToAiWithAlert = (alert: SecurityAlert) => {
    setSelectedAlertForAi(alert);
    setSelectedIncidentForAi(null);
    setActiveTab('ai');
  };

  const handleSelectTimelineBucket = (bucket: TimelineBucket) => {
    setTableSearchFilter(bucket.bucket);
    setActiveTab('logs');
  };

  const criticalAlertCount = analysis.alerts.filter((a) => a.severity === 'Critical').length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* 3-Zone Fixed Header */}
      <Header
        activeTab={activeTab}
        onTabChange={setActiveTab}
        onOpenUpload={() => setIsUploadOpen(true)}
        onOpenSamples={() => setIsSamplesOpen(true)}
        totalRecords={analysis.summary.totalLines}
        criticalAlerts={criticalAlertCount}
      />

      {/* Main Viewport Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* KPI Strip (Always visible or on Overview) */}
        <MetricCards summary={analysis.summary} criticalAlertCount={criticalAlertCount} />

        {/* Dynamic Tab Body */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            {/* Timeline Chart */}
            <TimelineChart
              timeline={analysis.timeline}
              onSelectBucket={handleSelectTimelineBucket}
            />

            {/* Split Grid: Critical Incidents & High-Risk Alerts */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              {/* Correlated Incidents Spotlight */}
              <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Layers className="w-4 h-4 text-cyan-400" />
                    <h3 className="text-xs font-semibold text-slate-200">
                      Correlated Multi-Source Incidents ({analysis.incidents.length})
                    </h3>
                  </div>
                  <button
                    onClick={() => setActiveTab('correlation')}
                    className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium transition-colors"
                  >
                    <span>View all incidents</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                </div>

                {analysis.incidents.length === 0 ? (
                  <div className="py-8 text-center text-xs text-slate-500">
                    No active correlated incidents formed.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {analysis.incidents.slice(0, 3).map((inc) => (
                      <div
                        key={inc.id}
                        onClick={() => {
                          setSelectedIncidentForAi(inc);
                          setActiveTab('correlation');
                        }}
                        className="p-3 bg-slate-950/70 border border-slate-800 hover:border-slate-700 rounded-lg cursor-pointer transition-colors"
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-mono text-[10px] text-slate-500 font-bold">{inc.id}</span>
                          <span
                            className={`text-[10px] uppercase font-bold ${
                              inc.severity === 'Critical' ? 'text-rose-400' : 'text-orange-400'
                            }`}
                          >
                            {inc.severity}
                          </span>
                        </div>
                        <h4 className="text-xs font-semibold text-slate-200">{inc.title}</h4>
                        <p className="text-[11px] text-slate-400 mt-0.5 line-clamp-1">{inc.rationale}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Active Security Alerts Spotlight */}
              <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-rose-400" />
                    <h3 className="text-xs font-semibold text-slate-200">
                      High-Priority Security Alerts ({analysis.alerts.length})
                    </h3>
                  </div>
                  <button
                    onClick={() => setActiveTab('alerts')}
                    className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium transition-colors"
                  >
                    <span>Triage alerts</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                </div>

                {analysis.alerts.length === 0 ? (
                  <div className="py-8 text-center text-xs text-slate-500">
                    No security alerts triggered under current thresholds.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {analysis.alerts.slice(0, 3).map((alert) => (
                      <div
                        key={alert.id}
                        onClick={() => setActiveTab('alerts')}
                        className="p-3 bg-slate-950/70 border border-slate-800 hover:border-slate-700 rounded-lg cursor-pointer transition-colors"
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-mono text-[10px] text-slate-500 font-bold">{alert.id}</span>
                          <span
                            className={`text-[10px] uppercase font-bold ${
                              alert.severity === 'Critical'
                                ? 'text-rose-400'
                                : alert.severity === 'High'
                                ? 'text-orange-400'
                                : 'text-amber-400'
                            }`}
                          >
                            {alert.severity}
                          </span>
                        </div>
                        <h4 className="text-xs font-semibold text-slate-200">{alert.title}</h4>
                        <div className="text-[10px] text-slate-500 mt-1 flex items-center gap-2">
                          <span>{alert.category}</span>
                          <span>·</span>
                          <span className="font-mono">{alert.status}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Quick Diagnostic Profiles */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Error Groups Spotlight */}
              <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-300">Top Error Signatures</span>
                  <span className="text-[11px] text-slate-500">{analysis.errorGroups.length} distinct</span>
                </div>
                <div className="space-y-1.5 text-xs font-mono">
                  {analysis.errorGroups.slice(0, 3).map((eg) => (
                    <div
                      key={eg.id}
                      onClick={() => handleJumpToLogsWithQuery(eg.signature.split(':')[0])}
                      className="p-2 bg-slate-950 border border-slate-850 rounded hover:bg-slate-900 cursor-pointer transition-colors flex items-center justify-between"
                    >
                      <span className="text-slate-300 truncate max-w-[200px]">{eg.signature}</span>
                      <span className="text-rose-400 font-bold tabular-nums ml-2">{eg.count}x</span>
                    </div>
                  ))}
                  {analysis.errorGroups.length === 0 && (
                    <div className="text-slate-500 py-3 text-center">No recurring errors found.</div>
                  )}
                </div>
              </div>

              {/* Authentication Posture */}
              <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-300">Auth Health Posture</span>
                  <button
                    onClick={() => setActiveTab('auth')}
                    className="text-[11px] text-cyan-400 hover:text-cyan-300"
                  >
                    Details →
                  </button>
                </div>
                <div className="space-y-1.5 text-xs">
                  <div className="p-2 bg-slate-950 border border-slate-850 rounded flex justify-between">
                    <span className="text-slate-400">Auth Attempts</span>
                    <span className="text-slate-200 font-mono font-bold tabular-nums">
                      {analysis.authStats.totalAttempts}
                    </span>
                  </div>
                  <div className="p-2 bg-slate-950 border border-slate-850 rounded flex justify-between">
                    <span className="text-slate-400">Failed Rate</span>
                    <span className="text-rose-400 font-mono font-bold tabular-nums">
                      {analysis.authStats.failureRate}% ({analysis.authStats.failedAttempts} fails)
                    </span>
                  </div>
                  <div className="p-2 bg-slate-950 border border-slate-850 rounded flex justify-between">
                    <span className="text-slate-400">Suspicious Sequences</span>
                    <span className="text-amber-400 font-mono font-bold tabular-nums">
                      {analysis.authStats.suspiciousSequences.length}
                    </span>
                  </div>
                </div>
              </div>

              {/* HTTP Perimeter Traffic */}
              <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-xl space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-300">Web Ingress Probing</span>
                  <button
                    onClick={() => setActiveTab('http')}
                    className="text-[11px] text-cyan-400 hover:text-cyan-300"
                  >
                    Details →
                  </button>
                </div>
                <div className="space-y-1.5 text-xs">
                  <div className="p-2 bg-slate-950 border border-slate-850 rounded flex justify-between">
                    <span className="text-slate-400">Total HTTP Reqs</span>
                    <span className="text-slate-200 font-mono font-bold tabular-nums">
                      {analysis.httpStats.totalRequests}
                    </span>
                  </div>
                  <div className="p-2 bg-slate-950 border border-slate-850 rounded flex justify-between">
                    <span className="text-slate-400">Probed 4xx Paths</span>
                    <span className="text-amber-400 font-mono font-bold tabular-nums">
                      {analysis.httpStats.top4xxPaths.length}
                    </span>
                  </div>
                  <div className="p-2 bg-slate-950 border border-slate-850 rounded flex justify-between">
                    <span className="text-slate-400">Scanner User-Agents</span>
                    <span className="text-rose-400 font-mono font-bold tabular-nums">
                      {analysis.httpStats.scannerUserAgents.length}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Live Stream View */}
        {activeTab === 'live' && (
          <LiveMonitor onAppendEntry={handleAppendEntry} />
        )}

        {/* Log Explorer */}
        {activeTab === 'logs' && (
          <LogTable entries={analysis.entries} initialSearch={tableSearchFilter} />
        )}

        {/* Security Alerts */}
        {activeTab === 'alerts' && (
          <AlertsManager
            alerts={analysis.alerts}
            onUpdateAlertStatus={handleUpdateAlertStatus}
            onInvestigateWithAi={handleJumpToAiWithAlert}
          />
        )}

        {/* Authentication Analysis */}
        {activeTab === 'auth' && (
          <AuthView
            authStats={analysis.authStats}
            onFilterUser={handleJumpToLogsWithQuery}
            onFilterIp={handleJumpToLogsWithQuery}
          />
        )}

        {/* HTTP Traffic Analysis */}
        {activeTab === 'http' && (
          <HttpView
            httpStats={analysis.httpStats}
            onFilterPath={handleJumpToLogsWithQuery}
            onFilterIp={handleJumpToLogsWithQuery}
          />
        )}

        {/* Incident Correlation */}
        {activeTab === 'correlation' && (
          <CorrelationView
            incidents={analysis.incidents}
            onInspectEvent={(e) => handleJumpToLogsWithQuery(e.sanitized)}
          />
        )}

        {/* AI Incident Assistant */}
        {activeTab === 'ai' && (
          <AiAssistant
            alerts={analysis.alerts}
            incidents={analysis.incidents}
            selectedAlert={selectedAlertForAi}
            selectedIncident={selectedIncidentForAi}
          />
        )}

        {/* Reports & Diagnostic Benchmarks */}
        {activeTab === 'reports' && (
          <ReportsView analysis={analysis} />
        )}

        {/* Detection Rules & Settings */}
        {activeTab === 'settings' && (
          <SettingsView
            rules={rules}
            onUpdateRule={handleUpdateRule}
            onResetRules={handleResetRules}
          />
        )}
      </main>

      {/* Modals */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onAnalyze={handleNewLogIngestion}
      />

      <SamplePickerModal
        isOpen={isSamplesOpen}
        onClose={() => setIsSamplesOpen(false)}
        onSelectSample={handleSelectSample}
      />

      {/* Footer */}
      <footer className="mt-auto border-t border-slate-800 bg-slate-950/80 py-4 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Server className="w-3.5 h-3.5 text-slate-400" />
            <span>Server Log Analyzer AI · 2026 Production Edition</span>
          </div>
          <div className="text-[11px] text-slate-400 font-mono">
            Defensive Security Analysis · Local PII & Credential Redactor Active
          </div>
        </div>
      </footer>
    </div>
  );
}
