import React from 'react';
import SummaryCards from '../components/SummaryCards';
import ThroughputChart from '../components/ThroughputChart';
import AlertFeed from '../components/AlertFeed';
import { Activity, ArrowRight, Zap, ShieldCheck } from 'lucide-react';

export default function LiveMonitorPage({
  telemetry,
  alerts,
  historyData,
  highestConfidence,
  autoDetectionEnabled,
  isExecutiveView,
  onSelectAlert,
  onOpenAiCopilot,
  onNavigateToTab,
  secondsUntilSync = 300
}) {
  const topAlert = alerts.length > 0
    ? alerts.reduce((best, alert) => ((alert.confidence_score || 0) > (best.confidence_score || 0) ? alert : best), alerts[0])
    : null;

  const mins = Math.floor(secondsUntilSync / 60);
  const secs = (secondsUntilSync % 60).toString().padStart(2, '0');
  const syncProgressPct = Math.round(((300 - secondsUntilSync) / 300) * 100);

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Page Title & Context Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1e293b]/60">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="p-1.5 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <Activity className="w-5 h-5" />
            </span>
            <h2 className="text-xl font-bold text-slate-100 tracking-tight">
              Live Threat Monitor & SOC Triage
            </h2>
            <span className="px-2.5 py-0.5 text-xs font-mono font-medium rounded-full bg-emerald-950/60 text-emerald-400 border border-emerald-800/40">
              Real-time Ingest
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Continuous passive flow telemetry across the unidirectional hardware diode with ML sliding-window anomaly detection.
          </p>
        </div>

        {/* Quick jump shortcuts */}
        <div className="flex items-center gap-2">
          <button
            onClick={() => onNavigateToTab('topology')}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-blue-300 bg-[#0f172a] hover:bg-slate-800 border border-[#1e293b] rounded-lg transition-colors"
          >
            <span>Attack Simulator</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => onNavigateToTab('forensics')}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-blue-300 bg-[#0f172a] hover:bg-slate-800 border border-[#1e293b] rounded-lg transition-colors"
          >
            <span>Target Scanner</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Live Threat Intel & Background Ingestion Status Banner with Live Countdown Timer */}
      <div className="bg-[#0b1120] border border-[#1e293b] rounded-xl p-3 px-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs shadow-sm">
        <div className="flex items-center gap-3 flex-wrap">
          <span className="relative flex h-2.5 w-2.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-400" />
          </span>
          <span className="font-semibold text-slate-200">
            Threat Intelligence Ingestion Pipeline:
          </span>
          <span className="text-slate-400">
            117 active indicators · Next background sync in{' '}
            <strong className="font-mono font-bold text-cyan-300 bg-cyan-950/90 px-2 py-0.5 rounded border border-cyan-700/50">
              {mins}:{secs}
            </strong>
          </span>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <div className="w-20 hidden md:block">
            <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-cyan-400 transition-all duration-1000"
                style={{ width: `${syncProgressPct}%` }}
              />
            </div>
          </div>
          <button
            onClick={() => onNavigateToTab('ingest')}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 text-xs font-medium transition-colors"
          >
            <span>Live Command Deck</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* KPI Summary Cards */}
      <SummaryCards
        telemetry={telemetry}
        totalAlerts={alerts.length}
        highestConfidence={highestConfidence}
        autoDetectionEnabled={autoDetectionEnabled}
        topAlert={topAlert}
      />

      {/* Real-time Streaming Throughput Chart (hidden in executive view) */}
      {!isExecutiveView && (
        <ThroughputChart historyData={historyData} />
      )}

      {/* Real-Time Alert Feed */}
      <AlertFeed
        alerts={alerts}
        onSelectAlert={onSelectAlert}
        onOpenAiCopilot={onOpenAiCopilot}
      />
    </div>
  );
}
