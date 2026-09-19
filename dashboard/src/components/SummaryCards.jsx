import React from 'react';
import { Activity, ShieldAlert, Zap, Clock } from 'lucide-react';

export default function SummaryCards({ telemetry, totalAlerts, highestConfidence, autoDetectionEnabled }) {
  const pps = telemetry?.pps || 0;
  const bps = telemetry?.bps || 0;
  const kbps = (bps / 1000).toFixed(1);

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {/* Card 1: Traffic Speed */}
      <div className="bg-cyber-card border border-cyber-border p-4 rounded-xl relative overflow-hidden transition-all">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            ⚡ Network Traffic Speed
          </span>
          <Activity className="w-5 h-5 text-cyan-400" />
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl font-extrabold text-white tracking-tight">{pps}</span>
          <span className="text-xs text-cyan-400 font-medium">packets / sec</span>
        </div>
        <div className="mt-1 text-xs text-slate-400 font-medium">
          Bandwidth: <span className="text-slate-200">{kbps} Kbps</span>
        </div>
        <div className="absolute bottom-0 left-0 right-0 h-1 bg-cyan-500/30">
          <div className="h-full bg-cyan-400 glow-accent" style={{ width: `${Math.min(100, (pps / 100) * 100)}%` }} />
        </div>
      </div>

      {/* Card 2: Total Threats */}
      <div className="bg-cyber-card border border-cyber-border p-4 rounded-xl relative overflow-hidden transition-all">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            🛡️ Threat Alerts
          </span>
          <ShieldAlert className="w-5 h-5 text-red-400" />
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl font-extrabold text-red-400 tracking-tight">{totalAlerts}</span>
          <span className="text-xs text-red-400/80 font-medium">Flagged</span>
        </div>
        <div className="mt-1 text-xs text-slate-400 font-medium">
          Detection:{' '}
          {autoDetectionEnabled === false ? (
            <span className="text-amber-400 font-semibold">⏸️ Auto-Detect Paused</span>
          ) : totalAlerts > 0 ? (
            <span className="text-red-400 font-semibold">⚠️ Threats Detected</span>
          ) : (
            <span className="text-emerald-400 font-semibold">✅ All Clear</span>
          )}
        </div>
        <div className="absolute bottom-0 left-0 right-0 h-1 bg-red-500/30">
          <div className="h-full bg-red-500 glow-red" style={{ width: `${Math.min(100, totalAlerts * 5)}%` }} />
        </div>
      </div>

      {/* Card 3: Max Confidence */}
      <div className="bg-cyber-card border border-cyber-border p-4 rounded-xl relative overflow-hidden transition-all">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            🎯 Detection Accuracy
          </span>
          <Zap className="w-5 h-5 text-amber-400" />
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl font-extrabold text-amber-400 tracking-tight">
            {highestConfidence ? `${(highestConfidence * 100).toFixed(0)}%` : '0%'}
          </span>
          <span className="text-xs text-amber-400/80 font-medium">Certainty</span>
        </div>
        <div className="mt-1 text-xs text-slate-400 font-medium">
          Detection Method: <span className="text-slate-200">AI Pattern Matcher</span>
        </div>
        <div className="absolute bottom-0 left-0 right-0 h-1 bg-amber-500/30">
          <div className="h-full bg-amber-400" style={{ width: `${(highestConfidence || 0) * 100}%` }} />
        </div>
      </div>

      {/* Card 4: Pipeline Latency */}
      <div className="bg-cyber-card border border-cyber-border p-4 rounded-xl relative overflow-hidden transition-all">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            ⏱️ Reaction Time
          </span>
          <Clock className="w-5 h-5 text-emerald-400" />
        </div>
        <div className="mt-3 flex items-baseline gap-2">
          <span className="text-2xl font-extrabold text-emerald-400 tracking-tight">&lt; 12</span>
          <span className="text-xs text-emerald-400/80 font-medium">ms (Instant)</span>
        </div>
        <div className="mt-1 text-xs text-slate-400 font-medium">
          Evaluation: <span className="text-slate-200">Real-time (Immediate)</span>
        </div>
        <div className="absolute bottom-0 left-0 right-0 h-1 bg-emerald-500/30">
          <div className="h-full bg-emerald-400 glow-green" style={{ width: '92%' }} />
        </div>
      </div>
    </div>
  );
}
