import React from 'react';
import { Activity, ShieldAlert, Gauge } from 'lucide-react';

/**
 * Clean SOC KPI strip: throughput, active incidents, sliding-window anomaly score.
 * Deep technical values live in the muted second line (progressive disclosure).
 */
export default function SummaryCards({ telemetry, totalAlerts, highestConfidence, autoDetectionEnabled, topAlert }) {
  const pps = telemetry?.pps || 0;
  const bps = telemetry?.bps || 0;
  const kbps = bps / 1000;
  const anomalyPct = Math.round((highestConfidence || 0) * 100);

  const anomalyTone = anomalyPct >= 90
    ? { text: 'text-soc-danger', bar: 'bg-soc-danger', label: 'Critical' }
    : anomalyPct >= 75
      ? { text: 'text-soc-warning', bar: 'bg-soc-warning', label: 'Elevated' }
      : anomalyPct > 0
        ? { text: 'text-soc-primary', bar: 'bg-soc-primary', label: 'Watch' }
        : { text: 'text-soc-success', bar: 'bg-soc-success', label: 'Nominal' };

  const evidence = topAlert?.supporting_evidence_feature || {};

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
      {/* Card 1: Throughput */}
      <div className="bg-soc-card border border-soc-border rounded-xl p-4" title="Packets and bytes observed inside the active 60s sliding window.">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Ingest Throughput</span>
          <Activity className="w-4 h-4 text-soc-primary" />
        </div>
        <div className="mt-3 flex items-baseline gap-1.5">
          <span className="text-2xl font-semibold text-slate-100 font-mono tabular-nums">{pps.toLocaleString()}</span>
          <span className="text-xs text-slate-400 font-mono">pps</span>
        </div>
        <p className="mt-1.5 text-[11px] text-slate-400 font-mono">
          {kbps >= 1000 ? `${(kbps / 1000).toFixed(2)} Mbps` : `${kbps.toFixed(1)} Kbps`} · one-way diode RX
        </p>
      </div>

      {/* Card 2: Active incidents */}
      <div className="bg-soc-card border border-soc-border rounded-xl p-4" title="Alerts raised in this session after the 3s per-entity cooldown.">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Active Incidents</span>
          <ShieldAlert className={`w-4 h-4 ${totalAlerts > 0 ? 'text-soc-danger' : 'text-soc-success'}`} />
        </div>
        <div className="mt-3 flex items-baseline gap-1.5">
          <span className={`text-2xl font-semibold font-mono tabular-nums ${totalAlerts > 0 ? 'text-soc-danger' : 'text-slate-100'}`}>
            {totalAlerts}
          </span>
          <span className="text-xs text-slate-400 font-mono">flagged</span>
        </div>
        <p className="mt-1.5 text-[11px] text-slate-400">
          Detection engine{' '}
          <span className={autoDetectionEnabled === false ? 'text-soc-warning' : 'text-soc-success'}>
            {autoDetectionEnabled === false ? 'paused' : 'active'}
          </span>
          {' · '}
          {totalAlerts === 0 ? 'no anomalies in window' : 'triage required'}
        </p>
      </div>

      {/* Card 3: Window anomaly score */}
      <div className="bg-soc-card border border-soc-border rounded-xl p-4" title="Highest confidence score produced by the tier-1 heuristics and isolation forest in the current window.">
        <div className="flex items-center justify-between">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Window Anomaly Score</span>
          <Gauge className={`w-4 h-4 ${anomalyTone.text}`} />
        </div>
        <div className="mt-3 flex items-baseline gap-1.5">
          <span className={`text-2xl font-semibold font-mono tabular-nums ${anomalyTone.text}`}>{anomalyPct}%</span>
          <span className="text-xs text-slate-400 font-mono">{anomalyTone.label}</span>
        </div>
        <p className="mt-1.5 text-[11px] text-slate-400 truncate" title={evidence.technical_reason || undefined}>
          {topAlert
            ? `${topAlert.threat_class} · ${evidence.technical_reason || evidence.reason || 'behavioural outlier'}`
            : 'baseline stable — no scoring deviation'}
        </p>
        <div className="mt-2 h-0.5 w-full rounded bg-soc-border overflow-hidden">
          <div className={`h-full ${anomalyTone.bar}`} style={{ width: `${anomalyPct}%` }} />
        </div>
      </div>
    </div>
  );
}
