import React from 'react';
import {
  ShieldAlert, HelpCircle, Power, Trash2, Eye, Sliders,
  Activity, Network, Search, Settings, Sparkles, Database
} from 'lucide-react';

const PRIMARY_TABS = [
  { id: 'monitor', name: 'Live Monitor', icon: Activity, description: 'Telemetry & incident triage' },
  { id: 'chat', name: 'AI Analyst', icon: Sparkles, description: 'Conversational threat analysis' },
  { id: 'ingest', name: 'Data Ingestion', icon: Database, description: 'Internet feed, PCAP & scenarios' }
];

const SECONDARY_TABS = [
  { id: 'topology', name: 'Topology Lab', icon: Network },
  { id: 'forensics', name: 'Forensic Scanner', icon: Search }
];

const STREAM_SOURCES = [
  { id: 'LIVE_BACKEND', label: 'Live backend stream' },
  { id: 'CLOUD_SIMULATION', label: 'Offline simulator' }
];

const iconButton = 'p-1.5 rounded-lg border border-soc-border bg-soc-bg text-slate-400 hover:text-slate-100 hover:border-slate-600 transition-colors';

export default function Header({
  isConnected,
  connectionMode = 'LIVE_BACKEND',
  onOpenBackendSettings,
  totalAlerts,
  hasCriticalThreat,
  autoDetectionEnabled,
  onToggleAutoDetection,
  onClearAlerts,
  onToggleGuide,
  isExecutiveView,
  onToggleViewMode,
  onSelectStreamSource,
  currentTab,
  onSelectTab
}) {
  const isLive = isConnected && connectionMode === 'LIVE_BACKEND';

  const statusLabel = !isConnected
    ? 'Diode: OFFLINE'
    : isLive
      ? 'Diode: ACTIVE (1-way)'
      : 'Diode: SIMULATED';

  const statusTone = !isConnected
    ? 'text-soc-danger border-soc-danger/40 bg-soc-danger/10'
    : isLive
      ? 'text-soc-success border-soc-success/40 bg-soc-success/10'
      : 'text-soc-primary border-soc-primary/40 bg-soc-primary/10';

  const facilityLine = hasCriticalThreat
    ? { tone: 'border-soc-danger/50 text-soc-danger', text: 'Critical incident in progress — immediate analyst review required.' }
    : totalAlerts > 0
      ? { tone: 'border-soc-warning/50 text-soc-warning', text: 'Elevated advisory — anomalous flow behaviour inside the current 60s window.' }
      : { tone: 'border-soc-success/50 text-soc-success', text: 'All monitored industrial endpoints nominal — zero anomalous signatures.' };

  return (
    <header className="bg-soc-card border-b border-soc-border px-4 md:px-6">
      {/* Top bar: identity, diode status, stream source, settings */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 py-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="p-2 rounded-lg bg-soc-primary/10 border border-soc-primary/30 text-soc-primary">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div className="min-w-0">
            <h1 className="text-base font-semibold text-slate-100 tracking-tight truncate">
              Cyber Threat SOC <span className="text-slate-400 font-normal">· Data Diode Defense</span>
            </h1>
            <p className="text-[11px] text-slate-400 truncate">
              Passive metadata-only inspection of unidirectional industrial traffic
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Diode status badge */}
          <span className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg border text-[11px] font-mono font-medium ${statusTone}`}>
            <span className="relative flex h-2 w-2">
              {isConnected && (
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-current opacity-60" />
              )}
              <span className="relative inline-flex rounded-full h-2 w-2 bg-current" />
            </span>
            {statusLabel}
          </span>

          {/* Threat Intel Auto-Sync Pill */}
          <button
            onClick={() => onSelectTab && onSelectTab('ingest')}
            className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 text-[11px] font-mono font-medium hover:bg-cyan-500/20 transition-colors"
            title="Out-of-band threat-intel adapter auto-sync running on 5-minute schedule. Click to view Data Ingestion Hub."
          >
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400" />
            </span>
            Intel: 5m Auto-Sync
          </button>

          {/* Stream source selector */}
          <label className="flex items-center gap-1.5 bg-soc-bg border border-soc-border rounded-lg pl-2.5 pr-1 py-1">
            <span className="text-[11px] text-slate-400 font-medium">Stream</span>
            <select
              value={connectionMode}
              onChange={(e) => onSelectStreamSource && onSelectStreamSource(e.target.value)}
              className="bg-transparent text-[11px] text-slate-100 font-mono py-0.5 focus:outline-none cursor-pointer"
              title="Select the telemetry source feeding this dashboard"
            >
              {STREAM_SOURCES.map((src) => (
                <option key={src.id} value={src.id} className="bg-soc-card">{src.label}</option>
              ))}
            </select>
          </label>

          {/* Engine enable/disable */}
          <button
            onClick={onToggleAutoDetection}
            className={`p-1.5 rounded-lg border transition-colors ${
              autoDetectionEnabled
                ? 'border-soc-success/40 bg-soc-success/10 text-soc-success hover:bg-soc-success/20'
                : 'border-soc-warning/40 bg-soc-warning/10 text-soc-warning hover:bg-soc-warning/20'
            }`}
            title={`Detection engine ${autoDetectionEnabled ? 'active — click to pause' : 'paused — click to resume'}`}
          >
            <Power className="w-4 h-4" />
          </button>

          {/* Clear alerts */}
          {totalAlerts > 0 && (
            <button
              onClick={onClearAlerts}
              className="p-1.5 rounded-lg border border-soc-border bg-soc-bg text-slate-400 hover:text-soc-danger hover:border-soc-danger/40 transition-colors"
              title={`Clear ${totalAlerts} logged alerts`}
            >
              <Trash2 className="w-4 h-4" />
            </button>
          )}

          {/* Executive / forensic detail toggle */}
          <button onClick={onToggleViewMode} className={iconButton} title="Toggle executive vs deep-forensic detail">
            {isExecutiveView ? <Eye className="w-4 h-4" /> : <Sliders className="w-4 h-4" />}
          </button>

          <button onClick={onToggleGuide} className={iconButton} title="How this system works">
            <HelpCircle className="w-4 h-4" />
          </button>

          {onOpenBackendSettings && (
            <button onClick={onOpenBackendSettings} className={iconButton} title="Backend gateway settings">
              <Settings className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Navigation: three pillars, plus lab tooling */}
      <nav className="flex items-center gap-1.5 pb-2 overflow-x-auto border-t border-soc-border/70 pt-2.5">
        {PRIMARY_TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = currentTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onSelectTab(tab.id)}
              title={tab.description}
              className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium border whitespace-nowrap transition-colors ${
                isActive
                  ? 'bg-soc-primary/12 border-soc-primary/40 text-soc-primary'
                  : 'border-transparent text-slate-400 hover:text-slate-100 hover:bg-soc-bg'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.name}
              {tab.id === 'monitor' && totalAlerts > 0 && (
                <span className="ml-0.5 px-1.5 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-soc-danger/15 text-soc-danger border border-soc-danger/30">
                  {totalAlerts}
                </span>
              )}
            </button>
          );
        })}

        <span className="mx-1.5 h-5 w-px bg-soc-border" />

        {SECONDARY_TABS.map((tab) => {
          const Icon = tab.icon;
          const isActive = currentTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onSelectTab(tab.id)}
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[11px] font-medium whitespace-nowrap transition-colors ${
                isActive ? 'text-slate-100 bg-soc-bg' : 'text-slate-500 hover:text-slate-300'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {tab.name}
            </button>
          );
        })}
      </nav>

      {/* Compact facility status line */}
      <div className={`mb-3 border-l-2 pl-3 py-0.5 text-[11px] flex items-center gap-2 ${facilityLine.tone}`}>
        <span className="font-semibold uppercase tracking-wide">
          {hasCriticalThreat ? 'Critical' : totalAlerts > 0 ? 'Advisory' : 'Normal'}
        </span>
        <span className="text-slate-400 truncate">{facilityLine.text}</span>
      </div>
    </header>
  );
}
