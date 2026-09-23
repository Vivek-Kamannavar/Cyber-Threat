import React from 'react';
import { 
  ShieldAlert, Radio, Lock, HelpCircle, Power, Trash2, 
  UploadCloud, Eye, Sliders, ShieldCheck, AlertTriangle 
} from 'lucide-react';

export default function Header({
  isConnected,
  totalAlerts,
  hasCriticalThreat,
  autoDetectionEnabled,
  onToggleAutoDetection,
  onClearAlerts,
  onToggleGuide,
  onOpenUpload,
  isExecutiveView,
  onToggleViewMode
}) {
  return (
    <header className="bg-[#151f32] border-b border-[#23324d] px-6 py-4 flex flex-col gap-4">
      {/* Top Bar */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-sky-950/60 border border-sky-500/40 rounded-xl text-sky-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold text-slate-100 tracking-tight">
                CYBER THREAT SOC <span className="text-sky-400 font-medium">| Data Diode Defense</span>
              </h1>
              <span className="px-2 py-0.5 text-[10px] font-mono bg-sky-950 text-sky-300 border border-sky-800 rounded font-semibold uppercase">
                Air-Gap Secured
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Zero-return-path passive analytical telemetry for critical industrial infrastructure
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Executive / Forensic Mode Toggle */}
          <button
            onClick={onToggleViewMode}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#0b1120] hover:bg-slate-800 border border-[#23324d] rounded-lg text-xs font-medium text-slate-200 transition-colors shadow-sm"
            title="Toggle between simplified executive explanations and deep forensic math metrics"
          >
            {isExecutiveView ? <Eye className="w-3.5 h-3.5 text-sky-400" /> : <Sliders className="w-3.5 h-3.5 text-sky-400" />}
            <span>Mode: {isExecutiveView ? 'Executive' : 'Deep Forensic'}</span>
          </button>

          {/* Upload PCAP / Zeek Button */}
          <button
            onClick={onOpenUpload}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-sky-500 hover:bg-sky-400 text-slate-950 rounded-lg text-xs font-semibold shadow-sm transition-colors"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            <span>Upload Capture</span>
          </button>

          {/* Auto-Detection Toggle */}
          <button
            onClick={onToggleAutoDetection}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors ${
              autoDetectionEnabled
                ? 'bg-emerald-950/60 border-emerald-800 text-emerald-300 hover:bg-emerald-900/60'
                : 'bg-amber-950/60 border-amber-800 text-amber-300 hover:bg-amber-900/60'
            }`}
          >
            <Power className="w-3.5 h-3.5" />
            <span>Engine: {autoDetectionEnabled ? 'Active' : 'Paused'}</span>
          </button>

          {/* Clear Alerts */}
          {totalAlerts > 0 && (
            <button
              onClick={onClearAlerts}
              className="flex items-center gap-1.5 px-2.5 py-1.5 bg-slate-900 hover:bg-rose-950/60 border border-[#23324d] hover:border-rose-800 rounded-lg text-xs font-medium text-slate-300 hover:text-rose-300 transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear ({totalAlerts})</span>
            </button>
          )}

          {/* WebSocket Status */}
          <div className="flex items-center gap-2 px-3 py-1.5 bg-[#0b1120] border border-[#23324d] rounded-lg">
            <Radio className={`w-3.5 h-3.5 ${isConnected ? 'text-emerald-400' : 'text-rose-400'}`} />
            <span className={`text-xs font-mono font-medium ${isConnected ? 'text-emerald-400' : 'text-rose-400'}`}>
              {isConnected ? 'LIVE FEED' : 'OFFLINE'}
            </span>
          </div>
        </div>
      </div>

      {/* Traffic Light Facility Status Banner */}
      <div className={`px-4 py-2.5 rounded-xl border text-xs font-medium flex items-center justify-between transition-colors shadow-sm ${
        hasCriticalThreat
          ? 'bg-rose-950/50 border-rose-800 text-rose-200'
          : totalAlerts > 0
          ? 'bg-amber-950/50 border-amber-800 text-amber-200'
          : 'bg-emerald-950/50 border-emerald-800 text-emerald-200'
      }`}>
        <div className="flex items-center gap-2.5">
          {hasCriticalThreat ? (
            <span className="flex h-3 w-3 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3 w-3 bg-rose-500"></span>
            </span>
          ) : totalAlerts > 0 ? (
            <span className="inline-flex rounded-full h-3 w-3 bg-amber-400"></span>
          ) : (
            <span className="inline-flex rounded-full h-3 w-3 bg-emerald-400"></span>
          )}

          <span className="font-bold tracking-wide uppercase text-[11px]">
            {hasCriticalThreat ? 'CRITICAL INCIDENT DETECTED:' : totalAlerts > 0 ? 'ELEVATED SECURITY ADVISORY:' : 'FACILITY STATUS: NORMAL'}
          </span>
          <span className="text-slate-300">
            {hasCriticalThreat
              ? 'Active high-confidence threat in progress across the unidirectional optical datalink. Immediate analyst review required.'
              : totalAlerts > 0
              ? 'Unusual traffic frequency or connection fan-out observed in the current 60s sliding window.'
              : 'All industrial controllers and air-gapped systems secure. Zero anomalous threat signatures detected.'}
          </span>
        </div>

        <span className="text-[11px] font-mono text-slate-400 hidden sm:inline">
          {totalAlerts} Total Alerts Logged
        </span>
      </div>
    </header>
  );
}
