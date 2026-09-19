import React from 'react';
import { ShieldAlert, Radio, Lock, HelpCircle, Power, Trash2 } from 'lucide-react';

export default function Header({
  isConnected,
  totalAlerts,
  diodeActive,
  onToggleGuide,
  autoDetectionEnabled,
  onToggleAutoDetection,
  onClearAlerts
}) {
  return (
    <header className="bg-cyber-card border-b border-cyber-border px-6 py-4 flex flex-col md:flex-row items-center justify-between gap-4">
      <div className="flex items-center gap-3">
        <div className="p-2.5 bg-cyan-950/60 border border-cyan-500/40 rounded-xl glow-accent">
          <ShieldAlert className="w-7 h-7 text-cyan-400 animate-pulse" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-xl font-bold text-white tracking-wide">
              CYBER SHIELD <span className="text-cyan-400">AI DETECTOR</span>
            </h1>
            <span className="px-2 py-0.5 text-xs bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 rounded font-semibold">
              ACTIVE
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-Time AI Security Guard: Watching one-way network traffic to spot and explain cyber attacks instantly
          </p>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2.5">
        {/* Auto-Detection ON / OFF Switch */}
        <button
          onClick={onToggleAutoDetection}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-bold transition-all shadow-sm ${
            autoDetectionEnabled
              ? 'bg-emerald-950/80 border-emerald-500 text-emerald-300 shadow-emerald-500/20 hover:bg-emerald-900/60'
              : 'bg-amber-950/80 border-amber-500 text-amber-300 shadow-amber-500/20 hover:bg-amber-900/60'
          }`}
          title="Turn continuous background AI auto-detection ON or OFF"
        >
          <Power className={`w-3.5 h-3.5 ${autoDetectionEnabled ? 'text-emerald-400' : 'text-amber-400'}`} />
          <span>Auto-Detection: {autoDetectionEnabled ? 'ON' : 'OFF'}</span>
        </button>

        {/* Clear Alerts Button */}
        {totalAlerts > 0 && (
          <button
            onClick={onClearAlerts}
            className="flex items-center gap-1.5 px-2.5 py-1.5 bg-slate-900 hover:bg-red-950/60 border border-slate-700 hover:border-red-500/50 rounded-lg text-xs font-medium text-slate-300 hover:text-red-300 transition-colors"
            title="Reset and clear all raised alerts"
          >
            <Trash2 className="w-3.5 h-3.5 text-slate-400 group-hover:text-red-400" />
            <span>Clear ({totalAlerts})</span>
          </button>
        )}

        {/* How It Works Button */}
        <button
          onClick={onToggleGuide}
          className="flex items-center gap-1.5 px-2.5 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded-lg text-xs font-medium text-slate-300 transition-colors"
        >
          <HelpCircle className="w-3.5 h-3.5 text-cyan-400" />
          <span>Guide</span>
        </button>

        {/* Data Diode Mode Badge */}
        <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-950/50 border border-emerald-500/40 rounded-lg">
          <Lock className="w-4 h-4 text-emerald-400" />
          <div className="text-left">
            <div className="text-[10px] uppercase text-emerald-400 font-bold">ONE-WAY</div>
            <div className="text-xs text-emerald-300">SAFE</div>
          </div>
        </div>

        {/* Live Stream Status */}
        <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg">
          <Radio className={`w-4 h-4 ${isConnected ? 'text-emerald-400 animate-ping' : 'text-red-400'}`} />
          <div className="text-left">
            <div className="text-[10px] uppercase text-slate-400">STREAM</div>
            <div className={`text-xs ${isConnected ? 'text-emerald-400' : 'text-red-400'}`}>
              {isConnected ? 'LIVE' : 'OFFLINE'}
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
