import React from 'react';
import { Shield, Radio, Power, Trash2, UploadCloud, Eye, Sliders } from 'lucide-react';

export default function Header({
  isConnected,
  totalAlerts,
  hasCriticalThreat,
  autoDetectionEnabled,
  onToggleAutoDetection,
  onClearAlerts,
  onOpenUpload,
  isExecutiveView,
  onToggleViewMode
}) {
  return (
    <header className="bg-[#FFF1D1] border-b border-black px-5 py-3">
      <div className="max-w-[1440px] mx-auto flex flex-wrap items-center justify-between gap-3">
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded border border-black bg-[#FFF1D1] flex items-center justify-center text-black">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-bold text-black tracking-tight">
                CYBER THREAT SOC
              </h1>
              <span className="text-[11px] font-normal text-black bg-[#FFF1D1] px-2 py-0.5 rounded border border-[#00B7CD]">
                DATA DIODE
              </span>
            </div>
            <p className="text-xs text-black font-normal">
              Zero-return-path passive analytical telemetry
            </p>
          </div>
        </div>

        {/* Facility Incident Banner - Clean, No AI slop dots, No light tint backgrounds */}
        <div className={`hidden md:flex items-center gap-2.5 px-3 py-1 rounded border text-xs font-normal bg-[#FFF1D1] ${
          hasCriticalThreat
            ? 'border-[#DF301C]'
            : totalAlerts > 0
            ? 'border-[#FF9100]'
            : 'border-black'
        }`}>
          <span className="font-bold text-black">
            {hasCriticalThreat ? 'CRITICAL THREAT ACTIVE' : totalAlerts > 0 ? 'ELEVATED ADVISORY' : 'SYSTEM NORMAL'}
          </span>
          <span className="text-black">|</span>
          <span className="text-black font-normal">{totalAlerts} Alerts Logged</span>
        </div>

        {/* Controls */}
        <div className="flex items-center gap-2">
          {/* Mode */}
          <button
            onClick={onToggleViewMode}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#FFF1D1] border border-black rounded text-xs font-normal text-black transition-colors"
          >
            {isExecutiveView ? <Eye className="w-3.5 h-3.5 text-black" /> : <Sliders className="w-3.5 h-3.5 text-black" />}
            <span>{isExecutiveView ? 'Executive' : 'Technical'}</span>
          </button>

          {/* Upload Capture */}
          <button
            onClick={onOpenUpload}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#00B7CD] text-black rounded text-xs font-bold border border-black transition-colors"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            <span>Upload Capture</span>
          </button>

          {/* Engine */}
          <button
            onClick={onToggleAutoDetection}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded border text-xs font-normal bg-[#FFF1D1] transition-colors ${
              autoDetectionEnabled
                ? 'border-black text-black'
                : 'border-[#FF9100] text-black'
            }`}
          >
            <Power className="w-3.5 h-3.5 text-black" />
            <span>{autoDetectionEnabled ? 'Engine Active' : 'Paused'}</span>
          </button>

          {/* Clear */}
          {totalAlerts > 0 && (
            <button
              onClick={onClearAlerts}
              className="flex items-center gap-1 px-2.5 py-1.5 border border-black rounded text-xs font-normal text-black bg-[#FFF1D1] transition-colors"
              title="Clear alerts"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>Clear</span>
            </button>
          )}

          {/* Status */}
          <div className="flex items-center gap-1.5 px-2.5 py-1.5 border border-black rounded text-xs font-normal text-black bg-[#FFF1D1]">
            <Radio className={`w-3.5 h-3.5 ${isConnected ? 'text-[#00B7CD]' : 'text-[#DF301C]'}`} />
            <span>{isConnected ? 'Live' : 'Offline'}</span>
          </div>
        </div>
      </div>
    </header>
  );
}
