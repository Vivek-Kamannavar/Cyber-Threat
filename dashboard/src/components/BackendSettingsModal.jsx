import React, { useState } from 'react';
import { Server, Check, X, RefreshCw, Globe, Shield } from 'lucide-react';
import { getStoredBackendUrl, setStoredBackendUrl } from '../services/apiService';

export default function BackendSettingsModal({ isOpen, onClose, onConfigSaved, connectionMode }) {
  const [url, setUrl] = useState(getStoredBackendUrl());
  const [savedSuccess, setSavedSuccess] = useState(false);

  if (!isOpen) return null;

  const handleSave = (e) => {
    e.preventDefault();
    setStoredBackendUrl(url);
    setSavedSuccess(true);
    setTimeout(() => {
      setSavedSuccess(false);
      if (onConfigSaved) onConfigSaved();
      onClose();
      // Reload stream cleanly
      window.location.reload();
    }, 600);
  };

  const handleResetToAuto = () => {
    setStoredBackendUrl('');
    setUrl('');
    setSavedSuccess(true);
    setTimeout(() => {
      setSavedSuccess(false);
      if (onConfigSaved) onConfigSaved();
      onClose();
      window.location.reload();
    }, 600);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-[#0f172a] border border-[#1e293b] rounded-2xl max-w-md w-full p-6 shadow-2xl relative space-y-4">
        <div className="flex items-center justify-between border-b border-[#1e293b] pb-3">
          <div className="flex items-center gap-2">
            <Server className="w-5 h-5 text-blue-400" />
            <h3 className="text-base font-semibold text-white">Backend Gateway Connection</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="text-xs text-slate-300 space-y-3">
          <div className="p-3 rounded-lg bg-[#090d16] border border-[#1e293b] flex items-center justify-between">
            <span className="text-slate-400">Current Operating Mode:</span>
            <span className="font-mono px-2 py-0.5 rounded text-[11px] font-semibold bg-blue-950 text-blue-300 border border-blue-800">
              {connectionMode === 'LIVE_BACKEND' ? '🟢 Live FastAPI Server' : '🚀 Autonomous Cloud Simulator'}
            </span>
          </div>

          <form onSubmit={handleSave} className="space-y-3 pt-1">
            <div>
              <label className="block text-slate-400 text-xs font-medium mb-1">
                FastAPI Backend URL:
              </label>
              <input
                type="text"
                placeholder="e.g. http://localhost:8000 or https://api.my-domain.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="w-full bg-[#090d16] border border-[#1e293b] focus:border-blue-500 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none font-mono"
              />
              <p className="text-[11px] text-slate-500 mt-1">
                Leave empty on cloud hosting to automatically use the autonomous client-side data diode engine.
              </p>
            </div>

            <div className="flex items-center justify-between pt-2">
              <button
                type="button"
                onClick={handleResetToAuto}
                className="text-xs text-slate-400 hover:text-blue-400 underline underline-offset-2"
              >
                Reset to Auto-Detect
              </button>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-3 py-1.5 rounded-lg border border-[#1e293b] text-slate-300 hover:bg-slate-800 text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex items-center gap-1.5 px-4 py-1.5 bg-blue-500 hover:bg-blue-400 text-slate-950 font-semibold rounded-lg text-xs transition-colors"
                >
                  {savedSuccess ? <Check className="w-3.5 h-3.5" /> : null}
                  <span>{savedSuccess ? 'Saved!' : 'Save & Connect'}</span>
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
