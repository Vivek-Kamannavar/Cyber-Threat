import React from 'react';
import { ShieldAlert, RefreshCw, CheckCircle2, AlertTriangle, X, Zap } from 'lucide-react';

export default function ToastContainer({ toasts, onDismiss }) {
  if (!toasts || toasts.length === 0) return null;

  return (
    <div className="fixed top-20 right-5 z-50 flex flex-col gap-2.5 max-w-md w-full pointer-events-none">
      {toasts.map((toast) => {
        const isThreat = toast.type === 'threat' || toast.type === 'error';
        const isSync = toast.type === 'sync' || toast.type === 'feed';
        const isSuccess = toast.type === 'success';

        return (
          <div
            key={toast.id}
            className={`pointer-events-auto flex items-start justify-between gap-3 p-3.5 rounded-xl border shadow-2xl backdrop-blur-md transition-all duration-300 animate-slideIn ${
              isThreat
                ? 'bg-[#18090e]/95 border-rose-500/50 text-rose-200'
                : isSync
                ? 'bg-[#061320]/95 border-cyan-500/50 text-cyan-200'
                : 'bg-[#081512]/95 border-emerald-500/50 text-emerald-200'
            }`}
          >
            <div className="flex items-start gap-3 min-w-0">
              <div
                className={`p-1.5 rounded-lg shrink-0 mt-0.5 ${
                  isThreat
                    ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                    : isSync
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                    : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                }`}
              >
                {isThreat ? (
                  <ShieldAlert className="w-4 h-4" />
                ) : isSync ? (
                  <RefreshCw className="w-4 h-4" />
                ) : (
                  <CheckCircle2 className="w-4 h-4" />
                )}
              </div>

              <div className="min-w-0">
                <div className="text-xs font-bold text-slate-100 flex items-center gap-2">
                  <span className="truncate">{toast.title}</span>
                  <span
                    className={`text-[9px] font-mono px-1.5 py-0.2 rounded uppercase border ${
                      isThreat
                        ? 'bg-rose-950 text-rose-400 border-rose-800/60'
                        : isSync
                        ? 'bg-cyan-950 text-cyan-400 border-cyan-800/60'
                        : 'bg-emerald-950 text-emerald-400 border-emerald-800/60'
                    }`}
                  >
                    {toast.type || 'NOTICE'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-300 mt-1 leading-snug">
                  {toast.message}
                </p>
                <div className="text-[9px] font-mono text-slate-500 mt-1">
                  {toast.timestamp || new Date().toLocaleTimeString()}
                </div>
              </div>
            </div>

            <button
              onClick={() => onDismiss(toast.id)}
              className="text-slate-400 hover:text-slate-200 p-1 rounded-md hover:bg-white/10 transition-colors shrink-0"
              title="Dismiss notification"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
}
