import React, { useEffect, useState, useCallback } from 'react';
import {
  Database, RefreshCw, UploadCloud, Globe, ShieldCheck, AlertTriangle,
  Loader2, Radio, ArrowRight, CheckCircle2, XCircle
} from 'lucide-react';
import SimulationControl from '../components/SimulationControl';
import { fetchFeedStatus, refreshFeed } from '../services/apiService';

const SEVERITY_TONE = {
  CRITICAL: 'text-soc-danger border-soc-danger/40 bg-soc-danger/10',
  HIGH: 'text-soc-warning border-soc-warning/40 bg-soc-warning/10',
  MEDIUM: 'text-soc-primary border-soc-primary/40 bg-soc-primary/10',
  LOW: 'text-slate-300 border-soc-border bg-soc-bg'
};

const OUTCOME_TONE = {
  ok: 'text-soc-success',
  stale: 'text-soc-warning',
  config_error: 'text-soc-danger',
  operational_error: 'text-soc-warning',
  timeout: 'text-soc-warning',
  unavailable: 'text-slate-400',
  error: 'text-soc-danger'
};

export default function IngestionHubPage({ onOpenUpload, onSimulate, onNavigateToTab }) {
  const [feed, setFeed] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [notice, setNotice] = useState(null);

  const loadFeed = useCallback(async () => {
    const status = await fetchFeedStatus();
    setFeed(status);
    setLoading(false);
  }, []);

  useEffect(() => {
    let cancelled = false;

    const poll = async () => {
      const status = await fetchFeedStatus();
      if (cancelled) return;
      setFeed(status);
      setLoading(false);
    };

    poll();
    const timer = setInterval(poll, 20000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  const handleRefresh = async () => {
    setRefreshing(true);
    setNotice(null);
    try {
      const result = await refreshFeed();
      setNotice({
        tone: result.status === 'refreshed' ? 'ok' : 'warn',
        text: result.status === 'refreshed'
          ? `Adapter run completed — ${result.indicators} indicators in the local cache.`
          : result.detail || `Adapter run finished with status "${result.status}".`
      });
      await loadFeed();
    } finally {
      setRefreshing(false);
    }
  };

  const handleDrop = (event) => {
    event.preventDefault();
    if (event.dataTransfer?.files?.length) onOpenUpload();
  };

  const severityEntries = Object.entries(feed?.by_severity || {});
  const indicators = feed?.indicators || [];
  const sources = feed?.sources || [];

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Page header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-soc-border/70">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="p-1.5 rounded-lg bg-soc-primary/10 text-soc-primary border border-soc-primary/30">
              <Database className="w-5 h-5" />
            </span>
            <h2 className="text-lg font-semibold text-slate-100 tracking-tight">Data Ingestion Hub</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Out-of-band internet feeds, capture replay, and controlled attack scenarios feeding the diode pipeline.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-soc-border bg-soc-card text-slate-200 hover:border-soc-primary/40 hover:text-soc-primary disabled:opacity-50 transition-colors"
          >
            {refreshing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
            Run adapter pipeline
          </button>
          <button
            onClick={onOpenUpload}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-soc-primary hover:bg-blue-400 text-slate-950 transition-colors"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            Upload capture
          </button>
        </div>
      </div>

      {notice && (
        <div
          className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-[11px] ${
            notice.tone === 'ok' ? 'border-soc-success/40 text-soc-success bg-soc-success/10' : 'border-soc-warning/40 text-soc-warning bg-soc-warning/10'
          }`}
        >
          {notice.tone === 'ok' ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
          {notice.text}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Feed status */}
        <div className="bg-soc-card border border-soc-border rounded-xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Live Internet Feed</span>
            <span
              className={`flex items-center gap-1.5 text-[11px] font-mono px-2 py-0.5 rounded border ${
                feed?.available ? 'text-soc-success border-soc-success/40 bg-soc-success/10' : 'text-slate-400 border-soc-border bg-soc-bg'
              }`}
            >
              <Radio className="w-3 h-3" />
              {loading ? 'checking…' : feed?.available ? 'collector online' : 'unavailable'}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="bg-soc-bg border border-soc-border rounded-lg p-3">
              <div className="text-[10px] uppercase tracking-wider text-slate-500">Cached indicators</div>
              <div className="text-xl font-mono font-semibold text-slate-100 mt-1">{feed?.indicator_count ?? 0}</div>
            </div>
            <div className="bg-soc-bg border border-soc-border rounded-lg p-3">
              <div className="text-[10px] uppercase tracking-wider text-slate-500">Adapters</div>
              <div className="text-xl font-mono font-semibold text-slate-100 mt-1">{sources.length}</div>
            </div>
          </div>

          {severityEntries.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {severityEntries.map(([severity, count]) => (
                <span key={severity} className={`px-2 py-0.5 rounded text-[10px] font-mono border ${SEVERITY_TONE[severity] || SEVERITY_TONE.LOW}`}>
                  {severity}: {count}
                </span>
              ))}
            </div>
          )}

          <div className="space-y-2">
            {sources.length === 0 ? (
              <p className="text-[11px] text-slate-400">
                No adapter store detected. Set <code className="font-mono text-slate-300">ADAPTER_INGESTION_DIR</code> to a checkout of
                <span className="font-mono text-slate-300"> @shrinivas-sn/adapter-ingestion</span> with adapter files in <span className="font-mono text-slate-300">adapters/</span>.
              </p>
            ) : (
              sources.map((source) => (
                <div key={source.host} className="flex items-center justify-between gap-2 px-2.5 py-2 rounded-lg bg-soc-bg border border-soc-border">
                  <div className="min-w-0">
                    <div className="text-[11px] font-mono text-slate-200 truncate">{source.host}</div>
                    <div className="text-[10px] text-slate-500">
                      {source.records} stored record{source.records === 1 ? '' : 's'}
                      {source.last_run ? ` · last run: ${source.last_run.outcome}` : ' · not run this session'}
                    </div>
                  </div>
                  {source.last_run?.outcome && (
                    <span className={`flex items-center gap-1 text-[10px] font-mono ${OUTCOME_TONE[source.last_run.outcome] || 'text-slate-400'}`}>
                      {source.last_run.outcome === 'ok' ? <CheckCircle2 className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                      {source.last_run.outcome}
                    </span>
                  )}
                </div>
              ))
            )}
          </div>

          <p className="text-[10px] text-slate-500 border-t border-soc-border pt-2 flex gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-soc-success shrink-0" />
            {feed?.compliance || 'Collector runs out of band; the enclave reads only the local indicator cache.'}
          </p>
        </div>

        {/* Capture dropzone + indicator preview */}
        <div className="space-y-4">
          <div
            onDragOver={(event) => event.preventDefault()}
            onDrop={handleDrop}
            onClick={onOpenUpload}
            role="button"
            tabIndex={0}
            onKeyDown={(event) => { if (event.key === 'Enter') onOpenUpload(); }}
            className="bg-soc-card border border-dashed border-soc-border hover:border-soc-primary/50 rounded-xl p-6 text-center cursor-pointer transition-colors"
          >
            <UploadCloud className="w-7 h-7 text-soc-primary mx-auto" />
            <p className="text-xs font-medium text-slate-200 mt-2">Drop a PCAP or Zeek log, or click to browse</p>
            <p className="text-[11px] text-slate-500 mt-1">
              .pcap · .pcapng · .log — replayed through the detection engine with selectable speed
            </p>
            <span className="inline-flex items-center gap-1 text-[11px] text-soc-primary mt-3">
              Open ingestion console <ArrowRight className="w-3.5 h-3.5" />
            </span>
          </div>

          <div className="bg-soc-card border border-soc-border rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Cached indicators</span>
              <button
                onClick={() => onNavigateToTab('monitor')}
                className="text-[11px] text-soc-primary hover:text-blue-300"
              >
                Back to monitor
              </button>
            </div>

            {indicators.length === 0 ? (
              <p className="text-[11px] text-slate-500 flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5" />
                Nothing cached yet — run the adapter pipeline to populate local threat intelligence.
              </p>
            ) : (
              <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                {indicators.map((indicator) => (
                  <div key={indicator.indicator_id || indicator.indicator} className="flex items-center justify-between gap-2 text-[11px] font-mono">
                    <span className="text-slate-200 truncate">{indicator.indicator}</span>
                    <span className={`shrink-0 px-1.5 py-0.5 rounded border text-[10px] ${SEVERITY_TONE[indicator.severity] || SEVERITY_TONE.LOW}`}>
                      {indicator.severity}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Scenario injector (reuses the detection engine's synthetic vectors) */}
      <SimulationControl onSimulate={onSimulate} />

      <p className="text-[11px] text-slate-500 flex items-center gap-1.5">
        <XCircle className="w-3.5 h-3.5 text-slate-500" />
        Scenario injection is synthetic and local — it never transmits on the monitored interface.
      </p>
    </div>
  );
}
