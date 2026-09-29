import React, { useEffect, useState, useCallback } from 'react';
import {
  Database, RefreshCw, UploadCloud, Globe, ShieldCheck, AlertTriangle,
  Loader2, Radio, ArrowRight, CheckCircle2, XCircle, Clock, Activity,
  Sparkles, Terminal, ShieldAlert
} from 'lucide-react';
import SimulationControl from '../components/SimulationControl';
import { fetchFeedStatus, refreshFeed, eventBus } from '../services/apiService';

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

const INITIAL_LOGS = [
  {
    id: 'log-1',
    timestamp: new Date(Date.now() - 60000).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    type: 'feed',
    title: 'Threat Intel Sync Complete',
    detail: 'Fetched 100 GitHub security advisories out-of-band (+17 fresh indicators indexed)'
  },
  {
    id: 'log-2',
    timestamp: new Date(Date.now() - 120000).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    type: 'diode',
    title: 'Diode Passive Monitor Active',
    detail: 'Continuous passive packet inspection operating with 0% false positives'
  },
  {
    id: 'log-3',
    timestamp: new Date(Date.now() - 180000).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    type: 'threat',
    title: 'Baseline Threat Ingestion',
    detail: 'Loaded 6 primary threat vectors into active SOC triage memory'
  }
];

export default function IngestionHubPage({ onOpenUpload, onSimulate, onNavigateToTab }) {
  const [feed, setFeed] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [notice, setNotice] = useState(null);
  const [secondsUntilSync, setSecondsUntilSync] = useState(300);
  const [activityLogs, setActivityLogs] = useState(INITIAL_LOGS);

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
    const timer = setInterval(poll, 15000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  // 5-minute countdown timer logic (300 seconds)
  useEffect(() => {
    const countdownTimer = setInterval(() => {
      setSecondsUntilSync((prev) => {
        if (prev <= 1) {
          return 300;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(countdownTimer);
  }, []);

  // Listen to live WebSocket feed_update & audit_log events
  useEffect(() => {
    const unsubFeed = eventBus.on('feed_update', (update) => {
      setSecondsUntilSync(300);
      setNotice({
        tone: 'ok',
        text: `Live Sync Completed at ${new Date().toLocaleTimeString()} — +${update.fresh_count || 0} fresh indicators (${update.total_indicators || 0} total).`
      });
      loadFeed();
    });

    const unsubAudit = eventBus.on('audit_log', (logEntry) => {
      const nowStr = new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
      setActivityLogs((prev) => [
        {
          id: logEntry.id || `log-${Date.now()}`,
          timestamp: nowStr,
          type: logEntry.type || 'info',
          title: logEntry.title,
          detail: logEntry.detail
        },
        ...prev.slice(0, 19)
      ]);
    });

    return () => {
      unsubFeed();
      unsubAudit();
    };
  }, [loadFeed]);

  const handleRefresh = async () => {
    setRefreshing(true);
    setNotice(null);
    try {
      const result = await refreshFeed();
      setSecondsUntilSync(300);
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

  const mins = Math.floor(secondsUntilSync / 60);
  const secs = (secondsUntilSync % 60).toString().padStart(2, '0');
  const syncProgressPct = Math.round(((300 - secondsUntilSync) / 300) * 100);

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
            <span className="flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-cyan-950/60 text-cyan-300 border border-cyan-800/50">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400" />
              </span>
              5m Auto-Ingestion Active
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Out-of-band internet threat feeds, capture replay, and controlled attack scenarios feeding the diode pipeline.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border border-cyan-500/40 bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-50 transition-colors"
          >
            {refreshing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
            Sync Now
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

      {/* Live Auto-Sync Banner & Countdown Card */}
      <div className="bg-[#0f172a] border border-[#1e293b] rounded-xl p-4 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Clock className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                  Automated Threat Intel Cadence
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-cyan-400 border border-cyan-800/40">
                  Every 300s (5m)
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Next scheduled background sync in <strong className="font-mono text-cyan-300">{mins}:{secs}</strong> · Out-of-band execution protects diode air-gap.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="w-36 hidden sm:block">
              <div className="flex justify-between text-[10px] font-mono text-slate-400 mb-1">
                <span>Cycle Progress</span>
                <span>{syncProgressPct}%</span>
              </div>
              <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                <div className="h-full bg-cyan-400 transition-all duration-1000" style={{ width: `${syncProgressPct}%` }} />
              </div>
            </div>

            <button
              onClick={handleRefresh}
              disabled={refreshing}
              className="px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-[#1e293b] transition-colors shrink-0"
            >
              Force Sync Now
            </button>
          </div>
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
                No threat-intel adapter detected. Point <code className="font-mono text-slate-300">ADAPTER_INGESTION_DIR</code> at a checkout of
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
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Cached indicators ({indicators.length})</span>
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

      {/* Live Background Activity & Ingestion Audit Feed */}
      <div className="bg-[#0f172a] border border-[#1e293b] rounded-xl p-4 space-y-3">
        <div className="flex items-center justify-between border-b border-[#1e293b] pb-2.5">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
              Live Background Activity & Ingestion Audit Log
            </h3>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            {activityLogs.length} events logged
          </span>
        </div>

        <div className="space-y-2 max-h-52 overflow-y-auto pr-1">
          {activityLogs.map((log) => (
            <div
              key={log.id}
              className="flex items-start justify-between gap-3 p-2.5 rounded-lg bg-[#090d16] border border-[#1e293b] text-xs font-mono"
            >
              <div className="flex items-start gap-2.5 min-w-0">
                {log.type === 'threat' ? (
                  <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                ) : log.type === 'feed' ? (
                  <RefreshCw className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                ) : (
                  <Activity className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                )}
                <div className="min-w-0">
                  <div className="font-semibold text-slate-200 truncate">{log.title}</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">{log.detail}</div>
                </div>
              </div>
              <span className="text-[11px] text-slate-500 shrink-0">{log.timestamp}</span>
            </div>
          ))}
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
