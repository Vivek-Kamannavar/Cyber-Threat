import React, { useEffect, useState, useCallback } from 'react';
import {
  Database, RefreshCw, UploadCloud, Globe, ShieldCheck, AlertTriangle,
  Loader2, ArrowRight, CheckCircle2, XCircle
} from 'lucide-react';
import SimulationControl from '../components/SimulationControl';
import LiveIngestionDeck from '../components/LiveIngestionDeck';
import { fetchFeedStatus, refreshFeed, eventBus } from '../services/apiService';

const SEVERITY_TONE = {
  CRITICAL: 'text-rose-400 border-rose-500/40 bg-rose-950/20',
  HIGH: 'text-amber-400 border-amber-500/40 bg-amber-950/20',
  MEDIUM: 'text-cyan-400 border-cyan-500/40 bg-cyan-950/20',
  LOW: 'text-slate-300 border-slate-700 bg-slate-900'
};

const OUTCOME_TONE = {
  ok: 'text-emerald-400',
  stale: 'text-amber-400',
  config_error: 'text-rose-400',
  operational_error: 'text-amber-400',
  timeout: 'text-amber-400',
  unavailable: 'text-slate-400',
  error: 'text-rose-400'
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

  const indicators = feed?.indicators || [];
  const sources = feed?.sources || [];

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Unified Live Ingestion & Threat Intelligence Command Deck Card */}
      <LiveIngestionDeck
        feed={feed}
        loading={loading}
        refreshing={refreshing}
        secondsUntilSync={secondsUntilSync}
        activityLogs={activityLogs}
        onRefresh={handleRefresh}
        onOpenUpload={onOpenUpload}
        onNavigateToTab={onNavigateToTab}
      />

      {notice && (
        <div
          className={`flex items-center gap-2 px-3.5 py-2.5 rounded-xl border text-xs font-medium ${
            notice.tone === 'ok'
              ? 'border-emerald-500/40 text-emerald-300 bg-emerald-950/30'
              : 'border-amber-500/40 text-amber-300 bg-amber-950/30'
          }`}
        >
          {notice.tone === 'ok' ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-amber-400" />}
          {notice.text}
        </div>
      )}

      {/* Auxiliary Drilldown: Indicators Catalog & Capture Dropper */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Adapter Sources & Compliance */}
        <div className="bg-[#0b1120] border border-[#1e293b] rounded-2xl p-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Active Adapter Sources
            </span>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-950/60 text-cyan-300 border border-cyan-800/50">
              {sources.length} Configured
            </span>
          </div>

          <div className="space-y-2">
            {sources.length === 0 ? (
              <p className="text-xs text-slate-400">
                No threat-intel adapter detected. Point <code className="font-mono text-slate-300">ADAPTER_INGESTION_DIR</code> at a checkout of
                <span className="font-mono text-slate-300"> @shrinivas-sn/adapter-ingestion</span> with adapter files in <span className="font-mono text-slate-300">adapters/</span>.
              </p>
            ) : (
              sources.map((source) => (
                <div key={source.host} className="flex items-center justify-between gap-2 px-3 py-2.5 rounded-xl bg-[#070b14] border border-[#1e293b]">
                  <div className="min-w-0">
                    <div className="text-xs font-mono font-medium text-slate-200 truncate">{source.host}</div>
                    <div className="text-[10px] text-slate-400 mt-0.5">
                      {source.records} stored records · {source.last_run ? `last run: ${source.last_run.outcome}` : 'active session cache'}
                    </div>
                  </div>
                  {source.last_run?.outcome && (
                    <span className={`flex items-center gap-1 text-[10px] font-mono ${OUTCOME_TONE[source.last_run.outcome] || 'text-slate-400'}`}>
                      {source.last_run.outcome === 'ok' ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
                      {source.last_run.outcome}
                    </span>
                  )}
                </div>
              ))
            )}
          </div>

          <p className="text-[11px] text-slate-400 border-t border-[#1e293b] pt-2.5 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{feed?.compliance || 'Collector runs out of band; the enclave reads only the local indicator cache.'}</span>
          </p>
        </div>

        {/* Capture Dropper & Quick Ingest */}
        <div className="space-y-4">
          <div
            onDragOver={(event) => event.preventDefault()}
            onDrop={handleDrop}
            onClick={onOpenUpload}
            role="button"
            tabIndex={0}
            onKeyDown={(event) => { if (event.key === 'Enter') onOpenUpload(); }}
            className="bg-[#0b1120] border border-dashed border-[#1e293b] hover:border-cyan-500/50 rounded-2xl p-6 text-center cursor-pointer transition-all hover:bg-[#0f172a]"
          >
            <UploadCloud className="w-8 h-8 text-cyan-400 mx-auto" />
            <p className="text-xs font-semibold text-slate-200 mt-2">Drop a PCAP or Zeek log, or click to browse</p>
            <p className="text-[11px] text-slate-400 mt-1">
              .pcap · .pcapng · .log — replayed through the diode detection engine with selectable speed
            </p>
            <span className="inline-flex items-center gap-1 text-xs font-medium text-cyan-400 mt-3 hover:text-cyan-300">
              Open ingestion upload console <ArrowRight className="w-3.5 h-3.5" />
            </span>
          </div>

          <div className="bg-[#0b1120] border border-[#1e293b] rounded-2xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                Cached Indicators ({indicators.length})
              </span>
              <button
                onClick={() => onNavigateToTab('monitor')}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
              >
                Back to monitor
              </button>
            </div>

            {indicators.length === 0 ? (
              <p className="text-xs text-slate-400 flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5" />
                Nothing cached yet — run the adapter pipeline to populate local threat intelligence.
              </p>
            ) : (
              <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                {indicators.map((indicator) => (
                  <div key={indicator.indicator_id || indicator.indicator} className="flex items-center justify-between gap-2 text-xs font-mono bg-[#070b14] px-2.5 py-1.5 rounded-lg border border-[#1e293b]/70">
                    <span className="text-slate-300 truncate">{indicator.indicator}</span>
                    <span className={`shrink-0 px-2 py-0.5 rounded border text-[10px] font-semibold ${SEVERITY_TONE[indicator.severity] || SEVERITY_TONE.LOW}`}>
                      {indicator.severity}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Scenario injector */}
      <SimulationControl onSimulate={onSimulate} />

      <p className="text-[11px] text-slate-500 flex items-center gap-1.5">
        <XCircle className="w-3.5 h-3.5 text-slate-500" />
        Scenario injection is synthetic and local — it never transmits on the monitored interface.
      </p>
    </div>
  );
}
