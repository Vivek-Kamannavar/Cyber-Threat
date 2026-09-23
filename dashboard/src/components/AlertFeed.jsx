import React, { useState, useMemo } from 'react';
import { 
  ShieldAlert, Terminal, ChevronRight, Filter, Search, Download, 
  Sparkles, CheckCircle2, Server, Globe, ExternalLink 
} from 'lucide-react';

export default function AlertFeed({ alerts, onSelectAlert, onOpenAiCopilot }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [selectedClass, setSelectedClass] = useState('ALL');

  const threatClasses = [
    'ALL',
    'Volumetric / Protocol DDoS',
    'Botnet C2 Beaconing',
    'DGA Domains & DNS Tunnelling',
    'Encrypted Malware (TLS/QUIC)',
    'Reconnaissance & Port Scanning',
    'Data Exfiltration',
    'Unsupervised Volumetric Anomaly'
  ];

  const getSeverity = (confidence) => {
    if (confidence >= 0.90) return 'CRITICAL';
    if (confidence >= 0.75) return 'HIGH';
    if (confidence >= 0.50) return 'MEDIUM';
    return 'LOW';
  };

  const filteredAlerts = useMemo(() => {
    return alerts.filter(a => {
      const sev = getSeverity(a.confidence_score);
      const matchesSeverity = selectedSeverity === 'ALL' || sev === selectedSeverity;
      const matchesClass = selectedClass === 'ALL' || a.threat_class === selectedClass;

      const q = searchQuery.toLowerCase().trim();
      const fid = a.flow_identifier || {};
      const matchesSearch = !q || (
        a.alert_id?.toLowerCase().includes(q) ||
        a.threat_class?.toLowerCase().includes(q) ||
        fid.src_ip?.toLowerCase().includes(q) ||
        fid.dst_ip?.toLowerCase().includes(q) ||
        fid.src_label?.toLowerCase().includes(q) ||
        fid.dst_label?.toLowerCase().includes(q)
      );

      return matchesSeverity && matchesClass && matchesSearch;
    });
  }, [alerts, selectedSeverity, selectedClass, searchQuery]);

  const exportToJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filteredAlerts, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute("href", dataStr);
    dlAnchor.setAttribute("download", `cyber_threat_alerts_${Date.now()}.json`);
    dlAnchor.click();
  };

  const exportToCsv = () => {
    const headers = ["Alert ID", "Timestamp", "Threat Class", "Severity", "Confidence", "Source IP", "Destination IP", "Protocol"];
    const rows = filteredAlerts.map(a => [
      a.alert_id,
      a.timestamp,
      `"${a.threat_class}"`,
      getSeverity(a.confidence_score),
      a.confidence_score,
      a.flow_identifier?.src_ip || '',
      a.flow_identifier?.dst_ip || '',
      a.flow_identifier?.protocol || 'TCP'
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.join(","))].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `cyber_threat_alerts_${Date.now()}.csv`);
    link.click();
  };

  return (
    <div className="bg-[#151f32] border border-[#23324d] rounded-xl p-5 mb-6 shadow-sm">
      {/* Top Header & Actions */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 mb-4">
        <div className="flex items-center gap-2.5">
          <ShieldAlert className="w-5 h-5 text-rose-400" />
          <h2 className="text-sm font-semibold text-slate-100">
            Live Incident Stream ({filteredAlerts.length} of {alerts.length})
          </h2>
        </div>

        {/* Action Controls: Search, Filters & Export */}
        <div className="flex flex-wrap items-center gap-2.5 w-full lg:w-auto">
          {/* Search Input */}
          <div className="relative flex-1 sm:w-56">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search IP, host, or alert..."
              className="w-full bg-[#0b1120] border border-[#23324d] rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex bg-[#0b1120] p-1 rounded-lg border border-[#23324d] text-[11px]">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(sev => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2.5 py-1 rounded font-medium ${
                  selectedSeverity === sev 
                    ? 'bg-slate-800 text-sky-400 shadow-sm' 
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          {/* Threat Class Dropdown */}
          <select
            value={selectedClass}
            onChange={(e) => setSelectedClass(e.target.value)}
            className="bg-[#0b1120] border border-[#23324d] text-xs text-slate-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-sky-500"
          >
            {threatClasses.map(tc => (
              <option key={tc} value={tc}>{tc === 'ALL' ? 'All Classes' : tc}</option>
            ))}
          </select>

          {/* Export Buttons */}
          <button
            onClick={exportToCsv}
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-[#23324d]"
            title="Export filtered alerts to CSV"
          >
            <Download className="w-3.5 h-3.5" /> CSV
          </button>
          <button
            onClick={exportToJson}
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-[#23324d]"
            title="Export filtered alerts to JSON"
          >
            JSON
          </button>
        </div>
      </div>

      {/* Alert Cards Feed */}
      {filteredAlerts.length === 0 ? (
        <div className="text-center py-12 bg-[#0b1120] border border-dashed border-[#23324d] rounded-xl">
          <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto mb-2" />
          <p className="text-xs text-slate-400">No threat alerts matching current filter criteria.</p>
        </div>
      ) : (
        <div className="space-y-2.5 max-h-[500px] overflow-y-auto pr-1">
          {filteredAlerts.slice().reverse().map((alert, idx) => {
            const fid = alert.flow_identifier || {};
            const evidence = alert.supporting_evidence_feature || {};
            const sev = getSeverity(alert.confidence_score);

            const srcLabel = fid.src_label || (fid.src_ip?.startsWith('192.168.') ? 'Internal SCADA Host' : 'Internal Node');
            const dstLabel = fid.dst_label || 'External Endpoint';

            return (
              <div
                key={`${alert.alert_id}-${idx}`}
                className="bg-[#111a2d] border border-[#23324d] hover:border-slate-600 rounded-xl p-3.5 transition-colors flex flex-col md:flex-row md:items-center justify-between gap-3"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2.5 mb-1.5 flex-wrap">
                    <span className="text-xs font-mono font-bold text-sky-400">{alert.alert_id}</span>
                    <span className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded uppercase ${
                      sev === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800/60' :
                      sev === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800/60' :
                      'bg-emerald-950 text-emerald-300 border border-emerald-800/60'
                    }`}>
                      {sev}
                    </span>
                    <span className="text-xs font-medium text-slate-100 bg-slate-900 px-2 py-0.5 rounded border border-[#23324d]">
                      {alert.threat_class}
                    </span>
                    <span className="text-[11px] text-slate-400 font-mono ml-auto">{alert.timestamp}</span>
                  </div>

                  {/* Flow 5-Tuple Identifier */}
                  <div className="text-xs font-mono text-slate-300 flex flex-wrap items-center gap-2 mb-2 bg-[#0b1120] px-3 py-1.5 rounded-lg border border-[#23324d]">
                    <div className="flex items-center gap-1.5 text-sky-300">
                      <Server className="w-3.5 h-3.5 text-sky-400" />
                      <span className="font-semibold">{srcLabel}</span>
                      <span className="text-slate-400 text-[11px]">({fid.src_ip}:{fid.src_port})</span>
                    </div>

                    <span className="text-slate-500">➔</span>

                    <div className="flex items-center gap-1.5 text-slate-300">
                      <Globe className="w-3.5 h-3.5 text-slate-400" />
                      <span className="font-semibold">{dstLabel}</span>
                      <span className="text-slate-400 text-[11px]">({fid.dst_ip}:{fid.dst_port})</span>
                    </div>

                    <span className="text-slate-500 font-semibold ml-auto">{fid.protocol}</span>
                  </div>

                  {/* Non-technical human reason */}
                  <p className="text-xs text-slate-300 line-clamp-1">
                    {evidence.reason || evidence.technical_reason || "Anomalous traffic signature flagged by detection heuristic."}
                  </p>
                </div>

                {/* Right Action Buttons */}
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => onOpenAiCopilot && onOpenAiCopilot(alert)}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-sky-500/10 hover:bg-sky-500/20 text-sky-400 border border-sky-500/30 transition-colors"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    AI Copilot
                  </button>
                  <button
                    onClick={() => onSelectAlert && onSelectAlert(alert)}
                    className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-[#23324d] transition-colors"
                  >
                    Deep Dive
                    <ChevronRight className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
