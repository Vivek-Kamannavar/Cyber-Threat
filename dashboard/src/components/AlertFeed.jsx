import React, { useState, useMemo } from 'react';
import { 
  ShieldAlert, ChevronRight, Search, Download, 
  Sparkles, Server, Globe, ArrowRight 
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
    <div className="bg-[#FFF1D1] border border-black rounded-lg p-3.5 mb-2.5">
      {/* Top Header & Actions */}
      <div className="flex flex-col gap-2.5 mb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-[#DF301C]" />
            <h2 className="text-xs font-bold text-black tracking-tight">
              Live Alert Stream ({filteredAlerts.length} of {alerts.length})
            </h2>
          </div>
          <div className="flex items-center gap-1.5">
            <button
              onClick={exportToCsv}
              className="flex items-center gap-1 px-2.5 py-1 text-xs font-normal rounded border border-black text-black bg-[#FFF1D1] transition-colors"
            >
              <Download className="w-3 h-3 text-black" /> CSV
            </button>
            <button
              onClick={exportToJson}
              className="px-2.5 py-1 text-xs font-normal rounded border border-black text-black bg-[#FFF1D1] transition-colors"
            >
              JSON
            </button>
          </div>
        </div>

        {/* Search & Filters */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1 min-w-[150px]">
            <Search className="w-3.5 h-3.5 text-black absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search alert, IP..."
              className="w-full bg-[#FFF1D1] border border-black rounded pl-7 pr-2.5 py-1 text-xs text-black placeholder-black font-normal focus:outline-none"
            />
          </div>

          <div className="flex border border-black rounded text-xs font-normal overflow-hidden">
            {['ALL', 'CRITICAL', 'HIGH'].map(sev => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-2 py-0.5 transition-colors ${
                  selectedSeverity === sev 
                    ? 'bg-black text-[#FFF1D1]' 
                    : 'text-black bg-[#FFF1D1]'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          <select
            value={selectedClass}
            onChange={(e) => setSelectedClass(e.target.value)}
            className="bg-[#FFF1D1] border border-black text-xs text-black font-normal rounded px-2 py-1 focus:outline-none"
          >
            {threatClasses.map(tc => (
              <option key={tc} value={tc}>{tc === 'ALL' ? 'All Classes' : tc}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Alert Cards Feed */}
      {filteredAlerts.length === 0 ? (
        <div className="text-center py-10 bg-[#FFF1D1] border border-dashed border-black rounded-lg">
          <ShieldAlert className="w-6 h-6 text-black mx-auto mb-1" />
          <p className="text-xs text-black font-normal">No alerts matching criteria.</p>
        </div>
      ) : (
        <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
          {filteredAlerts.slice().reverse().map((alert, idx) => {
            const fid = alert.flow_identifier || {};
            const evidence = alert.supporting_evidence_feature || {};
            const sev = getSeverity(alert.confidence_score);

            const srcLabel = fid.src_label || (fid.src_ip?.startsWith('192.168.') ? 'Internal SCADA' : 'Host');
            const dstLabel = fid.dst_label || 'External';

            return (
              <div
                key={`${alert.alert_id}-${idx}`}
                className="bg-[#FFF1D1] border border-black rounded-lg p-3 flex flex-col gap-2"
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-bold text-black">{alert.alert_id}</span>
                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase ${
                    sev === 'CRITICAL' ? 'bg-[#DF301C] text-[#FFF1D1]' :
                    sev === 'HIGH' ? 'bg-[#FF9100] text-black' :
                    'bg-[#00B7CD] text-black'
                  }`}>
                    {sev}
                  </span>
                  <span className="text-xs font-bold text-black">
                    {alert.threat_class}
                  </span>
                  <span className="text-[11px] text-black font-normal ml-auto">{alert.timestamp}</span>
                </div>

                {/* 5-Tuple Box */}
                <div className="text-xs font-normal text-black flex flex-wrap items-center gap-2 bg-[#FFF1D1] px-2.5 py-1 rounded border border-black">
                  <div className="flex items-center gap-1">
                    <Server className="w-3 h-3 text-[#00B7CD]" />
                    <span className="font-bold">{srcLabel}</span>
                    <span className="text-black text-[11px]">({fid.src_ip}:{fid.src_port})</span>
                  </div>

                  <ArrowRight className="w-3 h-3 text-black" />

                  <div className="flex items-center gap-1">
                    <Globe className="w-3 h-3 text-black" />
                    <span className="font-bold">{dstLabel}</span>
                    <span className="text-black text-[11px]">({fid.dst_ip}:{fid.dst_port})</span>
                  </div>

                  <span className="text-black text-[11px] ml-auto font-bold">{fid.protocol}</span>
                </div>

                {/* Reason description */}
                <p className="text-xs text-black line-clamp-1 font-normal">
                  {evidence.reason || evidence.technical_reason || "Anomalous traffic signature flagged."}
                </p>

                {/* Action Buttons */}
                <div className="flex items-center gap-2 pt-0.5 justify-end">
                  <button
                    onClick={() => onOpenAiCopilot && onOpenAiCopilot(alert)}
                    className="flex items-center gap-1 px-2.5 py-1 text-xs font-normal rounded bg-[#00B7CD] text-black border border-black transition-colors"
                  >
                    <Sparkles className="w-3 h-3" />
                    AI Copilot
                  </button>
                  <button
                    onClick={() => onSelectAlert && onSelectAlert(alert)}
                    className="flex items-center gap-1 px-2.5 py-1 text-xs font-normal rounded border border-black text-black bg-[#FFF1D1] transition-colors"
                  >
                    Evidence
                    <ChevronRight className="w-3 h-3" />
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
