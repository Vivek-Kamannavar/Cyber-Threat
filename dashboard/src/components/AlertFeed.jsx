import React, { useState } from 'react';
import { ShieldAlert, Terminal, ChevronRight, Filter, Globe, Server } from 'lucide-react';

export default function AlertFeed({ alerts, onSelectAlert }) {
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

  const filteredAlerts = selectedClass === 'ALL'
    ? alerts
    : alerts.filter(a => a.threat_class === selectedClass);

  const getSeverityBadge = (confidence) => {
    if (confidence >= 0.90) {
      return <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-red-950 text-red-400 border border-red-500/40 rounded uppercase">CRITICAL</span>;
    } else if (confidence >= 0.75) {
      return <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-amber-950 text-amber-400 border border-amber-500/40 rounded uppercase">HIGH</span>;
    } else if (confidence >= 0.50) {
      return <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-yellow-950 text-yellow-300 border border-yellow-500/40 rounded uppercase">MEDIUM</span>;
    }
    return <span className="px-2 py-0.5 text-[10px] font-mono font-bold bg-blue-950 text-blue-300 border border-blue-500/40 rounded uppercase">LOW</span>;
  };

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 mb-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-4">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-red-400" />
          <h2 className="text-sm font-bold font-mono text-white tracking-wide uppercase">
            Live Standardized Alert Stream ({filteredAlerts.length})
          </h2>
        </div>

        {/* Filter Dropdown */}
        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-slate-400" />
          <select
            value={selectedClass}
            onChange={(e) => setSelectedClass(e.target.value)}
            className="bg-slate-900 border border-slate-700 text-xs font-mono text-slate-200 rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            {threatClasses.map(tc => (
              <option key={tc} value={tc}>{tc === 'ALL' ? 'All Threat Classes' : tc}</option>
            ))}
          </select>
        </div>
      </div>

      {filteredAlerts.length === 0 ? (
        <div className="text-center py-12 bg-slate-950/40 border border-dashed border-slate-800 rounded-xl">
          <ShieldAlert className="w-8 h-8 text-slate-600 mx-auto mb-2" />
          <p className="text-xs font-mono text-slate-400">No threat alerts matching current filter criteria.</p>
        </div>
      ) : (
        <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
          {filteredAlerts.slice().reverse().map((alert, idx) => {
            const fid = alert.flow_identifier || {};
            const evidence = alert.supporting_evidence_feature || {};

            const srcLabel = fid.src_label || (fid.src_ip?.startsWith('192.168.') ? 'Internal SCADA Host' : 'External Host');
            const dstLabel = fid.dst_label || (fid.dst_ip === '8.8.8.8' ? 'Google DNS' : 'External Endpoint');

            return (
              <div
                key={`${alert.alert_id}-${idx}`}
                className="bg-slate-900/80 border border-slate-800 hover:border-slate-700 rounded-xl p-4 transition-all hover:bg-slate-900 duration-150 flex flex-col md:flex-row md:items-center justify-between gap-4"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-3 mb-1.5 flex-wrap">
                    <span className="text-xs font-mono text-cyan-400 font-bold">{alert.alert_id}</span>
                    {getSeverityBadge(alert.confidence_score)}
                    <span className="text-xs font-mono font-semibold text-white bg-slate-800 px-2 py-0.5 rounded">
                      {alert.threat_class}
                    </span>
                    <span className="text-[11px] font-mono text-slate-400 ml-auto">{alert.timestamp}</span>
                  </div>

                  {/* Flow 5-Tuple Identifier with Device & Website Labels */}
                  <div className="text-xs font-mono text-slate-300 flex flex-wrap items-center gap-2 mb-2 bg-slate-950 px-3 py-2 rounded-lg border border-slate-800/80">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    
                    {/* Source Device */}
                    <div className="flex items-center gap-1 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-500/30 text-cyan-300">
                      <Server className="w-3 h-3 text-cyan-400" />
                      <span className="font-semibold">{srcLabel}</span>
                      <span className="text-cyan-400/70 text-[11px]">({fid.src_ip}:{fid.src_port})</span>
                    </div>

                    <span className="text-slate-500">➔</span>

                    {/* Destination Website / Service */}
                    <div className="flex items-center gap-1 bg-emerald-950/80 px-2 py-0.5 rounded border border-emerald-500/30 text-emerald-300">
                      <Globe className="w-3 h-3 text-emerald-400" />
                      <span className="font-semibold">{dstLabel}</span>
                      <span className="text-emerald-400/70 text-[11px]">({fid.dst_ip}:{fid.dst_port})</span>
                    </div>

                    <span className="text-amber-300 font-bold ml-auto">[{fid.protocol}]</span>
                  </div>

                  {/* Kid-Friendly Reason snippet */}
                  <p className="text-xs text-slate-300 line-clamp-2 leading-relaxed mt-1">
                    <span className="font-semibold text-amber-300">💡 Why it's a threat: </span>
                    {(() => {
                      const r = evidence.reason || '';
                      if (r.includes('Shannon Entropy') || r.includes('flow burst') || alert.threat_class?.includes('DDoS')) {
                        return 'A huge crowd of robot computers is shouting at our server all at once so nobody else can get in — just like 100 people trying to push through a tiny classroom door at the exact same second!';
                      }
                      if (r.includes('inter-arrival') || alert.threat_class?.includes('C2')) {
                        return 'A secret bad program hiding inside is quietly whispering to a hacker\'s computer on a timer like a ticking clock, waiting for secret evil instructions.';
                      }
                      if (r.includes('Entropy') || r.includes('n-gram') || alert.threat_class?.includes('DGA')) {
                        return 'The computer is asking for weird scrambled secret-code website names (like \'x9z8q7w6\'), which hackers use to sneak stolen secrets out without anyone noticing.';
                      }
                      if (r.includes('JA3') || alert.threat_class?.includes('Malware')) {
                        return 'A dangerous computer virus was caught trying to wear a fake disguise to sneak past the security guards.';
                      }
                      if (r.includes('fan-out') || alert.threat_class?.includes('Scanning')) {
                        return 'A sneaky stranger is walking around trying to wiggle every single doorknob and window on our house to see if any door was left unlocked.';
                      }
                      if (r.includes('asymmetric') || alert.threat_class?.includes('Exfiltration')) {
                        return 'Someone is sneaking out a giant backpack stuffed with private files and secret photos through the back door!';
                      }
                      return r || 'Anomalous network telemetry metric detected.';
                    })()}
                  </p>
                </div>

                {/* Inspect Button */}
                <button
                  onClick={() => onSelectAlert(alert)}
                  className="px-3.5 py-2 bg-cyan-950/60 hover:bg-cyan-900/80 text-cyan-300 border border-cyan-500/40 rounded-lg text-xs font-mono flex items-center gap-1.5 shrink-0 transition-colors"
                >
                  Inspect Evidence
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
