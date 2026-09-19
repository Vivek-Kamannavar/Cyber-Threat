import React from 'react';
import { X, Code, ShieldAlert, Cpu, CheckCircle, Globe, Server } from 'lucide-react';

export default function ThreatDetailsModal({ alert, onClose }) {
  if (!alert) return null;

  const fid = alert.flow_identifier || {};
  const ev = alert.supporting_evidence_feature || {};

  const srcLabel = fid.src_label || (fid.src_ip?.startswith?.('192.168.') ? 'Internal SCADA Host' : 'External Host');
  const dstLabel = fid.dst_label || 'External Endpoint / Web Server';

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-cyber-card border border-cyber-border rounded-2xl w-full max-w-3xl max-h-[90vh] flex flex-col overflow-hidden shadow-2xl glow-accent">
        
        {/* Modal Header */}
        <div className="p-5 border-b border-cyber-border flex items-center justify-between bg-slate-900/60">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-950/80 border border-red-500/40 rounded-lg">
              <ShieldAlert className="w-6 h-6 text-red-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-mono text-cyan-400 font-bold">{alert.alert_id}</span>
                <span className="text-xs font-mono font-semibold text-white bg-slate-800 px-2 py-0.5 rounded">
                  {alert.threat_class}
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Timestamp: {alert.timestamp} | Confidence: {(alert.confidence_score * 100).toFixed(0)}%
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Content Scrollable Area */}
        <div className="p-6 overflow-y-auto space-y-5">

          {/* Kid-Friendly Simple Explanation Callout */}
          <div className="bg-gradient-to-r from-amber-950/50 to-orange-950/40 border border-amber-500/50 p-4 rounded-xl shadow-md">
            <div className="flex items-center gap-2 text-amber-300 font-bold text-xs uppercase tracking-wider mb-1.5">
              <span>💡 Simple Explanation (Like Telling a Small Kid):</span>
            </div>
            <p className="text-white text-sm font-semibold leading-relaxed">
              {(() => {
                const raw = ev.reason || '';
                if (raw.includes('Shannon Entropy') || raw.includes('flow burst') || alert.threat_class?.includes('DDoS')) {
                  return 'A huge crowd of robot computers is shouting at our server all at once so nobody else can get in — just like 100 people trying to push through a tiny classroom door at the exact same second!';
                }
                if (raw.includes('inter-arrival') || alert.threat_class?.includes('C2')) {
                  return 'A secret bad program hiding inside is quietly whispering to a hacker\'s computer on a timer like a ticking clock, waiting for secret evil instructions.';
                }
                if (raw.includes('Entropy') || raw.includes('n-gram') || alert.threat_class?.includes('DGA')) {
                  return 'The computer is asking for weird scrambled secret-code website names (like \'x9z8q7w6\'), which hackers use to sneak stolen secrets out without anyone noticing.';
                }
                if (raw.includes('JA3') || alert.threat_class?.includes('Malware')) {
                  return 'A dangerous computer virus was caught trying to wear a fake disguise to sneak past the security guards.';
                }
                if (raw.includes('fan-out') || alert.threat_class?.includes('Scanning')) {
                  return 'A sneaky stranger is walking around trying to wiggle every single doorknob and window on our house to see if any door was left unlocked.';
                }
                if (raw.includes('asymmetric') || alert.threat_class?.includes('Exfiltration')) {
                  return 'Someone is sneaking out a giant backpack stuffed with private files and secret photos through the back door!';
                }
                return raw || 'A strange computer activity was spotted!';
              })()}
            </p>
          </div>

          {/* Device & Website Identification Banner */}
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800">
            <h3 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <Cpu className="w-4 h-4 text-cyan-400" /> Endpoint Device & Website Domain Identity
            </h3>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 font-mono text-xs mb-4">
              {/* Source Device */}
              <div className="bg-cyan-950/40 border border-cyan-500/30 p-3 rounded-lg">
                <div className="text-[10px] text-cyan-400 uppercase font-bold flex items-center gap-1 mb-1">
                  <Server className="w-3.5 h-3.5" /> SOURCE DEVICE IDENTITY
                </div>
                <div className="text-white font-bold text-sm">{srcLabel}</div>
                <div className="text-cyan-300 text-xs mt-1">IP: {fid.src_ip} | Port: {fid.src_port}</div>
              </div>

              {/* Destination Website */}
              <div className="bg-emerald-950/40 border border-emerald-500/30 p-3 rounded-lg">
                <div className="text-[10px] text-emerald-400 uppercase font-bold flex items-center gap-1 mb-1">
                  <Globe className="w-3.5 h-3.5" /> DESTINATION WEBSITE / SERVICE
                </div>
                <div className="text-white font-bold text-sm">{dstLabel}</div>
                <div className="text-emerald-300 text-xs mt-1">IP: {fid.dst_ip} | Port: {fid.dst_port} [{fid.protocol}]</div>
              </div>
            </div>

            {/* 5-Tuple Raw Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 font-mono text-xs">
              <div className="bg-slate-900 p-2 rounded">
                <div className="text-[10px] text-slate-500">SOURCE IP</div>
                <div className="text-cyan-300 font-bold">{fid.src_ip}</div>
              </div>
              <div className="bg-slate-900 p-2 rounded">
                <div className="text-[10px] text-slate-500">SRC PORT</div>
                <div className="text-slate-200">{fid.src_port}</div>
              </div>
              <div className="bg-slate-900 p-2 rounded">
                <div className="text-[10px] text-slate-500">DEST IP</div>
                <div className="text-emerald-300 font-bold">{fid.dst_ip}</div>
              </div>
              <div className="bg-slate-900 p-2 rounded">
                <div className="text-[10px] text-slate-500">DEST PORT</div>
                <div className="text-slate-200">{fid.dst_port}</div>
              </div>
              <div className="bg-slate-900 p-2 rounded">
                <div className="text-[10px] text-slate-500">PROTOCOL</div>
                <div className="text-amber-300 font-bold">{fid.protocol}</div>
              </div>
            </div>
          </div>

          {/* Feature Evidence Key-Value Grid */}
          <div>
            <h3 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <CheckCircle className="w-4 h-4 text-emerald-400" /> Feature Evidence & Mathematical Artifacts
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
              {Object.entries(ev).map(([key, val]) => (
                <div key={key} className="bg-slate-900/60 p-3 rounded-lg border border-slate-800">
                  <div className="text-[10px] text-slate-400 uppercase tracking-wider">{key.replace(/_/g, ' ')}</div>
                  <div className="text-slate-200 font-semibold mt-1 break-all">
                    {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Standardized JSON Record Box */}
          <div>
            <h3 className="text-xs font-mono text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Code className="w-4 h-4 text-cyan-400" /> Standardized JSON Alert Record
            </h3>
            <pre className="bg-slate-950 text-cyan-300 font-mono text-xs p-4 rounded-xl border border-slate-800 overflow-x-auto">
              {JSON.stringify(alert, null, 2)}
            </pre>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-cyber-border bg-slate-900/60 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono transition-colors"
          >
            Close Evidence Inspector
          </button>
        </div>
      </div>
    </div>
  );
}
