import React from 'react';
import { X, Code, ShieldAlert, Cpu, CheckCircle, Globe, Server } from 'lucide-react';

export default function ThreatDetailsModal({ alert, onClose }) {
  if (!alert) return null;

  const fid = alert.flow_identifier || {};
  const ev = alert.supporting_evidence_feature || {};

  const srcLabel = fid.src_label || (fid.src_ip?.startsWith?.('192.168.') ? 'SCADA Host' : 'Host');
  const dstLabel = fid.dst_label || 'External Endpoint';

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
      <div className="bg-[#FFF1D1] border border-black rounded-lg w-full max-w-2xl max-h-[90vh] flex flex-col overflow-hidden shadow-2xl">
        
        {/* Header */}
        <div className="p-3.5 border-b border-black flex items-center justify-between bg-[#FFF1D1]">
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 bg-[#FFF1D1] text-[#DF301C] rounded border border-black">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-black">{alert.alert_id}</span>
                <span className="text-[10px] font-bold text-[#FFF1D1] bg-[#DF301C] px-2 py-0.5 rounded uppercase">
                  {alert.threat_class}
                </span>
              </div>
              <p className="text-[11px] text-black font-normal mt-0.5">
                Timestamp: {alert.timestamp} | Score: {(alert.confidence_score * 100).toFixed(0)}%
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-black bg-[#FFF1D1] border border-black rounded transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-4 overflow-y-auto space-y-3.5 text-xs text-black font-normal">
          {/* Plain-Language Explanation */}
          <div className="bg-[#FFF1D1] border border-black p-3 rounded-lg space-y-1">
            <div className="text-[10px] font-bold uppercase tracking-wider text-black">
              Plain-Language Explanation
            </div>
            <p className="text-xs text-black font-normal leading-relaxed">
              {ev.reason || ev.technical_reason || "Anomalous traffic signature flagged by automated detection heuristic."}
            </p>
          </div>

          {/* Endpoint Identity */}
          <div className="bg-[#FFF1D1] p-3 rounded-lg border border-black space-y-2.5">
            <h3 className="text-[10px] text-black uppercase tracking-wider flex items-center gap-1.5 font-bold">
              <Cpu className="w-3.5 h-3.5 text-[#00B7CD]" /> Endpoint Telemetry
            </h3>
            
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <div className="bg-[#FFF1D1] border border-black p-2.5 rounded-lg space-y-0.5">
                <div className="text-[10px] text-black uppercase font-bold flex items-center gap-1">
                  <Server className="w-3 h-3 text-[#00B7CD]" /> SOURCE
                </div>
                <div className="text-black font-bold text-xs">{srcLabel}</div>
                <div className="text-black text-[11px] font-normal">IP: {fid.src_ip}:{fid.src_port}</div>
              </div>

              <div className="bg-[#FFF1D1] border border-black p-2.5 rounded-lg space-y-0.5">
                <div className="text-[10px] text-black uppercase font-bold flex items-center gap-1">
                  <Globe className="w-3 h-3 text-[#FF9100]" /> DESTINATION
                </div>
                <div className="text-black font-bold text-xs">{dstLabel}</div>
                <div className="text-black text-[11px] font-normal">IP: {fid.dst_ip}:{fid.dst_port} [{fid.protocol}]</div>
              </div>
            </div>

            {/* 5-Tuple Box */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-1.5 text-[11px] text-center">
              <div className="border border-black bg-[#FFF1D1] p-1.5 rounded">
                <div className="text-[10px] text-black font-bold">SRC IP</div>
                <div className="text-black font-normal truncate">{fid.src_ip}</div>
              </div>
              <div className="border border-black bg-[#FFF1D1] p-1.5 rounded">
                <div className="text-[10px] text-black font-bold">SPORT</div>
                <div className="text-black font-normal">{fid.src_port}</div>
              </div>
              <div className="border border-black bg-[#FFF1D1] p-1.5 rounded">
                <div className="text-[10px] text-black font-bold">DST IP</div>
                <div className="text-black font-normal truncate">{fid.dst_ip}</div>
              </div>
              <div className="border border-black bg-[#FFF1D1] p-1.5 rounded">
                <div className="text-[10px] text-black font-bold">DPORT</div>
                <div className="text-black font-normal">{fid.dst_port}</div>
              </div>
              <div className="border border-black bg-[#FFF1D1] p-1.5 rounded">
                <div className="text-[10px] text-black font-bold">PROTO</div>
                <div className="text-black font-normal">{fid.protocol}</div>
              </div>
            </div>
          </div>

          {/* Evidence Grid */}
          <div className="space-y-1.5">
            <h3 className="text-[10px] text-black uppercase tracking-wider flex items-center gap-1.5 font-bold">
              <CheckCircle className="w-3.5 h-3.5 text-[#00B7CD]" /> Feature Metrics
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {Object.entries(ev).map(([key, val]) => (
                <div key={key} className="bg-[#FFF1D1] p-2 rounded-lg border border-black">
                  <div className="text-[10px] text-black uppercase font-bold">{key.replace(/_/g, ' ')}</div>
                  <div className="text-black font-normal mt-0.5 break-all text-xs">
                    {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* JSON Box */}
          <div className="space-y-1.5">
            <h3 className="text-[10px] text-black uppercase tracking-wider flex items-center gap-1.5 font-bold">
              <Code className="w-3.5 h-3.5 text-black" /> Alert JSON
            </h3>
            <pre className="bg-[#FFF1D1] text-black p-3 rounded-lg border border-black overflow-x-auto text-[11px] leading-tight font-normal">
              {JSON.stringify(alert, null, 2)}
            </pre>
          </div>
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-black bg-[#FFF1D1] flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-[#FFF1D1] border border-black text-black rounded text-xs font-normal transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
