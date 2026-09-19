import React from 'react';
import { Network, Shield, Server, Laptop, AlertOctagon } from 'lucide-react';

export default function NetworkTopologyGraph({ alerts }) {
  const latestAlert = alerts.length > 0 ? alerts[alerts.length - 1] : null;
  const threatSrc = latestAlert?.flow_identifier?.src_ip || '192.168.10.15';
  const threatDst = latestAlert?.flow_identifier?.dst_ip || '45.142.214.8';

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 mb-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Network className="w-5 h-5 text-cyan-400" />
          <h2 className="text-sm font-bold font-mono text-white tracking-wide uppercase">
            Data Diode Network Topology & Anomalous Path Mapping
          </h2>
        </div>
        <span className="text-xs font-mono text-emerald-400 flex items-center gap-1">
          <Shield className="w-3.5 h-3.5" /> Hardware Data Diode Active
        </span>
      </div>

      <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-6 relative overflow-hidden">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
          
          {/* Subnet 1: Protected OT/SCADA Zone */}
          <div className="bg-slate-900/90 border border-cyan-500/30 rounded-xl p-4 text-center glow-accent">
            <div className="text-[10px] font-mono text-cyan-400 uppercase font-bold mb-2">PROTECTED OT / SCADA SUBNET</div>
            <div className="flex justify-center gap-3 mb-2">
              <div className="p-2 bg-slate-800 rounded-lg text-cyan-300">
                <Server className="w-6 h-6" />
              </div>
              <div className="p-2 bg-slate-800 rounded-lg text-cyan-300">
                <Laptop className="w-6 h-6" />
              </div>
            </div>
            <div className="text-xs font-mono text-slate-200 font-semibold">{threatSrc}</div>
            <div className="text-[10px] text-slate-400 font-mono">Internal Host Node</div>
          </div>

          {/* Diode Barrier Icon */}
          <div className="flex flex-col items-center justify-center py-2">
            <div className="w-full h-0.5 bg-gradient-to-r from-cyan-500 via-emerald-400 to-red-500 relative flex items-center justify-center">
              <div className="px-3 py-1 bg-emerald-950 border border-emerald-500/50 rounded-full text-[10px] font-mono text-emerald-300 flex items-center gap-1">
                <span>➡</span> UNIDIRECTIONAL DIODE <span>➡</span>
              </div>
            </div>
            <div className="text-[10px] font-mono text-slate-400 mt-2">Zero Return Path / Read-Only Mirror</div>
          </div>

          {/* Subnet 2: External / Monitoring Zone */}
          <div className={`bg-slate-900/90 border rounded-xl p-4 text-center ${latestAlert ? 'border-red-500/50 glow-red' : 'border-slate-800'}`}>
            <div className="text-[10px] font-mono text-slate-400 uppercase font-bold mb-2">EXTERNAL DESTINATION / C2</div>
            <div className="flex justify-center gap-3 mb-2">
              <div className="p-2 bg-red-950/60 border border-red-500/40 rounded-lg text-red-400">
                <AlertOctagon className="w-6 h-6 animate-pulse" />
              </div>
            </div>
            <div className="text-xs font-mono text-red-300 font-semibold">{threatDst}</div>
            <div className="text-[10px] text-slate-400 font-mono">External Target / Destination</div>
          </div>
        </div>
      </div>
    </div>
  );
}
