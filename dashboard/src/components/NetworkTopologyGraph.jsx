import React, { useState, useEffect } from 'react';
import { Network, Shield, Server, Laptop, AlertTriangle, ArrowRight, RefreshCw } from 'lucide-react';

export default function NetworkTopologyGraph({ alerts }) {
  const [topology, setTopology] = useState({ nodes: [], edges: [], total_active_flows: 0 });
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchTopology = async () => {
    try {
      const res = await fetch('http://127.0.0.1:8000/api/topology');
      if (res.ok) {
        const data = await res.json();
        setTopology(data);
      }
    } catch (e) {
      console.error("Failed to fetch topology:", e);
    }
  };

  useEffect(() => {
    fetchTopology();
    const interval = setInterval(fetchTopology, 3000);
    return () => clearInterval(interval);
  }, [alerts]);

  const handleManualRefresh = async () => {
    setIsRefreshing(true);
    await fetchTopology();
    setTimeout(() => setIsRefreshing(false), 500);
  };

  const internalNodes = topology.nodes.filter(n => n.is_internal);
  const externalNodes = topology.nodes.filter(n => !n.is_internal);
  const hasActiveThreat = topology.nodes.some(n => n.is_threat);

  return (
    <div className="bg-[#151f32] border border-[#23324d] rounded-xl p-5 mb-6 shadow-sm">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2.5">
          <Network className="w-5 h-5 text-sky-400" />
          <h2 className="text-sm font-semibold text-slate-100">
            Real-Time Unidirectional Network Topology
          </h2>
          <span className="text-[11px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-[#23324d]">
            {topology.total_active_flows} Active Flows (60s Window)
          </span>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={handleManualRefresh}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
            title="Refresh Topology"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-sky-400' : ''}`} />
          </button>
          <span className="text-xs font-medium text-emerald-400 flex items-center gap-1.5 bg-emerald-950/40 px-2.5 py-1 rounded-full border border-emerald-800/40">
            <Shield className="w-3.5 h-3.5" /> Hardware Data Diode Enforced
          </span>
        </div>
      </div>

      <div className="bg-[#0b1120] border border-[#23324d] rounded-xl p-5 overflow-hidden">
        <div className="grid grid-cols-1 md:grid-cols-7 gap-4 items-center">
          
          {/* Subnet 1: Protected OT/SCADA Zone (Columns 1-3) */}
          <div className="md:col-span-3 bg-[#151f32]/70 border border-[#23324d] rounded-xl p-4 flex flex-col justify-between min-h-[160px]">
            <div className="flex items-center justify-between border-b border-[#23324d] pb-2 mb-3">
              <span className="text-[11px] font-bold uppercase tracking-wider text-sky-400">
                Protected SCADA Enclave
              </span>
              <span className="text-[10px] text-slate-400 font-mono">Tx Fiber Only</span>
            </div>

            <div className="grid grid-cols-2 gap-2">
              {internalNodes.length > 0 ? (
                internalNodes.slice(0, 4).map(node => (
                  <div
                    key={node.id}
                    className={`p-2.5 rounded-lg border text-xs flex items-center gap-2 ${
                      node.is_threat
                        ? 'bg-rose-950/40 border-rose-800 text-rose-300'
                        : 'bg-slate-900 border-[#23324d] text-slate-200'
                    }`}
                  >
                    {node.is_threat ? (
                      <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
                    ) : (
                      <Server className="w-4 h-4 text-sky-400 shrink-0" />
                    )}
                    <div className="overflow-hidden">
                      <div className="font-mono font-semibold truncate text-[11px]">{node.id}</div>
                      <div className="text-[10px] text-slate-400 truncate">{node.label}</div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="col-span-2 text-center py-4 text-xs text-slate-500">
                  Awaiting internal host traffic...
                </div>
              )}
            </div>
          </div>

          {/* Diode Barrier Center (Column 4) */}
          <div className="md:col-span-1 flex flex-col items-center justify-center py-2">
            <div className="relative flex flex-col items-center">
              <div className="w-8 h-8 rounded-full bg-emerald-950 border border-emerald-500/50 flex items-center justify-center text-emerald-400 shadow-sm">
                <ArrowRight className="w-4 h-4" />
              </div>
              <span className="text-[10px] font-semibold text-emerald-400 mt-1 uppercase tracking-tight text-center">
                1-Way Diode
              </span>
              <span className="text-[9px] text-slate-500 text-center font-mono">
                No Return Path
              </span>
            </div>
          </div>

          {/* Subnet 2: External / Monitoring Zone (Columns 5-7) */}
          <div className="md:col-span-3 bg-[#151f32]/70 border border-[#23324d] rounded-xl p-4 flex flex-col justify-between min-h-[160px]">
            <div className="flex items-center justify-between border-b border-[#23324d] pb-2 mb-3">
              <span className="text-[11px] font-bold uppercase tracking-wider text-slate-300">
                External / Cloud Perimeters
              </span>
              <span className="text-[10px] text-slate-400 font-mono">Passive Rx</span>
            </div>

            <div className="grid grid-cols-2 gap-2">
              {externalNodes.length > 0 ? (
                externalNodes.slice(0, 4).map(node => (
                  <div
                    key={node.id}
                    className={`p-2.5 rounded-lg border text-xs flex items-center gap-2 ${
                      node.is_threat
                        ? 'bg-rose-950/40 border-rose-800 text-rose-300'
                        : 'bg-slate-900 border-[#23324d] text-slate-200'
                    }`}
                  >
                    <Laptop className="w-4 h-4 text-slate-400 shrink-0" />
                    <div className="overflow-hidden">
                      <div className="font-mono font-semibold truncate text-[11px]">{node.id}</div>
                      <div className="text-[10px] text-slate-400 truncate">{node.label}</div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="col-span-2 text-center py-4 text-xs text-slate-500">
                  No external destinations logged
                </div>
              )}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
}
