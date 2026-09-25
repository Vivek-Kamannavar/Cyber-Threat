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

  return (
    <div className="bg-[#FFF1D1] border border-black rounded-lg p-3.5 mb-2.5">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-[#00B7CD]" />
          <h2 className="text-xs font-bold text-black tracking-tight">
            Network Topology
          </h2>
          <span className="text-[11px] font-normal text-black bg-[#FFF1D1] px-2 py-0.5 rounded border border-black">
            {topology.total_active_flows} Flows Active
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleManualRefresh}
            className="p-1 rounded bg-[#FFF1D1] border border-black text-black transition-colors"
            title="Refresh Topology"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-[#00B7CD]' : ''}`} />
          </button>
          <span className="text-[11px] font-normal text-black flex items-center gap-1.5 bg-[#FFF1D1] px-2 py-0.5 rounded border border-[#00B7CD]">
            <Shield className="w-3 h-3 text-[#00B7CD]" /> Data Diode Active
          </span>
        </div>
      </div>

      <div className="bg-[#FFF1D1] border border-black rounded-lg p-3">
        <div className="grid grid-cols-1 md:grid-cols-7 gap-3 items-center">
          
          {/* Subnet 1: Protected SCADA Zone (Columns 1-3) */}
          <div className="md:col-span-3 bg-[#FFF1D1] border border-black rounded-lg p-3 flex flex-col justify-between min-h-[140px]">
            <div className="flex items-center justify-between border-b border-black pb-1.5 mb-2.5">
              <span className="text-[11px] font-bold text-black">
                Protected SCADA Enclave
              </span>
              <span className="text-[10px] text-black font-normal">Tx Fiber Only</span>
            </div>

            <div className="grid grid-cols-2 gap-2">
              {internalNodes.length > 0 ? (
                internalNodes.slice(0, 4).map(node => (
                  <div
                    key={node.id}
                    className={`p-2 rounded border text-xs flex items-center gap-2 bg-[#FFF1D1] ${
                      node.is_threat
                        ? 'border-2 border-[#DF301C] text-black'
                        : 'border border-black text-black'
                    }`}
                  >
                    {node.is_threat ? (
                      <AlertTriangle className="w-3.5 h-3.5 text-[#DF301C] shrink-0" />
                    ) : (
                      <Server className="w-3.5 h-3.5 text-[#00B7CD] shrink-0" />
                    )}
                    <div className="overflow-hidden">
                      <div className="font-bold truncate text-[11px] text-black">{node.id}</div>
                      <div className="text-[10px] text-black truncate font-normal">{node.label}</div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="col-span-2 text-center py-4 text-xs text-black font-normal">
                  Awaiting internal host traffic...
                </div>
              )}
            </div>
          </div>

          {/* Diode Barrier Center (Column 4) */}
          <div className="md:col-span-1 flex flex-col items-center justify-center py-2">
            <div className="w-8 h-8 rounded border border-black bg-[#00B7CD] flex items-center justify-center text-black">
              <ArrowRight className="w-4 h-4" />
            </div>
            <span className="text-[10px] font-bold text-black mt-1 uppercase tracking-tight text-center">
              1-Way
            </span>
          </div>

          {/* Subnet 2: External Monitoring Zone (Columns 5-7) */}
          <div className="md:col-span-3 bg-[#FFF1D1] border border-black rounded-lg p-3 flex flex-col justify-between min-h-[140px]">
            <div className="flex items-center justify-between border-b border-black pb-1.5 mb-2.5">
              <span className="text-[11px] font-bold text-black">
                External Perimeters
              </span>
              <span className="text-[10px] text-black font-normal">Passive Rx</span>
            </div>

            <div className="grid grid-cols-2 gap-2">
              {externalNodes.length > 0 ? (
                externalNodes.slice(0, 4).map(node => (
                  <div
                    key={node.id}
                    className={`p-2 rounded border text-xs flex items-center gap-2 bg-[#FFF1D1] ${
                      node.is_threat
                        ? 'border-2 border-[#DF301C] text-black'
                        : 'border border-black text-black'
                    }`}
                  >
                    <Laptop className="w-3.5 h-3.5 text-black shrink-0" />
                    <div className="overflow-hidden">
                      <div className="font-bold truncate text-[11px] text-black">{node.id}</div>
                      <div className="text-[10px] text-black truncate font-normal">{node.label}</div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="col-span-2 text-center py-4 text-xs text-black font-normal">
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
