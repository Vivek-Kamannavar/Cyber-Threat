import React from 'react';
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { Activity } from 'lucide-react';

export default function ThroughputChart({ historyData }) {
  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 mb-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 mb-4">
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-cyan-400" />
          <h2 className="text-sm font-bold text-white tracking-wide uppercase">
            📈 Live Traffic Monitor & Threat Spikes
          </h2>
        </div>
        <div className="flex items-center gap-4 text-xs">
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full bg-cyan-400 inline-block" />
            <span className="text-slate-300">Network Traffic (pkts/sec)</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="w-3 h-3 rounded-full bg-rose-500 inline-block" />
            <span className="text-slate-300">Threat Alert Spikes</span>
          </div>
        </div>
      </div>

      <div className="h-64 w-full">
        {historyData.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={historyData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="ppsGlow" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00f0ff" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#00f0ff" stopOpacity={0.0} />
                </linearGradient>
                <linearGradient id="alertGlow" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ff0055" stopOpacity={0.5} />
                  <stop offset="95%" stopColor="#ff0055" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="timeStr" stroke="#64748b" tick={{ fontSize: 11 }} />
              {/* Primary Y-Axis for Packets/sec */}
              <YAxis yAxisId="left" stroke="#64748b" tick={{ fontSize: 11 }} domain={[0, 'auto']} />
              {/* Secondary Y-Axis for Alert Spikes */}
              <YAxis yAxisId="right" orientation="right" stroke="#ff0055" tick={{ fontSize: 11 }} domain={[0, 10]} hide={true} />
              <Tooltip
                contentStyle={{ backgroundColor: '#121824', borderColor: '#1e293b', borderRadius: '8px', color: '#fff', fontSize: '12px' }}
                labelStyle={{ color: '#00f0ff', fontWeight: 'bold' }}
                formatter={(value, name) => {
                  if (name === 'pps') return [`${value} pkts/s`, 'Traffic Speed'];
                  if (name === 'threatSpike') return [`${value} alerts`, 'Threat Spike'];
                  return [value, name];
                }}
              />
              <Area yAxisId="left" type="monotone" dataKey="pps" stroke="#00f0ff" strokeWidth={2} fillOpacity={1} fill="url(#ppsGlow)" />
              <Area yAxisId="right" type="monotone" dataKey="threatSpike" stroke="#ff0055" strokeWidth={2} fillOpacity={1} fill="url(#alertGlow)" />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-full text-slate-500 font-mono text-xs">
            Listening for live network data...
          </div>
        )}
      </div>
    </div>
  );
}
