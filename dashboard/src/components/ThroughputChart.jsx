import React from 'react';
import { ResponsiveContainer, LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { Activity } from 'lucide-react';

export default function ThroughputChart({ historyData }) {
  return (
    <div className="bg-[#FFF1D1] border border-black rounded-lg p-3.5 mb-2.5">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 mb-2">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-[#00B7CD]" />
          <h2 className="text-xs font-bold text-black tracking-tight">
            Traffic Pulse & Alert Spikes
          </h2>
        </div>
        <div className="flex items-center gap-4 text-xs font-normal">
          <div className="flex items-center gap-1.5 text-black">
            <span className="w-3 h-0.5 bg-[#00B7CD] inline-block" />
            <span className="text-black">Throughput (pkts/s)</span>
          </div>
          <div className="flex items-center gap-1.5 text-black">
            <span className="w-3 h-0.5 bg-[#DF301C] inline-block" />
            <span className="text-black">Threat Spikes</span>
          </div>
        </div>
      </div>

      <div className="h-44 w-full">
        {historyData.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={historyData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <XAxis dataKey="timeStr" stroke="#000000" tick={{ fontSize: 10, fill: '#000000' }} />
              <YAxis yAxisId="left" stroke="#000000" tick={{ fontSize: 10, fill: '#000000' }} domain={[0, 'auto']} />
              <YAxis yAxisId="right" orientation="right" stroke="#DF301C" tick={{ fontSize: 10, fill: '#DF301C' }} domain={[0, 10]} hide={true} />
              <Tooltip
                contentStyle={{ backgroundColor: '#FFF1D1', borderColor: '#000000', borderWidth: '1px', borderRadius: '4px', color: '#000000', fontSize: '11px' }}
                labelStyle={{ color: '#000000', fontWeight: 'bold' }}
                formatter={(value, name) => {
                  if (name === 'pps') return [`${value} pkts/s`, 'Rate'];
                  if (name === 'threatSpike') return [`${value} alerts`, 'Spike'];
                  return [value, name];
                }}
              />
              <Line yAxisId="left" type="monotone" dataKey="pps" stroke="#00B7CD" strokeWidth={2} dot={false} />
              <Line yAxisId="right" type="monotone" dataKey="threatSpike" stroke="#DF301C" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-full text-black text-xs font-normal">
            Listening for live telemetry data...
          </div>
        )}
      </div>
    </div>
  );
}
