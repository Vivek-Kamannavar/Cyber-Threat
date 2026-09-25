import React from 'react';
import { Activity, ShieldAlert, Zap, Clock } from 'lucide-react';

export default function SummaryCards({ telemetry, totalAlerts, highestConfidence, autoDetectionEnabled }) {
  const pps = telemetry?.pps || 0;
  const bps = telemetry?.bps || 0;
  const kbps = (bps / 1000).toFixed(1);

  return (
    <div className="bg-[#FFF1D1] border border-black rounded-lg p-3 grid grid-cols-2 md:grid-cols-4 divide-y md:divide-y-0 md:divide-x divide-black">
      {/* Metric 1: Throughput */}
      <div className="px-4 py-2 flex items-center justify-between">
        <div>
          <div className="text-xs text-black font-normal flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-[#00B7CD]" />
            Traffic Speed
          </div>
          <div className="mt-1 flex items-baseline gap-1.5">
            <span className="text-2xl font-bold text-black">{pps}</span>
            <span className="text-xs text-black font-normal">pkts/sec</span>
          </div>
          <div className="text-xs text-black font-normal mt-0.5">{kbps} Kbps bandwidth</div>
        </div>
      </div>

      {/* Metric 2: Threats Flagged */}
      <div className="px-4 py-2 flex items-center justify-between">
        <div>
          <div className="text-xs text-black font-normal flex items-center gap-1.5">
            <ShieldAlert className="w-3.5 h-3.5 text-[#DF301C]" />
            Flagged Alerts
          </div>
          <div className="mt-1 flex items-baseline gap-1.5">
            <span className="text-2xl font-bold text-[#DF301C]">{totalAlerts}</span>
            <span className="text-xs text-black font-normal">incidents</span>
          </div>
          <div className="text-xs text-black font-normal mt-0.5">
            {autoDetectionEnabled === false ? (
              <span className="text-[#FF9100]">Detection Paused</span>
            ) : totalAlerts > 0 ? (
              <span className="text-[#DF301C] font-bold">Threat Detected</span>
            ) : (
              <span className="text-[#00B7CD]">All Clear</span>
            )}
          </div>
        </div>
      </div>

      {/* Metric 3: Confidence Score */}
      <div className="px-4 py-2 flex items-center justify-between">
        <div>
          <div className="text-xs text-black font-normal flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-[#FF9100]" />
            AI Confidence
          </div>
          <div className="mt-1 flex items-baseline gap-1.5">
            <span className="text-2xl font-bold text-black">
              {highestConfidence ? `${(highestConfidence * 100).toFixed(0)}%` : '0%'}
            </span>
            <span className="text-xs text-black font-normal">score</span>
          </div>
          <div className="text-xs text-black font-normal mt-0.5">Isolation Forest ML</div>
        </div>
      </div>

      {/* Metric 4: Latency */}
      <div className="px-4 py-2 flex items-center justify-between">
        <div>
          <div className="text-xs text-black font-normal flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5 text-[#00B7CD]" />
            Pipeline Latency
          </div>
          <div className="mt-1 flex items-baseline gap-1.5">
            <span className="text-2xl font-bold text-black">&lt; 12</span>
            <span className="text-xs text-black font-normal">ms</span>
          </div>
          <div className="text-xs text-black font-normal mt-0.5">Deterministic Stream</div>
        </div>
      </div>
    </div>
  );
}
