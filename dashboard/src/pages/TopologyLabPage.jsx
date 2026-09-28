import React from 'react';
import NetworkTopologyGraph from '../components/NetworkTopologyGraph';
import SimulationControl from '../components/SimulationControl';
import { Network, ShieldAlert, ArrowRight, Activity, Flame, Radio, Globe, Lock, Radar, UploadCloud } from 'lucide-react';

export default function TopologyLabPage({
  alerts,
  onSimulate,
  onNavigateToTab
}) {
  const threatClassGuide = [
    {
      title: 'Volumetric / Protocol DDoS',
      formula: 'Shannon Entropy H(X) < 1.5 + PPS Spike',
      icon: Flame,
      color: 'border-red-500/30 text-red-400 bg-red-950/20',
      desc: 'Monitors source IP entropy distribution. Floods collapse entropy below baseline with sudden flow surges.'
    },
    {
      title: 'Botnet C2 Beaconing',
      formula: 'CV = σ_IAT / μ_IAT < 0.22',
      icon: Radio,
      color: 'border-amber-500/30 text-amber-400 bg-amber-950/20',
      desc: 'Calculates Inter-Arrival Time (IAT) variance. Low coefficient of variation indicates heartbeat beaconing.'
    },
    {
      title: 'DGA & DNS Tunnelling',
      formula: 'Query Shannon Entropy > 3.7 + N-Gram Rarity',
      icon: Globe,
      color: 'border-purple-500/30 text-purple-400 bg-purple-950/20',
      desc: 'Analyzes domain randomness, hex/base64 chunk lengths, and unusual DNS record types (TXT/NULL).'
    },
    {
      title: 'Encrypted Malware (TLS/QUIC)',
      formula: 'JA3 / JA4 MD5 Hash Fingerprint Matching',
      icon: Lock,
      color: 'border-cyan-500/30 text-cyan-400 bg-cyan-950/20',
      desc: 'Matches TLS Client Hello metadata hashes against C2 implants (Cobalt Strike, TrickBot) without decrypting payload.'
    },
    {
      title: 'Reconnaissance & Port Scan',
      formula: 'NetworkX Fan-Out Degree ≥ 15 Ports / 20 Hosts',
      icon: Radar,
      color: 'border-emerald-500/30 text-emerald-400 bg-emerald-950/20',
      desc: 'Constructs directed interaction graphs to flag rapid horizontal fan-out or vertical scanning.'
    },
    {
      title: 'Data Exfiltration',
      formula: 'Asymmetry Ratio Rout/in > 10.0 & Volume > 5MB',
      icon: UploadCloud,
      color: 'border-rose-500/30 text-rose-400 bg-rose-950/20',
      desc: 'Detects extreme outbound-to-inbound byte ratios characteristic of sensitive data dumping.'
    }
  ];

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#1e293b]/60">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="p-1.5 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <Network className="w-5 h-5" />
            </span>
            <h2 className="text-xl font-bold text-slate-100 tracking-tight">
              Network Topology & Attack Simulation Lab
            </h2>
            <span className="px-2.5 py-0.5 text-xs font-mono font-medium rounded-full bg-blue-950/60 text-blue-400 border border-blue-800/40">
              Interactive Lab
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Visualize real-time communication nodes across the data diode barrier and inject simulated attack scenarios to test ML pipeline responsiveness.
          </p>
        </div>

        <button
          onClick={() => onNavigateToTab('monitor')}
          className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-blue-400 hover:text-blue-300 bg-blue-950/60 hover:bg-blue-900/60 border border-blue-800/60 rounded-lg transition-colors shadow-sm self-start sm:self-auto"
        >
          <Activity className="w-3.5 h-3.5" />
          <span>View Live Alerts ({alerts.length})</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Network Topology Graph */}
      <div className="space-y-2">
        <NetworkTopologyGraph alerts={alerts} />
      </div>

      {/* Attack Scenario Simulation Controls */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
            <h3 className="text-base font-semibold text-slate-100">
              Simulated Cyber Threat Injection Matrix
            </h3>
          </div>
          <span className="text-xs text-slate-400">
            Click any threat vector below to inject synthetic flows into the diode ingest pipeline.
          </span>
        </div>

        <SimulationControl onSimulate={onSimulate} />
      </div>

      {/* Mathematical Detection Reference Cards */}
      <div className="bg-[#0f172a] border border-[#1e293b] rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-[#1e293b] pb-3">
          <div>
            <h4 className="text-sm font-semibold text-slate-100">
              Diode Detection Engine • Mathematical Detection Methodology
            </h4>
            <p className="text-xs text-slate-400 mt-0.5">
              How the 6 specialized algorithmic modules detect malicious activity without payload decryption
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {threatClassGuide.map((item, idx) => {
            const Icon = item.icon;
            return (
              <div
                key={idx}
                className="p-3.5 rounded-lg bg-[#090d16] border border-[#1e293b] hover:border-slate-700 transition-colors space-y-2"
              >
                <div className="flex items-center gap-2">
                  <div className={`p-1.5 rounded border ${item.color}`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <span className="text-xs font-semibold text-slate-200">
                    {item.title}
                  </span>
                </div>
                <div className="text-[11px] font-mono text-blue-400 bg-slate-900/80 px-2 py-1 rounded border border-[#1e293b]">
                  {item.formula}
                </div>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {item.desc}
                </p>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
