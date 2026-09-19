import React, { useState } from 'react';
import { Play, Flame, Radio, Globe, Lock, Radar, UploadCloud } from 'lucide-react';

export default function SimulationControl({ onSimulate }) {
  const [loadingType, setLoadingType] = useState(null);

  const threatScenarios = [
    {
      id: 'ddos',
      name: 'Traffic Overload (DDoS)',
      icon: Flame,
      color: 'hover:border-red-500 hover:text-red-400 text-red-500',
      description: 'Spams millions of fake requests to overwhelm and crash servers'
    },
    {
      id: 'c2_beacon',
      name: 'Zombie Spyware (C2)',
      icon: Radio,
      color: 'hover:border-amber-500 hover:text-amber-400 text-amber-500',
      description: 'Infected device secretly checking in with a hacker every few seconds'
    },
    {
      id: 'dga_dns',
      name: 'Hidden Messages (DNS)',
      icon: Globe,
      color: 'hover:border-purple-500 hover:text-purple-400 text-purple-500',
      description: 'Smuggling stolen data disguised inside harmless website lookups'
    },
    {
      id: 'encrypted_malware',
      name: 'Trojan in Disguise',
      icon: Lock,
      color: 'hover:border-cyan-500 hover:text-cyan-400 text-cyan-500',
      description: 'Known hacker tools (Cobalt Strike) trying to hide inside HTTPS'
    },
    {
      id: 'port_scan',
      name: 'Door Jiggling (Port Scan)',
      icon: Radar,
      color: 'hover:border-emerald-500 hover:text-emerald-400 text-emerald-500',
      description: 'Hacker knocking on 35+ network ports looking for unlocked doors'
    },
    {
      id: 'data_exfiltration',
      name: 'Data Theft (Exfiltration)',
      icon: UploadCloud,
      color: 'hover:border-rose-500 hover:text-rose-400 text-rose-500',
      description: 'A compromised device quietly uploading huge files to an external server'
    }
  ];

  const handleTrigger = async (scenarioId) => {
    setLoadingType(scenarioId);
    try {
      await onSimulate(scenarioId);
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingType(null);
    }
  };

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 mb-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2">
          <Play className="w-5 h-5 text-cyan-400" />
          <h2 className="text-sm font-bold text-white tracking-wide uppercase">
            🧪 Attack Simulator (Test the AI in Real-Time)
          </h2>
        </div>
        <span className="text-xs text-slate-400">
          Click any button below to see the AI detect it live ⬇️
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        {threatScenarios.map((sc) => {
          const IconComp = sc.icon;
          const isLoading = loadingType === sc.id;
          return (
            <button
              key={sc.id}
              onClick={() => handleTrigger(sc.id)}
              disabled={isLoading}
              className={`flex items-start gap-3 p-3 bg-slate-900/60 border border-slate-800 rounded-lg text-left transition-all duration-200 ${sc.color} hover:bg-slate-800/80 group disabled:opacity-50`}
            >
              <div className="p-2 bg-slate-800 rounded-md group-hover:scale-110 transition-transform">
                <IconComp className="w-5 h-5" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-xs font-bold text-slate-200 group-hover:text-white flex items-center justify-between">
                  {sc.name}
                  {isLoading && <span className="animate-spin text-cyan-400 text-xs">🌀</span>}
                </div>
                <div className="text-[11px] text-slate-400 mt-0.5 leading-relaxed">{sc.description}</div>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
