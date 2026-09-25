import React, { useState } from 'react';
import { Flame, Radio, Globe, Lock, Radar, UploadCloud, Loader2 } from 'lucide-react';

export default function SimulationControl({ onSimulate }) {
  const [loadingType, setLoadingType] = useState(null);

  const threatScenarios = [
    { id: 'ddos', name: 'DDoS Flood', icon: Flame, iconColor: '#DF301C' },
    { id: 'c2_beacon', name: 'C2 Beacon', icon: Radio, iconColor: '#FF9100' },
    { id: 'dga_dns', name: 'DNS Tunnel', icon: Globe, iconColor: '#00B7CD' },
    { id: 'encrypted_malware', name: 'TLS Malware', icon: Lock, iconColor: '#DF301C' },
    { id: 'port_scan', name: 'Port Scan', icon: Radar, iconColor: '#FF9100' },
    { id: 'data_exfiltration', name: 'Exfiltration', icon: UploadCloud, iconColor: '#DF301C' }
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
    <div className="bg-[#FFF1D1] border border-black rounded-lg p-3 flex flex-wrap items-center justify-between gap-2.5">
      <div className="flex items-center gap-2">
        <span className="text-xs font-bold text-black">
          Simulate Attack:
        </span>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {threatScenarios.map((sc) => {
          const IconComp = sc.icon;
          const isLoading = loadingType === sc.id;
          return (
            <button
              key={sc.id}
              onClick={() => handleTrigger(sc.id)}
              disabled={isLoading}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-[#FFF1D1] border border-black rounded text-xs font-normal text-black transition-colors disabled:opacity-50"
              title={`Simulate ${sc.name}`}
            >
              {isLoading ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin text-[#00B7CD]" />
              ) : (
                <IconComp className="w-3.5 h-3.5" style={{ color: sc.iconColor }} />
              )}
              <span>{sc.name}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
