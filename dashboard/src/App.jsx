import React, { useState, useEffect, useRef } from 'react';
import Header from './components/Header';
import SummaryCards from './components/SummaryCards';
import ManualInspectionPanel from './components/ManualInspectionPanel';
import ThroughputChart from './components/ThroughputChart';
import SimulationControl from './components/SimulationControl';
import AlertFeed from './components/AlertFeed';
import ThreatDetailsModal from './components/ThreatDetailsModal';
import NetworkTopologyGraph from './components/NetworkTopologyGraph';
import { HelpCircle, X, ShieldCheck, ArrowRight, Activity, Bell } from 'lucide-react';

export default function App() {
  const [isConnected, setIsConnected] = useState(false);
  const [telemetry, setTelemetry] = useState({ pps: 0, bps: 0 });
  const [historyData, setHistoryData] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [autoDetectionEnabled, setAutoDetectionEnabled] = useState(true);
  const [showGuideModal, setShowGuideModal] = useState(false);
  const [showBanner, setShowBanner] = useState(true);
  const wsRef = useRef(null);
  const prevAlertsRef = useRef(0);

  useEffect(() => {
    let ws = null;
    let reconnectTimeout = null;

    const connectWebSocket = () => {
      const wsUrl = `ws://${window.location.hostname}:8000/ws/alerts`;
      ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          
          if (msg.type === 'snapshot') {
            if (msg.recent_alerts) {
              setAlerts(msg.recent_alerts);
              prevAlertsRef.current = msg.total_alerts || msg.recent_alerts.length;
            }
            if (msg.auto_detection_enabled !== undefined) {
              setAutoDetectionEnabled(msg.auto_detection_enabled);
            }
          } else if (msg.type === 'config') {
            if (msg.auto_detection_enabled !== undefined) {
              setAutoDetectionEnabled(msg.auto_detection_enabled);
            }
          } else if (msg.type === 'alerts_cleared') {
            setAlerts([]);
            prevAlertsRef.current = 0;
            setHistoryData((prev) => prev.map(item => ({ ...item, threatSpike: 0, alerts: 0 })));
          } else if (msg.type === 'telemetry') {
            setTelemetry(msg.data || { pps: 0, bps: 0 });
            if (msg.auto_detection_enabled !== undefined) {
              setAutoDetectionEnabled(msg.auto_detection_enabled);
            }
            
            const nowStr = new Date(msg.timestamp * 1000).toLocaleTimeString([], {
              hour12: false,
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit'
            });

            const currentTotal = msg.total_alerts || 0;
            const threatSpike = prevAlertsRef.current > 0 ? Math.max(0, currentTotal - prevAlertsRef.current) : 0;
            prevAlertsRef.current = currentTotal;

            setHistoryData((prev) => {
              const updated = [
                ...prev,
                {
                  timeStr: nowStr,
                  pps: msg.data?.pps || 0,
                  bps: Math.round((msg.data?.bps || 0) / 1000),
                  threatSpike: threatSpike,
                  alerts: currentTotal
                }
              ];
              return updated.slice(-25); // Keep last 25 time ticks
            });

          } else if (msg.type === 'alert') {
            setAlerts((prev) => [...prev, msg.data]);
          }
        } catch (e) {
          console.error("Error parsing WebSocket message:", e);
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        reconnectTimeout = setTimeout(connectWebSocket, 3000);
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    connectWebSocket();

    return () => {
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, []);

  const handleToggleAutoDetection = async () => {
    const nextState = !autoDetectionEnabled;
    setAutoDetectionEnabled(nextState);
    try {
      await fetch(`http://${window.location.hostname}:8000/api/detection/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: nextState })
      });
    } catch (e) {
      console.error("Failed to toggle auto detection:", e);
    }
  };

  const handleClearAlerts = async () => {
    setAlerts([]);
    prevAlertsRef.current = 0;
    try {
      await fetch(`http://${window.location.hostname}:8000/api/alerts/clear`, {
        method: 'POST'
      });
    } catch (e) {
      console.error("Failed to clear alerts:", e);
    }
  };

  const handleSimulate = async (threatType) => {
    try {
      const res = await fetch(`http://${window.location.hostname}:8000/api/simulate/${threatType}`, {
        method: 'POST'
      });
      const data = await res.json();
      if (data.alerts && data.alerts.length > 0) {
        setAlerts((prev) => [...prev, ...data.alerts]);
      }
    } catch (e) {
      console.error("Simulation error:", e);
    }
  };

  const highestConfidence = alerts.length > 0
    ? Math.max(...alerts.map(a => a.confidence_score || 0))
    : 0;

  return (
    <div className="min-h-screen bg-transparent text-slate-100 flex flex-col font-sans relative">
      <Header
        isConnected={isConnected}
        totalAlerts={alerts.length}
        diodeActive={true}
        onToggleGuide={() => setShowGuideModal(true)}
        autoDetectionEnabled={autoDetectionEnabled}
        onToggleAutoDetection={handleToggleAutoDetection}
        onClearAlerts={handleClearAlerts}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 space-y-6">
        {/* Simple Plain-English Welcome Banner */}
        {showBanner && (
          <div className="bg-gradient-to-r from-cyan-950/70 via-slate-900 to-indigo-950/70 border border-cyan-500/30 rounded-xl p-4 relative shadow-lg">
            <button
              onClick={() => setShowBanner(false)}
              className="absolute top-3 right-3 text-slate-400 hover:text-white"
              title="Dismiss"
            >
              <X className="w-4 h-4" />
            </button>
            <div className="flex items-start gap-3">
              <div className="p-2 bg-cyan-500/20 border border-cyan-500/40 rounded-lg text-cyan-400 mt-0.5">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <div className="space-y-1 pr-6">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  What is this system doing?
                  <span className="text-[11px] font-normal px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300">
                    Simple Explanation
                  </span>
                </h3>
                <p className="text-xs text-slate-300 leading-relaxed">
                  Think of this system like a <strong>one-way digital security gate</strong> protecting a nuclear plant, power grid, or bank. 
                  Data enters through a one-way mirror. Our AI inspects every single packet <strong>without opening private contents</strong> and spots hidden attacks (like malware, spies, or data theft) in under 12 milliseconds!
                </p>
                <div className="flex flex-wrap gap-4 pt-2 text-xs text-slate-400 font-medium">
                  <span className="flex items-center gap-1 text-cyan-300">
                    <Activity className="w-3.5 h-3.5" /> 1. Click an attack button below to simulate a threat
                  </span>
                  <span className="flex items-center gap-1 text-amber-300">
                    <ArrowRight className="w-3.5 h-3.5" /> 2. Watch the AI detect the pattern live
                  </span>
                  <span className="flex items-center gap-1 text-rose-300">
                    <Bell className="w-3.5 h-3.5" /> 3. Click any alert below to see what happened
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        <SummaryCards
          telemetry={telemetry}
          totalAlerts={alerts.length}
          highestConfidence={highestConfidence}
          autoDetectionEnabled={autoDetectionEnabled}
        />

        {/* Manual Target IP & Website Threat Scanner */}
        <ManualInspectionPanel
          onInspectionComplete={(newAlerts) => {
            setAlerts((prev) => [...prev, ...newAlerts]);
          }}
        />

        <SimulationControl onSimulate={handleSimulate} />

        <ThroughputChart historyData={historyData} />

        <NetworkTopologyGraph alerts={alerts} />

        <AlertFeed alerts={alerts} onSelectAlert={(alert) => setSelectedAlert(alert)} />
      </main>

      {/* Threat Evidence Inspection Modal */}
      {selectedAlert && (
        <ThreatDetailsModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
      )}

      {/* Beginner-Friendly "How It Works" Modal */}
      {showGuideModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="bg-slate-900 border border-cyan-500/40 rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <HelpCircle className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">How This Cyber Threat System Works</h3>
              </div>
              <button
                onClick={() => setShowGuideModal(false)}
                className="p-1 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
              <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                <div className="font-semibold text-cyan-300 mb-1">1. What is a "Data Diode"?</div>
                <p>
                  A data diode is a physical fiber-optic cable that only sends light in one direction. It allows safe facilities (like power plants or hospitals) to receive data without any chance of hackers sending malicious replies or taking control back.
                </p>
              </div>

              <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                <div className="font-semibold text-amber-300 mb-1">2. How does the AI detect attacks without decrypting files?</div>
                <p>
                  Just like an airport luggage X-ray checks the shape, weight, and timing of packages without reading your private letters, our AI looks at packet timing, volume, and connection patterns to catch malware and data leaks instantly.
                </p>
              </div>

              <div className="bg-slate-950/60 p-3 rounded-lg border border-slate-800">
                <div className="font-semibold text-rose-300 mb-1">3. What do the 4 top cards tell you?</div>
                <ul className="list-disc list-inside space-y-1 pl-1 text-slate-400">
                  <li><strong className="text-slate-200">Traffic Speed:</strong> How much data is flowing through every second.</li>
                  <li><strong className="text-slate-200">Threat Alerts:</strong> How many suspicious or dangerous activities were stopped.</li>
                  <li><strong className="text-slate-200">Detection Accuracy:</strong> How certain the AI is that this is a real attack (up to 100%).</li>
                  <li><strong className="text-slate-200">Reaction Time:</strong> Time taken to analyze traffic (&lt; 12 milliseconds).</li>
                </ul>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setShowGuideModal(false)}
                className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded-lg text-xs"
              >
                Got It, Thanks!
              </button>
            </div>
          </div>
        </div>
      )}

      <footer className="border-t border-cyber-border py-4 text-center text-xs font-mono text-slate-500 bg-slate-950">
        AI-Based Cyber Threat Detection Engine • Safe One-Way Data Diode Architecture
      </footer>
    </div>
  );
}
