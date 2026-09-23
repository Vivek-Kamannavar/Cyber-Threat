import React, { useState, useEffect, useRef } from 'react';
import Header from './components/Header';
import SummaryCards from './components/SummaryCards';
import ManualInspectionPanel from './components/ManualInspectionPanel';
import ThroughputChart from './components/ThroughputChart';
import SimulationControl from './components/SimulationControl';
import AlertFeed from './components/AlertFeed';
import ThreatDetailsModal from './components/ThreatDetailsModal';
import NetworkTopologyGraph from './components/NetworkTopologyGraph';
import FileUploadModal from './components/FileUploadModal';
import AiCopilotDrawer from './components/AiCopilotDrawer';
import { HelpCircle, X, ShieldCheck, ArrowRight, Activity, Bell } from 'lucide-react';

export default function App() {
  const [isConnected, setIsConnected] = useState(false);
  const [telemetry, setTelemetry] = useState({ pps: 0, bps: 0 });
  const [historyData, setHistoryData] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [activeCopilotAlert, setActiveCopilotAlert] = useState(null);
  const [isAiDrawerOpen, setIsAiDrawerOpen] = useState(false);
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);
  const [isExecutiveView, setIsExecutiveView] = useState(false);
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

      ws.onerror = (err) => {
        console.error("WebSocket error:", err);
        ws.close();
      };
    };

    connectWebSocket();

    return () => {
      if (ws) ws.close();
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
    };
  }, []);

  const handleSimulate = async (threatType) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/simulate/${threatType}`, {
        method: 'POST'
      });
      if (!res.ok) {
        console.error(`Simulation failed for ${threatType}`);
      }
    } catch (e) {
      console.error("Failed to run simulation:", e);
    }
  };

  const handleToggleAutoDetection = async () => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/detection/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !autoDetectionEnabled })
      });
      if (res.ok) {
        const data = await res.json();
        setAutoDetectionEnabled(data.auto_detection_enabled);
      }
    } catch (e) {
      console.error("Failed to toggle auto-detection:", e);
    }
  };

  const handleClearAlerts = async () => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/alerts/clear`, {
        method: 'POST'
      });
      if (res.ok) {
        setAlerts([]);
        prevAlertsRef.current = 0;
        setHistoryData((prev) => prev.map(item => ({ ...item, threatSpike: 0, alerts: 0 })));
      }
    } catch (e) {
      console.error("Failed to clear alerts:", e);
    }
  };

  const handleOpenCopilot = (alert) => {
    setActiveCopilotAlert(alert);
    setIsAiDrawerOpen(true);
  };

  const highestConfidence = alerts.length > 0
    ? Math.max(...alerts.map(a => a.confidence_score || 0))
    : 0;

  const hasCriticalThreat = alerts.some(a => (a.confidence_score || 0) >= 0.90);

  return (
    <div className="min-h-screen flex flex-col bg-[#0b1120] text-slate-100">
      <Header
        isConnected={isConnected}
        totalAlerts={alerts.length}
        hasCriticalThreat={hasCriticalThreat}
        autoDetectionEnabled={autoDetectionEnabled}
        onToggleAutoDetection={handleToggleAutoDetection}
        onClearAlerts={handleClearAlerts}
        onToggleGuide={() => setShowGuideModal(true)}
        onOpenUpload={() => setIsUploadModalOpen(true)}
        isExecutiveView={isExecutiveView}
        onToggleViewMode={() => setIsExecutiveView(!isExecutiveView)}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 space-y-6">
        <SummaryCards
          telemetry={telemetry}
          totalAlerts={alerts.length}
          highestConfidence={highestConfidence}
          autoDetectionEnabled={autoDetectionEnabled}
        />

        {/* Manual Target IP & Website Threat Scanner (hidden in executive view) */}
        {!isExecutiveView && (
          <ManualInspectionPanel
            onInspectionComplete={(newAlerts) => {
              setAlerts((prev) => [...prev, ...newAlerts]);
            }}
          />
        )}

        <SimulationControl onSimulate={handleSimulate} />

        {!isExecutiveView && (
          <ThroughputChart historyData={historyData} />
        )}

        <NetworkTopologyGraph alerts={alerts} />

        <AlertFeed
          alerts={alerts}
          onSelectAlert={(alert) => setSelectedAlert(alert)}
          onOpenAiCopilot={handleOpenCopilot}
        />
      </main>

      {/* Threat Evidence Deep Dive Modal */}
      {selectedAlert && (
        <ThreatDetailsModal alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
      )}

      {/* PCAP / Zeek File Upload Modal */}
      <FileUploadModal
        isOpen={isUploadModalOpen}
        onClose={() => setIsUploadModalOpen(false)}
        onUploadComplete={() => {}}
      />

      {/* Groq AI Incident Copilot Drawer */}
      <AiCopilotDrawer
        isOpen={isAiDrawerOpen}
        onClose={() => setIsAiDrawerOpen(false)}
        alert={activeCopilotAlert}
      />

      {/* How It Works Guide Modal */}
      {showGuideModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-[#151f32] border border-[#23324d] rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative space-y-4">
            <div className="flex items-center justify-between border-b border-[#23324d] pb-3">
              <div className="flex items-center gap-2">
                <HelpCircle className="w-5 h-5 text-sky-400" />
                <h3 className="text-base font-semibold text-white">How This Cyber Threat System Works</h3>
              </div>
              <button
                onClick={() => setShowGuideModal(false)}
                className="p-1 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs text-slate-300 leading-relaxed">
              <div className="bg-[#0b1120] p-3 rounded-lg border border-[#23324d]">
                <div className="font-semibold text-sky-300 mb-1">1. What is a "Data Diode"?</div>
                <p>
                  A data diode is a physical optical fiber connection that strictly transmits light in one direction. It allows critical infrastructure (power plants, water systems, defense networks) to send telemetry out without any physical possibility of external attackers transmitting exploit payloads inward.
                </p>
              </div>

              <div className="bg-[#0b1120] p-3 rounded-lg border border-[#23324d]">
                <div className="font-semibold text-amber-300 mb-1">2. How does the AI detect attacks without decrypting payloads?</div>
                <p>
                  Traditional tools break TLS encryption. Across a one-way diode, decryption is impossible. Our system extracts mathematical physics from packet headers: Shannon entropy on byte distributions, Inter-Arrival Time variance (botnet beaconing), and TLS JA3/JA4 cryptographic fingerprints.
                </p>
              </div>

              <div className="bg-[#0b1120] p-3 rounded-lg border border-[#23324d]">
                <div className="font-semibold text-rose-300 mb-1">3. What does the AI Copilot do?</div>
                <p>
                  Powered by Groq's high-speed inference (Llama 3.3 70B), the copilot provides human-readable incident summaries, facility risk impact analyses, immediate step-by-step mitigation checklists, and copyable firewall rules for rapid containment.
                </p>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setShowGuideModal(false)}
                className="px-4 py-2 bg-sky-500 hover:bg-sky-400 text-slate-950 font-semibold rounded-lg text-xs"
              >
                Understood
              </button>
            </div>
          </div>
        </div>
      )}

      <footer className="border-t border-[#23324d] py-4 text-center text-xs font-mono text-slate-500 bg-[#0b1120]">
        AI-Based Cyber Threat Detection Engine • Safe Unidirectional Data Diode Architecture
      </footer>
    </div>
  );
}
