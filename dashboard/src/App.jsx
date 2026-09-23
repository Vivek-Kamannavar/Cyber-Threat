import React, { useState, useEffect, useRef } from 'react';
import Header from './components/Header';
import SummaryCards from './components/SummaryCards';
import ThroughputChart from './components/ThroughputChart';
import SimulationControl from './components/SimulationControl';
import AlertFeed from './components/AlertFeed';
import ThreatDetailsModal from './components/ThreatDetailsModal';
import NetworkTopologyGraph from './components/NetworkTopologyGraph';
import FileUploadModal from './components/FileUploadModal';
import AiCopilotDrawer from './components/AiCopilotDrawer';

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
  const wsRef = useRef(null);
  const prevAlertsRef = useRef(0);

  useEffect(() => {
    let ws = null;

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
              return updated.slice(-25);
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
        setTimeout(connectWebSocket, 2000);
      };

      ws.onerror = () => {
        setIsConnected(false);
      };
    };

    connectWebSocket();

    return () => {
      if (ws) ws.close();
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
    <div className="min-h-screen flex flex-col bg-[#FFF1D1] text-black">
      <Header
        isConnected={isConnected}
        totalAlerts={alerts.length}
        hasCriticalThreat={hasCriticalThreat}
        autoDetectionEnabled={autoDetectionEnabled}
        onToggleAutoDetection={handleToggleAutoDetection}
        onClearAlerts={handleClearAlerts}
        onOpenUpload={() => setIsUploadModalOpen(true)}
        isExecutiveView={isExecutiveView}
        onToggleViewMode={() => setIsExecutiveView(!isExecutiveView)}
      />

      <main className="flex-1 max-w-[1440px] w-full mx-auto p-3 space-y-2.5">
        {/* Top KPI Ribbon */}
        <SummaryCards
          telemetry={telemetry}
          totalAlerts={alerts.length}
          highestConfidence={highestConfidence}
          autoDetectionEnabled={autoDetectionEnabled}
        />

        {/* Compact Simulation Toolbar */}
        <SimulationControl onSimulate={handleSimulate} />

        {/* Dense 2-Column Split Workspace */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-2.5 items-start">
          {/* Left Column (7 cols): Topology & Throughput */}
          <div className="lg:col-span-7 space-y-2.5">
            <NetworkTopologyGraph alerts={alerts} />
            <ThroughputChart historyData={historyData} />
          </div>

          {/* Right Column (5 cols): Live Incident Stream Workbench */}
          <div className="lg:col-span-5">
            <AlertFeed
              alerts={alerts}
              onSelectAlert={(alert) => setSelectedAlert(alert)}
              onOpenAiCopilot={handleOpenCopilot}
            />
          </div>
        </div>
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

      <footer className="border-t border-black py-3 text-center text-xs font-normal text-black bg-[#FFF1D1]">
        CYBER THREAT DETECTION ENGINE • PASSIVE OPTICAL DIODE TELEMETRY
      </footer>
    </div>
  );
}
