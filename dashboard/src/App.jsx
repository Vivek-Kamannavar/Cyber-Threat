import React, { useState, useEffect, useRef } from 'react';
import Header from './components/Header';
import ThreatDetailsModal from './components/ThreatDetailsModal';
import FileUploadModal from './components/FileUploadModal';
import AiCopilotDrawer from './components/AiCopilotDrawer';
import BackendSettingsModal from './components/BackendSettingsModal';
import AiChatbotPanel from './components/AiChatbotPanel';
import LiveMonitorPage from './pages/LiveMonitorPage';
import IngestionHubPage from './pages/IngestionHubPage';
import TopologyLabPage from './pages/TopologyLabPage';
import ForensicScannerPage from './pages/ForensicScannerPage';
import ToastContainer from './components/ToastContainer';
import { 
  initializeSocketStream, 
  simulateThreat, 
  toggleAutoDetection, 
  clearAlerts, 
  setStreamSource,
  eventBus 
} from './services/apiService';
import { HelpCircle, X } from 'lucide-react';

export default function App() {
  const [isConnected, setIsConnected] = useState(false);
  const [connectionMode, setConnectionMode] = useState('LIVE_BACKEND'); // 'LIVE_BACKEND' | 'CLOUD_SIMULATION'
  const [isBackendSettingsOpen, setIsBackendSettingsOpen] = useState(false);
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
  const [toasts, setToasts] = useState([]);

  const addToast = (toast) => {
    const id = `toast-${Date.now()}`;
    const newToast = {
      id,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      ...toast
    };
    // Keep strictly 1 toast at a time so screen is never cluttered
    setToasts([newToast]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  };

  const handleDismissToast = (id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const getInitialRemainingSeconds = () => {
    try {
      const stored = localStorage.getItem('threat_intel_next_sync_target');
      const target = stored ? parseInt(stored, 10) : 0;
      const now = Date.now();
      if (target > now && target - now <= 300000) {
        return Math.max(1, Math.floor((target - now) / 1000));
      }
      const newTarget = now + 300000;
      localStorage.setItem('threat_intel_next_sync_target', newTarget.toString());
      return 300;
    } catch {
      return 300;
    }
  };

  const [secondsUntilSync, setSecondsUntilSync] = useState(getInitialRemainingSeconds);

  // 5-minute persistent real-time countdown (persists across page reloads)
  useEffect(() => {
    const updateCountdown = () => {
      try {
        let stored = localStorage.getItem('threat_intel_next_sync_target');
        let target = stored ? parseInt(stored, 10) : 0;
        const now = Date.now();
        if (!target || target <= now || target - now > 305000) {
          target = now + 300000;
          localStorage.setItem('threat_intel_next_sync_target', target.toString());
        }
        const remaining = Math.max(0, Math.floor((target - now) / 1000));
        setSecondsUntilSync(remaining === 0 ? 300 : remaining);
      } catch {
        setSecondsUntilSync((prev) => (prev <= 1 ? 300 : prev - 1));
      }
    };

    updateCountdown();
    const timer = setInterval(updateCountdown, 1000);
    return () => clearInterval(timer);
  }, []);

  const handleResetSyncTimer = (targetMs) => {
    const newTarget = targetMs || (Date.now() + 300000);
    localStorage.setItem('threat_intel_next_sync_target', newTarget.toString());
    const remaining = Math.max(1, Math.floor((newTarget - Date.now()) / 1000));
    setSecondsUntilSync(remaining);
  };

  // Hash-based routing for 3 distinct pages
  const getInitialTab = () => {
    const hash = window.location.hash.replace('#', '').toLowerCase();
    if (['monitor', 'chat', 'ingest', 'topology', 'forensics'].includes(hash)) {
      return hash;
    }
    return 'monitor';
  };

  const [activeTab, setActiveTab] = useState(getInitialTab);

  // Sync hash changes with browser navigation
  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace('#', '').toLowerCase();
      if (['monitor', 'chat', 'ingest', 'topology', 'forensics'].includes(hash)) {
        setActiveTab(hash);
      }
    };
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  const handleSelectTab = (tabId) => {
    setActiveTab(tabId);
    window.location.hash = tabId;
  };

  const prevAlertsRef = useRef(0);

  useEffect(() => {
    // Listen for global alert events (from file upload / simulation / scanner)
    const unsubAlert = eventBus.on('alert', (newAlert) => {
      setAlerts((prev) => [newAlert, ...prev].slice(0, 50));
    });

    const unsubFeed = eventBus.on('feed_update', (data) => {
      handleResetSyncTimer(data?.target_sync_timestamp_ms);
      addToast({
        type: 'feed',
        title: 'Threat Intel Synchronized',
        message: `+${data?.fresh_count || 0} fresh indicators indexed (${data?.total_indicators || 117} total).`
      });
    });

    const cleanup = initializeSocketStream({
      onStatusChange: (connected, mode) => {
        setIsConnected(connected);
        if (mode) setConnectionMode(mode);
      },
      onMessage: (msg) => {
        try {
          if (msg.type === 'snapshot') {
            if (msg.recent_alerts) {
              setAlerts(msg.recent_alerts.slice(0, 50));
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
            addToast({
              type: 'success',
              title: 'Incident Queue Cleared',
              message: 'All historical alerts in the active window have been reset.'
            });
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
            setAlerts((prev) => [msg.data, ...prev].slice(0, 50));
            eventBus.emit('audit_log', {
              id: msg.data.alert_id,
              timestamp: msg.data.timestamp || new Date().toISOString(),
              type: 'threat',
              title: `Threat Alert: ${msg.data.threat_class}`,
              detail: `${msg.data.flow_identifier?.src_ip} ➔ ${msg.data.flow_identifier?.dst_ip} (${Math.round((msg.data.confidence_score || 0.95) * 100)}% conf)`
            });
          } else if (msg.type === 'feed_update') {
            eventBus.emit('feed_update', msg.data);
            eventBus.emit('audit_log', {
              id: `SYNC-${Date.now()}`,
              timestamp: new Date().toISOString(),
              type: 'feed',
              title: 'Threat Intel 5-Min Auto-Sync',
              detail: `+${msg.data?.fresh_count || 0} fresh indicators extracted (${msg.data?.total_indicators || 0} cached)`
            });
          }
        } catch (e) {
          console.error("Error handling stream message:", e);
        }
      }
    });

    return () => {
      cleanup();
      unsubAlert();
    };
  }, []);

  const handleSimulate = async (threatType) => {
    try {
      addToast({
        type: 'threat',
        title: 'Scenario Injected',
        message: `Simulating controlled ${threatType.replace('_', ' ')} vector across diode.`
      });
      await simulateThreat(threatType, (newAlert) => {
        setAlerts((prev) => [newAlert, ...prev].slice(0, 50));
      });
    } catch (e) {
      console.error("Failed to run simulation:", e);
    }
  };

  const handleToggleAutoDetection = async () => {
    try {
      const data = await toggleAutoDetection();
      if (data && data.auto_detection_enabled !== undefined) {
        setAutoDetectionEnabled(data.auto_detection_enabled);
        addToast({
          type: data.auto_detection_enabled ? 'success' : 'warn',
          title: data.auto_detection_enabled ? 'Detection Active' : 'Detection Paused',
          message: data.auto_detection_enabled
            ? 'Threat detection engine is actively analyzing incoming flows.'
            : 'Threat detection engine paused. Traffic recorded for throughput only.'
        });
      }
    } catch (e) {
      console.error("Failed to toggle auto-detection:", e);
    }
  };

  const handleClearAlerts = async () => {
    try {
      await clearAlerts();
      setAlerts([]);
      prevAlertsRef.current = 0;
      setHistoryData((prev) => prev.map(item => ({ ...item, threatSpike: 0, alerts: 0 })));
    } catch (e) {
      console.error("Failed to clear alerts:", e);
    }
  };

  const handleSelectStreamSource = (mode) => {
    if (mode === connectionMode) return;
    setStreamSource(mode);
    window.location.reload();
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
    <div className="min-h-screen flex flex-col bg-[#090d16] text-slate-100 relative">
      {/* Real-time Human-Readable Toast Alerts */}
      <ToastContainer toasts={toasts} onDismiss={handleDismissToast} />

      <Header
        isConnected={isConnected}
        connectionMode={connectionMode}
        onOpenBackendSettings={() => setIsBackendSettingsOpen(true)}
        totalAlerts={alerts.length}
        hasCriticalThreat={hasCriticalThreat}
        autoDetectionEnabled={autoDetectionEnabled}
        onToggleAutoDetection={handleToggleAutoDetection}
        onClearAlerts={handleClearAlerts}
        onToggleGuide={() => setShowGuideModal(true)}
        onSelectStreamSource={handleSelectStreamSource}
        isExecutiveView={isExecutiveView}
        onToggleViewMode={() => setIsExecutiveView(!isExecutiveView)}
        currentTab={activeTab}
        onSelectTab={handleSelectTab}
        secondsUntilSync={secondsUntilSync}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6">
        {/* Page 1: Live Threat Monitor & Telemetry */}
        {activeTab === 'monitor' && (
          <LiveMonitorPage
            telemetry={telemetry}
            alerts={alerts}
            historyData={historyData}
            highestConfidence={highestConfidence}
            autoDetectionEnabled={autoDetectionEnabled}
            isExecutiveView={isExecutiveView}
            onSelectAlert={(alert) => setSelectedAlert(alert)}
            onOpenAiCopilot={handleOpenCopilot}
            onNavigateToTab={handleSelectTab}
            secondsUntilSync={secondsUntilSync}
          />
        )}

        {/* Page 2: Conversational AI Security Analyst */}
        {activeTab === 'chat' && (
          <AiChatbotPanel
            telemetry={telemetry}
            alerts={alerts}
            autoDetectionEnabled={autoDetectionEnabled}
            onOpenAlert={(alert) => setSelectedAlert(alert)}
          />
        )}

        {/* Page 3: Data Ingestion Hub (internet feed, capture replay, scenarios) */}
        {activeTab === 'ingest' && (
          <IngestionHubPage
            onOpenUpload={() => setIsUploadModalOpen(true)}
            onSimulate={handleSimulate}
            onNavigateToTab={handleSelectTab}
            secondsUntilSync={secondsUntilSync}
            onResetSyncTimer={handleResetSyncTimer}
          />
        )}

        {/* Page 4: Network Topology & Simulation Lab */}
        {activeTab === 'topology' && (
          <TopologyLabPage
            alerts={alerts}
            onSimulate={handleSimulate}
            onNavigateToTab={handleSelectTab}
          />
        )}

        {/* Page 3: Deep Forensic Scanner & PCAP Ingestion */}
        {activeTab === 'forensics' && (
          <ForensicScannerPage
            onInspectionComplete={(newAlerts) => {
              setAlerts((prev) => [...prev, ...newAlerts]);
            }}
            onOpenUpload={() => setIsUploadModalOpen(true)}
            onNavigateToTab={handleSelectTab}
          />
        )}
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

      {/* Backend Settings Gateway Modal */}
      <BackendSettingsModal
        isOpen={isBackendSettingsOpen}
        onClose={() => setIsBackendSettingsOpen(false)}
        connectionMode={connectionMode}
      />

      {/* How It Works Guide Modal */}
      {showGuideModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-[#0f172a] border border-[#1e293b] rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative space-y-4">
            <div className="flex items-center justify-between border-b border-[#1e293b] pb-3">
              <div className="flex items-center gap-2">
                <HelpCircle className="w-5 h-5 text-blue-400" />
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
              <div className="bg-[#090d16] p-3 rounded-lg border border-[#1e293b]">
                <div className="font-semibold text-blue-300 mb-1">1. What is a "Data Diode"?</div>
                <p>
                  A data diode is a physical optical fiber connection that strictly transmits light in one direction. It allows critical infrastructure (power plants, water systems, defense networks) to send telemetry out without any physical possibility of external attackers transmitting exploit payloads inward.
                </p>
              </div>

              <div className="bg-[#090d16] p-3 rounded-lg border border-[#1e293b]">
                <div className="font-semibold text-amber-300 mb-1">2. How does the AI detect attacks without decrypting payloads?</div>
                <p>
                  Traditional tools break TLS encryption. Across a one-way diode, decryption is impossible. Our system extracts mathematical physics from packet headers: Shannon entropy on byte distributions, Inter-Arrival Time variance (botnet beaconing), and TLS JA3/JA4 cryptographic fingerprints.
                </p>
              </div>

              <div className="bg-[#090d16] p-3 rounded-lg border border-[#1e293b]">
                <div className="font-semibold text-rose-300 mb-1">3. What does the AI Copilot do?</div>
                <p>
                  Powered by Groq's high-speed inference (Llama 3.3 70B), the copilot provides human-readable incident summaries, facility risk impact analyses, immediate step-by-step mitigation checklists, and copyable firewall rules for rapid containment.
                </p>
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setShowGuideModal(false)}
                className="px-4 py-2 bg-blue-500 hover:bg-blue-400 text-slate-950 font-semibold rounded-lg text-xs"
              >
                Understood
              </button>
            </div>
          </div>
        </div>
      )}

      <footer className="border-t border-[#1e293b] py-4 text-center text-xs font-mono text-slate-500 bg-[#090d16]">
        AI-Based Cyber Threat Detection Engine • Safe Unidirectional Data Diode Architecture
      </footer>
    </div>
  );
}
