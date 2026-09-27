/**
 * Unified API & Autonomous Simulation Gateway for Cyber Threat SOC
 * Supports live FastAPI backend (via REST & WebSockets) and seamless
 * client-side simulation when deployed on static CDNs like Firebase Hosting.
 */

// Custom event emitter for live telemetry and alert feeds
class EventBus {
  constructor() {
    this.listeners = new Map();
  }
  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event).add(callback);
    return () => this.listeners.get(event).delete(callback);
  }
  emit(event, data) {
    if (this.listeners.has(event)) {
      this.listeners.get(event).forEach(cb => {
        try { cb(data); } catch (e) { console.error('Listener error:', e); }
      });
    }
  }
}

export const eventBus = new EventBus();

// Persistent backend config
const STORAGE_KEY = 'CYBER_THREAT_API_URL';
const isHosted = typeof window !== 'undefined' && 
  window.location.hostname !== 'localhost' && 
  window.location.hostname !== '127.0.0.1';

export const getStoredBackendUrl = () => {
  if (typeof window === 'undefined') return '';
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored !== null) return stored;
  return isHosted ? '' : `http://${window.location.hostname}:8000`;
};

export const setStoredBackendUrl = (url) => {
  if (typeof window === 'undefined') return;
  if (!url) {
    localStorage.removeItem(STORAGE_KEY);
  } else {
    localStorage.setItem(STORAGE_KEY, url.trim().replace(/\/$/, ''));
  }
};

// Initial alerts baseline for authentic demo
const INITIAL_DEMO_ALERTS = [
  {
    alert_id: "ALT-70778D62",
    timestamp: new Date(Date.now() - 45000).toISOString(),
    flow_identifier: {
      src_ip: "192.168.10.22",
      src_port: 49204,
      src_label: "Engineering Workstation #2",
      dst_ip: "185.220.101.5",
      dst_port: 8443,
      dst_label: "External C2 Node",
      protocol: "TCP"
    },
    threat_class: "Botnet C2 Beaconing",
    confidence_score: 0.98,
    supporting_evidence_feature: {
      inter_arrival_time_mean_seconds: 5.0,
      inter_arrival_time_std_dev: 0.12,
      coefficient_of_variation: 0.024,
      flow_count: 8,
      reason: "Host is secretly sending regular 'tap-tap-tap' check-in signals to a known hacker command center."
    }
  },
  {
    alert_id: "ALT-9CA25794",
    timestamp: new Date(Date.now() - 120000).toISOString(),
    flow_identifier: {
      src_ip: "192.168.10.18",
      src_port: 53005,
      src_label: "ICS Telemetry Gateway",
      dst_ip: "8.8.8.8",
      dst_port: 53,
      dst_label: "Public DNS Resolver",
      protocol: "UDP"
    },
    threat_class: "DGA Domains & DNS Tunnelling",
    confidence_score: 0.96,
    supporting_evidence_feature: {
      dns_query: "x7q9b2m8w1z4v5k8p2a0c4f1.exfil-tunnel.badactor.top",
      entropy: 3.94,
      ngram_rarity: 0.91,
      qtype: "TXT",
      reason: "Computer is asking for scrambled secret-code domain names used to sneak stolen secrets out without detection."
    }
  }
];

// In-memory simulation state
let simAlerts = [...INITIAL_DEMO_ALERTS];
let simTotalAlerts = simAlerts.length;
let simAutoDetection = true;
let simInterval = null;
let activeWs = null;
let isSimulating = false;

// Heuristic calculation helpers
export const calculateEntropy = (str) => {
  if (!str) return 0;
  const len = str.length;
  const freqs = {};
  for (const c of str) freqs[c] = (freqs[c] || 0) + 1;
  let entropy = 0;
  for (const c in freqs) {
    const p = freqs[c] / len;
    entropy -= p * Math.log2(p);
  }
  return parseFloat(entropy.toFixed(3));
};

// Generate realistic alert vectors
export const generateSyntheticAlert = (threatType) => {
  const alertId = `ALT-${Math.random().toString(16).substring(2, 10).toUpperCase()}`;
  const now = new Date().toISOString();

  switch (threatType) {
    case 'ddos':
      return {
        alert_id: alertId,
        timestamp: now,
        flow_identifier: {
          src_ip: "10.200.1.15",
          src_port: Math.floor(Math.random() * 50000) + 10000,
          src_label: "External Threat Subnet",
          dst_ip: "192.168.10.50",
          dst_port: 80,
          dst_label: "SCADA Core Controller",
          protocol: "TCP"
        },
        threat_class: "Volumetric / Protocol DDoS",
        confidence_score: 0.99,
        supporting_evidence_feature: {
          source_entropy: 0.72,
          packet_rate_pps: 14250,
          tcp_syn_ratio: 0.98,
          flows_in_window: 40,
          reason: "Massive wave of identical half-open TCP SYN connection requests trying to overwhelm the SCADA controller."
        }
      };

    case 'c2_beacon':
      return {
        alert_id: alertId,
        timestamp: now,
        flow_identifier: {
          src_ip: "192.168.10.22",
          src_port: Math.floor(Math.random() * 2000) + 49000,
          src_label: "Engineering Workstation #2",
          dst_ip: "185.220.101.5",
          dst_port: 8443,
          dst_label: "External C2 Node",
          protocol: "TCP"
        },
        threat_class: "Botnet C2 Beaconing",
        confidence_score: 0.98,
        supporting_evidence_feature: {
          inter_arrival_time_mean_seconds: 5.02,
          inter_arrival_time_std_dev: 0.08,
          coefficient_of_variation: 0.016,
          flow_count: 8,
          reason: "Periodic heartbeat detected with microsecond precision (CV: 0.016), matching Cobalt Strike command beaconing."
        }
      };

    case 'dga_dns':
      return {
        alert_id: alertId,
        timestamp: now,
        flow_identifier: {
          src_ip: "192.168.10.18",
          src_port: 53120,
          src_label: "ICS Telemetry Gateway",
          dst_ip: "8.8.8.8",
          dst_port: 53,
          dst_label: "Google Public DNS",
          protocol: "UDP"
        },
        threat_class: "DGA Domains & DNS Tunnelling",
        confidence_score: 0.96,
        supporting_evidence_feature: {
          dns_query: "w9k4z2m8a1b7c3e5d0f8.tunnel-drop.xyz",
          entropy: 4.12,
          ngram_rarity: 0.94,
          qtype: "TXT",
          reason: "High-entropy pseudo-random domain query (Entropy: 4.12) attempting covert DNS tunnelling over port 53."
        }
      };

    case 'encrypted_malware':
      return {
        alert_id: alertId,
        timestamp: now,
        flow_identifier: {
          src_ip: "192.168.10.30",
          src_port: 51234,
          src_label: "Turbine Sensor Gateway",
          dst_ip: "91.215.102.14",
          dst_port: 4444,
          dst_label: "Known Malicious Host",
          protocol: "TCP"
        },
        threat_class: "Encrypted Malware (TLS/QUIC)",
        confidence_score: 0.98,
        supporting_evidence_feature: {
          ja3_hash: "a0e42d24b9c7c4b0959f676e939da290",
          ja4_fingerprint: "t13d151600_a0e4_badmalware",
          tls_sni: "update-service-raw.xyz",
          cipher_suite: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
          reason: "JA3 signature matches Cobalt Strike payload launcher transmitting on non-standard port 4444."
        }
      };

    case 'port_scan':
      return {
        alert_id: alertId,
        timestamp: now,
        flow_identifier: {
          src_ip: "192.168.10.99",
          src_port: 58042,
          src_label: "Rogue Wi-Fi Bridge",
          dst_ip: "10.0.0.1",
          dst_port: 445,
          dst_label: "Domain Controller",
          protocol: "TCP"
        },
        threat_class: "Reconnaissance & Port Scanning",
        confidence_score: 0.95,
        supporting_evidence_feature: {
          unique_ports_targeted: 35,
          scan_speed_pps: 700,
          tcp_flags: "SYN Sweep",
          reason: "Systematic rapid SYN scan mapping 35 distinct listening ports across internal industrial subnets."
        }
      };

    case 'data_exfiltration':
      return {
        alert_id: alertId,
        timestamp: now,
        flow_identifier: {
          src_ip: "192.168.10.15",
          src_port: 59120,
          src_label: "Historian Database Server",
          dst_ip: "45.142.214.8",
          dst_port: 443,
          dst_label: "External Drop Server",
          protocol: "TCP"
        },
        threat_class: "Data Exfiltration",
        confidence_score: 0.96,
        supporting_evidence_feature: {
          bytes_sent_outbound: 18450000,
          bytes_received_inbound: 12500,
          asymmetry_ratio: 1475.88,
          megabytes_exfiltrated: 18.45,
          reason: "Extreme asymmetric outbound transfer (18.45 MB sent, Ratio: 1475.88) through unidirectional diode monitor."
        }
      };

    default:
      return {
        alert_id: alertId,
        timestamp: now,
        flow_identifier: {
          src_ip: "192.168.10.42",
          src_port: 51290,
          src_label: "PLC Controller",
          dst_ip: "142.250.190.46",
          dst_port: 443,
          dst_label: "External Cloud",
          protocol: "TCP"
        },
        threat_class: "Isolation Forest Statistical Anomaly",
        confidence_score: 0.88,
        supporting_evidence_feature: {
          anomaly_score: -0.28,
          reason: "Unusual burst in flow packet density exceeding 3.5 standard deviations from baseline."
        }
      };
  }
};

// Start autonomous cloud simulation loop
function startCloudSimulation(onMessage) {
  if (simInterval) clearInterval(simInterval);
  isSimulating = true;

  // Send initial snapshot
  onMessage({
    type: 'snapshot',
    recent_alerts: simAlerts,
    total_alerts: simTotalAlerts,
    auto_detection_enabled: simAutoDetection
  });

  simInterval = setInterval(() => {
    if (!isSimulating) return;

    // Fluctuating realistic throughput
    const pps = Math.floor(1800 + Math.random() * 2400 + Math.sin(Date.now() / 10000) * 800);
    const bps = Math.floor(pps * (800 + Math.random() * 400));

    onMessage({
      type: 'telemetry',
      timestamp: Date.now() / 1000,
      data: { pps, bps },
      total_alerts: simTotalAlerts,
      auto_detection_enabled: simAutoDetection
    });
  }, 1000);
}

// Stop autonomous simulation loop
function stopCloudSimulation() {
  if (simInterval) {
    clearInterval(simInterval);
    simInterval = null;
  }
  isSimulating = false;
}

/**
 * Connects to WebSocket if available, or activates autonomous simulation.
 */
export function initializeSocketStream(handlers) {
  const { onStatusChange, onMessage } = handlers;
  let ws = null;
  let reconnectTimer = null;
  let backendUrl = getStoredBackendUrl();

  // If on hosted site without custom backend URL, immediately use autonomous simulation
  if (isHosted && !backendUrl) {
    console.log("🚀 Running on Cloud Hosting: Initializing Autonomous Data Diode Simulator");
    onStatusChange(true, 'CLOUD_SIMULATION');
    startCloudSimulation(onMessage);
    return () => {
      stopCloudSimulation();
    };
  }

  // Otherwise, attempt WebSocket connection to backend
  const connect = () => {
    backendUrl = getStoredBackendUrl();
    if (!backendUrl) {
      onStatusChange(true, 'CLOUD_SIMULATION');
      startCloudSimulation(onMessage);
      return;
    }

    let wsUrl = '';
    try {
      const parsed = new URL(backendUrl);
      const wsProto = parsed.protocol === 'https:' ? 'wss:' : 'ws:';
      wsUrl = `${wsProto}//${parsed.host}/ws/alerts`;
    } catch {
      wsUrl = `ws://${window.location.hostname}:8000/ws/alerts`;
    }

    try {
      ws = new WebSocket(wsUrl);
      activeWs = ws;

      ws.onopen = () => {
        stopCloudSimulation();
        onStatusChange(true, 'LIVE_BACKEND');
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          onMessage(msg);
        } catch (e) {
          console.error("WS Parse error:", e);
        }
      };

      ws.onclose = () => {
        activeWs = null;
        // Fallback to simulation if backend drops
        onStatusChange(true, 'CLOUD_SIMULATION');
        startCloudSimulation(onMessage);

        // Try reconnecting in 5s
        reconnectTimer = setTimeout(connect, 5000);
      };

      ws.onerror = () => {
        if (ws) ws.close();
      };
    } catch (err) {
      console.warn("WebSocket init error, starting cloud simulation:", err);
      onStatusChange(true, 'CLOUD_SIMULATION');
      startCloudSimulation(onMessage);
      reconnectTimer = setTimeout(connect, 5000);
    }
  };

  connect();

  return () => {
    if (ws) ws.close();
    if (reconnectTimer) clearTimeout(reconnectTimer);
    stopCloudSimulation();
  };
}

/**
 * Trigger an attack simulation vector.
 */
export async function simulateThreat(threatType, onAlertEmitted) {
  const backendUrl = getStoredBackendUrl();

  if (backendUrl && !isSimulating) {
    try {
      const res = await fetch(`${backendUrl}/api/simulate/${threatType}`, { method: 'POST' });
      if (res.ok) {
        return await res.json();
      }
    } catch (e) {
      console.warn("Backend simulate failed, executing client-side simulation:", e);
    }
  }

  // Client-side simulation fallback
  const alert = generateSyntheticAlert(threatType);
  simAlerts = [alert, ...simAlerts.slice(0, 49)];
  simTotalAlerts += 1;

  if (onAlertEmitted) {
    onAlertEmitted(alert);
  }
  eventBus.emit('alert', alert);

  return {
    status: "threat_injected",
    threat_type: threatType,
    flows_processed: 40,
    alerts_raised: 1,
    alerts: [alert]
  };
}

/**
 * Toggle auto-detection.
 */
export async function toggleAutoDetection() {
  const backendUrl = getStoredBackendUrl();
  if (backendUrl && !isSimulating) {
    try {
      const res = await fetch(`${backendUrl}/api/detection/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !simAutoDetection })
      });
      if (res.ok) {
        const data = await res.json();
        simAutoDetection = data.auto_detection_enabled;
        return data;
      }
    } catch (e) {
      console.warn("Backend toggle failed, falling back client-side:", e);
    }
  }

  simAutoDetection = !simAutoDetection;
  return { status: "success", auto_detection_enabled: simAutoDetection };
}

/**
 * Clear alerts.
 */
export async function clearAlerts() {
  const backendUrl = getStoredBackendUrl();
  if (backendUrl && !isSimulating) {
    try {
      await fetch(`${backendUrl}/api/alerts/clear`, { method: 'POST' });
    } catch (e) {
      console.warn("Backend clear failed, falling back client-side:", e);
    }
  }
  simAlerts = [];
  simTotalAlerts = 0;
  return { status: "alerts_cleared", total_alerts: 0 };
}

/**
 * Fetch dynamic topology.
 */
export async function fetchTopology() {
  const backendUrl = getStoredBackendUrl();
  if (backendUrl && !isSimulating) {
    try {
      const res = await fetch(`${backendUrl}/api/topology`);
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn("Backend topology fetch failed, using realistic topology simulation:", e);
    }
  }

  // Realistic Critical Infrastructure Data Diode Topology
  return {
    nodes: [
      { id: "192.168.10.1", label: "Industrial OT Gateway", is_internal: true, is_threat: false },
      { id: "192.168.10.15", label: "Historian Database Server", is_internal: true, is_threat: true },
      { id: "192.168.10.18", label: "ICS Telemetry Gateway", is_internal: true, is_threat: true },
      { id: "192.168.10.22", label: "Engineering Workstation #2", is_internal: true, is_threat: true },
      { id: "192.168.10.30", label: "Turbine Sensor Gateway", is_internal: true, is_threat: false },
      { id: "192.168.10.50", label: "SCADA Core Controller", is_internal: true, is_threat: true },
      { id: "192.168.10.99", label: "Rogue Wi-Fi Bridge", is_internal: true, is_threat: true },
      { id: "8.8.8.8", label: "Google Public DNS", is_internal: false, is_threat: false },
      { id: "185.220.101.5", label: "External C2 Node", is_internal: false, is_threat: true },
      { id: "45.142.214.8", label: "External Drop Server", is_internal: false, is_threat: true },
      { id: "91.215.102.14", label: "Known Malicious Host", is_internal: false, is_threat: true },
      { id: "142.250.190.46", label: "Google CDN Node", is_internal: false, is_threat: false },
      { id: "10.0.0.1", label: "Domain Controller", is_internal: true, is_threat: false }
    ],
    edges: [
      { source: "192.168.10.22", target: "185.220.101.5", protocol: "TCP", bytes: 2450 },
      { source: "192.168.10.18", target: "8.8.8.8", protocol: "UDP", bytes: 1420 },
      { source: "192.168.10.15", target: "45.142.214.8", protocol: "TCP", bytes: 18450000 },
      { source: "192.168.10.99", target: "10.0.0.1", protocol: "TCP", bytes: 6400 },
      { source: "192.168.10.30", target: "192.168.10.1", protocol: "TCP", bytes: 980 },
      { source: "192.168.10.1", target: "142.250.190.46", protocol: "TCP", bytes: 4200 }
    ],
    total_active_flows: 148
  };
}

/**
 * Deep Forensic Target Inspection (IP, Domain, Email, Phone).
 */
export async function inspectTarget(payload) {
  const backendUrl = getStoredBackendUrl();
  if (backendUrl && !isSimulating) {
    try {
      const res = await fetch(`${backendUrl}/api/inspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (res.ok) return await res.json();
    } catch (e) {
      console.warn("Backend inspect failed, executing client-side forensic engine:", e);
    }
  }

  // Client-side Heuristic Forensic Engine
  const rawIp = (payload.ip_address || '').trim();
  const rawWebsite = (payload.website || '').trim();
  const rawEmail = (payload.email || '').trim();
  const rawPhone = (payload.phone_number || '').trim();

  let cleanDomain = rawWebsite.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].toLowerCase();
  const entropy = calculateEntropy(cleanDomain);
  
  const PHISHING_KEYWORDS = ["login", "verify", "secure", "update", "bank", "account", "support", "portal", "confirm", "recovery"];
  const isPhishing = PHISHING_KEYWORDS.some(kw => cleanDomain.includes(kw));
  const isDga = entropy > 3.6 && cleanDomain.length > 18;
  const isKnownBadIp = ["185.220.101.5", "45.142.214.8", "91.215.102.14"].includes(rawIp);
  const isSuspiciousEmail = rawEmail.includes("tempmail") || rawEmail.includes("burner") || rawEmail.includes("support-verify");
  const isSuspiciousPhone = rawPhone.startsWith("+882") || rawPhone.startsWith("+247") || rawPhone.includes("9999");

  const hasThreat = isPhishing || isDga || isKnownBadIp || isSuspiciousEmail || isSuspiciousPhone;
  const threatLevel = hasThreat ? "CRITICAL" : "CLEAN";

  let title = "Normal & Verified";
  let explanation = "Telemetry and parameters match expected operational baselines with zero anomalous signatures.";

  if (isPhishing) {
    title = "Brand Impersonation & Phishing Domain";
    explanation = "Lexical analysis detected deceptive credentials harvesting patterns and misleading domain naming.";
  } else if (isDga) {
    title = "DGA Algorithmically Generated Domain";
    explanation = `High character entropy (${entropy}) indicates automated domain generation for C2 rendezvous or DNS tunnelling.`;
  } else if (isKnownBadIp) {
    title = "Blacklisted Malicious IP";
    explanation = "Target IP address is indexed on global threat intelligence feeds for C2 infrastructure or botnet operation.";
  } else if (isSuspiciousEmail) {
    title = "Suspicious Email Identity";
    explanation = "Disposable or deceptive email domain used to bypass sender authentication and SPF checks.";
  } else if (isSuspiciousPhone) {
    title = "Flagged Telephony Origin";
    explanation = "Premium-rate or high-risk international destination commonly utilized in Wangiri toll fraud.";
  }

  return {
    status: "completed",
    inspected_target: {
      ip_address: rawIp || "192.168.10.15",
      website: rawWebsite || "N/A",
      clean_domain: cleanDomain || "N/A",
      email: rawEmail || "N/A",
      phone_number: rawPhone || "N/A",
      port: payload.port || 443,
      protocol: payload.protocol || "TCP",
      ip_classification: {
        network_type: rawIp.startsWith("192.168.") ? "Internal OT Network" : "Public Internet Host",
        risk_score: hasThreat ? 92 : 5
      },
      website_classification: cleanDomain ? {
        domain: cleanDomain,
        entropy: entropy,
        is_high_risk: hasThreat
      } : null
    },
    verdict: {
      is_threat: hasThreat,
      threat_level: threatLevel,
      confidence_score: hasThreat ? 0.96 : 0.0,
      summary: `${title}: ${explanation}`,
      kid_friendly_title: title,
      kid_friendly_explanation: explanation
    },
    dns_analysis: cleanDomain ? {
      query: cleanDomain,
      entropy: entropy,
      ngram_rarity: isDga ? 0.94 : 0.22,
      is_dga_pattern: isDga
    } : null,
    alerts_raised: hasThreat ? 1 : 0,
    alerts: hasThreat ? [generateSyntheticAlert(isDga ? 'dga_dns' : isKnownBadIp ? 'encrypted_malware' : 'data_exfiltration')] : [],
    security_advisory: {
      title: "Data Diode Zero-Return-Path Defense Analysis",
      key_reasons: [
        {
          reason: "Physical Optical Separation",
          detail: "Data diode hardware allows only forward photons; no reverse channel exists for attackers to execute interactive shells or receive return responses."
        },
        {
          reason: "Zero Decryption Metadata Inspection",
          detail: "Inspection relies strictly on Layer 3/4/7 packet timing, JA3/JA4 TLS headers, and entropy calculations without breaking cipher confidentiality."
        }
      ]
    }
  };
}

/**
 * AI SOC Incident Assistant - Alert Analysis.
 */
export async function analyzeAlertWithAi(alertId, alert) {
  const backendUrl = getStoredBackendUrl();
  if (backendUrl && !isSimulating) {
    try {
      const res = await fetch(`${backendUrl}/api/ai/analyze-alert/${alertId}`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        return data.analysis;
      }
    } catch (e) {
      console.warn("Backend AI analysis failed, generating contextual SOC triage client-side:", e);
    }
  }

  // High-fidelity Client-Side SOC Analysis
  const threatClass = alert?.threat_class || "Data Diode Incident";
  const src = alert?.flow_identifier?.src_ip || "192.168.10.15";
  const dst = alert?.flow_identifier?.dst_ip || "45.142.214.8";
  const score = Math.round((alert?.confidence_score || 0.95) * 100);

  return {
    executive_summary: `Critical SOC Alert: ${threatClass} detected originating from ${src} targeting ${dst} with ${score}% algorithmic confidence. Optical unidirectional isolation successfully blocked bidirectional handshake response.`,
    mitre_attack: {
      tactic: threatClass.includes("Exfiltration") ? "Exfiltration (TA0010)" : threatClass.includes("C2") ? "Command & Control (TA0011)" : "Impact / Defense Evasion",
      technique: threatClass.includes("Exfiltration") ? "T1048 - Exfiltration Over Alternative Protocol" : threatClass.includes("DNS") ? "T1568.002 - Domain Generation Algorithms" : "T1071.001 - Web Protocols"
    },
    threat_impact_score: score,
    air_gap_validation: "Unidirectional data diode physical barrier confirmed active: Zero return packets transmitted to external origin.",
    containment_actions: [
      `Physically isolate host ${src} at the OT edge switch to prevent lateral movement.`,
      `Blacklist external destination ${dst} across upstream perimeter routing nodes.`,
      `Capture volatile RAM dump from host ${src} for root-cause forensic attribution.`,
      `Audit PLC firmware and supervisory SCADA logs for unauthorized configuration modifications.`
    ],
    recommended_snort_rule: `alert tcp ${src} any -> ${dst} any (msg:"SOC_DIODE_${threatClass.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}"; flow:to_server,established; classtype:trojan-activity; sid:9001042; rev:1;)`
  };
}

/**
 * AI SOC Interactive Chat.
 */
export async function chatWithAi(message, alertContext, history) {
  const backendUrl = getStoredBackendUrl();
  if (backendUrl && !isSimulating) {
    try {
      const res = await fetch(`${backendUrl}/api/ai/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message,
          alert_id: alertContext?.alert_id,
          alert_context: alertContext,
          history: history?.slice(-4)
        })
      });
      if (res.ok) {
        const data = await res.json();
        return data.reply;
      }
    } catch (e) {
      console.warn("Backend AI chat failed, answering with client-side SOC expert:", e);
    }
  }

  // Contextual SOC Analyst Assistant Reply
  const query = message.toLowerCase();
  const tClass = alertContext?.threat_class || "threat";
  const src = alertContext?.flow_identifier?.src_ip || "the suspect host";

  if (query.includes("contain") || query.includes("remediate") || query.includes("fix")) {
    return `In a hardware data diode architecture, this ${tClass} from ${src} is strictly constrained to one-way transmission. However, you should immediately:\n1. Disconnect ${src}'s physical patch cable from the industrial LAN.\n2. Review adjacent PLC logs to verify no internal lateral pivot occurred prior to diode capture.\n3. Add the destination IP to perimeter firewall egress blocklists.`;
  }

  if (query.includes("mitre") || query.includes("technique")) {
    return `This threat correlates with MITRE ATT&CK:\n• **Tactic**: Command & Control (TA0011) / Exfiltration (TA0010)\n• **Technique**: Automated C2 beaconing with jitter evasion.\n• **Telemetry Evidence**: Zero payload decryption was needed; analysis is derived purely from inter-arrival timing variances and byte transfer asymmetry.`;
  }

  return `Regarding the ${tClass} on ${src}: The physical data diode ensures zero inbound command reception from the adversary. I recommend maintaining isolation while our analytical models track packet sequence timing to confirm whether other OT endpoints are attempting synchronized beaconing.`;
}
