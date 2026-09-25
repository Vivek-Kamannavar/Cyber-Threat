import React, { useState, useEffect, useRef } from 'react';
import { 
  X, Copy, Check, Send, 
  Terminal, AlertTriangle, Sparkles, Loader2, CheckCircle2, ArrowRight 
} from 'lucide-react';

export default function AiCopilotDrawer({ isOpen, onClose, alert }) {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);
  const [chatMessages, setChatMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatBottomRef = useRef(null);

  useEffect(() => {
    if (isOpen && alert) {
      fetchAnalysis(alert.alert_id);
      setChatMessages([
        {
          role: 'assistant',
          content: `AI Copilot active for Incident ${alert.alert_id} (${alert.threat_class}). What containment steps do you require?`
        }
      ]);
    }
  }, [isOpen, alert]);

  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [chatMessages]);

  const fetchAnalysis = async (alertId) => {
    setLoading(true);
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/ai/analyze-alert/${alertId}`, {
        method: 'POST'
      });
      if (res.ok) {
        const data = await res.json();
        setAnalysis(data.analysis);
      }
    } catch (e) {
      console.error("Failed to fetch AI analysis:", e);
    } finally {
      setLoading(false);
    }
  };

  const handleCopyRule = (ruleText) => {
    navigator.clipboard.writeText(ruleText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!inputMessage.trim() || chatLoading) return;

    const userText = inputMessage.trim();
    setInputMessage('');
    setChatMessages(prev => [...prev, { role: 'user', content: userText }]);
    setChatLoading(true);

    try {
      const res = await fetch('http://127.0.0.1:8000/api/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: userText,
          alert_id: alert?.alert_id,
          alert_context: alert,
          history: chatMessages.slice(-4)
        })
      });

      if (res.ok) {
        const data = await res.json();
        setChatMessages(prev => [...prev, { role: 'assistant', content: data.reply }]);
      } else {
        setChatMessages(prev => [...prev, { role: 'assistant', content: "Offline assistant: Request timed out." }]);
      }
    } catch (err) {
      setChatMessages(prev => [...prev, { role: 'assistant', content: "Offline assistant: Backend AI unavailable." }]);
    } finally {
      setChatLoading(false);
    }
  };

  if (!isOpen || !alert) return null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-lg bg-[#FFF1D1] border-l border-black shadow-2xl flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-black bg-[#FFF1D1]">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded border border-black bg-[#FFF1D1] text-[#00B7CD]">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-xs font-bold text-black tracking-tight">
              AI Security Copilot
            </h2>
            <div className="flex items-center gap-1.5 text-[11px] text-black font-normal">
              <span>{alert.flow_identifier?.src_ip}</span>
              <ArrowRight className="w-3 h-3 text-black" />
              <span>{alert.flow_identifier?.dst_ip}</span>
            </div>
          </div>
        </div>
        <button 
          onClick={onClose} 
          className="p-1 rounded border border-black text-black bg-[#FFF1D1] transition-colors"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Main Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3.5 text-black">
        {loading ? (
          <div className="flex flex-col items-center justify-center py-16 space-y-2">
            <Loader2 className="w-6 h-6 animate-spin text-[#00B7CD]" />
            <p className="text-xs text-black font-normal">Generating forensic summary...</p>
          </div>
        ) : analysis ? (
          <>
            {/* Executive Summary Card */}
            <div className="bg-[#FFF1D1] border border-black rounded-lg p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold uppercase tracking-wider text-black">EXECUTIVE SUMMARY</span>
                <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                  analysis.severity_rating?.toUpperCase() === 'CRITICAL' || analysis.severity_rating?.toUpperCase() === 'HIGH'
                    ? 'bg-[#DF301C] text-[#FFF1D1]'
                    : 'bg-[#FF9100] text-black'
                }`}>
                  {analysis.severity_rating} RISK
                </span>
              </div>
              <p className="text-xs text-black font-normal leading-relaxed">
                {analysis.summary}
              </p>
            </div>

            {/* Attack Vector & Facility Impact */}
            <div className="grid grid-cols-1 gap-2.5">
              <div className="bg-[#FFF1D1] border border-black rounded-lg p-3 text-xs space-y-1">
                <span className="text-[10px] font-bold uppercase tracking-wider text-black">ATTACK METHODOLOGY</span>
                <p className="text-black font-normal leading-relaxed">{analysis.attack_vector_breakdown}</p>
              </div>
              <div className="bg-[#FFF1D1] border border-black rounded-lg p-3 text-xs space-y-1">
                <span className="text-[10px] font-bold uppercase tracking-wider text-black flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-[#FF9100]" />
                  FACILITY IMPACT
                </span>
                <p className="text-black font-normal leading-relaxed">{analysis.potential_business_impact}</p>
              </div>
            </div>

            {/* Step-by-Step Remediation Checklist */}
            <div className="space-y-1.5">
              <h3 className="text-[10px] font-bold uppercase tracking-wider text-black">REMEDIATION CHECKLIST</h3>
              <div className="space-y-1.5">
                {analysis.recommended_remediation_steps?.map((step, idx) => (
                  <div key={idx} className="flex items-start gap-2 bg-[#FFF1D1] border border-black p-2.5 rounded-lg text-xs font-normal text-black">
                    <CheckCircle2 className="w-3.5 h-3.5 text-[#00B7CD] shrink-0 mt-0.5" />
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Copyable Firewall Mitigation Rule */}
            {analysis.firewall_mitigation_rule && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold uppercase tracking-wider text-black flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-black" />
                    GATEWAY FIREWALL RULE
                  </span>
                  <button
                    onClick={() => handleCopyRule(analysis.firewall_mitigation_rule)}
                    className="flex items-center gap-1 text-[11px] text-black font-normal"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-[#00B7CD]" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <pre className="bg-[#FFF1D1] border border-black p-2.5 rounded-lg text-[11px] text-black font-normal overflow-x-auto">
                  {analysis.firewall_mitigation_rule}
                </pre>
              </div>
            )}
          </>
        ) : null}

        {/* Interactive Chatbot Area */}
        <div className="border-t border-black pt-3 space-y-2">
          <h3 className="text-[10px] font-bold uppercase tracking-wider text-black">ANALYST CONSOLE</h3>
          <div className="bg-[#FFF1D1] border border-black rounded-lg p-3 min-h-[120px] max-h-[170px] overflow-y-auto space-y-2">
            {chatMessages.map((msg, i) => (
              <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[85%] rounded-lg p-2.5 text-xs font-normal ${
                  msg.role === 'user' 
                    ? 'bg-[#00B7CD] text-black border border-black' 
                    : 'bg-[#FFF1D1] border border-black text-black'
                }`}>
                  {msg.content}
                </div>
              </div>
            ))}
            {chatLoading && (
              <div className="flex items-center gap-1.5 text-xs text-black font-normal">
                <Loader2 className="w-3 h-3 animate-spin text-[#00B7CD]" />
                <span>Copilot formulating...</span>
              </div>
            )}
            <div ref={chatBottomRef} />
          </div>

          {/* Chat Input */}
          <form onSubmit={handleSendMessage} className="flex gap-2">
            <input
              type="text"
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              placeholder="Ask Copilot for analysis or containment..."
              className="flex-1 bg-[#FFF1D1] border border-black rounded px-3 py-1.5 text-xs text-black placeholder-black font-normal focus:outline-none"
            />
            <button
              type="submit"
              disabled={!inputMessage.trim() || chatLoading}
              className="bg-[#00B7CD] text-black px-3.5 py-1.5 rounded text-xs font-bold border border-black flex items-center justify-center transition-colors disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" />
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
