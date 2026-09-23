import React, { useState, useEffect, useRef } from 'react';
import { 
  Bot, X, ShieldAlert, CheckCircle, Copy, Check, Send, 
  Terminal, AlertTriangle, Sparkles, Loader2 
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
          content: `AI Copilot active for Incident **${alert.alert_id}** (${alert.threat_class}). How can I assist you with containment or forensic verification?`
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
        setChatMessages(prev => [...prev, { role: 'assistant', content: "Offline assistant: Request timed out. Please verify network connectivity." }]);
      }
    } catch (err) {
      setChatMessages(prev => [...prev, { role: 'assistant', content: "Offline assistant: Unable to contact backend AI service." }]);
    } finally {
      setChatLoading(false);
    }
  };

  if (!isOpen || !alert) return null;

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-xl bg-[#151f32] border-l border-[#23324d] shadow-2xl flex flex-col transition-transform duration-300">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#23324d] bg-slate-900/60">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-sky-500/10 border border-sky-500/30 text-sky-400">
            <Sparkles className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              Groq AI Incident Copilot
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-sky-950 text-sky-400 border border-sky-800">
                Llama 3.3
              </span>
            </h2>
            <p className="text-xs text-slate-400">Target: {alert.flow_identifier?.src_ip} → {alert.flow_identifier?.dst_ip}</p>
          </div>
        </div>
        <button onClick={onClose} className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200">
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Main Scrollable Body */}
      <div className="flex-1 overflow-y-auto p-6 space-y-5 text-slate-200">
        {loading ? (
          <div className="flex flex-col items-center justify-center py-16 space-y-3">
            <Loader2 className="w-8 h-8 animate-spin text-sky-400" />
            <p className="text-xs text-slate-400">Generating forensic incident analysis...</p>
          </div>
        ) : analysis ? (
          <>
            {/* Executive Summary Card */}
            <div className="bg-slate-900/50 border border-[#23324d] rounded-xl p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Executive Summary</span>
                <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                  analysis.severity_rating === 'CRITICAL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                  analysis.severity_rating === 'HIGH' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                  'bg-emerald-950 text-emerald-300 border border-emerald-800'
                }`}>
                  {analysis.severity_rating} Risk
                </span>
              </div>
              <p className="text-xs text-slate-200 leading-relaxed font-medium">
                {analysis.summary}
              </p>
            </div>

            {/* Attack Vector & Business Impact */}
            <div className="grid grid-cols-1 gap-3">
              <div className="bg-slate-900/40 border border-[#23324d] rounded-lg p-3 text-xs space-y-1">
                <span className="text-[11px] font-semibold text-slate-400">Attack Methodology:</span>
                <p className="text-slate-300 leading-snug">{analysis.attack_vector_breakdown}</p>
              </div>
              <div className="bg-slate-900/40 border border-[#23324d] rounded-lg p-3 text-xs space-y-1">
                <span className="text-[11px] font-semibold text-rose-300 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                  Air-Gapped Facility Impact:
                </span>
                <p className="text-slate-300 leading-snug">{analysis.potential_business_impact}</p>
              </div>
            </div>

            {/* Step-by-Step Remediation Checklist */}
            <div className="space-y-2">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Recommended Response Checklist</h3>
              <div className="space-y-2">
                {analysis.recommended_remediation_steps?.map((step, idx) => (
                  <div key={idx} className="flex items-start gap-2.5 bg-slate-900/60 border border-[#23324d] p-2.5 rounded-lg text-xs">
                    <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span className="text-slate-200">{step}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Copyable Firewall Mitigation Rule */}
            {analysis.firewall_mitigation_rule && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-sky-400" />
                    Gateway Mitigation Rule
                  </span>
                  <button
                    onClick={() => handleCopyRule(analysis.firewall_mitigation_rule)}
                    className="flex items-center gap-1 text-[11px] text-sky-400 hover:text-sky-300 font-medium"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copied ? 'Copied' : 'Copy Command'}
                  </button>
                </div>
                <pre className="bg-slate-950 border border-[#23324d] p-2.5 rounded-lg font-mono text-[11px] text-emerald-400 overflow-x-auto">
                  {analysis.firewall_mitigation_rule}
                </pre>
              </div>
            )}
          </>
        ) : null}

        {/* Interactive Chatbot Area */}
        <div className="border-t border-[#23324d] pt-4 space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400">Ask Copilot About This Threat</h3>
          <div className="bg-slate-950/70 border border-[#23324d] rounded-xl p-3 min-h-[160px] max-h-[220px] overflow-y-auto space-y-2.5">
            {chatMessages.map((msg, i) => (
              <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                <div className={`max-w-[85%] rounded-lg px-3 py-2 text-xs leading-relaxed ${
                  msg.role === 'user' 
                    ? 'bg-sky-600 text-white' 
                    : 'bg-slate-900 border border-[#23324d] text-slate-200'
                }`}>
                  {msg.content}
                </div>
              </div>
            ))}
            {chatLoading && (
              <div className="flex items-center gap-2 text-xs text-slate-400">
                <Loader2 className="w-3.5 h-3.5 animate-spin text-sky-400" />
                <span>Copilot is formulating response...</span>
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
              placeholder="Ask for investigation steps, packet verification, or commands..."
              className="flex-1 bg-slate-900 border border-[#23324d] rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500"
            />
            <button
              type="submit"
              disabled={!inputMessage.trim() || chatLoading}
              className="bg-sky-500 hover:bg-sky-400 disabled:opacity-50 text-slate-950 px-3 py-2 rounded-lg text-xs font-semibold flex items-center justify-center shadow-sm"
            >
              <Send className="w-3.5 h-3.5" />
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
