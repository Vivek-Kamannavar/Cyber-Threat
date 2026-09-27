import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Bot, Send, Loader2, User, Sparkles, ShieldAlert, Activity, Radio } from 'lucide-react';
import { chatWithAnalyst } from '../services/apiService';

/** Renders a small, safe markdown subset: headings, bullets, code fences, **bold**, `code`. */
function renderInline(text, keyPrefix) {
  const nodes = [];
  const pattern = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let lastIndex = 0;
  let match;
  let index = 0;

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > lastIndex) nodes.push(text.slice(lastIndex, match.index));
    const token = match[0];
    if (token.startsWith('**')) {
      nodes.push(<strong key={`${keyPrefix}-b-${index}`} className="text-slate-100 font-semibold">{token.slice(2, -2)}</strong>);
    } else {
      nodes.push(
        <code key={`${keyPrefix}-c-${index}`} className="px-1 py-0.5 rounded bg-soc-bg border border-soc-border font-mono text-[11px] text-soc-primary">
          {token.slice(1, -1)}
        </code>
      );
    }
    lastIndex = match.index + token.length;
    index += 1;
  }

  if (lastIndex < text.length) nodes.push(text.slice(lastIndex));
  return nodes;
}

function MarkdownBlock({ content }) {
  const blocks = [];
  const lines = (content || '').split('\n');
  let codeBuffer = null;

  lines.forEach((line, lineIndex) => {
    if (line.trim().startsWith('```')) {
      if (codeBuffer === null) {
        codeBuffer = [];
      } else {
        blocks.push(
          <pre key={`code-${lineIndex}`} className="bg-soc-bg border border-soc-border rounded-lg p-2.5 overflow-x-auto font-mono text-[11px] text-soc-success">
            {codeBuffer.join('\n')}
          </pre>
        );
        codeBuffer = null;
      }
      return;
    }

    if (codeBuffer !== null) {
      codeBuffer.push(line);
      return;
    }

    if (!line.trim()) return;

    if (line.startsWith('### ')) {
      blocks.push(
        <h4 key={`h-${lineIndex}`} className="text-xs font-semibold text-slate-100 mt-1">
          {line.slice(4)}
        </h4>
      );
      return;
    }

    if (/^\s*[-*]\s+/.test(line)) {
      blocks.push(
        <div key={`li-${lineIndex}`} className="flex gap-2 pl-1">
          <span className="text-soc-primary">•</span>
          <span>{renderInline(line.replace(/^\s*[-*]\s+/, ''), `li-${lineIndex}`)}</span>
        </div>
      );
      return;
    }

    if (/^\s*\d+\.\s+/.test(line)) {
      const marker = line.trim().match(/^(\d+)\./)[1];
      blocks.push(
        <div key={`ol-${lineIndex}`} className="flex gap-2 pl-1">
          <span className="text-slate-400 font-mono text-[11px] pt-0.5">{marker}.</span>
          <span>{renderInline(line.replace(/^\s*\d+\.\s+/, ''), `ol-${lineIndex}`)}</span>
        </div>
      );
      return;
    }

    blocks.push(<p key={`p-${lineIndex}`}>{renderInline(line, `p-${lineIndex}`)}</p>);
  });

  if (codeBuffer !== null && codeBuffer.length) {
    blocks.push(
      <pre key="code-open" className="bg-soc-bg border border-soc-border rounded-lg p-2.5 overflow-x-auto font-mono text-[11px] text-soc-success">
        {codeBuffer.join('\n')}
      </pre>
    );
  }

  return <div className="space-y-1.5 leading-relaxed">{blocks}</div>;
}

/** Opening briefing derived from the incidents already in the window. */
function buildGreeting(alerts) {
  const list = alerts || [];
  if (list.length === 0) {
    return '### AI Security Analyst online\n\nThe window is clean right now. Ask me to summarise the threat posture, explain how the data diode constrains an attacker, or tell you what I would watch for next.';
  }

  const top = list.reduce((best, alert) => ((alert.confidence_score || 0) > (best.confidence_score || 0) ? alert : best), list[0]);
  const confidence = Math.round((top.confidence_score || 0) * 100);
  return `### AI Security Analyst online\n\nI can see **${list.length}** active incident${list.length === 1 ? '' : 's'} in the current 60s window, the highest-confidence being **${top.threat_class}** (${confidence}%). Ask me to explain an incident, draft containment steps, or produce firewall rules.`;
}

export default function AiChatbotPanel({ telemetry, alerts, autoDetectionEnabled, onOpenAlert }) {
  const [messages, setMessages] = useState(() => [{ role: 'assistant', content: buildGreeting(alerts) }]);
  const [suggestions, setSuggestions] = useState([
    'Summarize threat posture',
    'Explain the latest incident',
    'Generate firewall rules',
    'What should I contain first?'
  ]);
  const [mode, setMode] = useState(null);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef(null);

  const incidentCount = alerts?.length || 0;

  const topAlert = useMemo(() => {
    if (!alerts || alerts.length === 0) return null;
    return alerts.reduce((best, alert) => ((alert.confidence_score || 0) > (best.confidence_score || 0) ? alert : best), alerts[0]);
  }, [alerts]);

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [messages, loading]);

  const ask = async (prompt) => {
    const question = (prompt ?? input).trim();
    if (!question || loading) return;

    const history = messages.map(({ role, content }) => ({ role, content }));
    setMessages((prev) => [...prev, { role: 'user', content: question }]);
    setInput('');
    setLoading(true);

    try {
      const result = await chatWithAnalyst(question, { history, telemetry, alerts, alertId: topAlert?.alert_id });
      setMode(result.mode);
      if (Array.isArray(result.suggestions) && result.suggestions.length) setSuggestions(result.suggestions);
      setMessages((prev) => [...prev, { role: 'assistant', content: result.response }]);
    } catch {
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: 'I could not reach the analysis service and my local heuristics failed too. Please retry.' }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const modeLabel = mode === 'GROQ' ? 'Groq Llama 3.3' : mode === 'OFFLINE_HEURISTIC' ? 'Offline heuristics' : 'Standby';

  return (
    <div className="space-y-4 animate-fadeIn">
      {/* Context strip */}
      <div className="bg-soc-card border border-soc-border rounded-xl p-4 flex flex-wrap items-center gap-4">
        <div className="flex items-center gap-2.5">
          <span className="p-2 rounded-lg bg-soc-primary/10 border border-soc-primary/30 text-soc-primary">
            <Bot className="w-5 h-5" />
          </span>
          <div>
            <h2 className="text-sm font-semibold text-slate-100">AI Security Analyst</h2>
            <p className="text-[11px] text-slate-400">Conversational triage grounded in the live sliding window</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 ml-auto text-[11px] font-mono">
          <span className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-soc-bg border border-soc-border text-slate-300">
            <Activity className="w-3.5 h-3.5 text-soc-primary" />
            {Math.round(telemetry?.pps || 0)} pps
          </span>
          <span className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-soc-bg border border-soc-border text-slate-300">
            <ShieldAlert className={`w-3.5 h-3.5 ${incidentCount > 0 ? 'text-soc-danger' : 'text-soc-success'}`} />
            {incidentCount} incident{incidentCount === 1 ? '' : 's'}
          </span>
          <span
            className={`flex items-center gap-1.5 px-2 py-1 rounded-lg border ${
              mode === 'GROQ' ? 'border-soc-primary/40 text-soc-primary bg-soc-primary/10' : 'border-soc-border text-slate-400 bg-soc-bg'
            }`}
            title="Inference mode: live Groq model or deterministic offline heuristics"
          >
            <Radio className="w-3.5 h-3.5" />
            {modeLabel}
          </span>
        </div>
      </div>

      {/* Conversation */}
      <div className="bg-soc-card border border-soc-border rounded-xl flex flex-col h-[560px]">
        <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-3 text-xs text-slate-200">
          {messages.map((message, index) => (
            <div key={index} className={`flex gap-2.5 ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              {message.role === 'assistant' && (
                <span className="w-6 h-6 shrink-0 rounded-md bg-soc-primary/10 border border-soc-primary/30 text-soc-primary flex items-center justify-center">
                  <Sparkles className="w-3.5 h-3.5" />
                </span>
              )}
              <div
                className={`max-w-[85%] rounded-lg px-3 py-2 border ${
                  message.role === 'user'
                    ? 'bg-soc-primary/15 border-soc-primary/40 text-slate-100'
                    : 'bg-soc-bg border-soc-border'
                }`}
              >
                {message.role === 'user' ? message.content : <MarkdownBlock content={message.content} />}
              </div>
              {message.role === 'user' && (
                <span className="w-6 h-6 shrink-0 rounded-md bg-soc-bg border border-soc-border text-slate-400 flex items-center justify-center">
                  <User className="w-3.5 h-3.5" />
                </span>
              )}
            </div>
          ))}

          {loading && (
            <div className="flex items-center gap-2 text-slate-400">
              <Loader2 className="w-3.5 h-3.5 animate-spin text-soc-primary" />
              <span>Correlating telemetry and incident history…</span>
            </div>
          )}
        </div>

        {/* Quick actions */}
        <div className="px-4 pt-3 border-t border-soc-border flex flex-wrap gap-2">
          {suggestions.slice(0, 4).map((chip) => (
            <button
              key={chip}
              onClick={() => ask(chip)}
              disabled={loading}
              className="px-2.5 py-1 rounded-lg text-[11px] border border-soc-border bg-soc-bg text-slate-300 hover:text-soc-primary hover:border-soc-primary/40 transition-colors disabled:opacity-50"
            >
              {chip}
            </button>
          ))}
          {topAlert && onOpenAlert && (
            <button
              onClick={() => onOpenAlert(topAlert)}
              className="px-2.5 py-1 rounded-lg text-[11px] border border-soc-border bg-soc-bg text-slate-300 hover:text-slate-100 transition-colors"
            >
              Open incident evidence
            </button>
          )}
        </div>

        {/* Composer */}
        <form
          onSubmit={(event) => {
            event.preventDefault();
            ask();
          }}
          className="p-4 flex gap-2"
        >
          <input
            type="text"
            value={input}
            onChange={(event) => setInput(event.target.value)}
            placeholder="Ask about an incident, containment steps, or the current posture…"
            className="flex-1 bg-soc-bg border border-soc-border rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-soc-primary"
          />
          <button
            type="submit"
            disabled={!input.trim() || loading}
            className="px-3 py-2 rounded-lg bg-soc-primary hover:bg-blue-400 disabled:opacity-40 text-slate-950 text-xs font-semibold flex items-center gap-1.5 transition-colors"
          >
            <Send className="w-3.5 h-3.5" />
            Send
          </button>
        </form>
      </div>

      {!autoDetectionEnabled && (
        <p className="text-[11px] text-soc-warning">
          Detection engine is paused — answers will only reflect already-logged incidents.
        </p>
      )}
    </div>
  );
}
