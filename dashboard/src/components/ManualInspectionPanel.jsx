import React, { useState } from 'react';
import {
  Search,
  ShieldAlert,
  ShieldCheck,
  Globe,
  Server,
  Mail,
  PhoneCall,
  Loader2,
  AlertTriangle,
  Wifi,
  History,
  Calendar,
  Building2,
  CheckCircle2,
  HelpCircle,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  ShieldOff,
  UserX,
  Radio
} from 'lucide-react';

export default function ManualInspectionPanel({ onInspectionComplete }) {
  const [ipAddress, setIpAddress] = useState('');
  const [website, setWebsite] = useState('');
  const [email, setEmail] = useState('');
  const [phoneNumber, setPhoneNumber] = useState('');
  const [port, setPort] = useState('443');
  const [protocol, setProtocol] = useState('TCP');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);
  const [showAdvisory, setShowAdvisory] = useState(false);

  const sampleTargets = [
    {
      label: 'Wi-Fi / Enterprise LAN',
      ip: '10.63.2.207',
      website: '',
      email: '',
      phone: '',
      desc: 'Internal Wi-Fi subnet host'
    },
    {
      label: 'Phishing URL (Microsoft Spoof)',
      ip: '',
      website: 'http://microsoft-support-fix.xyz/claim',
      email: '',
      phone: '',
      desc: 'Brand spoofing & phishing'
    },
    {
      label: 'Suspicious Spoofed Email',
      ip: '',
      website: '',
      email: 'support@micros0ft-security.xyz',
      phone: '',
      desc: 'Typosquatted brand email'
    },
    {
      label: 'Tech Support Scam Phone',
      ip: '',
      website: '',
      email: '',
      phone: '+1 (800) 555-0199',
      desc: 'Fake popup support hotline'
    },
    {
      label: 'Wangiri Toll Scam Phone',
      ip: '',
      website: '',
      email: '',
      phone: '+232 76 123456',
      desc: 'One-ring international toll fraud'
    },
    {
      label: 'C2 Beacon (Cobalt Strike)',
      ip: '45.142.214.8',
      website: 'c2-command.evil-corp.net',
      email: '',
      phone: '',
      desc: 'Known hacker control server'
    },
    {
      label: 'Safe Site (Google)',
      ip: '8.8.8.8',
      website: 'google.com',
      email: 'contact@google.com',
      phone: '',
      desc: 'Legitimate search engine'
    }
  ];

  const handleInspect = async (e) => {
    if (e) e.preventDefault();
    if (!ipAddress.trim() && !website.trim() && !email.trim() && !phoneNumber.trim()) {
      setErrorMsg('Please enter at least one target to inspect: an IP address, Website / URL, Email address, or Mobile number.');
      return;
    }

    setErrorMsg(null);
    setLoading(true);

    try {
      const res = await fetch(`http://${window.location.hostname}:8000/api/inspect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ip_address: ipAddress.trim() || undefined,
          website: website.trim() || undefined,
          email: email.trim() || undefined,
          phone_number: phoneNumber.trim() || undefined,
          port: parseInt(port, 10) || 443,
          protocol: protocol
        })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || 'Inspection failed');
      }

      const data = await res.json();
      setResult(data);
      if (onInspectionComplete && data.alerts && data.alerts.length > 0) {
        onInspectionComplete(data.alerts);
      }
    } catch (err) {
      console.error('Inspection error:', err);
      setErrorMsg(err.message || 'Inspection failed. Please ensure the backend server is running.');
    } finally {
      setLoading(false);
    }
  };

  const setSample = (sample) => {
    setIpAddress(sample.ip || '');
    setWebsite(sample.website || '');
    setEmail(sample.email || '');
    setPhoneNumber(sample.phone || '');
    setErrorMsg(null);
    setResult(null);
  };

  const clearForm = () => {
    setIpAddress('');
    setWebsite('');
    setEmail('');
    setPhoneNumber('');
    setErrorMsg(null);
    setResult(null);
  };

  return (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 mb-6 shadow-xl">
      {/* Top Header & Context */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-3 mb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-cyan-500/20 border border-cyan-500/40 rounded-xl text-cyan-400">
            <Search className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="text-sm font-bold text-white tracking-wide uppercase">
                Multi-Vector Threat Scanner & Manual Inspector
              </h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                IP • URL • EMAIL • PHONE
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Inspect any Wi-Fi IP address, website URL, suspicious email, or mobile phone number for cyber threats
            </p>
          </div>
        </div>

        {/* Why Can Threats Look Safe? Advisory Toggle Button */}
        <button
          type="button"
          onClick={() => setShowAdvisory(!showAdvisory)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-amber-950/40 text-amber-300 border border-amber-500/40 hover:bg-amber-900/40 transition-colors shrink-0 cursor-pointer"
        >
          <HelpCircle className="w-4 h-4 text-amber-400" />
          <span>Why Did a Threat Site / IP Test as Safe?</span>
          {showAdvisory ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>
      </div>

      {/* Educational Advisory Box: Answering the User's "How is it possible?" question */}
      {showAdvisory && (
        <div className="mb-5 p-4 rounded-xl bg-amber-950/20 border border-amber-500/40 text-xs text-amber-200/90 space-y-2.5 transition-all">
          <div className="flex items-center gap-2 font-bold text-amber-300 text-sm">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>Why Some Threat Websites & IPs Can Initially Test as "Safe" on Basic Scanners</span>
          </div>
          <p className="text-slate-300 leading-relaxed text-[11px]">
            If a known dangerous website or hacker IP was previously detected as "Clean / Safe", here is exactly why that happens in cybersecurity:
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="font-bold text-amber-400 block mb-1">1. Zero-Day & Newly Registered Domains</span>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Over 70% of phishing domains are active for less than 4 hours before being abandoned. Public blacklists (like Spamhaus or VirusTotal) have a latency of several hours before indexing them.
              </p>
            </div>
            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="font-bold text-amber-400 block mb-1">2. Lexical Camouflage & Dictionary Words</span>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Phishing sites use familiar dictionary terms (e.g. <code>microsoft-support-fix.xyz/claim</code>) rather than random gibberish, which keeps Shannon entropy normal and evades basic DGA filters.
              </p>
            </div>
            <div className="bg-slate-900/80 p-3 rounded-lg border border-slate-800">
              <span className="font-bold text-amber-400 block mb-1">3. Cloud Reverse Proxies (Fast-Flux)</span>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Attackers place domains behind Cloudflare or AWS proxies. A naive IP lookup returns Cloudflare's clean IP instead of the malicious server origin.
              </p>
            </div>
          </div>
          <p className="text-cyan-300 text-[11px] font-medium pt-1">
            ✨ Our upgraded Multi-Vector Engine now combines brand-spoofing NLP, high-risk TLD analysis, phishing path detection, email typosquatting, and toll fraud pattern scanning to detect threats instantly!
          </p>
        </div>
      )}

      {/* Quick Sample Targets */}
      <div className="flex flex-wrap items-center gap-1.5 text-xs mb-4 pb-3 border-b border-slate-800/80">
        <span className="text-slate-400 text-[11px] mr-1 font-medium">Quick Test Presets:</span>
        {sampleTargets.map((s, idx) => (
          <button
            key={idx}
            type="button"
            onClick={() => setSample(s)}
            className="px-2.5 py-1 bg-slate-900 hover:bg-slate-800 border border-slate-700 hover:border-cyan-500/50 rounded-md text-slate-300 text-[11px] transition-colors cursor-pointer"
          >
            {s.label}
          </button>
        ))}
        {(ipAddress || website || email || phoneNumber) && (
          <button
            type="button"
            onClick={clearForm}
            className="ml-auto text-[11px] text-slate-400 hover:text-red-400 transition-colors"
          >
            Clear Fields
          </button>
        )}
      </div>

      {/* Multi-Vector Inspection Form */}
      <form onSubmit={handleInspect} className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
          {/* Target IP Address Field */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1 flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-cyan-400" /> Target IP Address
              </span>
              <span className="text-[10px] text-slate-500">Wi-Fi or Host</span>
            </label>
            <input
              type="text"
              placeholder="e.g. 10.63.2.207 or 45.142.214.8"
              value={ipAddress}
              onChange={(e) => setIpAddress(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 focus:border-cyan-500 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none transition-colors"
            />
          </div>

          {/* Website / URL Field */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1 flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-emerald-400" /> Website / URL
              </span>
              <span className="text-[10px] text-slate-500">Domain or Link</span>
            </label>
            <input
              type="text"
              placeholder="e.g. http://microsoft-support-fix.xyz/claim"
              value={website}
              onChange={(e) => setWebsite(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 focus:border-emerald-500 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none transition-colors"
            />
          </div>

          {/* Suspicious Email Address Field */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1 flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <Mail className="w-3.5 h-3.5 text-purple-400" /> Suspicious Email
              </span>
              <span className="text-[10px] text-purple-400/80 font-normal">NEW</span>
            </label>
            <input
              type="text"
              placeholder="e.g. support@micros0ft-security.xyz"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 focus:border-purple-500 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none transition-colors"
            />
          </div>

          {/* Suspicious Mobile / Phone Number Field */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1 flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <PhoneCall className="w-3.5 h-3.5 text-amber-400" /> Mobile / Phone No.
              </span>
              <span className="text-[10px] text-amber-400/80 font-normal">NEW</span>
            </label>
            <input
              type="text"
              placeholder="e.g. +1 (800) 555-0199 or +232 76 123456"
              value={phoneNumber}
              onChange={(e) => setPhoneNumber(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 focus:border-amber-500 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none transition-colors"
            />
          </div>
        </div>

        {/* Scan Controls Row */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-1">
          <div className="flex items-center gap-3 text-xs text-slate-400 w-full sm:w-auto">
            <span className="text-slate-500 text-[11px]">Network Config:</span>
            <div className="flex items-center gap-1.5">
              <span>Port:</span>
              <input
                type="number"
                value={port}
                onChange={(e) => setPort(e.target.value)}
                className="w-16 bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs text-white"
              />
            </div>
            <div className="flex items-center gap-1.5">
              <span>Proto:</span>
              <select
                value={protocol}
                onChange={(e) => setProtocol(e.target.value)}
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs text-white"
              >
                <option value="TCP">TCP</option>
                <option value="UDP">UDP</option>
                <option value="DNS">DNS</option>
              </select>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full sm:w-auto bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold px-6 py-2.5 rounded-lg text-xs flex items-center justify-center gap-2 transition-all shadow-lg shadow-cyan-500/20 disabled:opacity-50 cursor-pointer"
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Analyzing Multi-Vector Threat Intelligence...
              </>
            ) : (
              <>
                <Search className="w-4 h-4" />
                Inspect & Scan All Target Vectors
              </>
            )}
          </button>
        </div>

        {errorMsg && (
          <div className="flex items-center gap-2 p-3 bg-red-950/50 border border-red-500/40 rounded-lg text-xs text-red-300">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}
      </form>

      {/* In-Detail Inspection Results Card */}
      {result && (
        <div className={`mt-6 p-5 rounded-xl border transition-all ${
          result.verdict.is_threat
            ? 'bg-red-950/30 border-red-500/50 shadow-xl shadow-red-500/10'
            : 'bg-emerald-950/30 border-emerald-500/50 shadow-xl shadow-emerald-500/10'
        }`}>
          {/* Header Row: Threat Verdict & In-Detail Breakdown Badge */}
          <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-4 pb-4 border-b border-slate-800/80">
            <div className="flex items-start gap-3.5">
              {result.verdict.is_threat ? (
                <div className="p-2.5 bg-red-500/20 border border-red-500 rounded-xl text-red-400 shrink-0 mt-0.5">
                  <ShieldAlert className="w-7 h-7 animate-pulse" />
                </div>
              ) : (
                <div className="p-2.5 bg-emerald-500/20 border border-emerald-500 rounded-xl text-emerald-400 shrink-0 mt-0.5">
                  <ShieldCheck className="w-7 h-7" />
                </div>
              )}
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`text-xs font-bold uppercase px-2.5 py-1 rounded-md tracking-wider ${
                    result.verdict.is_threat
                      ? 'bg-red-900/90 text-red-100 border border-red-500/50 shadow-sm'
                      : 'bg-emerald-900/90 text-emerald-100 border border-emerald-500/50 shadow-sm'
                  }`}>
                    {result.verdict.is_threat ? '⚠️ THREAT DETECTED' : '✅ CLEAN & SAFE'}
                  </span>

                  {result.verdict.is_threat && (
                    <span className="text-xs font-bold text-red-400 bg-red-950 px-2 py-0.5 rounded border border-red-900">
                      Confidence: {(result.verdict.confidence_score * 100).toFixed(0)}%
                    </span>
                  )}

                  {/* Entity Badges */}
                  {result.inspected_target.ip_classification?.is_wifi_lan && (
                    <span className="text-xs font-semibold px-2 py-0.5 rounded-md border bg-cyan-950/80 text-cyan-300 border-cyan-500/40 flex items-center gap-1">
                      <Wifi className="w-3.5 h-3.5" />
                      Wi-Fi / LAN IP
                    </span>
                  )}
                  {result.inspected_target.website !== 'N/A' && (
                    <span className="text-xs font-semibold px-2 py-0.5 rounded-md border bg-emerald-950/80 text-emerald-300 border-emerald-500/40 flex items-center gap-1">
                      <Globe className="w-3.5 h-3.5" />
                      Web URL
                    </span>
                  )}
                  {result.email_analysis && (
                    <span className="text-xs font-semibold px-2 py-0.5 rounded-md border bg-purple-950/80 text-purple-300 border-purple-500/40 flex items-center gap-1">
                      <Mail className="w-3.5 h-3.5" />
                      Email Verified
                    </span>
                  )}
                  {result.phone_analysis && (
                    <span className="text-xs font-semibold px-2 py-0.5 rounded-md border bg-amber-950/80 text-amber-300 border-amber-500/40 flex items-center gap-1">
                      <PhoneCall className="w-3.5 h-3.5" />
                      Phone Checked
                    </span>
                  )}
                </div>

                <div className="mt-3 p-3.5 rounded-xl bg-slate-900/90 border border-amber-500/40 shadow-md">
                  <div className="flex items-center gap-1.5 text-[11px] font-bold text-amber-300 uppercase tracking-wider mb-1">
                    <span>💡 Reason Explained (Like Telling a Kid):</span>
                  </div>
                  <p className="text-sm sm:text-base text-white font-semibold leading-relaxed">
                    {(() => {
                      const summary = result.verdict.kid_friendly_explanation || result.verdict.summary || '';
                      if (summary.includes('Shannon Entropy') || summary.includes('flow burst') || summary.includes('DDoS')) {
                        return 'A huge crowd of robot computers is shouting at our server all at once so nobody else can get in — just like 100 people trying to push through a tiny classroom door at the exact same second!';
                      }
                      if (summary.includes('inter-arrival') || summary.includes('C2')) {
                        return 'A secret bad program hiding inside is quietly whispering to a hacker\'s computer on a timer like a ticking clock, waiting for secret evil instructions.';
                      }
                      if (summary.includes('JA3') || summary.includes('Malware')) {
                        return 'A dangerous computer virus was caught trying to wear a fake disguise to sneak past the security guards.';
                      }
                      if (summary.includes('fan-out') || summary.includes('Scanning')) {
                        return 'A sneaky stranger is walking around trying to wiggle every single doorknob and window on our house to see if any door was left unlocked.';
                      }
                      if (summary.includes('asymmetric') || summary.includes('Exfiltration')) {
                        return 'Someone is sneaking out a giant backpack stuffed with private files and secret photos through the back door!';
                      }
                      return summary;
                    })()}
                  </p>

                  {/* Optional Technical Jargon Collapsible for Engineers */}
                  {result.alerts && result.alerts.length > 0 && result.alerts[0].supporting_evidence_feature?.technical_reason && (
                    <details className="mt-2 pt-2 border-t border-slate-800 text-[11px] text-slate-400 cursor-pointer">
                      <summary className="hover:text-cyan-300 transition-colors">
                        Show Technical Details (For Network Engineers)
                      </summary>
                      <div className="mt-1.5 p-2 bg-slate-950 rounded font-mono text-[11px] text-cyan-300 border border-slate-800">
                        {result.alerts[0].supporting_evidence_feature.technical_reason}
                      </div>
                    </details>
                  )}
                </div>
              </div>
            </div>

            {/* In-Detail Target Breakdown Box */}
            <div className="bg-slate-900/95 p-3.5 rounded-xl border border-slate-700/80 min-w-[300px] shrink-0 text-xs shadow-inner">
              <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-2 pb-1.5 border-b border-slate-800 flex items-center justify-between">
                <span>In-Detail Target Profile</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 font-medium">
                  {result.inspected_target.ip_classification?.is_wifi_lan ? 'Wi-Fi / LAN Subnet' : 'Internet'}
                </span>
              </div>
              <div className="space-y-1.5 font-mono text-[11px]">
                <div className="flex justify-between items-center gap-2">
                  <span className="text-slate-400 font-sans">Entity Type:</span>
                  <span className="font-semibold text-cyan-300 font-sans text-right">
                    {result.inspected_target.ip_classification?.is_wifi_lan
                      ? 'Wi-Fi IP Address'
                      : result.inspected_target.website !== 'N/A'
                        ? 'Website / Domain'
                        : 'Public Network Host'}
                  </span>
                </div>
                <div className="flex justify-between items-center gap-2">
                  <span className="text-slate-400 font-sans">IP Address:</span>
                  <span className="text-cyan-400 font-bold">{result.inspected_target.ip_address}</span>
                </div>
                <div className="flex justify-between items-center gap-2">
                  <span className="text-slate-400 font-sans">Website / URL:</span>
                  <span className={`truncate max-w-[180px] ${result.inspected_target.website !== 'N/A' ? 'text-emerald-400 font-bold' : 'text-slate-500'}`} title={result.inspected_target.website}>
                    {result.inspected_target.website}
                  </span>
                </div>
                {result.inspected_target.email !== 'N/A' && (
                  <div className="flex justify-between items-center gap-2">
                    <span className="text-slate-400 font-sans">Email Address:</span>
                    <span className="text-purple-300 font-bold truncate max-w-[180px]" title={result.inspected_target.email}>
                      {result.inspected_target.email}
                    </span>
                  </div>
                )}
                {result.inspected_target.phone_number !== 'N/A' && (
                  <div className="flex justify-between items-center gap-2">
                    <span className="text-slate-400 font-sans">Phone / Mobile:</span>
                    <span className="text-amber-300 font-bold">{result.inspected_target.phone_number}</span>
                  </div>
                )}
                <div className="flex justify-between items-center gap-2">
                  <span className="text-slate-400 font-sans">Port / Proto:</span>
                  <span className="text-slate-300">{result.inspected_target.port} / {result.inspected_target.protocol}</span>
                </div>
                <div className="flex justify-between items-center gap-2 pt-1.5 border-t border-slate-800/80">
                  <span className="text-slate-400 font-sans">Past Attacks:</span>
                  <span className={`font-bold font-sans ${result.previous_attacks_count > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                    {result.previous_attacks_count > 0 ? `${result.previous_attacks_count} Incident(s) Recorded` : '0 (Clean Record)'}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Grid of Vectors: Network Profile, Website Profile, Email Profile, Phone Profile */}
          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3.5">
            {/* 1. Network & IP Identification */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-200 uppercase tracking-wide mb-3">
                {result.inspected_target.ip_classification?.is_wifi_lan ? (
                  <Wifi className="w-4 h-4 text-cyan-400" />
                ) : (
                  <Server className="w-4 h-4 text-blue-400" />
                )}
                <span>Network & Wi-Fi IP Classification</span>
              </div>

              <div className="space-y-2 text-xs">
                <div className="flex items-start justify-between gap-2">
                  <span className="text-slate-400">Target Category:</span>
                  <span className="font-semibold text-slate-200 text-right">
                    {result.inspected_target.ip_classification?.category || 'Standard IPv4 Host'}
                  </span>
                </div>
                <div className="flex items-start justify-between gap-2">
                  <span className="text-slate-400">Network Scope:</span>
                  <span className={`font-medium px-2 py-0.5 rounded text-[11px] ${
                    result.inspected_target.ip_classification?.is_private
                      ? 'bg-cyan-950/70 text-cyan-300 border border-cyan-500/30'
                      : 'bg-blue-950/70 text-blue-300 border border-blue-500/30'
                  }`}>
                    {result.inspected_target.ip_classification?.scope || 'Public Internet'}
                    {result.inspected_target.ip_classification?.is_private && ' (Private / LAN)'}
                  </span>
                </div>
                <div className="flex items-start justify-between gap-2">
                  <span className="text-slate-400">Device Role:</span>
                  <span className="text-slate-300 text-right">
                    {result.inspected_target.ip_classification?.device_type || 'Network Node'}
                  </span>
                </div>
                <div className="flex items-start justify-between gap-2">
                  <span className="text-slate-400">Typical Usage:</span>
                  <span className="text-slate-300 text-right">
                    {result.inspected_target.ip_classification?.common_usage || 'Standard Network Traffic'}
                  </span>
                </div>
              </div>
            </div>

            {/* 2. Website & Domain Reputation */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-200 uppercase tracking-wide mb-3">
                <Globe className="w-4 h-4 text-emerald-400" />
                <span>Website & Phishing Heuristic Profile</span>
              </div>

              <div className="space-y-2 text-xs">
                <div className="flex items-start justify-between gap-2">
                  <span className="text-slate-400">Classification:</span>
                  <span className={`font-semibold text-right ${
                    result.inspected_target.website_classification?.category?.includes('Phishing')
                      ? 'text-red-400'
                      : 'text-slate-200'
                  }`}>
                    {result.inspected_target.website_classification?.category || 'Standard Internet Domain'}
                  </span>
                </div>
                <div className="flex items-start justify-between gap-2">
                  <span className="text-slate-400">Reputation Level:</span>
                  <span className={`font-medium px-2 py-0.5 rounded text-[11px] ${
                    result.inspected_target.website_classification?.reputation?.includes('Trusted')
                      ? 'bg-emerald-950/70 text-emerald-300 border border-emerald-500/30'
                      : result.inspected_target.website_classification?.reputation?.includes('Malicious')
                        ? 'bg-red-950/70 text-red-300 border border-red-500/30'
                        : 'bg-slate-800 text-slate-300'
                  }`}>
                    {result.inspected_target.website_classification?.reputation || 'Neutral'}
                  </span>
                </div>
                {result.inspected_target.website_classification?.reasons && (
                  <div className="pt-1 text-[11px] text-red-300/90 space-y-1">
                    {result.inspected_target.website_classification.reasons.map((r, i) => (
                      <div key={i} className="flex items-start gap-1.5">
                        <span className="text-red-400">•</span>
                        <span>{r}</span>
                      </div>
                    ))}
                  </div>
                )}
                {result.dns_analysis && (
                  <div className="flex items-start justify-between gap-2 pt-1 border-t border-slate-800">
                    <span className="text-slate-400">Shannon Entropy:</span>
                    <span className="text-cyan-300 font-mono font-medium">
                      {result.dns_analysis.entropy} ({result.dns_analysis.is_dga_pattern ? 'Algorithmic / DGA' : 'Natural Words'})
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* 3. Suspicious Email Security Profile (If email inspected) */}
            {result.email_analysis && (
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
                <div className="flex items-center justify-between gap-2 mb-3">
                  <div className="flex items-center gap-2 text-xs font-bold text-slate-200 uppercase tracking-wide">
                    <Mail className="w-4 h-4 text-purple-400" />
                    <span>Email Phishing & Spoof Analysis</span>
                  </div>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                    result.email_analysis.is_suspicious
                      ? 'bg-red-950 text-red-300 border border-red-500/40'
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-500/40'
                  }`}>
                    {result.email_analysis.is_suspicious ? 'HIGH RISK SENDER' : 'CLEAN SENDER'}
                  </span>
                </div>

                <div className="space-y-2 text-xs">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-slate-400">Sender Address:</span>
                    <span className="font-mono text-purple-300 font-semibold truncate max-w-[200px]">
                      {result.email_analysis.email_address}
                    </span>
                  </div>
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-slate-400">Threat Category:</span>
                    <span className="font-semibold text-slate-200">
                      {result.email_analysis.threat_category}
                    </span>
                  </div>
                  <div className="space-y-1 pt-1 border-t border-slate-800">
                    <span className="text-slate-400 block">Security Flags:</span>
                    {result.email_analysis.detected_reasons.map((r, i) => (
                      <div key={i} className="flex items-start gap-1.5 text-[11px] text-slate-300">
                        <span className={result.email_analysis.is_suspicious ? 'text-red-400' : 'text-emerald-400'}>•</span>
                        <span>{r}</span>
                      </div>
                    ))}
                  </div>
                  <div className="pt-2">
                    <span className="text-[10px] font-semibold text-purple-300 bg-purple-950/60 px-2 py-1 rounded block border border-purple-500/30">
                      {result.email_analysis.recommended_action}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* 4. Suspicious Mobile / Phone Profile (If phone inspected) */}
            {result.phone_analysis && (
              <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
                <div className="flex items-center justify-between gap-2 mb-3">
                  <div className="flex items-center gap-2 text-xs font-bold text-slate-200 uppercase tracking-wide">
                    <PhoneCall className="w-4 h-4 text-amber-400" />
                    <span>Phone Fraud & Smishing Analysis</span>
                  </div>
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                    result.phone_analysis.is_suspicious
                      ? 'bg-red-950 text-red-300 border border-red-500/40'
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-500/40'
                  }`}>
                    {result.phone_analysis.is_suspicious ? 'FRAUD / SCAM NUMBER' : 'LEGITIMATE NUMBER'}
                  </span>
                </div>

                <div className="space-y-2 text-xs">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-slate-400">Phone Number:</span>
                    <span className="font-mono text-amber-300 font-semibold">
                      {result.phone_analysis.phone_number}
                    </span>
                  </div>
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-slate-400">Origin / Type:</span>
                    <span className="text-slate-200 font-medium">
                      {result.phone_analysis.origin_country}
                    </span>
                  </div>
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-slate-400">Scam Category:</span>
                    <span className="font-semibold text-slate-200">
                      {result.phone_analysis.threat_category}
                    </span>
                  </div>
                  <div className="space-y-1 pt-1 border-t border-slate-800">
                    <span className="text-slate-400 block">Fraud Indicators:</span>
                    {result.phone_analysis.detected_reasons.map((r, i) => (
                      <div key={i} className="flex items-start gap-1.5 text-[11px] text-slate-300">
                        <span className={result.phone_analysis.is_suspicious ? 'text-red-400' : 'text-emerald-400'}>•</span>
                        <span>{r}</span>
                      </div>
                    ))}
                  </div>
                  <div className="pt-2">
                    <span className="text-[10px] font-semibold text-amber-300 bg-amber-950/60 px-2 py-1 rounded block border border-amber-500/30">
                      {result.phone_analysis.recommended_action}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Previous Attacks & Security Incidents Section */}
          <div className="mt-5 pt-4 border-t border-slate-800">
            <div className="flex items-center justify-between gap-2 mb-3">
              <div className="flex items-center gap-2">
                <History className="w-4 h-4 text-cyan-400" />
                <h3 className="text-xs font-bold text-white uppercase tracking-wider">
                  Previous Recorded Attacks & Security Incidents
                </h3>
              </div>
              <span className={`text-[11px] font-bold px-2 py-0.5 rounded-full border ${
                result.previous_attacks_count > 0
                  ? 'bg-red-950 text-red-300 border-red-500/40'
                  : 'bg-emerald-950 text-emerald-300 border-emerald-500/40'
              }`}>
                {result.previous_attacks_count > 0 ? `${result.previous_attacks_count} Attack(s) Matched` : 'Clean History'}
              </span>
            </div>

            {result.previous_attacks && result.previous_attacks.length > 0 ? (
              <div className="space-y-2.5">
                {result.previous_attacks.map((atk, idx) => (
                  <div
                    key={idx}
                    className="bg-slate-900/95 border border-slate-800 hover:border-slate-700 rounded-xl p-3.5 transition-all text-xs"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2 pb-2 border-b border-slate-800/80">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider ${
                          atk.severity === 'CRITICAL'
                            ? 'bg-red-500/20 text-red-300 border border-red-500/50'
                            : atk.severity === 'HIGH'
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/50'
                              : 'bg-blue-500/20 text-blue-300 border border-blue-500/50'
                        }`}>
                          {atk.severity} SEVERITY
                        </span>
                        <span className="font-bold text-white text-sm">
                          {atk.attack_type}
                        </span>
                      </div>

                      <div className="flex items-center gap-3 text-slate-400 text-[11px]">
                        {atk.date && (
                          <span className="flex items-center gap-1">
                            <Calendar className="w-3.5 h-3.5 text-slate-500" />
                            {atk.date}
                          </span>
                        )}
                        {atk.target_sector && (
                          <span className="flex items-center gap-1 text-slate-300">
                            <Building2 className="w-3.5 h-3.5 text-cyan-500" />
                            Target: {atk.target_sector}
                          </span>
                        )}
                      </div>
                    </div>

                    <p className="text-slate-300 leading-relaxed">
                      {atk.description}
                    </p>
                  </div>
                ))}
              </div>
            ) : (
              <div className="flex items-center gap-3 p-3.5 bg-slate-900/60 border border-slate-800 rounded-xl text-xs text-slate-300">
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                <div>
                  <p className="font-semibold text-emerald-300">No Previous Recorded Attacks (Clean History)</p>
                  <p className="text-slate-400 text-[11px] mt-0.5">
                    This target IP address, website, or entity has no prior recorded security incidents or blacklist records in the threat database.
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
