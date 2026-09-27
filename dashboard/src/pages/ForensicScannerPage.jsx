import React from 'react';
import ManualInspectionPanel from '../components/ManualInspectionPanel';
import { Search, UploadCloud, Shield, FileText, ArrowRight, Activity, CheckCircle, Database } from 'lucide-react';

export default function ForensicScannerPage({
  onInspectionComplete,
  onOpenUpload,
  onNavigateToTab
}) {
  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#23324d]/60">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="p-1.5 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
              <Search className="w-5 h-5" />
            </span>
            <h2 className="text-xl font-bold text-slate-100 tracking-tight">
              Target Inspection & Forensic Ingestion
            </h2>
            <span className="px-2.5 py-0.5 text-xs font-mono font-medium rounded-full bg-purple-950/60 text-purple-400 border border-purple-800/40">
              Forensic Suite
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Conduct on-demand passive mathematical inspection of target endpoints or ingest PCAP / Zeek logs for offline threat classification.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5">
          <button
            onClick={onOpenUpload}
            className="flex items-center gap-1.5 px-3.5 py-1.5 bg-sky-500 hover:bg-sky-400 text-slate-950 rounded-lg text-xs font-semibold shadow-sm transition-colors"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            <span>Upload PCAP / Zeek Logs</span>
          </button>
          <button
            onClick={() => onNavigateToTab('monitor')}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-sky-300 bg-[#151f32] hover:bg-slate-800 border border-[#23324d] rounded-lg transition-colors"
          >
            <Activity className="w-3.5 h-3.5 text-sky-400" />
            <span>Live Monitor</span>
          </button>
        </div>
      </div>

      {/* Forensic Ingestion Quick Banner */}
      <div className="bg-gradient-to-r from-[#151f32] to-[#0e1726] border border-[#23324d] rounded-xl p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-sky-500/10 border border-sky-500/20 rounded-lg text-sky-400">
            <Database className="w-5 h-5" />
          </div>
          <div>
            <h4 className="text-xs font-semibold text-slate-100">
              Passive Metadata Ingestion Capabilities
            </h4>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Supports live network streaming sockets, Zeek TSV files (<span className="font-mono text-sky-300">conn.log</span>, <span className="font-mono text-sky-300">dns.log</span>, <span className="font-mono text-sky-300">ssl.log</span>), and Scapy PCAP byte parsers.
            </p>
          </div>
        </div>

        <button
          onClick={onOpenUpload}
          className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-sky-400 bg-sky-950/60 hover:bg-sky-900/60 border border-sky-800/60 rounded-lg transition-colors shrink-0"
        >
          <span>Batch Log Analysis</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Target IP & Website Deep Scanner */}
      <ManualInspectionPanel onInspectionComplete={onInspectionComplete} />
    </div>
  );
}
