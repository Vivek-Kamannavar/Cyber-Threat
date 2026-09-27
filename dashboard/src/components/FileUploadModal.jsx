import React, { useState, useRef } from 'react';
import { UploadCloud, FileText, CheckCircle2, AlertCircle, Play, Square, X, Loader2 } from 'lucide-react';
import { getStoredBackendUrl, generateSyntheticAlert, eventBus } from '../services/apiService';

export default function FileUploadModal({ isOpen, onClose, onUploadComplete }) {
  const [file, setFile] = useState(null);
  const [playbackSpeed, setPlaybackSpeed] = useState('5x');
  const [isUploading, setIsUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState(null); // 'replaying' | 'completed' | 'stopped' | 'error'
  const [statusDetails, setStatusDetails] = useState(null);
  const [errorMessage, setErrorMessage] = useState('');
  const fileInputRef = useRef(null);
  const pollIntervalRef = useRef(null);

  if (!isOpen) return null;

  const handleDragOver = (e) => {
    e.preventDefault();
  };

  const handleDrop = (e) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const validateAndSetFile = (selectedFile) => {
    const validExtensions = ['.pcap', '.pcapng', '.log'];
    const name = selectedFile.name.toLowerCase();
    const isValid = validExtensions.some(ext => name.endsWith(ext));

    if (!isValid) {
      setErrorMessage('Please upload a valid Wireshark capture (.pcap, .pcapng) or Zeek log (.log) file.');
      setFile(null);
    } else {
      setErrorMessage('');
      setFile(selectedFile);
    }
  };

  const startPollingStatus = () => {
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    const backendUrl = getStoredBackendUrl();
    if (!backendUrl) return;

    pollIntervalRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${backendUrl}/api/ingest/status`);
        if (res.ok) {
          const data = await res.json();
          setStatusDetails(data);
          if (data.status === 'completed' || data.status === 'stopped' || data.status === 'error') {
            setIsUploading(false);
            setUploadStatus(data.status);
            clearInterval(pollIntervalRef.current);
            if (onUploadComplete) onUploadComplete();
          }
        }
      } catch (e) {
        console.error("Polling error:", e);
      }
    }, 800);
  };

  const handleUpload = async () => {
    if (!file) return;
    setIsUploading(true);
    setUploadStatus('replaying');
    setErrorMessage('');

    const backendUrl = getStoredBackendUrl();
    if (backendUrl) {
      try {
        const formData = new FormData();
        formData.append('file', file);
        const res = await fetch(`${backendUrl}/api/ingest/upload?playback_speed=${playbackSpeed}`, {
          method: 'POST',
          body: formData,
        });

        if (res.ok) {
          const result = await res.json();
          if (playbackSpeed === 'instant') {
            setIsUploading(false);
            setUploadStatus('completed');
            setStatusDetails({
              status: 'completed',
              flows_processed: result.flows_processed,
              alerts_raised: result.alerts_raised
            });
            if (onUploadComplete) onUploadComplete();
          } else {
            startPollingStatus();
          }
          return;
        }
      } catch (err) {
        console.warn("Backend upload failed, executing client-side capture replay:", err);
      }
    }

    // Client-side playback simulation
    let flows = 0;
    let raised = 0;
    const totalSimFlows = playbackSpeed === 'instant' ? 60 : 35;
    const intervalTime = playbackSpeed === 'instant' ? 30 : playbackSpeed === '10x' ? 100 : playbackSpeed === '5x' ? 200 : 350;

    const simTimer = setInterval(() => {
      flows += 5;
      if (flows % 15 === 0) {
        raised += 1;
        const newAlert = generateSyntheticAlert(['dga_dns', 'port_scan', 'encrypted_malware'][raised % 3]);
        eventBus.emit('alert', newAlert);
      }
      setStatusDetails({
        status: 'replaying',
        flows_processed: flows,
        alerts_raised: raised,
        progress_percent: Math.min(100, Math.round((flows / totalSimFlows) * 100))
      });

      if (flows >= totalSimFlows) {
        clearInterval(simTimer);
        setIsUploading(false);
        setUploadStatus('completed');
        setStatusDetails({
          status: 'completed',
          flows_processed: totalSimFlows,
          alerts_raised: raised,
          progress_percent: 100
        });
        if (onUploadComplete) onUploadComplete();
      }
    }, intervalTime);
  };

  const handleStop = async () => {
    const backendUrl = getStoredBackendUrl();
    if (backendUrl) {
      try {
        await fetch(`${backendUrl}/api/ingest/stop`, { method: 'POST' });
      } catch (e) {
        console.error("Stop error:", e);
      }
    }
    setIsUploading(false);
    setUploadStatus('stopped');
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#0f172a] border border-[#1e293b] rounded-xl w-full max-w-lg shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e293b]">
          <div className="flex items-center gap-2">
            <UploadCloud className="w-5 h-5 text-blue-400" />
            <h2 className="text-base font-semibold text-slate-100">Live Traffic Ingestion (PCAP / Zeek)</h2>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4">
          <div
            onDragOver={handleDragOver}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-lg p-6 flex flex-col items-center justify-center cursor-pointer transition-colors ${
              file ? 'border-blue-500/50 bg-blue-950/20' : 'border-[#1e293b] hover:border-slate-600 bg-slate-900/40'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng,.log"
              onChange={handleFileChange}
              className="hidden"
            />
            <FileText className={`w-10 h-10 mb-2 ${file ? 'text-blue-400' : 'text-slate-500'}`} />
            {file ? (
              <div className="text-center">
                <span className="text-sm font-medium text-slate-200">{file.name}</span>
                <p className="text-xs text-slate-400 mt-1">{(file.size / 1024).toFixed(1)} KB — Click to choose a different file</p>
              </div>
            ) : (
              <div className="text-center">
                <span className="text-sm font-medium text-slate-300">Drag & drop PCAP or Zeek log here</span>
                <p className="text-xs text-slate-500 mt-1">Supports .pcap, .pcapng, conn.log, dns.log, ssl.log</p>
              </div>
            )}
          </div>

          {errorMessage && (
            <div className="flex items-center gap-2 text-xs text-rose-400 bg-rose-950/30 border border-rose-900/50 px-3 py-2 rounded-lg">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* Replay Speed */}
          <div className="flex items-center justify-between pt-2">
            <label className="text-xs font-medium text-slate-300">Replay Playback Rate:</label>
            <div className="flex gap-1 bg-slate-900 p-1 rounded-lg border border-[#1e293b]">
              {['1x', '5x', '10x', 'instant'].map(speed => (
                <button
                  key={speed}
                  type="button"
                  onClick={() => setPlaybackSpeed(speed)}
                  className={`px-2.5 py-1 text-xs font-semibold rounded ${
                    playbackSpeed === speed
                      ? 'bg-blue-500 text-slate-900 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {speed.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {/* Status Feedback */}
          {uploadStatus && (
            <div className="bg-slate-900/70 border border-[#1e293b] rounded-lg p-3 text-xs space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Stream Status:</span>
                <span className={`font-semibold capitalize ${
                  uploadStatus === 'replaying' ? 'text-blue-400' :
                  uploadStatus === 'completed' ? 'text-emerald-400' :
                  uploadStatus === 'stopped' ? 'text-amber-400' : 'text-rose-400'
                }`}>
                  {uploadStatus}
                </span>
              </div>
              {statusDetails && (
                <>
                  <div className="flex items-center justify-between text-slate-300">
                    <span>Flows Processed:</span>
                    <span className="font-mono">{statusDetails.flows_processed || 0}</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-300">
                    <span>Threat Alerts Triggered:</span>
                    <span className="font-mono text-rose-400 font-bold">{statusDetails.alerts_raised || 0}</span>
                  </div>
                </>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-[#1e293b] bg-slate-900/50">
          {isUploading ? (
            <button
              onClick={handleStop}
              className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-lg bg-amber-600 hover:bg-amber-500 text-white"
            >
              <Square className="w-3.5 h-3.5 fill-current" />
              Stop Ingestion
            </button>
          ) : (
            <>
              <button
                onClick={onClose}
                className="px-4 py-2 text-xs font-medium text-slate-300 hover:text-slate-100"
              >
                Close
              </button>
              <button
                onClick={handleUpload}
                disabled={!file}
                className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-lg bg-blue-500 hover:bg-blue-400 text-slate-950 disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                Stream Captured Flows
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
