import React, { useState, useRef } from 'react';
import { UploadCloud, FileText, CheckCircle2, AlertCircle, Play, Square, X, Loader2 } from 'lucide-react';

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
    pollIntervalRef.current = setInterval(async () => {
      try {
        const res = await fetch('http://127.0.0.1:8000/api/ingest/status');
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

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch(`http://127.0.0.1:8000/api/ingest/upload?playback_speed=${playbackSpeed}`, {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Upload failed');
      }

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
    } catch (err) {
      setIsUploading(false);
      setUploadStatus('error');
      setErrorMessage(err.message || 'Error uploading file');
    }
  };

  const handleStop = async () => {
    try {
      await fetch('http://127.0.0.1:8000/api/ingest/stop', { method: 'POST' });
      setIsUploading(false);
      setUploadStatus('stopped');
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current);
    } catch (e) {
      console.error("Stop error:", e);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#151f32] border border-[#23324d] rounded-xl w-full max-w-lg shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#23324d]">
          <div className="flex items-center gap-2">
            <UploadCloud className="w-5 h-5 text-sky-400" />
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
              file ? 'border-sky-500/50 bg-sky-950/20' : 'border-[#23324d] hover:border-slate-600 bg-slate-900/40'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng,.log"
              onChange={handleFileChange}
              className="hidden"
            />
            <FileText className={`w-10 h-10 mb-2 ${file ? 'text-sky-400' : 'text-slate-500'}`} />
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
            <div className="flex gap-1 bg-slate-900 p-1 rounded-lg border border-[#23324d]">
              {['1x', '5x', '10x', 'instant'].map(speed => (
                <button
                  key={speed}
                  type="button"
                  onClick={() => setPlaybackSpeed(speed)}
                  className={`px-2.5 py-1 text-xs font-semibold rounded ${
                    playbackSpeed === speed
                      ? 'bg-sky-500 text-slate-900 shadow-sm'
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
            <div className="bg-slate-900/70 border border-[#23324d] rounded-lg p-3 text-xs space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Stream Status:</span>
                <span className={`font-semibold capitalize ${
                  uploadStatus === 'replaying' ? 'text-sky-400' :
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
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-[#23324d] bg-slate-900/50">
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
                className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-lg bg-sky-500 hover:bg-sky-400 text-slate-950 disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
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
