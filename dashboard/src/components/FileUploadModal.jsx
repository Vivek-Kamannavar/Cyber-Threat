import React, { useState, useRef } from 'react';
import { UploadCloud, FileText, AlertCircle, Play, Square, X } from 'lucide-react';

export default function FileUploadModal({ isOpen, onClose, onUploadComplete }) {
  const [file, setFile] = useState(null);
  const [playbackSpeed, setPlaybackSpeed] = useState('5x');
  const [isUploading, setIsUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState(null);
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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="bg-[#FFF1D1] border border-black rounded-lg w-full max-w-md shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 bg-[#FFF1D1] border-b border-black">
          <div className="flex items-center gap-2 text-black">
            <UploadCloud className="w-4 h-4 text-[#00B7CD]" />
            <h2 className="text-xs font-bold uppercase tracking-tight">Capture Ingest (PCAP / Zeek)</h2>
          </div>
          <button 
            onClick={onClose} 
            className="p-1 rounded border border-black text-black bg-[#FFF1D1] transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content */}
        <div className="p-4 space-y-3.5 text-black">
          <div
            onDragOver={handleDragOver}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className="border-2 border-dashed border-black rounded-lg p-5 flex flex-col items-center justify-center cursor-pointer bg-[#FFF1D1]"
          >
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng,.log"
              onChange={handleFileChange}
              className="hidden"
            />
            <FileText className={`w-8 h-8 mb-2 ${file ? 'text-[#00B7CD]' : 'text-black'}`} />
            {file ? (
              <div className="text-center">
                <span className="text-xs font-bold text-black">{file.name}</span>
                <p className="text-[11px] text-black font-normal mt-0.5">{(file.size / 1024).toFixed(1)} KB (Ready to Stream)</p>
              </div>
            ) : (
              <div className="text-center">
                <span className="text-xs font-bold text-black">Click or drag PCAP or Zeek file</span>
                <p className="text-[11px] text-black font-normal mt-0.5">Supports .pcap, .pcapng, and conn.log</p>
              </div>
            )}
          </div>

          {errorMessage && (
            <div className="flex items-center gap-2 text-xs text-black bg-[#FFF1D1] border-2 border-[#DF301C] p-2.5 rounded-lg font-normal">
              <AlertCircle className="w-4 h-4 text-[#DF301C] shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* Replay Speed */}
          <div className="flex items-center justify-between text-xs font-normal">
            <span className="text-black">Playback Rate:</span>
            <div className="flex border border-black rounded overflow-hidden">
              {['1x', '5x', '10x', 'instant'].map(speed => (
                <button
                  key={speed}
                  type="button"
                  onClick={() => setPlaybackSpeed(speed)}
                  className={`px-2 py-0.5 text-xs transition-colors ${
                    playbackSpeed === speed
                      ? 'bg-black text-[#FFF1D1] font-bold'
                      : 'text-black bg-[#FFF1D1] font-normal'
                  }`}
                >
                  {speed.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          {/* Status Feedback */}
          {uploadStatus && (
            <div className="bg-[#FFF1D1] border border-black rounded-lg p-3 text-xs space-y-1.5 font-normal">
              <div className="flex items-center justify-between">
                <span className="text-black">Status:</span>
                <span className={`font-bold uppercase ${uploadStatus === 'error' ? 'text-[#DF301C]' : 'text-black'}`}>
                  {uploadStatus}
                </span>
              </div>
              {statusDetails && (
                <>
                  <div className="flex items-center justify-between text-black">
                    <span>Flows Processed:</span>
                    <span className="font-bold text-black">{statusDetails.flows_processed || 0}</span>
                  </div>
                  <div className="flex items-center justify-between text-black">
                    <span>Alerts Raised:</span>
                    <span className="font-bold text-[#DF301C]">{statusDetails.alerts_raised || 0}</span>
                  </div>
                </>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 px-4 py-3 border-t border-black bg-[#FFF1D1]">
          {isUploading ? (
            <button
              onClick={handleStop}
              className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-bold rounded bg-[#DF301C] text-[#FFF1D1] border border-black transition-colors"
            >
              <Square className="w-3.5 h-3.5 fill-current" />
              Stop Ingest
            </button>
          ) : (
            <>
              <button
                onClick={onClose}
                className="px-3 py-1.5 text-xs font-normal border border-black text-black bg-[#FFF1D1] rounded transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleUpload}
                disabled={!file}
                className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-bold rounded bg-[#00B7CD] text-black border border-black transition-colors disabled:opacity-40"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                Stream Flows
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
