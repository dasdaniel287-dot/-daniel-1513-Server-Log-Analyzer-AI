import React, { useState, useRef } from 'react';
import { Upload, FileText, X, AlertCircle } from 'lucide-react';

interface UploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAnalyze: (rawText: string) => void;
}

export const UploadModal: React.FC<UploadModalProps> = ({ isOpen, onClose, onAnalyze }) => {
  const [text, setText] = useState<string>('');
  const [fileName, setFileName] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  if (!isOpen) return null;

  const handleFileUpload = (file: File) => {
    // 25MB safety boundary for browser file reader
    if (file.size > 25 * 1024 * 1024) {
      setErrorMsg('File exceeds 25MB limit. Please upload chunks or use streaming mode.');
      return;
    }

    setFileName(file.name);
    setErrorMsg(null);

    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      setText(content);
    };
    reader.onerror = () => {
      setErrorMsg('Failed to read file contents.');
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const handleSubmit = () => {
    if (!text.trim()) {
      setErrorMsg('Please paste or upload log content to analyze.');
      return;
    }
    onAnalyze(text);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Upload className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-100">
              Ingest & Analyze Server Logs
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 text-slate-400 hover:text-slate-200 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 overflow-y-auto space-y-4">
          {/* File Dropzone */}
          <div
            onDragOver={(e) => e.preventDefault()}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className="p-6 border-2 border-dashed border-slate-800 hover:border-cyan-500/60 bg-slate-950/60 rounded-xl flex flex-col items-center justify-center cursor-pointer transition-colors text-center"
          >
            <FileText className="w-8 h-8 text-slate-500 mb-2" />
            <div className="text-xs font-semibold text-slate-200">
              {fileName ? fileName : 'Drag & drop server log file here, or click to browse'}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              Supports .log, .txt, .json, .csv (Syslog, Nginx, Apache, Auth, Python, Windows)
            </div>
            <input
              ref={fileInputRef}
              type="file"
              accept=".log,.txt,.json,.csv"
              onChange={(e) => {
                if (e.target.files && e.target.files[0]) {
                  handleFileUpload(e.target.files[0]);
                }
              }}
              className="hidden"
            />
          </div>

          <div className="flex items-center gap-3 text-xs text-slate-500">
            <span className="flex-1 border-b border-slate-800" />
            <span>OR PASTE RAW LOG ENTRIES DIRECTLY</span>
            <span className="flex-1 border-b border-slate-800" />
          </div>

          {/* Textarea */}
          <div>
            <textarea
              rows={8}
              value={text}
              onChange={(e) => {
                setText(e.target.value);
                setErrorMsg(null);
              }}
              placeholder="Paste raw log lines here..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500 leading-relaxed placeholder-slate-600"
            />
            {text && (
              <div className="text-[11px] text-slate-500 mt-1 font-mono">
                {text.split(/\r?\n/).filter((l) => l.trim().length > 0).length} lines ready for parsing
              </div>
            )}
          </div>

          {errorMsg && (
            <div className="p-3 bg-rose-950/40 border border-rose-900 rounded-lg text-rose-300 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <span className="text-[11px] text-slate-500">
            Input data is processed in-memory and sanitized automatically.
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-3.5 py-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleSubmit}
              className="px-4 py-2 bg-cyan-400 hover:bg-cyan-300 text-slate-950 font-semibold rounded-lg text-xs transition-colors shadow-sm"
            >
              Start Analysis Engine
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
