import React from 'react';
import { X, FileText, FileCode, FileSpreadsheet, Download, CheckCircle2 } from 'lucide-react';
import { api } from '../services/api';

export default function ExportModal({ jobId, filename, onClose }) {
  if (!jobId) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-dark-800 border border-slate-700 w-full max-w-md rounded-2xl shadow-2xl overflow-hidden">
        
        {/* Header */}
        <div className="p-5 bg-dark-900 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Download className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold text-white">Export Audit Report</h3>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Formats Grid */}
        <div className="p-6 space-y-3 text-xs">
          <p className="text-slate-400 mb-4">
            Download full cryptographic posture assessment and vulnerability findings for capture <span className="font-mono text-cyan-400 font-bold">{filename}</span>:
          </p>

          {/* 1. PDF Report */}
          <a
            href={api.getExportUrl(jobId, 'pdf')}
            target="_blank"
            rel="noreferrer"
            className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-800/80 flex items-center justify-between transition-all group"
          >
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg bg-rose-950/80 text-rose-400 border border-rose-800">
                <FileText className="w-5 h-5" />
              </div>
              <div>
                <h4 className="font-bold text-white text-sm group-hover:text-cyan-400 transition-colors">Executive PDF Audit Report</h4>
                <p className="text-slate-500 text-[11px]">Formatted with tables, score gauges, findings & remediations</p>
              </div>
            </div>
            <Download className="w-4 h-4 text-slate-400 group-hover:text-cyan-400" />
          </a>

          {/* 2. HTML Report */}
          <a
            href={api.getExportUrl(jobId, 'html')}
            target="_blank"
            rel="noreferrer"
            className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-800/80 flex items-center justify-between transition-all group"
          >
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg bg-blue-950/80 text-blue-400 border border-blue-800">
                <FileCode className="w-5 h-5" />
              </div>
              <div>
                <h4 className="font-bold text-white text-sm group-hover:text-cyan-400 transition-colors">Interactive HTML Report</h4>
                <p className="text-slate-500 text-[11px]">Standalone offline web report with interactive drawers</p>
              </div>
            </div>
            <Download className="w-4 h-4 text-slate-400 group-hover:text-cyan-400" />
          </a>

          {/* 3. JSON Audit Export */}
          <a
            href={api.getExportUrl(jobId, 'json')}
            target="_blank"
            rel="noreferrer"
            className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-800/80 flex items-center justify-between transition-all group"
          >
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg bg-emerald-950/80 text-emerald-400 border border-emerald-800">
                <FileSpreadsheet className="w-5 h-5" />
              </div>
              <div>
                <h4 className="font-bold text-white text-sm group-hover:text-cyan-400 transition-colors">Structured JSON Export</h4>
                <p className="text-slate-500 text-[11px]">Machine-readable audit data and session telemetry</p>
              </div>
            </div>
            <Download className="w-4 h-4 text-slate-400 group-hover:text-cyan-400" />
          </a>
        </div>

        {/* Footer */}
        <div className="p-4 bg-dark-900 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-bold rounded-lg text-xs transition-colors"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
}
