import React from 'react';
import UploadZone from '../components/UploadZone';
import { Shield, Sparkles, CheckCircle2, AlertTriangle, Layers, Cpu } from 'lucide-react';

export default function UploadPage({ onAnalysisComplete }) {
  return (
    <div className="max-w-4xl mx-auto space-y-8 py-4">
      
      {/* Intro Header */}
      <div className="text-center space-y-2">
        <h1 className="text-3xl font-extrabold text-white tracking-tight">
          Network Traffic Capture & Vulnerability Analyzer
        </h1>
        <p className="text-xs text-slate-400 max-w-xl mx-auto">
          Upload PCAP/PCAPNG email traffic captures or run automated synthetic test scenarios to evaluate cryptographic protocol compliance, cipher security, and certificate chains.
        </p>
      </div>

      {/* Main Upload Area */}
      <UploadZone onAnalysisComplete={onAnalysisComplete} />

      {/* Features Overview */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1.5">
          <div className="flex items-center space-x-2 text-cyan-400 font-bold">
            <Shield className="w-4 h-4" />
            <span>Full X.509 Chain Verification</span>
          </div>
          <p className="text-slate-400 text-[11px]">
            Cryptographically validates certificate signatures from Leaf to Intermediate to Root Trust Anchors.
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1.5">
          <div className="flex items-center space-x-2 text-emerald-400 font-bold">
            <Layers className="w-4 h-4" />
            <span>Multi-Protocol Deep Inspection</span>
          </div>
          <p className="text-slate-400 text-[11px]">
            Covers SMTP, IMAP, POP3, SMTPS, IMAPS, POP3S, and tracks plaintext STARTTLS handshakes.
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1.5">
          <div className="flex items-center space-x-2 text-purple-400 font-bold">
            <Cpu className="w-4 h-4" />
            <span>Dual-Model Machine Learning</span>
          </div>
          <p className="text-slate-400 text-[11px]">
            Random Forest cryptographic posture classification paired with Isolation Forest behavioral anomaly detection.
          </p>
        </div>
      </div>

    </div>
  );
}
