import React, { useState } from 'react';
import { Download, RefreshCw, Layers, ShieldCheck, AlertTriangle } from 'lucide-react';
import ScoreGauge from '../components/ScoreGauge';
import ProtocolChart from '../components/ProtocolChart';
import TlsVersionChart from '../components/TlsVersionChart';
import CipherChart from '../components/CipherChart';
import CertChainView from '../components/CertChainView';
import FindingsList from '../components/FindingsList';
import SessionTable from '../components/SessionTable';
import SessionDrawer from '../components/SessionDrawer';
import ExportModal from '../components/ExportModal';

export default function Dashboard({ currentJob, sessions = [], findings = [], certificates = [], onRefresh }) {
  const [selectedSession, setSelectedSession] = useState(null);
  const [showExportModal, setShowExportModal] = useState(false);

  if (!currentJob) {
    return (
      <div className="cyber-card p-12 text-center border border-slate-800 my-8">
        <Layers className="w-12 h-12 text-slate-600 mx-auto mb-3" />
        <h3 className="text-base font-bold text-slate-300">No Capture Analyzed Yet</h3>
        <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
          Please upload a PCAP file or select a pre-generated test matrix scenario from the Upload & Lab tab to view the live dashboard.
        </p>
      </div>
    );
  }

  const assessment = currentJob.summary_data?.assessment || currentJob.summary || {};
  const score = currentJob.overall_score ?? assessment.overall_score ?? 100;
  const riskLevel = currentJob.overall_risk_level || assessment.overall_risk_level || 'SECURE';
  const grade = currentJob.security_grade || assessment.security_grade || 'A+';
  const fsRatio = assessment.forward_secrecy_ratio ?? 0.0;

  return (
    <div className="space-y-6">
      
      {/* Top Action Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-2">
        <div>
          <span className="text-[11px] font-bold text-cyan-400 uppercase tracking-wider font-mono">Live Posture Telemetry</span>
          <h2 className="text-xl font-extrabold text-white">{currentJob.filename}</h2>
        </div>

        <div className="flex items-center space-x-2">
          {onRefresh && (
            <button
              onClick={onRefresh}
              className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white hover:border-slate-700 transition-colors"
              title="Refresh Assessment"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          )}

          <button
            onClick={() => setShowExportModal(true)}
            className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center space-x-1.5 shadow-md shadow-cyan-500/20 transition-all"
          >
            <Download className="w-4 h-4" />
            <span>Export Report (PDF/HTML/JSON)</span>
          </button>
        </div>
      </div>

      {/* 1. Master Score Gauge */}
      <ScoreGauge
        score={score}
        riskLevel={riskLevel}
        grade={grade}
        totalSessions={sessions.length}
        totalFindings={findings.length}
        fsRatio={fsRatio}
      />

      {/* 2. Cryptographic Distribution Charts Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <ProtocolChart protocolCounts={assessment.protocol_counts || {}} />
        <TlsVersionChart tlsCounts={assessment.tls_version_counts || {}} />
        <CipherChart cipherCounts={assessment.cipher_counts || {}} />
      </div>

      {/* 3. Full X.509 Chain-of-Trust Hierarchy */}
      <CertChainView certificates={certificates} />

      {/* 4. Identified Vulnerabilities & Findings Accordion */}
      <FindingsList findings={findings} />

      {/* 5. Reassembled TCP Sessions Stream Table */}
      <SessionTable sessions={sessions} onSelectSession={(s) => setSelectedSession(s)} />

      {/* Session Deep Inspector Drawer */}
      {selectedSession && (
        <SessionDrawer session={selectedSession} onClose={() => setSelectedSession(null)} />
      )}

      {/* Export Reports Modal */}
      {showExportModal && (
        <ExportModal
          jobId={currentJob.id || currentJob.analysis_id}
          filename={currentJob.filename}
          onClose={() => setShowExportModal(false)}
        />
      )}

    </div>
  );
}
