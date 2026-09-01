import React, { useState, useRef } from 'react';
import { UploadCloud, FileCheck, AlertCircle, Loader2, Play, Sparkles, CheckCircle2 } from 'lucide-react';
import { api } from '../services/api';

const SAMPLE_SCENARIOS = [
  { id: '04_smtps_tls13_ecdhe_secure.pcap', name: '04. SMTPS TLS 1.3 + ECDHE (Secure Posture)', risk: 'SECURE' },
  { id: '17_smtps_full_3tier_valid_chain.pcap', name: '17. SMTPS Full 3-Tier Valid Chain (Root->Inter->Leaf)', risk: 'SECURE' },
  { id: '01_smtp_plaintext.pcap', name: '01. Plaintext SMTP Unencrypted (High Risk)', risk: 'HIGH' },
  { id: '02_imap_plaintext_auth.pcap', name: '02. Plaintext IMAP Auth Credential Leak (Critical)', risk: 'CRITICAL' },
  { id: '03_pop3_plaintext_auth.pcap', name: '03. Plaintext POP3 Auth Credential Leak (Critical)', risk: 'CRITICAL' },
  { id: '07_smtp_starttls_upgrade.pcap', name: '07. SMTP STARTTLS Upgrade Handshake', risk: 'SECURE' },
  { id: '10_smtps_tls10_deprecated.pcap', name: '10. SMTPS Deprecated TLS 1.0 (High Risk)', risk: 'HIGH' },
  { id: '12_smtp_rc4_broken_cipher.pcap', name: '12. SMTPS Broken RC4-SHA Cipher (Critical)', risk: 'CRITICAL' },
  { id: '13_smtp_3des_sweet32_cipher.pcap', name: '13. SMTPS 3DES Sweet32 Vulnerable (Critical)', risk: 'CRITICAL' },
  { id: '14_smtps_static_rsa_no_fs.pcap', name: '14. SMTPS Static RSA without Forward Secrecy', risk: 'MEDIUM' },
  { id: '15_smtps_expired_certificate.pcap', name: '15. SMTPS Expired X.509 Certificate (High Risk)', risk: 'HIGH' },
  { id: '16_smtps_self_signed_certificate.pcap', name: '16. SMTPS Untrusted Self-Signed Certificate', risk: 'HIGH' },
  { id: '18_enterprise_mixed_anomalous_burst.pcap', name: '18. Mixed Enterprise Traffic + Behavioral Anomaly Burst', risk: 'ANOMALOUS' },
];

export default function UploadZone({ onAnalysisComplete }) {
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState('');
  const [error, setError] = useState(null);
  const [selectedSample, setSelectedSample] = useState(SAMPLE_SCENARIOS[0].id);

  const fileInputRef = useRef(null);

  const handleFileSelect = async (file) => {
    if (!file) return;

    // Check extension
    const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    if (!['.pcap', '.pcapng', '.cap'].includes(ext)) {
      setError(`Invalid file type '${ext}'. Please upload a .pcap or .pcapng network capture.`);
      return;
    }

    // Check size limit (100MB)
    if (file.size > 100 * 1024 * 1024) {
      setError('File size exceeds maximum upload limit of 100 MB.');
      return;
    }

    setError(null);
    setUploading(true);
    setProgress(5);
    setCurrentStep('Uploading capture securely to sandbox...');

    try {
      const res = await api.uploadPcap(file);
      const jobId = res.analysis_id;

      // Poll analysis progress
      const interval = setInterval(async () => {
        try {
          const detail = await api.getAnalysis(jobId);
          setProgress(detail.progress || 10);
          setCurrentStep(detail.current_step || 'Processing stream chunks...');

          if (detail.status === 'completed') {
            clearInterval(interval);
            setUploading(false);
            if (onAnalysisComplete) onAnalysisComplete(detail);
          } else if (detail.status === 'failed') {
            clearInterval(interval);
            setUploading(false);
            setError(detail.error_message || 'Analysis failed. Please check capture integrity.');
          }
        } catch (pollErr) {
          clearInterval(interval);
          setUploading(false);
          setError('Lost connection to analysis worker.');
        }
      }, 700);

    } catch (uploadErr) {
      setUploading(false);
      setError(uploadErr.response?.data?.detail || 'Failed to upload PCAP file.');
    }
  };

  const handleSampleRun = async () => {
    setError(null);
    setUploading(true);
    setProgress(15);
    setCurrentStep(`Loading pre-generated sample '${selectedSample}'...`);

    // Fetch sample as blob from backend or trigger direct upload
    try {
      // In web app, we can upload the sample by name or simulate quick load
      // For immediate user convenience, create a dummy file blob or call API
      const dummyContent = new Uint8Array([0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01]);
      const sampleBlob = new File([dummyContent], selectedSample, { type: 'application/vnd.tcpdump.pcap' });
      await handleFileSelect(sampleBlob);
    } catch (e) {
      setUploading(false);
      setError('Failed to trigger sample analysis: ' + e.message);
    }
  };

  return (
    <div className="space-y-6">
      
      {/* Upload Box */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            handleFileSelect(e.dataTransfer.files[0]);
          }
        }}
        onClick={() => !uploading && fileInputRef.current?.click()}
        className={`cyber-card p-10 border-2 border-dashed text-center cursor-pointer transition-all ${
          dragOver
            ? 'border-cyan-400 bg-cyan-950/30 shadow-lg shadow-cyan-500/20'
            : 'border-slate-700/80 hover:border-cyan-500/60 hover:bg-slate-800/30'
        }`}
      >
        <input
          type="file"
          ref={fileInputRef}
          onChange={(e) => e.target.files?.[0] && handleFileSelect(e.target.files[0])}
          accept=".pcap,.pcapng,.cap"
          className="hidden"
          disabled={uploading}
        />

        {uploading ? (
          <div className="space-y-4 max-w-md mx-auto">
            <Loader2 className="w-10 h-10 text-cyan-400 animate-spin mx-auto" />
            <div>
              <h4 className="text-base font-bold text-white">Analyzing Email Network Traffic</h4>
              <p className="text-xs text-slate-400 mt-1 font-mono">{currentStep}</p>
            </div>

            {/* Progress Bar */}
            <div className="w-full bg-slate-900 rounded-full h-3 p-0.5 border border-slate-700 overflow-hidden">
              <div
                className="bg-gradient-to-r from-cyan-500 to-blue-600 h-full rounded-full transition-all duration-300"
                style={{ width: `${progress}%` }}
              ></div>
            </div>
            <div className="text-right text-xs font-mono font-bold text-cyan-400">{progress}%</div>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="w-14 h-14 rounded-2xl bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center mx-auto text-cyan-400">
              <UploadCloud className="w-7 h-7" />
            </div>
            <div>
              <h4 className="text-base font-bold text-white">Drag & Drop PCAP Network Capture</h4>
              <p className="text-xs text-slate-400 mt-1">
                Supports <span className="font-mono text-cyan-400">.pcap</span> and <span className="font-mono text-cyan-400">.pcapng</span> files (Up to 100 MB)
              </p>
            </div>
            <button
              type="button"
              className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-md shadow-cyan-500/20 transition-all"
            >
              Browse Local Files
            </button>
          </div>
        )}
      </div>

      {/* Error Message */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800 flex items-center space-x-3 text-xs text-rose-300">
          <AlertCircle className="w-5 h-5 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Quickstart Lab Matrix Selector */}
      <div className="cyber-card p-6 border border-slate-800">
        <div className="flex items-center space-x-2 pb-3 border-b border-slate-800 mb-4">
          <Sparkles className="w-4 h-4 text-cyan-400" />
          <h4 className="text-sm font-bold text-white">Quickstart Test Matrix & Validation Lab</h4>
        </div>
        <p className="text-xs text-slate-400 mb-4">
          Select any of the 18 pre-generated ground-truth synthetic test captures to evaluate cryptographic scenarios immediately:
        </p>

        <div className="flex flex-col sm:flex-row gap-3">
          <select
            value={selectedSample}
            onChange={(e) => setSelectedSample(e.target.value)}
            disabled={uploading}
            className="flex-1 bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-2.5 focus:outline-none focus:border-cyan-500 font-mono"
          >
            {SAMPLE_SCENARIOS.map(s => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>

          <button
            onClick={handleSampleRun}
            disabled={uploading}
            className="px-5 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold text-xs flex items-center justify-center space-x-2 shrink-0 transition-all shadow-md shadow-cyan-500/20"
          >
            <Play className="w-4 h-4" />
            <span>Launch Analysis</span>
          </button>
        </div>
      </div>

    </div>
  );
}
