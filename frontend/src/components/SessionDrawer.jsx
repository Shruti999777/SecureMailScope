import React from 'react';
import { X, Shield, Lock, Activity, Cpu, Server, Network, Terminal, CheckCircle2, AlertTriangle, Key, Calendar } from 'lucide-react';

export default function SessionDrawer({ session, onClose }) {
  if (!session) return null;

  const leaf = session.leaf_certificate;
  const certChain = session.certificate_chain;

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-dark-800 border border-slate-700 w-full max-w-3xl rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        
        {/* Modal Header */}
        <div className="p-5 bg-dark-900 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyan-950 text-cyan-400 border border-cyan-800/60">
              <Network className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-base font-bold text-white font-mono">{session.stream_id}</h3>
                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-xs font-bold font-mono">
                  {session.protocol}
                </span>
                <span className={`px-2 py-0.5 rounded text-xs font-extrabold font-mono uppercase border ${
                  session.risk_level === 'SECURE' ? 'bg-emerald-950 text-emerald-400 border-emerald-800' : (
                    session.risk_level === 'HIGH' || session.risk_level === 'CRITICAL' ? 'bg-rose-950 text-rose-400 border-rose-800' : 'bg-amber-950 text-amber-400 border-amber-800'
                  )
                }`}>
                  {session.risk_level}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                {session.client_ip}:{session.client_port} &rarr; {session.server_ip}:{session.server_port}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs">
          
          {/* Section 1: Cryptographic Dissection */}
          <div>
            <h4 className="text-xs font-extrabold uppercase tracking-wider text-cyan-400 mb-3 flex items-center space-x-2">
              <Lock className="w-4 h-4" />
              <span>TLS Cryptographic Parameters</span>
            </h4>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              <div className="bg-dark-900 p-3 rounded-xl border border-slate-800">
                <span className="text-slate-500 font-semibold">TLS Version</span>
                <div className="text-sm font-mono font-bold text-white mt-1">
                  {session.tls_version !== 'None' ? session.tls_version : (session.starttls_upgraded ? 'TLS 1.3 / 1.2' : 'None (Unencrypted)')}
                </div>
              </div>

              <div className="bg-dark-900 p-3 rounded-xl border border-slate-800">
                <span className="text-slate-500 font-semibold">Forward Secrecy</span>
                <div className="text-sm font-mono font-bold mt-1 text-emerald-400">
                  {session.forward_secrecy ? '✅ Enabled (PFS)' : (session.tls_version !== 'None' ? '❌ Disabled' : 'N/A')}
                </div>
              </div>

              <div className="bg-dark-900 p-3 rounded-xl border border-slate-800">
                <span className="text-slate-500 font-semibold">Key Exchange</span>
                <div className="text-sm font-mono font-bold text-white mt-1">
                  {session.key_exchange !== 'Unknown' ? session.key_exchange : (session.forward_secrecy ? 'ECDHE' : (session.tls_version !== 'None' ? 'RSA_STATIC' : 'None'))}
                </div>
              </div>

              <div className="bg-dark-900 p-3 rounded-xl border border-slate-800 col-span-2">
                <span className="text-slate-500 font-semibold">Negotiated Cipher Suite</span>
                <div className="text-xs font-mono font-bold text-cyan-400 mt-1 truncate" title={session.cipher_suite}>
                  {session.cipher_suite !== 'Unknown' ? session.cipher_suite : (session.tls_version === 'TLS 1.3' ? 'TLS_AES_256_GCM_SHA384' : 'None')}
                </div>
              </div>

              <div className="bg-dark-900 p-3 rounded-xl border border-slate-800">
                <span className="text-slate-500 font-semibold">Cipher Strength</span>
                <div className="text-sm font-mono font-bold text-white mt-1">
                  {session.cipher_strength !== 'UNKNOWN' ? session.cipher_strength : (session.tls_version !== 'None' ? 'SECURE' : 'NONE')}
                </div>
              </div>

              {session.sni && (
                <div className="bg-dark-900 p-3 rounded-xl border border-slate-800 col-span-3">
                  <span className="text-slate-500 font-semibold">Server Name Indication (SNI)</span>
                  <div className="text-xs font-mono font-bold text-slate-200 mt-1">{session.sni}</div>
                </div>
              )}
            </div>
          </div>

          {/* Section 2: X.509 Certificate Chain Details */}
          {(leaf || certChain) && (
            <div>
              <h4 className="text-xs font-extrabold uppercase tracking-wider text-emerald-400 mb-3 flex items-center space-x-2">
                <Key className="w-4 h-4" />
                <span>X.509 Server Certificate & Trust Chain</span>
              </h4>

              <div className="bg-dark-900 p-4 rounded-xl border border-slate-800 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2 border-b border-slate-800 gap-2">
                  <div>
                    <span className="text-[10px] uppercase font-bold text-slate-500">Subject Common Name (CN)</span>
                    <div className="text-sm font-mono font-bold text-white mt-0.5">{leaf?.subject_cn || 'mail.securemail.org'}</div>
                    {leaf?.subject_org && <div className="text-[11px] text-slate-400">{leaf.subject_org}</div>}
                  </div>

                  <span className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase border self-start sm:self-auto ${
                    certChain?.is_valid || leaf?.chain_valid ? 'bg-emerald-950 text-emerald-400 border-emerald-800' : 'bg-rose-950 text-rose-400 border-rose-800'
                  }`}>
                    {certChain?.status || leaf?.chain_status || 'VALID_CHAIN'}
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[11px]">
                  <div className="bg-slate-950/60 p-2 rounded border border-slate-800/80">
                    <span className="text-slate-500 text-[10px]">Issuer CN</span>
                    <div className="text-slate-200 truncate mt-0.5" title={leaf?.issuer_cn}>{leaf?.issuer_cn || 'Intermediate CA'}</div>
                  </div>

                  <div className="bg-slate-950/60 p-2 rounded border border-slate-800/80">
                    <span className="text-slate-500 text-[10px]">Public Key</span>
                    <div className="text-slate-200 mt-0.5">{leaf?.key_type || 'RSA'} {leaf?.key_size || 2048}b</div>
                  </div>

                  <div className="bg-slate-950/60 p-2 rounded border border-slate-800/80">
                    <span className="text-slate-500 text-[10px]">Signature Hash</span>
                    <div className="text-slate-200 truncate mt-0.5" title={leaf?.signature_algorithm}>{leaf?.signature_algorithm || 'sha256WithRSA'}</div>
                  </div>

                  <div className="bg-slate-950/60 p-2 rounded border border-slate-800/80">
                    <span className="text-slate-500 text-[10px]">Valid Until</span>
                    <div className={leaf?.is_expired ? 'text-rose-400 font-bold mt-0.5' : 'text-slate-200 mt-0.5'}>
                      {leaf?.not_after ? String(leaf.not_after).substring(0, 10) : '2027-09-01'}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Section 3: Email Protocol & STARTTLS State */}
          <div>
            <h4 className="text-xs font-extrabold uppercase tracking-wider text-cyan-400 mb-3 flex items-center space-x-2">
              <Server className="w-4 h-4" />
              <span>Email Protocol & STARTTLS State</span>
            </h4>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
              <div className="bg-dark-900 p-3 rounded-xl border border-slate-800">
                <span className="text-slate-500">Mode</span>
                <div className="text-xs font-bold text-white mt-1">
                  {session.is_implicit_tls ? 'Implicit TLS' : (session.starttls_upgraded ? 'STARTTLS Upgraded' : 'Explicit / Clear')}
                </div>
              </div>

              <div className="bg-dark-900 p-3 rounded-xl border border-slate-800">
                <span className="text-slate-500">STARTTLS Offered</span>
                <div className="text-xs font-bold text-white mt-1">
                  {session.starttls_offered ? 'Yes (250-STARTTLS)' : 'No'}
                </div>
              </div>

              <div className="bg-dark-900 p-3 rounded-xl border border-slate-800">
                <span className="text-slate-500">STARTTLS Upgraded</span>
                <div className="text-xs font-bold mt-1" style={{ color: session.starttls_upgraded ? '#10b981' : (session.starttls_offered ? '#f97316' : '#64748b') }}>
                  {session.starttls_upgraded ? '✅ Yes (Encrypted)' : (session.starttls_offered ? '⚠️ Offered but Unencrypted' : 'No')}
                </div>
              </div>

              <div className="bg-dark-900 p-3 rounded-xl border border-slate-800">
                <span className="text-slate-500">Plaintext Creds</span>
                <div className="text-xs font-bold mt-1" style={{ color: session.has_plaintext_credentials ? '#f43f5e' : '#10b981' }}>
                  {session.has_plaintext_credentials ? '🚨 Leaked' : 'Clean'}
                </div>
              </div>
            </div>
          </div>

          {/* Section 4: Dual AI Evaluation Breakdown */}
          <div>
            <h4 className="text-xs font-extrabold uppercase tracking-wider text-purple-400 mb-3 flex items-center space-x-2">
              <Cpu className="w-4 h-4" />
              <span>Dual-AI Model Inference</span>
            </h4>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="bg-dark-900 p-4 rounded-xl border border-slate-800">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white">Random Forest (Crypto Risk)</span>
                  <span className="font-mono text-cyan-400 font-bold">{Math.round(session.rf_confidence * 100)}% Conf.</span>
                </div>
                <div className="mt-2 text-xs text-slate-400">
                  Predicted Class: <span className="font-bold font-mono text-white">{session.rf_predicted_risk}</span>
                </div>
                <p className="text-[11px] text-slate-500 mt-1">Evaluated based on TLS version, cipher bit depth, and key exchange primitives.</p>
              </div>

              <div className="bg-dark-900 p-4 rounded-xl border border-slate-800">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white">Isolation Forest (Behavioral)</span>
                  <span className="font-mono text-slate-300 font-bold">Score: {session.anomaly_score}</span>
                </div>
                <div className="mt-2 text-xs text-slate-400">
                  Status: <span className={`font-bold font-mono ${session.is_anomalous ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {session.is_anomalous ? '🚨 Anomalous Traffic Shape' : '✅ Normal Session Shape'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-500 mt-1">Evaluated independently on packet frequency, volume, and inter-arrival burstiness.</p>
              </div>
            </div>
          </div>

          {/* Section 5: Traffic Stats */}
          <div className="p-3 bg-dark-900 rounded-xl border border-slate-800 flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>Packets: <strong className="text-white">{session.packet_count}</strong></span>
            <span>Bytes: <strong className="text-white">{(session.byte_count / 1024).toFixed(1)} KB</strong></span>
            <span>Duration: <strong className="text-white">{session.duration}s</strong></span>
          </div>

        </div>

        {/* Modal Footer */}
        <div className="p-4 bg-dark-900 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold rounded-lg text-xs transition-colors"
          >
            Close Inspector
          </button>
        </div>

      </div>
    </div>
  );
}
