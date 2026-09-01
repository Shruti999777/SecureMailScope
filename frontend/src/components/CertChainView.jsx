import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, Key, Calendar, Link2, CheckCircle2, XCircle, ChevronDown, ChevronRight, Layers } from 'lucide-react';

export default function CertChainView({ certificates = [] }) {
  const [selectedCertIdx, setSelectedCertIdx] = useState(0);

  if (!certificates || certificates.length === 0) {
    return (
      <div className="cyber-card p-8 text-center border border-slate-800">
        <Layers className="w-10 h-10 text-slate-600 mx-auto mb-2" />
        <h4 className="text-sm font-bold text-slate-300">No X.509 Certificates Detected</h4>
        <p className="text-xs text-slate-500 mt-1">Traffic was transmitted unencrypted or did not contain TLS Certificate handshake messages.</p>
      </div>
    );
  }

  const activeCert = certificates[selectedCertIdx] || certificates[0];
  const hierarchy = activeCert.hierarchy_json || [
    {
      level: 'Leaf (Server)',
      subject_cn: activeCert.subject_cn,
      subject_org: activeCert.subject_org,
      issuer_cn: activeCert.issuer_cn,
      key_type: activeCert.key_type,
      key_size: activeCert.key_size,
      signature_algorithm: activeCert.signature_algorithm,
      is_expired: activeCert.is_expired,
      not_after: activeCert.not_after,
      is_self_signed: activeCert.is_self_signed
    }
  ];

  return (
    <div className="cyber-card p-6 border border-slate-800">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-6 pb-4 border-b border-slate-800">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-800/50 text-cyan-400">
            <Link2 className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-base font-bold text-white flex items-center space-x-2">
              <span>X.509 Chain-of-Trust Verification</span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase border ${
                activeCert.chain_valid ? 'bg-emerald-950 text-emerald-400 border-emerald-800' : 'bg-rose-950 text-rose-400 border-rose-800'
              }`}>
                {activeCert.chain_status || (activeCert.chain_valid ? 'VALID_CHAIN' : 'BROKEN_CHAIN')}
              </span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Cryptographic signature chain verification from Leaf certificate to Root Trust Anchor.
            </p>
          </div>
        </div>

        {/* Stream Selector if multiple certs */}
        {certificates.length > 1 && (
          <div className="flex items-center space-x-2 text-xs">
            <span className="text-slate-400 font-semibold">Select Session:</span>
            <select
              value={selectedCertIdx}
              onChange={(e) => setSelectedCertIdx(Number(e.target.value))}
              className="bg-slate-900 border border-slate-700 text-slate-200 rounded-lg px-2.5 py-1 text-xs focus:outline-none focus:border-cyan-500 font-mono"
            >
              {certificates.map((c, idx) => (
                <option key={idx} value={idx}>
                  {c.stream_id} - {c.subject_cn || 'Cert'}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Visual Chain Nodes */}
      <div className="space-y-4 relative">
        {hierarchy.map((node, idx) => {
          const isLeaf = idx === 0;
          const isRoot = idx === hierarchy.length - 1 && hierarchy.length > 1;
          const isInter = !isLeaf && !isRoot;
          const isInvalid = node.is_expired || (activeCert.chain_status === 'SELF_SIGNED' && !activeCert.chain_valid);

          return (
            <div key={idx} className="relative">
              {/* Connector line between nodes */}
              {idx < hierarchy.length - 1 && (
                <div className="absolute left-6 top-12 w-0.5 h-8 bg-gradient-to-b from-cyan-500 to-slate-700 z-0"></div>
              )}

              <div className={`p-4 rounded-xl border relative z-10 transition-all ${
                isInvalid
                  ? 'bg-rose-950/20 border-rose-800/60'
                  : 'bg-slate-900/80 border-slate-800/80 hover:border-slate-700'
              }`}>
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                  <div className="flex items-start space-x-3">
                    <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${
                      isInvalid ? 'bg-rose-900/60 text-rose-400' : 'bg-cyan-950/80 text-cyan-400 border border-cyan-800/60'
                    }`}>
                      <Key className="w-4 h-4" />
                    </div>

                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="text-[11px] font-bold uppercase tracking-wider text-cyan-400 font-mono">
                          {node.level || (isLeaf ? 'Leaf (Server)' : isRoot ? 'Root CA' : `Intermediate CA ${idx}`)}
                        </span>
                        {node.is_self_signed && (
                          <span className="px-1.5 py-0.2 rounded bg-amber-950 text-amber-400 text-[10px] font-bold border border-amber-800">
                            Self-Signed
                          </span>
                        )}
                        {node.is_expired && (
                          <span className="px-1.5 py-0.2 rounded bg-rose-950 text-rose-400 text-[10px] font-bold border border-rose-800">
                            Expired
                          </span>
                        )}
                      </div>

                      <h4 className="text-sm font-bold text-white mt-0.5 font-mono">
                        {node.subject_cn || 'Unknown Common Name'}
                      </h4>
                      {node.subject_org && (
                        <p className="text-xs text-slate-400">{node.subject_org}</p>
                      )}
                    </div>
                  </div>

                  {/* Node Technical Specs */}
                  <div className="flex flex-wrap items-center gap-3 text-xs font-mono">
                    <div className="bg-slate-950/60 border border-slate-800 px-2.5 py-1 rounded-md text-slate-300">
                      <span className="text-slate-500 mr-1.5">Key:</span>
                      <span className={node.is_weak_key ? 'text-rose-400 font-bold' : 'text-slate-200'}>
                        {node.key_type} {node.key_size}b
                      </span>
                    </div>

                    <div className="bg-slate-950/60 border border-slate-800 px-2.5 py-1 rounded-md text-slate-300">
                      <span className="text-slate-500 mr-1.5">Sig:</span>
                      <span className={node.is_weak_signature ? 'text-rose-400 font-bold' : 'text-slate-200'}>
                        {node.signature_algorithm}
                      </span>
                    </div>

                    <div className="bg-slate-950/60 border border-slate-800 px-2.5 py-1 rounded-md text-slate-300">
                      <span className="text-slate-500 mr-1.5">Expires:</span>
                      <span className={node.is_expired ? 'text-rose-400 font-bold' : 'text-slate-200'}>
                        {node.not_after ? String(node.not_after).substring(0, 10) : 'N/A'}
                      </span>
                    </div>
                  </div>

                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
