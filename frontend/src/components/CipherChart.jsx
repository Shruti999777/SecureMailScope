import React from 'react';
import { ShieldCheck, ShieldAlert, ShieldX, Lock } from 'lucide-react';

export default function CipherChart({ cipherCounts = {} }) {
  const entries = Object.entries(cipherCounts);

  const getCipherBadge = (name) => {
    const up = name.toUpperCase();
    if (up.includes('RC4') || up.includes('NULL')) {
      return { label: 'CRITICAL', color: 'bg-rose-950 text-rose-400 border-rose-800' };
    }
    if (up.includes('3DES')) {
      return { label: 'INSECURE', color: 'bg-orange-950 text-orange-400 border-orange-800' };
    }
    if (up.includes('CBC') || up.includes('RSA_WITH')) {
      return { label: 'MEDIUM', color: 'bg-amber-950 text-amber-400 border-amber-800' };
    }
    if (up.includes('GCM') || up.includes('POLY1305') || up.includes('AES_128_GCM') || up.includes('AES_256_GCM')) {
      return { label: 'SECURE', color: 'bg-emerald-950 text-emerald-400 border-emerald-800' };
    }
    return { label: 'INFO', color: 'bg-slate-800 text-slate-300 border-slate-700' };
  };

  return (
    <div className="cyber-card p-5 border border-slate-800 flex flex-col justify-between">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-bold text-white tracking-wide">Negotiated Cipher Suites</h3>
        <span className="text-[11px] font-mono text-slate-400">{entries.length} Unique</span>
      </div>

      <div className="space-y-2 max-h-44 overflow-y-auto pr-1">
        {entries.length === 0 ? (
          <p className="text-xs text-slate-500 py-4 text-center">No TLS ciphers observed</p>
        ) : (
          entries.map(([cipher, count]) => {
            const badge = getCipherBadge(cipher);
            return (
              <div key={cipher} className="flex items-center justify-between p-2 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs">
                <div className="flex items-center space-x-2 truncate max-w-[220px]">
                  <Lock className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                  <span className="font-mono text-[11px] text-slate-200 truncate" title={cipher}>{cipher}</span>
                </div>
                <div className="flex items-center space-x-2 shrink-0">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${badge.color}`}>
                    {badge.label}
                  </span>
                  <span className="font-mono text-slate-400 font-bold">{count}</span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
