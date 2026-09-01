import React, { useState } from 'react';
import { Search, Filter, Shield, AlertTriangle, Eye, ShieldCheck, Zap } from 'lucide-react';

const RISK_BADGES = {
  SECURE: 'bg-emerald-950 text-emerald-400 border-emerald-800',
  LOW: 'bg-blue-950 text-blue-400 border-blue-800',
  MEDIUM: 'bg-amber-950 text-amber-400 border-amber-800',
  HIGH: 'bg-orange-950 text-orange-400 border-orange-800',
  CRITICAL: 'bg-rose-950 text-rose-400 border-rose-800'
};

export default function SessionTable({ sessions = [], onSelectSession }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [anomalyOnly, setAnomalyOnly] = useState(false);

  const protocols = ['ALL', ...Array.from(new Set(sessions.map(s => s.protocol)))];

  const filtered = sessions.filter(s => {
    const matchesSearch =
      s.stream_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.client_ip.includes(searchTerm) ||
      s.server_ip.includes(searchTerm) ||
      s.cipher_suite.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (s.sni && s.sni.toLowerCase().includes(searchTerm.toLowerCase()));

    const matchesProto = protocolFilter === 'ALL' || s.protocol === protocolFilter;
    const matchesAnom = !anomalyOnly || s.is_anomalous;

    return matchesSearch && matchesProto && matchesAnom;
  });

  return (
    <div className="cyber-card p-6 border border-slate-800">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-5 pb-4 border-b border-slate-800">
        <div>
          <h3 className="text-base font-bold text-white flex items-center space-x-2">
            <span>Reassembled TCP Email Streams</span>
            <span className="px-2 py-0.5 rounded-full text-xs font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
              {filtered.length} of {sessions.length}
            </span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Deep packet inspection and cryptographic feature extraction per TCP 4-tuple stream.
          </p>
        </div>

        {/* Filters and search */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search IP, cipher, SNI..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-slate-900/90 border border-slate-700 text-slate-200 text-xs rounded-lg pl-8 pr-3 py-1.5 focus:outline-none focus:border-cyan-500 w-44"
            />
          </div>

          {/* Protocol dropdown */}
          <select
            value={protocolFilter}
            onChange={(e) => setProtocolFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500"
          >
            {protocols.map(p => (
              <option key={p} value={p}>{p === 'ALL' ? 'All Protocols' : p}</option>
            ))}
          </select>

          {/* Anomalous toggle */}
          <button
            onClick={() => setAnomalyOnly(!anomalyOnly)}
            className={`px-2.5 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center space-x-1.5 border ${
              anomalyOnly
                ? 'bg-rose-500 text-white border-rose-400 shadow-md shadow-rose-500/20'
                : 'bg-slate-900 text-slate-400 border-slate-700 hover:text-slate-200'
            }`}
          >
            <Zap className="w-3.5 h-3.5" />
            <span>Anomalies Only</span>
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-[11px] text-slate-400 uppercase font-bold tracking-wider">
              <th className="pb-3 px-3">Stream</th>
              <th className="pb-3 px-3">Protocol</th>
              <th className="pb-3 px-3">Endpoints</th>
              <th className="pb-3 px-3">TLS Version</th>
              <th className="pb-3 px-3">Cipher Suite</th>
              <th className="pb-3 px-3">FS</th>
              <th className="pb-3 px-3">Risk Level</th>
              <th className="pb-3 px-3">AI Anomaly</th>
              <th className="pb-3 px-3 text-right">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan="9" className="text-center py-8 text-slate-500 font-sans">
                  No sessions found matching filters.
                </td>
              </tr>
            ) : (
              filtered.map((s) => {
                const riskBadge = RISK_BADGES[s.risk_level] || RISK_BADGES.SECURE;

                return (
                  <tr
                    key={s.stream_id}
                    className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    onClick={() => onSelectSession && onSelectSession(s)}
                  >
                    <td className="py-3 px-3 font-bold text-cyan-400">{s.stream_id}</td>
                    
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 font-bold border border-slate-700">
                        {s.protocol}
                      </span>
                    </td>

                    <td className="py-3 px-3 text-slate-300 font-sans">
                      <div className="text-[11px]">{s.client_ip}:{s.client_port}</div>
                      <div className="text-[10px] text-slate-500">&rarr; {s.server_ip}:{s.server_port}</div>
                    </td>

                    <td className="py-3 px-3">
                      <span className={`font-semibold ${
                        s.tls_version === 'TLS 1.3' ? 'text-emerald-400' : (
                          s.tls_version === 'TLS 1.2' ? 'text-cyan-400' : (
                            s.tls_version === 'None' ? 'text-slate-500' : 'text-orange-400'
                          )
                        )
                      }`}>
                        {s.tls_version}
                      </span>
                    </td>

                    <td className="py-3 px-3 truncate max-w-[200px] text-slate-300" title={s.cipher_suite}>
                      {s.cipher_suite}
                    </td>

                    <td className="py-3 px-3">
                      {s.forward_secrecy ? (
                        <span className="text-emerald-400 font-bold">ECDHE</span>
                      ) : (
                        <span className="text-slate-600">None</span>
                      )}
                    </td>

                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase border ${riskBadge}`}>
                        {s.risk_level}
                      </span>
                    </td>

                    <td className="py-3 px-3">
                      {s.is_anomalous ? (
                        <span className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-400 text-[10px] font-bold border border-rose-800 animate-pulse">
                          Anomalous ({s.anomaly_score})
                        </span>
                      ) : (
                        <span className="text-slate-500 text-[11px]">Normal</span>
                      )}
                    </td>

                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectSession && onSelectSession(s);
                        }}
                        className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-cyan-400 hover:bg-slate-700 transition-colors"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
