import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const TLS_COLORS = {
  'TLS 1.3': '#10b981', // Secure Green
  'TLS 1.2': '#38bdf8', // Blue
  'TLS 1.1': '#f59e0b', // Amber
  'TLS 1.0': '#f97316', // Orange
  'SSL 3.0': '#f43f5e', // Red
  'None': '#64748b'     // Plaintext Gray
};

export default function TlsVersionChart({ tlsCounts = {} }) {
  const data = Object.entries(tlsCounts).map(([name, value]) => ({
    name: name === 'None' ? 'Plaintext' : name,
    value,
    color: TLS_COLORS[name] || '#64748b'
  }));

  return (
    <div className="cyber-card p-5 border border-slate-800 flex flex-col justify-between">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-bold text-white tracking-wide">TLS Protocol Versions</h3>
        <span className="text-[11px] font-mono text-slate-400">Cryptographic Depth</span>
      </div>

      <div className="h-44 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
            <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
            <Tooltip
              contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
              itemStyle={{ color: '#10b981' }}
            />
            <Bar dataKey="value" radius={[4, 4, 0, 0]}>
              {data.map((entry, index) => (
                <Cell key={`tls-cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
