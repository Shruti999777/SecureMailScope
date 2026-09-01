import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const PROTO_COLORS = {
  'SMTPS': '#10b981',
  'SMTP': '#38bdf8',
  'IMAPS': '#a855f7',
  'IMAP': '#f59e0b',
  'POP3S': '#06b6d4',
  'POP3': '#f43f5e',
  'UNKNOWN': '#64748b'
};

export default function ProtocolChart({ protocolCounts = {} }) {
  const data = Object.entries(protocolCounts).map(([name, value]) => ({
    name,
    value,
    color: PROTO_COLORS[name] || '#38bdf8'
  }));

  if (data.length === 0) {
    return (
      <div className="cyber-card p-5 text-center text-slate-400 text-xs">
        No protocol data available
      </div>
    );
  }

  return (
    <div className="cyber-card p-5 border border-slate-800 flex flex-col justify-between">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-bold text-white tracking-wide">Protocol Distribution</h3>
        <span className="text-[11px] font-mono text-slate-400">{data.reduce((a, b) => a + b.value, 0)} Streams</span>
      </div>

      <div className="h-44 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
            <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
            <Tooltip
              contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', fontSize: '12px' }}
              itemStyle={{ color: '#38bdf8' }}
            />
            <Bar dataKey="value" radius={[4, 4, 0, 0]}>
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
