import React from 'react';
import { Shield, ShieldAlert, AlertTriangle, CheckCircle, Award } from 'lucide-react';

export default function ScoreGauge({ score = 100, riskLevel = 'SECURE', grade = 'A+', totalSessions = 0, totalFindings = 0, fsRatio = 0 }) {
  // Score color mappings
  let color = '#10b981'; // emerald
  let glow = 'rgba(16, 185, 129, 0.2)';
  let label = 'SECURE';

  if (riskLevel === 'CRITICAL' || score < 40) {
    color = '#f43f5e'; // rose
    glow = 'rgba(244, 63, 94, 0.25)';
    label = 'CRITICAL RISK';
  } else if (riskLevel === 'HIGH' || score < 65) {
    color = '#f97316'; // orange
    glow = 'rgba(249, 115, 22, 0.25)';
    label = 'HIGH RISK';
  } else if (riskLevel === 'MEDIUM' || score < 80) {
    color = '#f59e0b'; // amber
    glow = 'rgba(245, 158, 11, 0.25)';
    label = 'MEDIUM RISK';
  } else if (riskLevel === 'LOW' || score < 95) {
    color = '#38bdf8'; // blue
    glow = 'rgba(56, 189, 248, 0.25)';
    label = 'LOW RISK';
  }

  // SVG Gauge calculations
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="cyber-card p-6 border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-6 relative overflow-hidden">
      {/* Glow background accent */}
      <div
        className="absolute -right-16 -top-16 w-64 h-64 rounded-full blur-3xl pointer-events-none opacity-30"
        style={{ background: color }}
      ></div>

      {/* Left: Circular Gauge */}
      <div className="flex items-center space-x-6">
        <div className="relative w-40 h-40 flex items-center justify-center">
          <svg className="w-full h-full transform -rotate-90" viewBox="0 0 160 160">
            {/* Track */}
            <circle
              cx="80"
              cy="80"
              r={radius}
              stroke="#1e293b"
              strokeWidth="12"
              fill="transparent"
            />
            {/* Value Arc */}
            <circle
              cx="80"
              cy="80"
              r={radius}
              stroke={color}
              strokeWidth="12"
              strokeDasharray={circumference}
              strokeDashoffset={strokeDashoffset}
              strokeLinecap="round"
              fill="transparent"
              style={{
                transition: 'stroke-dashoffset 1s ease-in-out',
                filter: `drop-shadow(0 0 6px ${glow})`
              }}
            />
          </svg>

          {/* Center text */}
          <div className="absolute flex flex-col items-center justify-center text-center">
            <span className="text-3xl font-black text-white tracking-tight">{score}</span>
            <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">/ 100</span>
          </div>
        </div>

        {/* Posture Summary text */}
        <div>
          <div className="flex items-center space-x-2">
            <span
              className="px-3 py-1 rounded-full text-xs font-extrabold uppercase tracking-wider border"
              style={{
                background: `${color}15`,
                color: color,
                borderColor: `${color}40`,
              }}
            >
              {label}
            </span>
            <span className="px-2.5 py-0.5 rounded-md bg-slate-800 text-slate-300 font-mono font-bold text-xs border border-slate-700">
              Grade {grade}
            </span>
          </div>
          <h2 className="text-xl font-bold text-white mt-2">Cryptographic Posture</h2>
          <p className="text-xs text-slate-400 mt-1 max-w-sm">
            Automated zero-trust evaluation of TLS handshakes, cipher strengths, and X.509 chain-of-trust hierarchies.
          </p>
        </div>
      </div>

      {/* Right: Quick Stat Metrics */}
      <div className="grid grid-cols-3 gap-3 w-full md:w-auto">
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 text-center min-w-[100px]">
          <span className="text-[11px] font-semibold uppercase text-slate-400 tracking-wider">Sessions</span>
          <div className="text-2xl font-black text-white mt-0.5">{totalSessions}</div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 text-center min-w-[100px]">
          <span className="text-[11px] font-semibold uppercase text-slate-400 tracking-wider">Findings</span>
          <div className="text-2xl font-black mt-0.5" style={{ color: totalFindings > 0 ? '#f43f5e' : '#10b981' }}>
            {totalFindings}
          </div>
        </div>

        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 text-center min-w-[100px]">
          <span className="text-[11px] font-semibold uppercase text-slate-400 tracking-wider">Forward Sec.</span>
          <div className="text-2xl font-black text-cyan-400 mt-0.5">{Math.round(fsRatio * 100)}%</div>
        </div>
      </div>
    </div>
  );
}
