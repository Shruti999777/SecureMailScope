import React, { useState } from 'react';
import { ShieldAlert, AlertTriangle, Info, CheckCircle2, ChevronDown, ChevronUp, Terminal, Wrench } from 'lucide-react';

const SEVERITY_CONFIG = {
  CRITICAL: {
    bg: 'bg-rose-950/40',
    border: 'border-rose-800/80',
    badge: 'bg-rose-950 text-rose-400 border-rose-800',
    icon: ShieldAlert,
    color: '#f43f5e'
  },
  HIGH: {
    bg: 'bg-orange-950/30',
    border: 'border-orange-800/70',
    badge: 'bg-orange-950 text-orange-400 border-orange-800',
    icon: AlertTriangle,
    color: '#f97316'
  },
  MEDIUM: {
    bg: 'bg-amber-950/25',
    border: 'border-amber-800/60',
    badge: 'bg-amber-950 text-amber-400 border-amber-800',
    icon: AlertTriangle,
    color: '#f59e0b'
  },
  LOW: {
    bg: 'bg-blue-950/20',
    border: 'border-blue-800/50',
    badge: 'bg-blue-950 text-blue-400 border-blue-800',
    icon: Info,
    color: '#38bdf8'
  }
};

export default function FindingsList({ findings = [] }) {
  const [filter, setFilter] = useState('ALL');
  const [expandedId, setExpandedId] = useState(null);

  const filtered = findings.filter(f => filter === 'ALL' || f.severity === filter);

  const counts = {
    ALL: findings.length,
    CRITICAL: findings.filter(f => f.severity === 'CRITICAL').length,
    HIGH: findings.filter(f => f.severity === 'HIGH').length,
    MEDIUM: findings.filter(f => f.severity === 'MEDIUM').length,
    LOW: findings.filter(f => f.severity === 'LOW').length,
  };

  return (
    <div className="cyber-card p-6 border border-slate-800">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-5 pb-4 border-b border-slate-800">
        <div>
          <h3 className="text-base font-bold text-white flex items-center space-x-2">
            <span>Identified Cryptographic Vulnerabilities</span>
            <span className="px-2 py-0.5 rounded-full text-xs font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
              {findings.length}
            </span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Rule-based vulnerability findings categorized by CVSS severity with remediation guidance.
          </p>
        </div>

        {/* Severity Filter Tabs */}
        <div className="flex flex-wrap items-center gap-1.5 text-xs">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
            <button
              key={sev}
              onClick={() => setFilter(sev)}
              className={`px-3 py-1 rounded-lg font-bold transition-all ${
                filter === sev
                  ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-500/20'
                  : 'bg-slate-900 text-slate-400 border border-slate-800 hover:border-slate-700 hover:text-white'
              }`}
            >
              {sev} ({counts[sev]})
            </button>
          ))}
        </div>
      </div>

      {/* Findings Accordion */}
      {filtered.length === 0 ? (
        <div className="p-8 text-center bg-slate-900/40 rounded-xl border border-slate-800/80">
          <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
          <h4 className="text-sm font-bold text-slate-200">No findings matching filter "{filter}"</h4>
          <p className="text-xs text-slate-500 mt-1">All examined streams comply with target baseline security rules.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((finding, idx) => {
            const id = finding.id || idx;
            const isExpanded = expandedId === id;
            const cfg = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.LOW;
            const Icon = cfg.icon;

            return (
              <div
                key={id}
                className={`rounded-xl border transition-all overflow-hidden ${cfg.bg} ${cfg.border}`}
              >
                {/* Header row */}
                <div
                  onClick={() => setExpandedId(isExpanded ? null : id)}
                  className="p-4 flex items-center justify-between cursor-pointer hover:bg-white/[0.02]"
                >
                  <div className="flex items-center space-x-3 truncate">
                    <Icon className="w-5 h-5 shrink-0" style={{ color: cfg.color }} />
                    <div className="truncate">
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-extrabold uppercase border ${cfg.badge}`}>
                          {finding.severity}
                        </span>
                        <span className="font-mono text-xs text-slate-400 font-semibold">{finding.rule_id}</span>
                        <span className="px-1.5 py-0.2 rounded bg-slate-800 text-[10px] font-mono text-slate-300 font-bold border border-slate-700">
                          CVSS {finding.cvss_score}
                        </span>
                      </div>
                      <h4 className="text-sm font-bold text-white mt-1 truncate">{finding.title}</h4>
                    </div>
                  </div>

                  <div className="flex items-center space-x-3 shrink-0">
                    <span className="hidden sm:inline text-xs font-mono text-slate-400 bg-slate-900/80 px-2 py-1 rounded border border-slate-800">
                      {finding.stream_id} ({finding.protocol})
                    </span>
                    {isExpanded ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="px-4 pb-4 pt-1 border-t border-slate-800/80 space-y-3 bg-dark-900/60 text-xs">
                    <div>
                      <span className="font-bold text-slate-300 uppercase tracking-wider text-[11px]">Observation:</span>
                      <p className="text-slate-300 mt-1 leading-relaxed bg-slate-900/80 p-3 rounded-lg border border-slate-800">
                        {finding.description}
                      </p>
                    </div>

                    <div>
                      <span className="font-bold text-cyan-400 uppercase tracking-wider text-[11px] flex items-center space-x-1.5">
                        <Wrench className="w-3.5 h-3.5" />
                        <span>Recommended Remediation:</span>
                      </span>
                      <p className="text-cyan-200 mt-1 leading-relaxed bg-cyan-950/30 p-3 rounded-lg border border-cyan-800/40 font-mono">
                        {finding.recommendation}
                      </p>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
