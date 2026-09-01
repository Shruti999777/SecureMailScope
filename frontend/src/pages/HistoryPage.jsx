import React, { useEffect, useState } from 'react';
import { History, Eye, Trash2, Calendar, FileText, CheckCircle2, AlertCircle } from 'lucide-react';
import { api } from '../services/api';

export default function HistoryPage({ onSelectJob }) {
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchJobs = async () => {
    try {
      setLoading(true);
      const data = await api.listAnalyses();
      setJobs(data);
    } catch (e) {
      console.error('Failed to fetch job history', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchJobs();
  }, []);

  return (
    <div className="max-w-6xl mx-auto space-y-6 py-2">
      <div className="flex items-center justify-between">
        <div>
          <span className="text-[11px] font-bold text-cyan-400 uppercase tracking-wider font-mono">Historical Captures</span>
          <h2 className="text-2xl font-extrabold text-white">Analysis History</h2>
          <p className="text-xs text-slate-400 mt-1">Review past email PCAP security evaluations stored in database.</p>
        </div>
      </div>

      <div className="cyber-card p-6 border border-slate-800">
        {loading ? (
          <div className="text-center py-12 text-slate-400 text-xs font-mono">Loading history...</div>
        ) : jobs.length === 0 ? (
          <div className="text-center py-12 text-slate-500 text-xs">No analysis jobs in database yet.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase font-bold text-[11px]">
                  <th className="pb-3 px-3">Capture Name</th>
                  <th className="pb-3 px-3">Job ID</th>
                  <th className="pb-3 px-3">Date</th>
                  <th className="pb-3 px-3">Score</th>
                  <th className="pb-3 px-3">Risk Level</th>
                  <th className="pb-3 px-3">Sessions</th>
                  <th className="pb-3 px-3">Findings</th>
                  <th className="pb-3 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {jobs.map(job => (
                  <tr key={job.analysis_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-3 font-bold text-white font-sans truncate max-w-[200px]" title={job.filename}>
                      {job.filename}
                    </td>
                    <td className="py-3 px-3 text-slate-400">{job.analysis_id}</td>
                    <td className="py-3 px-3 text-slate-400 text-[11px]">
                      {job.created_at ? String(job.created_at).substring(0, 19).replace('T', ' ') : 'N/A'}
                    </td>
                    <td className="py-3 px-3">
                      <span className="font-extrabold text-cyan-400">{job.overall_score ?? 'N/A'}/100</span>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                        job.overall_risk_level === 'SECURE' ? 'bg-emerald-950 text-emerald-400 border-emerald-800' : (
                          job.overall_risk_level === 'HIGH' || job.overall_risk_level === 'CRITICAL' ? 'bg-rose-950 text-rose-400 border-rose-800' : 'bg-amber-950 text-amber-400 border-amber-800'
                        )
                      }`}>
                        {job.overall_risk_level || 'N/A'}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-300">{job.total_sessions}</td>
                    <td className="py-3 px-3" style={{ color: job.total_findings > 0 ? '#f43f5e' : '#10b981' }}>
                      {job.total_findings}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={() => onSelectJob && onSelectJob(job)}
                        className="px-3 py-1 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-lg text-xs transition-colors shadow-sm"
                      >
                        Open Dashboard
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
