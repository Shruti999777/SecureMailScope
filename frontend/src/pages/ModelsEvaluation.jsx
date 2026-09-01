import React from 'react';
import MlInsights from '../components/MlInsights';
import { Cpu, Award, ShieldCheck, Zap } from 'lucide-react';

export default function ModelsEvaluation({ currentJob }) {
  return (
    <div className="max-w-6xl mx-auto space-y-6 py-2">
      
      {/* Title */}
      <div>
        <span className="text-[11px] font-bold text-cyan-400 uppercase tracking-wider font-mono">Artificial Intelligence & Statistical Benchmarks</span>
        <h2 className="text-2xl font-extrabold text-white">Machine Learning & Dual-AI Evaluation</h2>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          Comprehensive evaluation of the Random Forest cryptographic posture risk classifier and the Isolation Forest behavioral session shape anomaly detector.
        </p>
      </div>

      {/* Main ML Insights Component */}
      <MlInsights mlSummary={currentJob?.summary_data?.ml_summary} />

    </div>
  );
}
