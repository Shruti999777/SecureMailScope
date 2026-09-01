import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import Dashboard from './pages/Dashboard';
import UploadPage from './pages/UploadPage';
import ModelsEvaluation from './pages/ModelsEvaluation';
import HistoryPage from './pages/HistoryPage';
import { api } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('upload');
  const [currentJob, setCurrentJob] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [findings, setFindings] = useState([]);
  const [certificates, setCertificates] = useState([]);
  const [loadingJob, setLoadingJob] = useState(false);

  const loadJobData = async (jobId) => {
    setLoadingJob(true);
    try {
      const [jobDetail, sessData, findData, certData] = await Promise.all([
        api.getAnalysis(jobId),
        api.getSessions(jobId),
        api.getFindings(jobId),
        api.getCertificates(jobId)
      ]);

      setCurrentJob(jobDetail);
      setSessions(sessData);
      setFindings(findData);
      setCertificates(certData);
      setActiveTab('dashboard');
    } catch (e) {
      console.error('Failed to load full job telemetry', e);
    } finally {
      setLoadingJob(false);
    }
  };

  const handleAnalysisComplete = (completedJob) => {
    loadJobData(completedJob.analysis_id || completedJob.id);
  };

  const handleSelectJobFromHistory = (job) => {
    loadJobData(job.analysis_id || job.id);
  };

  return (
    <div className="min-h-screen bg-dark-900 text-slate-100 flex flex-col">
      {/* Navigation Header */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        currentJob={currentJob}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {loadingJob ? (
          <div className="py-24 text-center">
            <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
            <p className="text-sm font-bold text-slate-300 font-mono">Loading Cryptographic Telemetry...</p>
          </div>
        ) : (
          <>
            {activeTab === 'upload' && (
              <UploadPage onAnalysisComplete={handleAnalysisComplete} />
            )}

            {activeTab === 'dashboard' && (
              <Dashboard
                currentJob={currentJob}
                sessions={sessions}
                findings={findings}
                certificates={certificates}
                onRefresh={() => currentJob && loadJobData(currentJob.id || currentJob.analysis_id)}
              />
            )}

            {activeTab === 'ml' && (
              <ModelsEvaluation currentJob={currentJob} />
            )}

            {activeTab === 'history' && (
              <HistoryPage onSelectJob={handleSelectJobFromHistory} />
            )}
          </>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-dark-900/60 py-4 text-center text-xs text-slate-500">
        <p>SECUREMAILSCOPE &bull; Cryptographic Security Posture & Behavioral Anomaly Assessment &bull; v2.0</p>
      </footer>
    </div>
  );
}
