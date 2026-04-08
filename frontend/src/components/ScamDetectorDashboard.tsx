'use client';

import { useState, useCallback } from 'react';
import TabNavigation from './TabNavigation';
import InputCard from './InputCard';
import ResultsCard from './ResultsCard';
import Sidebar from './Sidebar';
import './dashboard.css';

interface ScanResult {
  id: number;
  verdict: 'safe' | 'suspicious' | 'likely_scam';
  confidence: number;
  explanation: string;
  red_flags: string[];
  analyzer_used: string;
  created_at: string;
}

export default function ScamDetectorDashboard() {
  const [currentTab, setCurrentTab] = useState<'text' | 'email' | 'url'>('text');
  const [inputContent, setInputContent] = useState('');
  const [results, setResults] = useState<ScanResult | null>(null);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [showResults, setShowResults] = useState(false);

  const handleAnalyze = useCallback(async () => {
    if (!inputContent.trim()) {
      alert('Please enter some content to analyze');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('http://localhost:8000/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          input_type: currentTab,
          content: inputContent,
        }),
      });

      if (!response.ok) throw new Error('Analysis failed');
      const result = await response.json();
      
      setResults(result);
      setShowResults(true);
      setHistory([result, ...history.slice(0, 4)]);
    } catch (error) {
      alert('Error: ' + (error instanceof Error ? error.message : 'Unknown error'));
    } finally {
      setLoading(false);
    }
  }, [inputContent, currentTab, history]);

  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.ctrlKey && e.key === 'Enter') {
      handleAnalyze();
    }
  };

  return (
    <div className="dashboard-container">
      {/* Header */}
      <header className="dashboard-header">
        <div className="logo">🛡️ SCAM DETECTOR</div>
        <div className="subtitle">Advanced Threat Analysis Dashboard</div>
      </header>

      {/* Main Dashboard */}
      <div className="container">
        <div className="dashboard-grid">
          {/* Main Content */}
          <div className="main-content">
            {/* Tabs */}
            <TabNavigation currentTab={currentTab} onTabChange={setCurrentTab} />

            {/* Input Card */}
            <InputCard
              currentTab={currentTab}
              inputContent={inputContent}
              onInputChange={setInputContent}
              onAnalyze={handleAnalyze}
              loading={loading}
              onKeyDown={handleKeyDown}
            />

            {/* Results or Empty State */}
            {showResults && results ? (
              <ResultsCard result={results} />
            ) : (
              <div className="card">
                <div className="empty-state">
                  <div className="empty-icon">🔒</div>
                  <div className="empty-text">Enter a message to begin threat analysis</div>
                </div>
              </div>
            )}
          </div>

          {/* Sidebar */}
          <Sidebar history={history} />
        </div>
      </div>
    </div>
  );
}
