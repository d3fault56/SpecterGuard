'use client';

import { ChangeEvent, KeyboardEvent } from 'react';

interface InputCardProps {
  currentTab: 'text' | 'email' | 'url';
  inputContent: string;
  onInputChange: (content: string) => void;
  onAnalyze: () => void;
  loading: boolean;
  onKeyDown?: (e: KeyboardEvent) => void;
}

export default function InputCard({
  currentTab,
  inputContent,
  onInputChange,
  onAnalyze,
  loading,
  onKeyDown,
}: InputCardProps) {
  const placeholders = {
    text: 'Paste the text message you want to analyze...',
    email: 'Paste the full email (From, Subject, Authentication-Results, body)...',
    url: 'https://example.com',
  };

  const labels = {
    text: 'SMS / Text Message',
    email: 'Email Headers + Body',
    url: 'Website URL or Domain',
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement | HTMLInputElement>) => {
    if (e.ctrlKey && e.key === 'Enter') {
      onAnalyze();
    }
    onKeyDown?.(e);
  };

  return (
    <div className="card">
      <div className="input-section">
        <label className="input-label">{labels[currentTab]}</label>
        {currentTab === 'url' ? (
          <input
            type="text"
            value={inputContent}
            onChange={(e: ChangeEvent<HTMLInputElement>) => onInputChange(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={placeholders[currentTab]}
            disabled={loading}
          />
        ) : (
          <textarea
            value={inputContent}
            onChange={(e: ChangeEvent<HTMLTextAreaElement>) => onInputChange(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={placeholders[currentTab]}
            disabled={loading}
          />
        )}
      </div>

      <button
        className="btn-analyze"
        onClick={onAnalyze}
        disabled={loading}
      >
        {loading ? (
          <>
            <span className="loading"></span> Analyzing...
          </>
        ) : (
          '🔍 Analyze Now'
        )}
      </button>
    </div>
  );
}
