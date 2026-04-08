'use client';

interface ScanResult {
  id: number;
  verdict: 'safe' | 'suspicious' | 'likely_scam';
  confidence: number;
  explanation: string;
  red_flags: string[];
  analyzer_used: string;
  created_at: string;
}

interface ResultsCardProps {
  result: ScanResult;
}

export default function ResultsCard({ result }: ResultsCardProps) {
  const confidence = Math.round(result.confidence * 100);

  const icons = {
    safe: '✅',
    suspicious: '⚠️',
    likely_scam: '🚨',
  };

  const calculateContentRisk = () => {
    if (result.verdict === 'likely_scam') return 90;
    if (result.verdict === 'suspicious') return 50;
    return 10;
  };

  const calculateUrlRisk = () => {
    const flags = result.red_flags.join('').toLowerCase();
    if (flags.includes('url') || flags.includes('domain')) return 80;
    if (flags.includes('ip')) return 70;
    return 20;
  };

  const calculateAuthRisk = () => {
    const flags = result.red_flags.join('').toLowerCase();
    if (flags.includes('spf') || flags.includes('dkim') || flags.includes('dmarc')) return 85;
    if (flags.includes('spoofing') || flags.includes('mismatch')) return 70;
    return 10;
  };

  const getFlagIcon = (flag: string) => {
    if (flag.includes('SPF') || flag.includes('DKIM') || flag.includes('DMARC')) return '🔒';
    if (flag.includes('URL') || flag.includes('domain')) return '🌐';
    if (flag.includes('credential')) return '🔑';
    return '⚠️';
  };

  const getFlagClass = (flag: string) => {
    if (flag.includes('SPF') || flag.includes('DKIM') || flag.includes('DMARC')) return 'warning';
    if (flag.includes('URL') || flag.includes('domain')) return 'info';
    return '';
  };

  return (
    <div className="card">
      <div className="results-section">
        {/* Status Badge */}
        <div className={`status-badge ${result.verdict}`}>
          <span className="badge-icon">{icons[result.verdict]}</span>
          {result.verdict.replace('_', ' ').toUpperCase()}
        </div>

        {/* Confidence Bar */}
        <div className="confidence-section">
          <div className="confidence-label">
            <span>Confidence Score</span>
            <span>{confidence}%</span>
          </div>
          <div className="confidence-bar">
            <div className="confidence-fill" style={{ width: `${confidence}%` }}></div>
          </div>
        </div>

        {/* Risk Breakdown */}
        <div className="risk-breakdown">
          <div className="breakdown-title">📊 Risk Breakdown</div>
          <div className="breakdown-items">
            <div className="breakdown-item">
              <div className="breakdown-label">Content Risk</div>
              <div className="breakdown-value">{calculateContentRisk()}%</div>
            </div>
            <div className="breakdown-item">
              <div className="breakdown-label">URL Risk</div>
              <div className="breakdown-value">{calculateUrlRisk()}%</div>
            </div>
            <div className="breakdown-item">
              <div className="breakdown-label">Auth Risk</div>
              <div className="breakdown-value">{calculateAuthRisk()}%</div>
            </div>
          </div>
        </div>

        {/* Analysis */}
        <div className="analysis-section">
          <div className="analysis-label">📋 Analysis</div>
          <div>{result.explanation}</div>
        </div>

        {/* Red Flags */}
        <div className="red-flags">
          <div className="flags-title">⚠️ Red Flags Detected</div>
          <div className="flags-list">
            {result.red_flags.length > 0 ? (
              result.red_flags.map((flag, idx) => (
                <div
                  key={idx}
                  className={`flag-item ${getFlagClass(flag)}`}
                >
                  <span className="flag-icon">{getFlagIcon(flag)}</span>
                  {flag}
                </div>
              ))
            ) : (
              <div className="flag-item info">
                <span className="flag-icon">✓</span>
                No red flags detected
              </div>
            )}
          </div>
        </div>

        {/* Analyzer Info */}
        <div style={{
          fontSize: '12px',
          color: 'var(--text-muted)',
          marginTop: '20px',
          textAlign: 'center',
        }}>
          Analyzed by: <strong>{result.analyzer_used}</strong>
        </div>
      </div>
    </div>
  );
}
