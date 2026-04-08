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

interface SidebarProps {
  history: ScanResult[];
}

export default function Sidebar({ history }: SidebarProps) {
  const totalScans = history.length;
  const threats = history.filter(h => h.verdict !== 'safe').length;
  const threatPercentage = totalScans > 0 ? Math.round((threats / totalScans) * 100) : 0;

  return (
    <div className="sidebar">
      {/* Scan History */}
      <div className="scan-history">
        <div className="history-title">📝 Recent Scans</div>
        <div className="history-list">
          {history.length > 0 ? (
            history.map((item) => (
              <div key={item.id} className={`history-item ${item.verdict}`}>
                <div className="history-verdict">
                  {item.verdict.replace('_', ' ')}
                </div>
                <div className="history-confidence">
                  {Math.round(item.confidence * 100)}% • {item.id}
                </div>
              </div>
            ))
          ) : (
            <div style={{
              color: 'var(--text-muted)',
              fontSize: '12px',
              textAlign: 'center',
              padding: '20px',
            }}>
              No scans yet
            </div>
          )}
        </div>
      </div>

      {/* Stats */}
      <div className="stats-card">
        <div className="stat-number">{totalScans}</div>
        <div className="stat-label">Total Scans</div>
      </div>

      <div className="stats-card">
        <div className="stat-number">{threatPercentage}%</div>
        <div className="stat-label">Threats Found</div>
      </div>
    </div>
  );
}
