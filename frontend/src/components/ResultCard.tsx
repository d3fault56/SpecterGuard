"use client";

import { ScanResponse } from "@/lib/types";

interface Props {
  result: ScanResponse;
}

export default function ResultCard({ result }: Props) {
  const verdictClass =
    result.verdict === "safe"
      ? "verdict-safe"
      : result.verdict === "suspicious"
      ? "verdict-suspicious"
      : "verdict-scam";

  const verdictLabel =
    result.verdict === "safe"
      ? "✅ Safe"
      : result.verdict === "suspicious"
      ? "⚠️ Suspicious"
      : "🚨 Likely Scam";

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 space-y-4">
      <div>
        <span className={`verdict-badge ${verdictClass}`}>{verdictLabel}</span>
        <div className="mt-3 text-sm text-slate-400">
          Confidence: <strong className="text-white">{(result.confidence * 100).toFixed(0)}%</strong>
        </div>
      </div>

      <div>
        <h3 className="font-semibold mb-2">Analysis</h3>
        <p className="text-slate-300">{result.explanation}</p>
      </div>

      {result.red_flags.length > 0 && (
        <div>
          <h3 className="font-semibold mb-2">Red Flags Detected</h3>
          <ul className="space-y-1">
            {result.red_flags.map((flag, i) => (
              <li key={i} className="text-sm text-red-300 flex items-start gap-2">
                <span className="text-red-500 mt-0.5">•</span>
                {flag}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="text-xs text-slate-500 mt-4">
        Detected by: <strong>{result.analyzer_used}</strong> • ID: {result.id}
      </div>
    </div>
  );
}