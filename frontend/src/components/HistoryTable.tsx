"use client";

import { ScanResponse } from "@/lib/types";
import { formatDistanceToNow } from "date-fns";

interface Props {
  scans: ScanResponse[];
}

export default function HistoryTable({ scans }: Props) {
  if (scans.length === 0) {
    return (
      <div className="text-center py-12 text-slate-400">
        No scans yet. Start by analyzing some content.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-700">
            <th className="px-4 py-2 text-left font-semibold">When</th>
            <th className="px-4 py-2 text-left font-semibold">Type</th>
            <th className="px-4 py-2 text-left font-semibold">Verdict</th>
            <th className="px-4 py-2 text-left font-semibold">Confidence</th>
            <th className="px-4 py-2 text-left font-semibold">Flags</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id} className="border-b border-slate-700 hover:bg-slate-700">
              <td className="px-4 py-3 text-slate-400">
                {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
              </td>
              <td className="px-4 py-3 capitalize">{scan.input_type}</td>
              <td className="px-4 py-3">
                <span
                  className={`verdict-badge ${
                    scan.verdict === "safe"
                      ? "verdict-safe"
                      : scan.verdict === "suspicious"
                      ? "verdict-suspicious"
                      : "verdict-scam"
                  }`}
                >
                  {scan.verdict === "safe"
                    ? "Safe"
                    : scan.verdict === "suspicious"
                    ? "Suspicious"
                    : "Likely Scam"}
                </span>
              </td>
              <td className="px-4 py-3">{(scan.confidence * 100).toFixed(0)}%</td>
              <td className="px-4 py-3 text-slate-400">{scan.red_flags.length}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}