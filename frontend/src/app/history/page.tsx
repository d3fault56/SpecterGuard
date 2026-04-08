"use client";

import { useState, useEffect } from "react";
import { getHistory } from "@/lib/api";
import { HistoryResponse } from "@/lib/types";
import HistoryTable from "@/components/HistoryTable";
import LoadingSpinner from "@/components/LoadingSpinner";

export default function HistoryPage() {
  const [history, setHistory] = useState<HistoryResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const data = await getHistory();
        setHistory(data);
      } catch (err: any) {
        setError(err.message || "Failed to load history");
      } finally {
        setLoading(false);
      }
    };

    fetchHistory();
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Scan History</h1>

      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        {error && (
          <div className="text-red-300 mb-4">
            <strong>Error:</strong> {error}
          </div>
        )}

        {loading ? <LoadingSpinner /> : <HistoryTable scans={history?.scans || []} />}

        {history && (
          <div className="mt-4 text-sm text-slate-400">
            Total scans: <strong>{history.total}</strong>
          </div>
        )}
      </div>
    </div>
  );
}