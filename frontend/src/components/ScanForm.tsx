"use client";

import { useState } from "react";
import { ScanRequest, ScanResponse } from "@/lib/types";
import { submitScan } from "@/lib/api";
import ResultCard from "./ResultCard";
import LoadingSpinner from "./LoadingSpinner";

export default function ScanForm() {
  const [inputType, setInputType] = useState<"text" | "email" | "url">("text");
  const [content, setContent] = useState("");
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const request: ScanRequest = { input_type: inputType, content };
      const response = await submitScan(request);
      setResult(response);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Scan failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Form */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <h1 className="text-3xl font-bold mb-6">Analyze for Scams</h1>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Input Type Selector */}
          <div>
            <label className="block text-sm font-semibold mb-2">
              What are you checking?
            </label>
            <div className="grid grid-cols-3 gap-2">
              {(["text", "email", "url"] as const).map((type) => (
                <button
                  key={type}
                  type="button"
                  onClick={() => setInputType(type)}
                  className={`px-4 py-2 rounded font-medium transition ${
                    inputType === type
                      ? "bg-blue-600 text-white"
                      : "bg-slate-700 text-slate-300 hover:bg-slate-600"
                  }`}
                >
                  {type.charAt(0).toUpperCase() + type.slice(1)}
                </button>
              ))}
            </div>
          </div>

          {/* Content Input */}
          <div>
            <label className="block text-sm font-semibold mb-2">
              {inputType === "text" && "Paste the text message"}
              {inputType === "email" && "Paste the email (headers + body)"}
              {inputType === "url" && "Paste the URL"}
            </label>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder={
                inputType === "text"
                  ? "e.g., Click here to verify your account..."
                  : inputType === "email"
                  ? "From: support@example.com\nSubject: Verify your account..."
                  : "e.g., https://example.com/verify"
              }
              rows={6}
              className="w-full bg-slate-700 border border-slate-600 rounded px-4 py-2 text-white placeholder-slate-400 focus:outline-none focus:border-blue-500"
              disabled={loading}
            />
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={!content.trim() || loading}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 text-white font-semibold py-2 rounded transition"
          >
            {loading ? "Analyzing..." : "Analyze"}
          </button>
        </form>

        {/* Error Message */}
        {error && (
          <div className="mt-4 p-4 bg-red-900 border border-red-700 rounded text-red-200">
            <strong>Error:</strong> {error}
          </div>
        )}
      </div>

      {/* Loading */}
      {loading && <LoadingSpinner />}

      {/* Result */}
      {result && <ResultCard result={result} />}
    </div>
  );
}