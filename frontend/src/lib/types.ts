export interface ScanRequest {
  input_type: "text" | "email" | "url";
  content: string;
}

export interface ScanResponse {
  id: number;
  verdict: "likely_scam" | "suspicious" | "safe";
  confidence: number;
  explanation: string;
  red_flags: string[];
  analyzer_used: "llm" | "heuristic";
  created_at: string;
}

export interface HistoryResponse {
  scans: ScanResponse[];
  total: number;
}