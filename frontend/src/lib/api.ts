import axios from "axios";
import { ScanRequest, ScanResponse, HistoryResponse } from "./types";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

const api = axios.create({
  baseURL: API_BASE_URL,
});

export async function submitScan(request: ScanRequest): Promise<ScanResponse> {
  const response = await api.post("/api/scans", request);
  return response.data;
}

export async function getHistory(): Promise<HistoryResponse> {
  const response = await api.get("/api/scans");
  return response.data;
}