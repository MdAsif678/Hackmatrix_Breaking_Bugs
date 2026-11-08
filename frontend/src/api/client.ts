// Typed API client for the FastAPI backend (AGENTS.md §5). Owner: P1.
// Vite proxies /api -> http://localhost:8000 in dev (see vite.config.ts).
import type {
  AnalysisReport,
  ChainRecord,
  CorrelationResult,
  VerifyResult,
} from '../types'

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detail || `Request failed (${res.status})`)
  }
  return res.json() as Promise<T>
}

export const api = {
  health: () => request<{ status: string }>('/health'),
  analyzeUrl: (url: string) =>
    request<AnalysisReport>('/analyze/url', { method: 'POST', body: JSON.stringify({ url }) }),
  analyzeMessage: (text: string) =>
    request<AnalysisReport>('/analyze/message', { method: 'POST', body: JSON.stringify({ text }) }),
  listReports: (limit = 50) => request<AnalysisReport[]>(`/reports?limit=${limit}`),
  getReport: (id: string) => request<AnalysisReport>(`/reports/${encodeURIComponent(id)}`),
  submitToRegistry: (id: string) =>
    request<ChainRecord>(`/registry/submit/${encodeURIComponent(id)}`, { method: 'POST' }),
  verifyReport: (id: string) => request<VerifyResult>(`/registry/verify/${encodeURIComponent(id)}`),
  correlations: (id: string) => request<CorrelationResult>(`/correlations/${encodeURIComponent(id)}`),
}
