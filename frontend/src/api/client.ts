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

const API_BASE = (import.meta.env.VITE_API_URL || '/api').replace(/\/+$/, '')

/** Plain-English message for a failed request, with what to do next. */
function friendly(status: number, detail: string): string {
  if (status === 429) return detail || 'Too many checks from your network in a short time. Wait a minute and try again.'
  if (status === 502 || status === 503 || status === 504)
    return 'The TrustLens server is starting up or busy. Wait a minute and try again.'
  if (status >= 500) return 'Something went wrong on the TrustLens server. Try again in a moment.'
  return detail || `Request failed (${status}).`
}

async function request<T>(path: string, init?: RequestInit & { timeoutMs?: number }): Promise<T> {
  const url = `${API_BASE}${path}`
  // Never wait forever: a sleeping free server can take up to a minute to answer, so the long calls get more time.
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), init?.timeoutMs ?? 30_000)
  let res: Response
  try {
    res = await fetch(url, {
      ...init,
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json', ...init?.headers },
    })
  } catch {
    if (controller.signal.aborted)
      throw new ApiError(0, 'The TrustLens server took too long to answer. It may have been asleep; try again in a minute.')
    throw new ApiError(0, 'Could not reach the TrustLens server. Check your internet connection and try again.')
  } finally {
    clearTimeout(timer)
  }
  if (!res.ok) {
    let detail = ''
    try {
      const body = await res.json()
      detail = typeof body.detail === 'string' ? body.detail : ''
    } catch {
      /* non-JSON error body (for example a proxy error page) */
    }
    throw new ApiError(res.status, friendly(res.status, detail))
  }
  return res.json() as Promise<T>
}

export const api = {
  health: () => request<{ status: string }>('/health', { timeoutMs: 90_000 }),
  analyzeUrl: (url: string) =>
    request<AnalysisReport>('/analyze/url', { method: 'POST', body: JSON.stringify({ url }), timeoutMs: 150_000 }),
  analyzeMessage: (text: string) =>
    request<AnalysisReport>('/analyze/message', { method: 'POST', body: JSON.stringify({ text }), timeoutMs: 150_000 }),
  listReports: (limit = 50) => request<AnalysisReport[]>(`/reports?limit=${limit}`),
  getReport: (id: string) => request<AnalysisReport>(`/reports/${encodeURIComponent(id)}`),
  submitToRegistry: (id: string) =>
    request<ChainRecord>(`/registry/submit/${encodeURIComponent(id)}`, { method: 'POST', timeoutMs: 150_000 }),
  verifyReport: (id: string) => request<VerifyResult>(`/registry/verify/${encodeURIComponent(id)}`),
  correlations: (id: string) => request<CorrelationResult>(`/correlations/${encodeURIComponent(id)}`),
  // The exact text that is fingerprinted, so the browser can recompute the hash itself (Verify page).
  canonical: (id: string) =>
    request<{ canonical: string; sha256: string; chain: ChainRecord | null }>(`/reports/${encodeURIComponent(id)}/canonical`),
}
