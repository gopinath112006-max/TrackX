import type {
  AnalysisProgress,
  AnalysisResult,
  Correlation,
  EvidenceFile,
  EventFilters,
  Finding,
  GraphEdge,
  GraphNode,
  InvestigationOverview,
  NormalizedEvent,
  ReportData,
  Scenario,
  TimelineEntry,
} from '../types'

// Local dev falls back to '/api' (Vite proxies to the backend on :8000).
// For cloud deploys, set VITE_API_BASE at build time to the backend's URL.
const BASE = (import.meta.env.VITE_API_BASE as string) || '/api'

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const resp = await fetch(`${BASE}${path}`, options)
  if (!resp.ok) {
    let detail = `Request failed (${resp.status})`
    try {
      const body = await resp.json()
      if (body?.detail) detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch {
      /* ignore */
    }
    throw new Error(detail)
  }
  return resp.json() as Promise<T>
}

function encodeParams(params: Record<string, string | number | undefined>): string {
  const qs = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '' && v !== null) qs.set(k, String(v))
  }
  const s = qs.toString()
  return s ? `?${s}` : ''
}

export const api = {
  // Scenarios
  listScenarios: () => request<Scenario[]>('/scenarios'),
  loadScenario: (id: string) => request<AnalysisResult>(`/scenarios/${id}/load`, { method: 'POST' }),

  // Evidence
  uploadEvidence: async (investigationId: number, file: File, category: string): Promise<EvidenceFile> => {
    const form = new FormData()
    form.append('investigation_id', String(investigationId))
    form.append('category', category)
    form.append('file', file)
    return request<EvidenceFile>('/evidence/upload', { method: 'POST', body: form })
  },
  listEvidence: (investigationId: number) =>
    request<EvidenceFile[]>(`/evidence${encodeParams({ investigation_id: investigationId })}`),

  // Events
  listEvents: (investigationId: number, filters?: EventFilters) => {
    const params = { investigation_id: investigationId, ...(filters ?? {}) }
    return request<NormalizedEvent[]>(`/events${encodeParams(params as unknown as Record<string, string>)}`)
  },
  getEvent: (eventId: string) => request<NormalizedEvent>(`/events/${eventId}`),

  // Analysis
  analyze: (investigationId: number) =>
    request<AnalysisResult>(`/analyze?investigation_id=${investigationId}`, { method: 'POST' }),
  getFindings: (investigationId: number) =>
    request<Finding[]>(`/findings${encodeParams({ investigation_id: investigationId })}`),
  getTimeline: (investigationId: number) => {
    return request<{ entries: TimelineEntry[]; total_count: number }>(
      `/timeline${encodeParams({ investigation_id: investigationId })}`,
    )
  },
  getRelationships: (investigationId: number) =>
    request<{ nodes: GraphNode[]; edges: GraphEdge[] }>(
      `/relationships${encodeParams({ investigation_id: investigationId })}`,
    ),
  getInvestigation: (investigationId: number) =>
    request<InvestigationOverview>(`/investigation${encodeParams({ investigation_id: investigationId })}`),
  getCorrelations: (investigationId: number) =>
    request<Correlation[]>(`/correlations${encodeParams({ investigation_id: investigationId })}`),
  getReport: (investigationId: number) =>
    request<ReportData>(`/report${encodeParams({ investigation_id: investigationId })}`),

  // Raw HTML report (opens in new tab for download/print)
  reportHtmlUrl: (investigationId: number) => `${BASE}/report/html?investigation_id=${investigationId}`,

  // Server-Sent Events pipeline progress (FR-14). Returns a close() function.
  streamProgress: (investigationId: number, onEvent: (data: AnalysisProgress) => void): (() => void) => {
    const src = new EventSource(`${BASE}/analysis/progress?investigation_id=${investigationId}`)
    src.onmessage = (e) => {
      try {
        onEvent(JSON.parse(e.data) as AnalysisProgress)
      } catch {
        /* ignore malformed frames */
      }
    }
    return () => src.close()
  },
}