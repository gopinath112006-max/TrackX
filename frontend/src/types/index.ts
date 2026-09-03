export interface NormalizedEvent {
  id?: number
  event_id: string
  timestamp: string
  event_type: string
  user?: string | null
  source_ip?: string | null
  destination_ip?: string | null
  source_host?: string | null
  destination_host?: string | null
  file_path?: string | null
  action: string
  status?: string | null
  severity: string
  source?: string | null
  raw_data?: Record<string, unknown> | null
}

export interface EventFilters {
  user?: string
  source_ip?: string
  event_type?: string
  severity?: string
  status?: string
  source?: string
  start_time?: string
  end_time?: string
  search?: string
}

export interface AnalysisProgress {
  event: 'open' | 'progress' | 'error'
  stage: string
  label: string
  percent: number
  payload: Record<string, unknown>
}

export interface EvidenceFile {
  filename: string
  category: string
  event_count: number
  sha256_hash: string
  message: string
}

export interface Finding {
  id: number
  finding_id: string
  title: string
  description: string
  severity: string
  confidence: number
  related_event_ids: string[]
  reason: string
  category: string
}

export interface EntryPoint {
  event_id: string
  timestamp: string
  user?: string | null
  source_ip?: string | null
  destination_host?: string | null
  description: string
  confidence: number
  reasoning: string[]
  related_event_ids: string[]
}

export interface BlastRadius {
  users: string[]
  ips: string[]
  hosts: string[]
  files: string[]
  total_affected: number
}

export interface ConfidenceDetail {
  score: number
  factors: string[]
  level: string
}

export interface InvestigationOverview {
  entry_point: EntryPoint | null
  blast_radius: BlastRadius
  confidence: ConfidenceDetail
  risk_level: string
  counts: {
    total_events: number
    suspicious_events: number
    findings: number
    correlations: number
    timeline_entries: number
    graph_nodes: number
    graph_edges: number
  }
  story: {
    narrative: string
    key_findings: string[]
    limitations: string[]
  }
}

export interface TimelineEntry {
  event_id: string
  timestamp: string
  display_text: string
  sequence_order: number
  severity: string
  details?: NormalizedEvent | null
}

export interface GraphNode {
  id: string
  type: string
  label: string
  color: string
  data?: Record<string, unknown>
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  label: string
  evidence_event_ids?: string[]
  inferred?: boolean
  reason?: string
}

export interface Correlation {
  event_a_event_id: string
  event_b_event_id: string
  score: number
  factors: string[]
}

export interface Scenario {
  id: string
  name: string
  description: string
  category: string
  event_count: number
  expected_findings?: string[]
  files?: string[]
}

export interface AnalysisResult {
  message: string
  investigation_id: number
  findings_count: number
  timeline_count: number
  relationships_count: number
}

export interface ReportData {
  investigation: {
    id: number
    name: string
    scenario_type?: string | null
    status: string
    risk_level: string
    confidence: number
    total_events: number
    suspicious_events: number
    affected_users: string[]
    affected_ips: string[]
    affected_hosts: string[]
    affected_files: string[]
    total_findings: number
    created_at: string
  }
  findings: Finding[]
  timeline: TimelineEntry[]
  blast_radius: BlastRadius
  attack_story: {
    narrative: string
    key_findings: string[]
    limitations: string[]
    confidence: ConfidenceDetail
  }
  relationships: {
    nodes: GraphNode[]
    edges: GraphEdge[]
  }
  evidence_files: EvidenceFile[]
}

export interface InvestigationSummary {
  id: number
  name: string
  scenario_type?: string | null
  status: string
  risk_level: string
  confidence: number
  total_events: number
  suspicious_events: number
  affected_users: string[]
  affected_ips: string[]
  affected_hosts: string[]
  affected_files: string[]
  initial_entry_point?: Finding | null
  total_findings: number
  created_at: string
}