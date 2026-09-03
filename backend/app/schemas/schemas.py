from pydantic import BaseModel, Field


class RawRef(BaseModel):
    """Immutable forensic provenance pointer (FR-02.3).

    Links a canonical event back to the exact source file (by SHA-256 hash)
    and the 1-based logical line/record index within that file.
    """
    file_hash: str = Field(..., description="SHA-256 hash of the source file")
    line_index: int = Field(..., description="1-based line/record index in the source file")


class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: str
    event_type: str
    user: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_host: str | None = None
    destination_host: str | None = None
    file_path: str | None = None
    action: str
    status: str | None = None
    severity: str = "INFO"
    source: str | None = None
    raw_ref: RawRef | None = None
    raw_data: dict | None = None


class EventResponse(BaseModel):
    id: int
    event_id: str
    timestamp: str
    event_type: str
    user: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_host: str | None = None
    destination_host: str | None = None
    file_path: str | None = None
    action: str
    status: str | None = None
    severity: str = "INFO"
    source: str | None = None
    raw_ref: RawRef | None = None
    raw_data: dict | None = None


class EventFilters(BaseModel):
    user: str | None = None
    source_ip: str | None = None
    event_type: str | None = None
    severity: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    search: str | None = None


class EvidenceUploadResponse(BaseModel):
    filename: str
    category: str
    event_count: int
    sha256_hash: str
    message: str


class FindingResponse(BaseModel):
    id: int
    finding_id: str
    title: str
    description: str
    severity: str
    confidence: float
    related_event_ids: list[str]
    reason: str
    category: str


class CorrelationResponse(BaseModel):
    event_a_event_id: str
    event_b_event_id: str
    score: float
    factors: list[str]


class InvestigationSummary(BaseModel):
    id: int
    name: str
    scenario_type: str | None = None
    status: str
    risk_level: str
    confidence: float
    total_events: int
    suspicious_events: int
    affected_users: list[str]
    affected_ips: list[str]
    affected_hosts: list[str]
    affected_files: list[str]
    initial_entry_point: FindingResponse | None = None
    total_findings: int
    created_at: str


class TimelineEntrySchema(BaseModel):
    event_id: str
    timestamp: str
    display_text: str
    sequence_order: int
    severity: str
    details: EventResponse | None = None


class TimelineResponse(BaseModel):
    entries: list[TimelineEntrySchema]
    total_count: int


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    color: str
    data: dict | None = None


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    animated: bool = False
    evidence_event_ids: list[str] = []
    inferred: bool = False
    reason: str | None = None


class RelationshipGraphResponse(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class BlastRadius(BaseModel):
    users: list[str]
    ips: list[str]
    hosts: list[str]
    files: list[str]
    total_affected: int


class ConfidenceDetail(BaseModel):
    score: float
    factors: list[str]
    level: str


class AttackStoryResponse(BaseModel):
    narrative: str
    key_findings: list[str]
    limitations: list[str]
    confidence: ConfidenceDetail


class ReportData(BaseModel):
    investigation: InvestigationSummary
    findings: list[FindingResponse]
    timeline: list[TimelineEntrySchema]
    blast_radius: BlastRadius
    attack_story: AttackStoryResponse
    relationships: RelationshipGraphResponse
    evidence_files: list[EvidenceUploadResponse]


class ScenarioInfo(BaseModel):
    id: str
    name: str
    description: str
    category: str
    event_count: int


class AnalysisResult(BaseModel):
    message: str
    investigation_id: int
    findings_count: int
    timeline_count: int
    relationships_count: int
