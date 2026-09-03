# Detailed System Architecture

**Project:** TraceLine — Automated Digital Forensics Reconstruction & Attack Story Pipeline  
**Version:** 1.0.0

This architecture document defines the structural components, data models, and technical boundaries for TraceLine. The architecture strictly enforces the non-functional requirements (NFRs) of local execution, determinism, and unbroken evidence traceability.

---

## 1. Architectural Principles

1. **Evidence-First (Traceability):** No data exists in the system without a cryptographic or structural link (`raw_ref`) back to the immutable source file.
2. **Decoupled Pipeline:** The system operates as a sequence of independent modules (Parsers $\rightarrow$ Correlator $\rightarrow$ Scorer $\rightarrow$ Generator), allowing isolated testing and plugin extensibility.
3. **Deterministic State:** No opaque AI/ML heuristics are used for correlation; all findings are rule-based or topologically derived to ensure 100% reproducibility.
4. **Local Portability:** Designed for incident response triage, the system relies on embedded databases and containerization rather than cloud-dependent microservices.

---

## 2. High-Level Component Architecture

```mermaid
graph TD
    %% External Inputs
    UI[Web UI (React/Vue)]
    Logs[(Raw Log Files CSV/JSON)]
    
    %% Ingestion Layer
    subgraph Ingestion Layer
        API[REST API Gateway]
        Dispatcher[File Dispatcher & Hasher]
        P_Auth[Auth Log Parser]
        P_File[File Access Parser]
        P_Host[Host Event Parser]
        P_Net[NetFlow Parser]
        Normalizer[Data Normalizer]
    end

    %% Storage Layer
    subgraph Data Layer
        DB[(Unified Event Store - SQLite)]
    end

    %% Analysis Engine
    subgraph Correlation & Analysis Engine
        Timeline[Timeline Builder]
        GraphEngine[Activity Graph Tracer]
        BlastRadius[Blast Radius Calculator]
        RuleEngine[Suspicious Pattern Rules]
    end
    
    %% Synthesis Layer
    subgraph Intelligence & Synthesis
        Scorer[Confidence Scorer]
        NarrativeGen[Deterministic Story Generator]
    end
    
    %% Export Layer
    subgraph Export Layer
        ReportGen[PDF/HTML Reporter]
    end

    %% Data Flow
    Logs --> UI
    UI --> API
    API --> Dispatcher
    Dispatcher --> P_Auth & P_File & P_Host & P_Net
    P_Auth & P_File & P_Host & P_Net --> Normalizer
    Normalizer --> DB
    
    DB --> Timeline
    Timeline --> GraphEngine
    GraphEngine --> BlastRadius
    GraphEngine --> RuleEngine
    
    GraphEngine & BlastRadius & RuleEngine --> Scorer
    Scorer --> NarrativeGen
    NarrativeGen --> UI
    NarrativeGen --> ReportGen
    
    %% Drill-down flow
    UI -. "Drill-Down Query (raw_ref)" .-> DB
```

---

## 3. Component Specifications

### 3.1 Ingestion & Normalization Layer
* **Role:** Accepts raw files, validates them, and transforms them into a unified format.
* **Architecture:** Plugin-based. Each log type (Auth, Host, Network) has a specific parser script that inherits from a base interface.
* **Output:** Canonical Event Objects.

### 3.2 Unified Event Store (Data Layer)
* **Role:** The central source of truth for the investigation.
* **Technology:** SQLite (embedded) or local PostgreSQL for larger datasets.
* **Schema (Canonical Event Table):**
  * `event_id` (Primary Key, UUID)
  * `timestamp` (UTC ISO 8601)
  * `event_type` (Enum: AUTH, FILE, EXEC, NET)
  * `actor_principal` (User, Service Account)
  * `source_ip` / `target_ip`
  * `action_verb` (LOGIN, READ, EXECUTE)
  * `target_asset` (File path, hostname)
  * `raw_ref` (JSON string containing `{file_hash, line_index}`)

### 3.3 Correlation & Analysis Engine
* **Timeline Builder:** Issues sorted queries to the DB to map chronological sequences.
* **Activity Graph Tracer:** Uses Breadth-First Search (BFS) and temporal adjacency to link events. If IP A logs in at T1, and IP A accesses File B at T1+2m, an edge is created.
* **Blast Radius Calculator:** Traverses the graph to flag entities connected within 2 degrees of a known compromised asset.
* **Rule Engine:** Externalized YAML configuration files containing heuristic rules (e.g., `rule_off_hours_access`, `rule_rapid_auth_failure`).

### 3.4 Intelligence & Synthesis Layer
* **Confidence Scorer:** A deterministic algorithm that assigns H/M/L scores based on corroboration. Example: If an event is supported by *only* a firewall log (Low), if supported by firewall *and* endpoint log (High).
* **Story Generator:** Maps the scored graph into natural language templates. Example template: `[Actor] accessed [Target] from [Source] at [Time] (Confidence: [Score] - [Rationale]).`

### 3.5 Presentation Layer
* **Frontend:** A lightweight React or Vue.js Single Page Application (SPA).
* **Features:** Interactive timeline, force-directed relationship graph, narrative text view with hyperlinked drill-down tokens.

---

## 4. Technical Stack

* **Backend / API:** Python 3.11+ using FastAPI (high performance, asynchronous).
* **Database:** SQLite (Default for portability and file-based state management).
* **Data Processing:** Pandas/Polars for rapid in-memory dataframe manipulations during normalization.
* **Frontend:** React.js, TailwindCSS, D3.js (or Cytoscape.js) for graph rendering.
* **Deployment:** Docker Desktop / Docker Compose. The entire platform runs in two containers (`traceline-api`, `traceline-ui`).

---

## 5. Security & Isolation boundary
* No external API calls are made during the processing loop.
* Log data remains strictly within the Docker volume bind mounts.
* Session state is entirely local and wiped between investigations to ensure idempotent, clean-room execution.
