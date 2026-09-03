# Non-Functional Requirements Specification (NFRS)

**Project Name:** TraceLine — Automated Digital Forensics Reconstruction & Attack Story Pipeline  
**Document Version:** 1.0.0  
**Problem Statement ID:** PS-03 (X'O Code 2026)  
**Target Domain:** Tier-A Academic & Research Institution Digital Incident Response  
**Classification:** Technical / Implementation Specification  
**Status:** Approved for Architecture & Implementation  

---

## 1. Document Overview

### 1.1 Purpose
This Non-Functional Requirements Specification (NFRS) defines the quality attributes, system constraints, and operational guidelines for **TraceLine**, an automated digital forensics reconstruction platform. While the Functional Requirements Specification (FRS) dictates *what* the system must do, this NFRS specifies *how well* the system must perform its functions.

The architectural philosophy of TraceLine demands strict adherence to auditability, deterministic behavior, and explainability over black-box accuracy. This document sets the mandatory thresholds for performance, extensibility, reproducibility, security, and user experience necessary to deploy a forensically sound, legally defensible, and cognitively accessible incident response platform.

### 1.2 Document Conventions & Definitions
* **Shall / Must:** An absolute requirement necessary for system compliance and acceptance.
* **Should:** A highly recommended requirement, expected for production robustness unless a documented constraint prevents it.
* **Traceability Constraint:** The architectural requirement that every derived conclusion or finding must maintain an unbroken pointer back to a raw ingested log.
* **Black-Box Prohibition:** The explicit ban on using non-explainable heuristic models or AI/ML algorithms that cannot generate a deterministic citation of their underlying logic and evidence.

---

## 2. Usability & User Experience (UX) Requirements

### 2.1 Target Persona Capabilities
* **NFR-U-01 (Analyst Accessibility):** The system shall be usable by Level-1 Security Operation Center (SOC) analysts or incident responders without formal data science, programming, or database administration expertise.
* **NFR-U-02 (Learning Curve):** An analyst with basic cybersecurity knowledge shall be able to upload evidence, execute a correlation pipeline, and generate an initial narrative report within fifteen (15) minutes of initial onboarding.

### 2.2 Interface & Interaction
* **NFR-U-03 (Frictionless Ingestion):** The Graphical User Interface (GUI) shall provide a direct drag-and-drop mechanism for evidence upload, bypassing the need for command-line staging or complex configuration files for standard log formats (CSV, JSON).
* **NFR-U-04 (Progress Transparency):** During pipeline execution, the system must provide real-time, step-by-step progress indicators reflecting the current stage (e.g., "Parsing VPN Logs," "Correlating Lateral Movement," "Scoring Confidence"), updating at least every three (3) seconds.
* **NFR-U-05 (Drill-Down Navigation):** Any summary view, graph node, or narrative sentence displayed in the UI shall be clickable, instantly transitioning the user to a detailed view of the underlying raw log evidence within two (2) clicks.

---

## 3. Explainability, Auditability, & Transparency

TraceLine operates on the principle of **Explainability over Accuracy**. A well-justified medium-confidence finding is strictly preferred over an unexplained high-confidence finding.

### 3.1 Explainability of Outputs
* **NFR-EX-01 (Mandatory Rationale):** Every assertion in the generated Attack Story and every edge in the correlation graph must be accompanied by a human-readable justification stating exactly *why* the correlation was made (e.g., "Linked by IP address 192.168.1.50 occurring within 3 minutes of authentication event").
* **NFR-EX-02 (Confidence Scoring Transparency):** Confidence scores (High, Medium, Low) attached to findings shall be derived from explicitly documented, visible rules (e.g., number of correlating sources, signature exactness) rather than opaque neural network activations.
* **NFR-EX-03 (Black-Box Prohibition):** The system shall not utilize opaque machine learning models for final narrative assertions. If probabilistic models (like NLP) are used for summary generation, they must be rigorously constrained to synthesize only from a deterministic fact-base, and the fact-base itself must be independently viewable.

### 3.2 Auditability & Chain of Evidence
* **NFR-AU-01 (Immutable Raw Storage):** Uploaded log files must be stored immutably during the lifecycle of an investigation. The system shall not alter, overwrite, or destructively parse the original source files.
* **NFR-AU-02 (Unbroken Traceability):** Every canonical event in the unified data store shall maintain a `raw_ref` pointer identifying the exact source file, line number, and cryptographic hash of the file from which it was derived.
* **NFR-AU-03 (Forensic Logging):** The system itself must generate an audit log of analyst actions (e.g., uploading files, adjusting correlation parameters, exporting reports) to maintain chain-of-custody integrity for the investigation timeline.

---

## 4. Performance & Scalability Requirements

### 4.1 Throughput & Processing Speed
* **NFR-P-01 (Processing Latency):** For a standard evaluation dataset consisting of up to 100,000 heterogeneous log rows (typical for the specified hackathon scale), the complete end-to-end pipeline (Ingestion → Normalization → Correlation → Scoring → Narrative Generation) must complete execution within three (3) minutes on standard commodity hardware (e.g., 4-core CPU, 8GB RAM).
* **NFR-P-02 (Ingestion Throughput):** The ingestion and normalization module should process and write structured CSV/JSON log entries to the unified event store at a sustained rate of at least 10,000 rows per second.

### 4.2 System Responsiveness
* **NFR-P-03 (UI Rendering):** Frontend rendering of the Attack Story and unified timeline shall complete within two (2) seconds of the backend pipeline completion.
* **NFR-P-04 (Query Latency):** When a user clicks to drill down from a narrative statement to the underlying evidence, the raw log rows must be retrieved and displayed within 500 milliseconds.

### 4.3 Scalability
* **NFR-P-05 (Batch Over Streaming):** The architecture is optimized for batch processing of historical incident data. Streaming, real-time ingestion is explicitly out of scope for the current design phase, ensuring resources are dedicated to deep correlation rather than low-latency state management.

---

## 5. Extensibility & Modularity Requirements

### 5.1 Architecture Design
* **NFR-M-01 (Pipeline Modularity):** The system backend must be designed as a decoupled pipeline where ingestion, correlation, and narrative generation operate as independent services or modules with well-defined contracts.
* **NFR-M-02 (Parser Pluggability):** The system must support the addition of new log formats (e.g., a new endpoint telemetry format) by adding a single configuration file or parser script, without requiring recompilation or modification of the core correlation engine.

### 5.2 Rule Engine Expansion
* **NFR-M-03 (Heuristics Externalization):** Correlation rules, anomaly detection thresholds, and confidence scoring weights must be externalized from the core source code (e.g., in YAML or JSON configuration files) to allow forensic experts to tune parameters without developer intervention.

---

## 6. Reproducibility & Determinism

### 6.1 Deterministic Outcomes
* **NFR-R-01 (Pipeline Reproducibility):** Given identical input data sets and identical rule configurations, the system shall deterministically produce the exact same correlations, confidence scores, blast radius calculations, and attack story factual assertions upon every execution.
* **NFR-R-02 (LLM Constraint):** If Large Language Models (LLMs) are used strictly for formatting the final human-readable narrative, they must be set to a temperature of zero (0.0) or utilize heavily constrained decoding to guarantee consistent wording and completely eliminate hallucinatory assertions. The facts fed to the LLM must be deterministic.

### 6.2 State Management
* **NFR-R-03 (Idempotent Execution):** Rerunning the correlation pipeline on an existing dataset must clear previous state and regenerate the exact same graph and report, preventing data duplication or artifact bleed-over.

---

## 7. Security & Privacy Requirements

### 7.1 Data Protection
* **NFR-S-01 (Local Execution):** Due to the highly sensitive nature of institutional security logs (which may contain PII, credentials, or proprietary research filenames), the core pipeline must be capable of running entirely locally or within an isolated institutional virtual private cloud (VPC) without requiring external internet calls for data processing.
* **NFR-S-02 (Data Sanitization Handling):** The system should gracefully handle pre-anonymized or redacted log files, utilizing logical identifiers rather than relying exclusively on real IP addresses or usernames to form graph edges.

### 7.2 Access Control
* **NFR-S-03 (Single-Tenant Scope):** For the initial hackathon build, complex multi-tenant Role-Based Access Control (RBAC) and enterprise SSO are considered Out of Scope. The system assumes execution in a trusted, single-tenant investigative environment.

---

## 8. Deployment, Portability & Operational Requirements

### 8.1 Environment & Hosting
* **NFR-D-01 (Containerization):** The entire platform (database, backend processing engine, frontend UI) must be deployable via Docker/Docker Compose to ensure environment parity across developer machines, CI/CD pipelines, and analyst workstations.
* **NFR-D-02 (OS Agnosticism):** The software stack must run natively on Linux, macOS, and Windows (via WSL2 or native Docker Desktop).

### 8.2 Dependencies
* **NFR-D-03 (Minimal External Dependencies):** The core pipeline should rely on lightweight, embedded datastores (e.g., SQLite, local file system) rather than requiring heavy external cluster infrastructure (e.g., Hadoop, Kafka, or clustered Elasticsearch) to ensure portability and low overhead for rapid incident response deployments.

---

## 9. Compliance & Interoperability Standards

### 9.1 Data Export
* **NFR-C-01 (Standardized Export):** All final narrative reports must be exportable in human-readable formats (PDF, HTML) and all correlation graphs/timeline data must be exportable in machine-readable formats (JSON, CSV).
* **NFR-C-02 (Timeline Formatting):** Exported chronological data must strictly adhere to ISO 8601 formatting for timestamps and explicit timezone offsets (UTC default).

### 9.2 Legal Defensibility
* **NFR-C-03 (Evidence Integrity):** The platform’s design must support the principles of digital evidence handling by ensuring that the transition from raw logs to the final narrative report represents a provable, unbroken mathematical or logical derivation, suitable for review by institutional audit boards or legal counsel.
