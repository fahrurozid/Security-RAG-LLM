# RAG – System Architecture

## 1. Alert Processing Workflow

```mermaid
flowchart TD
    A["Wazuh Alerts"] --> B["Redis VM<br/>Alert Provider :17771"]
    B -->|"HTTP polling"| C["LLM VM<br/>Alert Receiver"]
    
    C --> D["Alert Parser & Normalizer"]
    
    D --> E["PostgreSQL + pgvector<br/>Hybrid Retrieval"]
    E -->|"ATT&CK evidence"| F["Neo4j<br/>D3FEND Graph Retrieval"]
    
    F --> G["LLM Relevance Assessment"]
    G --> H["Ollama<br/>Incident Report Generation"]
    
    H --> I["Result Sender<br/>HTTP NDJSON Stream :17772"]
    I -->|"GET /stream"| J["Redis VM<br/>Stream Consumer"]
```

## 2. Knowledge Ingestion Workflow

```mermaid
flowchart TD
    A["MITRE ATT&CK Dataset"] --> C["Preprocessing & Ingestion"]
    B["MITRE D3FEND Dataset"] --> C

    C --> D["PostgreSQL<br/>Knowledge Items & Relations"]
    D --> E["Embedding Generation"]
    E --> F["pgvector<br/>Vector Storage"]

    D --> G["Neo4j Synchronization"]
    G --> H["Graph Nodes & Relationships"]
```

## 3. Main Components

| Component | Responsibility |
|---|---|
| Alert Receiver | Retrieves enriched alerts from the Redis VM |
| Alert Parser | Normalizes alert data into compact retrieval context |
| PostgreSQL + pgvector | Stores knowledge and performs hybrid retrieval |
| Neo4j | Retrieves framework relationships and graph evidence |
| Relevance Assessment | Evaluates retrieved evidence against the alert |
| Ollama | Generates the incident analysis report |
| Result Sender | Streams generated reports to the Redis VM |

## 4. Communication

- Alert input: HTTP polling from the Redis VM on port `17771`.
- Report output: HTTP streaming through `GET /stream` on port `17772`.
- Database connections: PostgreSQL and Neo4j.
- LLM inference: Local Ollama service.

**Note:** The current alert processing workflow is sequential. The HTTP result stream uses NDJSON and is not Redis Pub/Sub or Redis Streams.
