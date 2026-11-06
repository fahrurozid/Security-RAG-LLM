CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS knowledge_items (
    id BIGSERIAL PRIMARY KEY,
    framework TEXT NOT NULL,
    external_id TEXT NOT NULL,
    stix_id TEXT,
    name TEXT NOT NULL,
    description TEXT,
    content_text TEXT NOT NULL DEFAULT '',
    data_type TEXT,
    platforms TEXT[],
    source_url TEXT,
    source_version TEXT,
    source_file TEXT,
    source_modified TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (framework, external_id)
);

CREATE TABLE IF NOT EXISTS knowledge_relations (
    id BIGSERIAL PRIMARY KEY,
    framework TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    provenance_type TEXT NOT NULL DEFAULT 'official',
    description TEXT,
    source_version TEXT,
    source_file TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (
        framework, source_id, target_id,
        relation_type, provenance_type
    )
);

CREATE TABLE IF NOT EXISTS knowledge_embeddings (
    id BIGSERIAL PRIMARY KEY,
    knowledge_item_id BIGINT NOT NULL
        REFERENCES knowledge_items(id) ON DELETE CASCADE,
    model TEXT NOT NULL,
    embedding VECTOR(768) NOT NULL,
    content_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (knowledge_item_id, model)
);

CREATE INDEX IF NOT EXISTS idx_knowledge_items_framework
    ON knowledge_items(framework);

CREATE INDEX IF NOT EXISTS idx_knowledge_items_stix_id
    ON knowledge_items(stix_id);

CREATE INDEX IF NOT EXISTS idx_knowledge_relations_source
    ON knowledge_relations(source_id);

CREATE INDEX IF NOT EXISTS idx_knowledge_relations_target
    ON knowledge_relations(target_id);

CREATE INDEX IF NOT EXISTS idx_knowledge_embeddings_vector
    ON knowledge_embeddings
    USING hnsw (embedding vector_cosine_ops);
