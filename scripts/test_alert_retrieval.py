import argparse
import json
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv
from pgvector.sqlalchemy import Vector
from sqlalchemy import bindparam, create_engine, text

MODEL = "nomic-embed-text:latest"
OLLAMA_URL = "http://localhost:11434/api/embed"
DIMENSIONS = 768
RRF_K = 60

VECTOR_SQL = text("""
    SELECT
        k.framework, k.external_id, k.name, k.description,
        k.data_type, k.source_version,
        1 - (e.embedding <=> :embedding) AS similarity
    FROM knowledge_embeddings e
    JOIN knowledge_items k ON k.id = e.knowledge_item_id
    WHERE e.model = :model
    AND (
        CAST(:framework AS TEXT) IS NULL
        OR k.framework = CAST(:framework AS TEXT)
    )
    ORDER BY e.embedding <=> :embedding
    LIMIT :limit
""").bindparams(bindparam("embedding", type_=Vector(DIMENSIONS)))

LEXICAL_SQL = text("""
    WITH query_terms AS (
        SELECT to_tsquery(
            'simple',
            string_agg(quote_literal(token) || ':*', ' | ')
        ) AS tsq
        FROM (
            SELECT DISTINCT token
            FROM unnest(
                regexp_split_to_array(lower(:query), '[^a-zA-Z0-9_.-]+')
            ) AS token
            WHERE token <> ''
        ) terms
    ),
    searchable AS (
        SELECT
            k.framework, k.external_id, k.name, k.description,
            k.data_type, k.source_version,
            to_tsvector(
                'simple',
                coalesce(k.external_id, '') || ' ' ||
                coalesce(k.name, '') || ' ' ||
                coalesce(k.description, '') || ' ' ||
                coalesce(k.content_text, '')
            ) AS document_vector
        FROM knowledge_items k
        WHERE (
            CAST(:framework AS TEXT) IS NULL
            OR k.framework = CAST(:framework AS TEXT)
        )
    )
    SELECT
        s.framework, s.external_id, s.name, s.description,
        s.data_type, s.source_version,
        ts_rank_cd(s.document_vector, q.tsq) AS lexical_score
    FROM searchable s
    CROSS JOIN query_terms q
    WHERE q.tsq IS NOT NULL
      AND s.document_vector @@ q.tsq
    ORDER BY lexical_score DESC, s.external_id
    LIMIT :limit
""")


def load_alert(path):
    alert = json.loads(Path(path).read_text(encoding="utf-8"))
    original = alert.get("original", {})

    # The final alert may store "original" as a JSON string.
    if isinstance(original, str):
        try:
            original = json.loads(original)
        except json.JSONDecodeError:
            original = {}

    if not isinstance(original, dict):
        original = {}

    rule = original.get("rule") or {}
    agent = original.get("agent") or {}
    data = original.get("data") or {}

    # Keep the retrieval query focused on observed behavior.
    fields = [
        alert.get("alert_title"),
        rule.get("description"),
        original.get("decoder"),
        original.get("full_log"),
        f"Source IP {data.get('srcip', '')}",
        f"User {data.get('dstuser', '')}",
        f"Destination host {agent.get('name', '')}",
        f"Destination IP {agent.get('ip', '')}",
    ]

    query = "\n".join(str(value) for value in fields if value)
    return alert, query


def embed_query(query):
    response = httpx.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "input": [f"search_query: {query}"],
        },
        timeout=120.0,
    )
    response.raise_for_status()

    embeddings = response.json()["embeddings"]
    if not embeddings or len(embeddings[0]) != DIMENSIONS:
        raise RuntimeError("Embedding kosong atau dimensinya tidak sesuai.")

    return embeddings[0]


def fuse(vector_rows, lexical_rows, limit):
    combined = {}

    for source, rows in (
        ("vector", vector_rows),
        ("lexical", lexical_rows),
    ):
        for rank, row in enumerate(rows, start=1):
            key = (row["framework"], row["external_id"])

            if key not in combined:
                combined[key] = {
                    **dict(row),
                    "rrf_score": 0.0,
                    "sources": [],
                }

            item = combined[key]
            item["rrf_score"] += 1 / (RRF_K + rank)
            item["sources"].append(source)

            for score in ("similarity", "lexical_score"):
                if score in row:
                    item[score] = row[score]

    return sorted(
        combined.values(),
        key=lambda item: item["rrf_score"],
        reverse=True,
    )[:limit]


def main():
    parser = argparse.ArgumentParser(
        description="Test alert retrieval using vector + lexical search only."
    )
    parser.add_argument("alert", help="Path to the alert JSON file")
    parser.add_argument("-k", type=int, default=10)
    parser.add_argument(
        "--framework",
        choices=["attack", "d3fend", "car", "atlas"],
        default=None,
    )
    args = parser.parse_args()

    if args.k < 1:
        parser.error("-k must be at least 1")

    load_dotenv()
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise SystemExit("DATABASE_URL is missing from .env")

    alert, query = load_alert(args.alert)
    if not query.strip():
        raise SystemExit("No searchable alert fields found.")

    print("Retrieval query:")
    print(query)
    print("\nSearching knowledge base...")

    embedding = embed_query(query)
    candidate_limit = max(args.k * 5, 50)
    engine = create_engine(database_url)

    try:
        with engine.connect() as conn:
            params = {
                "framework": args.framework,
                "limit": candidate_limit,
            }

            vector_rows = (
                conn.execute(
                    VECTOR_SQL,
                    {
                        **params,
                        "embedding": embedding,
                        "model": MODEL,
                    },
                )
                .mappings()
                .all()
            )

            lexical_rows = (
                conn.execute(
                    LEXICAL_SQL,
                    {
                        **params,
                        "query": query,
                    },
                )
                .mappings()
                .all()
            )

            results = fuse(vector_rows, lexical_rows, args.k)
    finally:
        engine.dispose()

    print(f"\nFramework: {args.framework or 'all'}")
    print(f"Vector candidates: {len(vector_rows)}")
    print(f"Lexical candidates: {len(lexical_rows)}")
    print(f"Final results: {len(results)}")

    if not results:
        print("No results found.")
        return

    for rank, row in enumerate(results, start=1):
        print(
            f"\n{rank}. [{row['framework']}] " f"{row['external_id']} — {row['name']}"
        )
        print(f"   Type       : {row['data_type']}")
        print(f"   Sources    : {', '.join(row['sources'])}")
        print(f"   RRF score  : {row['rrf_score']:.6f}")

        if "similarity" in row:
            print(f"   Similarity : {row['similarity']:.4f}")
        if "lexical_score" in row:
            print(f"   Lexical    : {row['lexical_score']:.4f}")

        description = row["description"] or ""
        if description:
            print(f"   Description: {description[:400]}")


if __name__ == "__main__":
    main()
