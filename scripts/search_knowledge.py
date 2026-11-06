import json
import argparse
import os
import re

import httpx
from dotenv import load_dotenv
from pgvector.sqlalchemy import Vector
from sqlalchemy import bindparam, create_engine, text

MODEL = "nomic-embed-text:latest"
OLLAMA_URL = "http://localhost:11434/api/embed"
DIMENSIONS = 768
RRF_K = 60

# Vector retrieval: baseline.
SEARCH_SQL = text("""
    SELECT
        k.framework,
        k.external_id,
        k.name,
        k.description,
        k.data_type,
        k.source_version,
        1 - (e.embedding <=> :query_embedding) AS similarity
    FROM knowledge_embeddings e
    JOIN knowledge_items k ON k.id = e.knowledge_item_id
    WHERE e.model = :model
      AND (
          CAST(:framework AS TEXT) IS NULL
          OR k.framework = CAST(:framework AS TEXT)
      )
    ORDER BY e.embedding <=> :query_embedding
    LIMIT :limit
""").bindparams(bindparam("query_embedding", type_=Vector(DIMENSIONS)))


# Exact-ID retrieval.
EXACT_ID_SQL = text("""
    SELECT
        k.framework,
        k.external_id,
        k.name,
        k.description,
        k.data_type,
        k.source_version
    FROM knowledge_items k
    WHERE (
        CAST(:framework AS TEXT) IS NULL
        OR k.framework = CAST(:framework AS TEXT)
    )
      AND k.external_id = ANY(:ids)
    ORDER BY k.external_id
    LIMIT :limit
""")


# Lexical retrieval: OR antarterm agar query panjang
# tidak mengharuskan semua kata muncul pada dokumen yang sama.
LEXICAL_SQL = text("""
    WITH query_terms AS (
        SELECT to_tsquery(
            'simple',
            string_agg(
                quote_literal(token) || ':*',
                ' | '
            )
        ) AS tsq
        FROM (
            SELECT DISTINCT token
            FROM unnest(
                regexp_split_to_array(
                    lower(:query),
                    '[^a-zA-Z0-9_.-]+'
                )
            ) AS token
            WHERE token <> ''
        ) AS terms
    ),
    searchable AS (
        SELECT
            k.framework,
            k.external_id,
            k.name,
            k.description,
            k.data_type,
            k.source_version,
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
        s.framework,
        s.external_id,
        s.name,
        s.description,
        s.data_type,
        s.source_version,
        ts_rank_cd(s.document_vector, q.tsq) AS lexical_score
    FROM searchable s
    CROSS JOIN query_terms q
    WHERE q.tsq IS NOT NULL
      AND s.document_vector @@ q.tsq
    ORDER BY lexical_score DESC, s.external_id
    LIMIT :limit
""")


def extract_ids(query):
    """Ambil ID framework yang eksplisit disebut dalam query."""
    pattern = (
        r"\b(?:"
        r"T\d{4}(?:\.\d{3})?"
        r"|S\d{4}"
        r"|G\d{4}"
        r"|M\d{4}"
        r"|DET\d{4}"
        r"|AN\d{4}"
        r"|D3-[A-Z0-9]+(?:-[A-Z0-9]+)*"
        r")\b"
    )
    return sorted(set(re.findall(pattern, query.upper())))


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
    if not embeddings:
        raise RuntimeError("Ollama tidak mengembalikan embedding.")

    embedding = embeddings[0]
    if len(embedding) != DIMENSIONS:
        raise RuntimeError(f"Dimensi embedding tidak sesuai: {len(embedding)}")

    return embedding


def reciprocal_rank_fusion(result_lists, k=RRF_K):
    """Gabungkan ranking dari beberapa jalur retrieval."""
    fused = {}

    for results in result_lists:
        for rank, row in enumerate(results, start=1):
            key = (row["framework"], row["external_id"])

            if key not in fused:
                fused[key] = {
                    **dict(row),
                    "rrf_score": 0.0,
                    "retrieval_sources": [],
                }

            fused[key]["rrf_score"] += 1.0 / (k + rank)

            source = row.get("retrieval_source")
            if source and source not in fused[key]["retrieval_sources"]:
                fused[key]["retrieval_sources"].append(source)

            if "similarity" in row:
                fused[key]["similarity"] = row["similarity"]

            if "lexical_score" in row:
                fused[key]["lexical_score"] = row["lexical_score"]

    return sorted(
        fused.values(),
        key=lambda row: row["rrf_score"],
        reverse=True,
    )


def main():
    parser = argparse.ArgumentParser(
        description="Vector dan hybrid retrieval untuk knowledge cybersecurity."
    )
    parser.add_argument("query", help="Teks query atau konteks alert")
    parser.add_argument(
        "--framework",
        choices=["attack", "d3fend", "car", "atlas"],
        default=None,
        help="Batasi pencarian ke satu framework",
    )
    parser.add_argument(
        "--mode",
        choices=["vector", "hybrid"],
        default="hybrid",
        help="vector = baseline; hybrid = exact-ID + lexical + vector",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="The output will be in JSON format.",
    )
    parser.add_argument(
        "-k",
        type=int,
        default=10,
        help="Jumlah hasil akhir",
    )
    args = parser.parse_args()

    if args.k < 1:
        parser.error("-k harus minimal 1")

    load_dotenv()
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise SystemExit("DATABASE_URL belum tersedia di .env")

    query_embedding = embed_query(args.query)
    engine = create_engine(database_url)
    candidate_limit = max(args.k * 5, 50)

    with engine.connect() as conn:
        vector_rows = (
            conn.execute(
                SEARCH_SQL,
                {
                    "query_embedding": query_embedding,
                    "model": MODEL,
                    "framework": args.framework,
                    "limit": (candidate_limit if args.mode == "hybrid" else args.k),
                },
            )
            .mappings()
            .all()
        )

        vector_results = [
            {**dict(row), "retrieval_source": "vector"} for row in vector_rows
        ]

        if args.mode == "vector":
            results = vector_results
        else:
            ids = extract_ids(args.query)

            exact_results = []
            if ids:
                exact_rows = (
                    conn.execute(
                        EXACT_ID_SQL,
                        {
                            "framework": args.framework,
                            "ids": ids,
                            "limit": candidate_limit,
                        },
                    )
                    .mappings()
                    .all()
                )

                exact_results = [
                    {**dict(row), "retrieval_source": "exact_id"} for row in exact_rows
                ]

            lexical_rows = (
                conn.execute(
                    LEXICAL_SQL,
                    {
                        "framework": args.framework,
                        "query": args.query,
                        "limit": candidate_limit,
                    },
                )
                .mappings()
                .all()
            )

            lexical_results = [
                {**dict(row), "retrieval_source": "lexical"} for row in lexical_rows
            ]

            results = reciprocal_rank_fusion(
                [exact_results, lexical_results, vector_results]
            )[: args.k]

    if args.json:
        print(
            json.dumps(
                {
                    "mode": args.mode,
                    "framework": args.framework,
                    "query_ids": extract_ids(args.query),
                    "results": [
                        {
                            **row,
                            "similarity": row.get("similarity"),
                            "lexical_score": row.get("lexical_score"),
                            "rrf_score": row.get("rrf_score"),
                        }
                        for row in results
                    ],
                },
                ensure_ascii=False,
                default=str,
            )
        )
        return

    if not results:
        print("Tidak ada hasil.")
        return

    print(f"Mode       : {args.mode}")
    print(f"Framework  : {args.framework or 'semua'}")

    if args.mode == "hybrid":
        print("ID query   : " + (", ".join(extract_ids(args.query)) or "(tidak ada)"))

    for index, row in enumerate(results, start=1):
        print(
            f"\n{index}. [{row['framework']}] " f"{row['external_id']} — {row['name']}"
        )
        print(f"   Tipe       : {row['data_type']}")
        print(f"   Versi      : {row['source_version']}")

        if args.mode == "vector":
            print(f"   Similarity : {row['similarity']:.4f}")
        else:
            print(f"   RRF score  : {row['rrf_score']:.6f}")
            print("   Sumber     : " + ", ".join(row["retrieval_sources"]))

            if "similarity" in row:
                print(f"   Similarity : {row['similarity']:.4f}")

            if "lexical_score" in row:
                print(f"   Lexical    : {row['lexical_score']:.6f}")

        description = row["description"] or ""
        print(f"   Deskripsi  : {description[:500]}")


if __name__ == "__main__":
    main()
