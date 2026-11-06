import argparse
import hashlib
import os

import httpx
from dotenv import load_dotenv
from sqlalchemy import create_engine, text, bindparam
from pgvector.sqlalchemy import Vector

MODEL = "nomic-embed-text:latest"
OLLAMA_URL = "http://localhost:11434/api/embed"
DIMENSIONS = 768
BATCH_SIZE = 32

SELECT_SQL = text("""
    SELECT
        k.id,
        k.content_text,
        e.content_hash AS old_hash
    FROM knowledge_items k
    LEFT JOIN knowledge_embeddings e
        ON e.knowledge_item_id = k.id
        AND e.model = :model
    WHERE k.framework = 'd3fend'
    ORDER BY k.id
""")

UPSERT_SQL = text("""
    INSERT INTO knowledge_embeddings (
        knowledge_item_id,
        model,
        embedding,
        content_hash
    )
    VALUES (
        :knowledge_item_id,
        :model,
        :embedding,
        :content_hash
    )
    ON CONFLICT (knowledge_item_id, model) DO UPDATE SET
        embedding = EXCLUDED.embedding,
        content_hash = EXCLUDED.content_hash,
        created_at = NOW()
""").bindparams(
    bindparam("embedding", type_=Vector(DIMENSIONS))
)

def make_embeddings(client, texts):
    response = client.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "input": [
                f"search_document: {content}"
                for content in texts
            ],
        },
    )
    response.raise_for_status()

    embeddings = response.json()["embeddings"]

    if len(embeddings) != len(texts):
        raise RuntimeError(
            "Jumlah embedding tidak sesuai dengan jumlah input."
        )

    for embedding in embeddings:
        if len(embedding) != DIMENSIONS:
            raise RuntimeError(
                f"Dimensi embedding tidak sesuai: {len(embedding)}"
            )

    return embeddings

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        action="store_true",
        help="Buat ulang semua embedding D3FEND.",
    )
    args = parser.parse_args()

    load_dotenv()
    database_url = os.environ.get("DATABASE_URL")

    if not database_url:
        raise SystemExit("DATABASE_URL belum tersedia di .env")

    engine = create_engine(database_url)

    with engine.connect() as conn:
        rows = conn.execute(
            SELECT_SQL,
            {"model": MODEL},
        ).mappings().all()

    if not rows:
        raise SystemExit(
            "Tidak ada entitas D3FEND di knowledge_items."
        )

    pending = []

    for row in rows:
        content_hash = hashlib.sha256(
            row["content_text"].encode("utf-8")
        ).hexdigest()

        if args.force or row["old_hash"] != content_hash:
            pending.append({
                "knowledge_item_id": row["id"],
                "content_text": row["content_text"],
                "content_hash": content_hash,
            })

    print(f"Entitas D3FEND ditemukan : {len(rows)}")
    print(f"Embedding perlu dibuat   : {len(pending)}")
    print(f"Model                    : {MODEL}")

    if not pending:
        print("Semua embedding sudah terbaru.")
        return

    processed = 0

    with httpx.Client(timeout=120.0) as client:
        for start in range(0, len(pending), BATCH_SIZE):
            batch = pending[start:start + BATCH_SIZE]

            embeddings = make_embeddings(
                client,
                [item["content_text"] for item in batch],
            )

            records = []

            for item, embedding in zip(batch, embeddings):
                records.append({
                    "knowledge_item_id": item["knowledge_item_id"],
                    "model": MODEL,
                    "embedding": embedding,
                    "content_hash": item["content_hash"],
                })

            with engine.begin() as conn:
                conn.execute(UPSERT_SQL, records)

            processed += len(records)
            print(
                f"Progres: {processed}/{len(pending)}"
            )

    with engine.connect() as conn:
        total = conn.execute(
            text("""
                SELECT COUNT(*)
                FROM knowledge_embeddings e
                JOIN knowledge_items k
                  ON k.id = e.knowledge_item_id
                WHERE k.framework = 'd3fend'
                  AND e.model = :model
            """),
            {"model": MODEL},
        ).scalar_one()

    print(f"Embedding D3FEND di DB : {total}")

if __name__ == "__main__":
    main()
