
import hashlib
import os
import sys

import httpx
from dotenv import load_dotenv
from pgvector.sqlalchemy import Vector
from sqlalchemy import bindparam, create_engine, text

MODEL = "nomic-embed-text:latest"
OLLAMA_URL = "http://localhost:11434/api/embed"
BATCH_SIZE = 32
DIMENSIONS = 768


def content_hash(content):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def embed_batch(client, texts):
    response = client.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "input": [f"search_document: {item}" for item in texts],
        },
    )
    response.raise_for_status()
    embeddings = response.json()["embeddings"]

    if len(embeddings) != len(texts):
        raise RuntimeError("Jumlah embedding tidak sesuai jumlah dokumen.")

    for embedding in embeddings:
        if len(embedding) != DIMENSIONS:
            raise RuntimeError(
                f"Dimensi embedding tidak sesuai: {len(embedding)}"
            )

    return embeddings


def main():
    load_dotenv()
    database_url = os.environ.get("DATABASE_URL")

    if not database_url:
        raise RuntimeError("DATABASE_URL belum diatur di .env")

    engine = create_engine(database_url)

    with engine.connect() as conn:
        items = conn.execute(
            text("""
                SELECT id, content_text
                FROM knowledge_items
                WHERE framework = 'attack'
                  AND content_text <> ''
                ORDER BY id
            """)
        ).mappings().all()

        existing = conn.execute(
            text("""
                SELECT knowledge_item_id, content_hash
                FROM knowledge_embeddings
                WHERE model = :model
            """),
            {"model": MODEL},
        ).mappings().all()

    existing_hashes = {
        row["knowledge_item_id"]: row["content_hash"]
        for row in existing
    }

    pending = []
    skipped = 0

    for item in items:
        digest = content_hash(item["content_text"])
        if existing_hashes.get(item["id"]) == digest:
            skipped += 1
            continue

        pending.append({
            "id": item["id"],
            "content_text": item["content_text"],
            "content_hash": digest,
        })

    print(f"Total item ATT&CK : {len(items)}")
    print(f"Sudah sesuai      : {skipped}")
    print(f"Perlu diproses    : {len(pending)}")

    insert_stmt = text("""
        INSERT INTO knowledge_embeddings
            (knowledge_item_id, model, embedding, content_hash)
        VALUES
            (:id, :model, :embedding, :content_hash)
        ON CONFLICT (knowledge_item_id, model)
        DO UPDATE SET
            embedding = EXCLUDED.embedding,
            content_hash = EXCLUDED.content_hash,
            created_at = NOW()
    """).bindparams(
        bindparam("embedding", type_=Vector(DIMENSIONS))
    )

    processed = 0

    with httpx.Client(timeout=180.0) as client:
        for start in range(0, len(pending), BATCH_SIZE):
            batch = pending[start:start + BATCH_SIZE]
            vectors = embed_batch(
                client,
                [item["content_text"] for item in batch],
            )

            rows = [
                {
                    "id": item["id"],
                    "model": MODEL,
                    "embedding": vector,
                    "content_hash": item["content_hash"],
                }
                for item, vector in zip(batch, vectors)
            ]

            with engine.begin() as conn:
                conn.execute(insert_stmt, rows)

            processed += len(rows)
            print(f"Progress: {processed}/{len(pending)}")

    with engine.connect() as conn:
        count = conn.execute(
            text("""
                SELECT COUNT(*)
                FROM knowledge_embeddings
                WHERE model = :model
            """),
            {"model": MODEL},
        ).scalar_one()

    print(f"Embedding baru/diperbarui: {processed}")
    print(f"Embedding dilewati       : {skipped}")
    print(f"Total embedding model    : {count}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
