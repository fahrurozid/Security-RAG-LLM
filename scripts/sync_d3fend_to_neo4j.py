import os

from dotenv import load_dotenv
from neo4j import GraphDatabase
from sqlalchemy import create_engine, text

BATCH_SIZE = 500

ITEMS_SQL = text("""
    SELECT
        framework,
        external_id,
        stix_id,
        name,
        description,
        content_text,
        data_type,
        source_version
    FROM knowledge_items
    WHERE framework = 'd3fend'
      AND stix_id IS NOT NULL
    ORDER BY stix_id
""")

RELATIONS_SQL = text("""
    SELECT
        r.source_id,
        r.target_id,
        r.relation_type,
        r.provenance_type,
        r.description,
        r.source_version,
        r.source_file
    FROM knowledge_relations r
    WHERE r.framework = 'd3fend'
      AND EXISTS (
          SELECT 1 FROM knowledge_items k
          WHERE k.framework = 'd3fend'
            AND k.stix_id = r.source_id
      )
      AND EXISTS (
          SELECT 1 FROM knowledge_items k
          WHERE k.framework = 'd3fend'
            AND k.stix_id = r.target_id
      )
    ORDER BY r.source_id, r.target_id, r.relation_type
""")

CREATE_CONSTRAINT = """
CREATE CONSTRAINT d3fend_item_key IF NOT EXISTS
FOR (n:D3FENDItem) REQUIRE n.key IS UNIQUE
"""

UPSERT_NODES = """
UNWIND $rows AS row
MERGE (n:D3FENDItem {key: row.key})
SET n.framework = row.framework,
    n.external_id = row.external_id,
    n.stix_id = row.stix_id,
    n.name = row.name,
    n.description = row.description,
    n.content_text = row.content_text,
    n.data_type = row.data_type,
    n.source_version = row.source_version
"""

UPSERT_RELATIONS = """
UNWIND $rows AS row
MATCH (source:D3FENDItem {key: row.source_key})
MATCH (target:D3FENDItem {key: row.target_key})
MERGE (source)-[r:RELATED_TO {
    relation_key: row.relation_key
}]->(target)
SET r.relation_type = row.relation_type,
    r.provenance_type = row.provenance_type,
    r.description = row.description,
    r.source_version = row.source_version,
    r.source_file = row.source_file
"""


def batches(rows, size=BATCH_SIZE):
    for start in range(0, len(rows), size):
        yield rows[start : start + size]


def main():
    load_dotenv()

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise SystemExit("DATABASE_URL belum tersedia di .env")

    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD")
    if not password:
        raise SystemExit("NEO4J_PASSWORD belum tersedia di .env")

    pg_engine = create_engine(database_url)

    with pg_engine.connect() as conn:
        items = [dict(row) for row in conn.execute(ITEMS_SQL).mappings()]
        relations = [dict(row) for row in conn.execute(RELATIONS_SQL).mappings()]

    if not items:
        raise SystemExit("Tidak ada item D3FEND dengan stix_id di PostgreSQL")

    for item in items:
        item["key"] = f"d3fend:{item['stix_id']}"

    relation_rows = []
    for rel in relations:
        source_key = f"d3fend:{rel['source_id']}"
        target_key = f"d3fend:{rel['target_id']}"
        relation_key = "|".join(
            [
                source_key,
                rel["relation_type"],
                target_key,
            ]
        )
        relation_rows.append(
            {
                **rel,
                "source_key": source_key,
                "target_key": target_key,
                "relation_key": relation_key,
            }
        )

    driver = GraphDatabase.driver(uri, auth=(user, password))
    try:
        driver.verify_connectivity()

        with driver.session() as session:
            session.run(CREATE_CONSTRAINT).consume()

            for batch in batches(items):
                session.run(UPSERT_NODES, rows=batch).consume()

            for batch in batches(relation_rows):
                session.run(UPSERT_RELATIONS, rows=batch).consume()

            node_count = session.run(
                "MATCH (n:D3FENDItem) RETURN count(n) AS count"
            ).single()["count"]

            edge_count = session.run(
                "MATCH (:D3FENDItem)-[r:RELATED_TO]->(:D3FENDItem) "
                "RETURN count(r) AS count"
            ).single()["count"]

        print(f"Item D3FEND dari PostgreSQL: {len(items)}")
        print(f"Relasi dengan kedua endpoint tersedia: {len(relation_rows)}")
        print(f"Node D3FEND di Neo4j: {node_count}")
        print(f"Edge D3FEND di Neo4j: {edge_count}")
    finally:
        driver.close()
        pg_engine.dispose()


if __name__ == "__main__":
    main()
