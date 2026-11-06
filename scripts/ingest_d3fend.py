import argparse
from pathlib import Path

from sqlalchemy import create_engine, text
from dotenv import load_dotenv

from d3fend_pre import load_d3fend, load_d3fend_relations

ITEM_SQL = text("""
    INSERT INTO knowledge_items (
        framework, external_id, stix_id, name, description,
        content_text, data_type, source_url, source_version, source_file
    )
    VALUES (
        :framework, :external_id, :stix_id, :name, :description,
        :content_text, :data_type, :source_url, :source_version, :source_file
    )
    ON CONFLICT (framework, external_id) DO UPDATE SET
        stix_id = EXCLUDED.stix_id,
        name = EXCLUDED.name,
        description = EXCLUDED.description,
        content_text = EXCLUDED.content_text,
        data_type = EXCLUDED.data_type,
        source_url = EXCLUDED.source_url,
        source_version = EXCLUDED.source_version,
        source_file = EXCLUDED.source_file
""")

RELATION_SQL = text("""
    INSERT INTO knowledge_relations (
        framework, source_id, target_id, relation_type,
        provenance_type, source_version, source_file
    )
    VALUES (
        'd3fend', :source_id, :target_id, :relation_type,
        :provenance_type, :source_version, :source_file
    )
    ON CONFLICT (
        framework, source_id, target_id, relation_type, provenance_type
    ) DO UPDATE SET
        source_version = EXCLUDED.source_version,
        source_file = EXCLUDED.source_file
""")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default="data/frameworks/d3fend/d3fend-1.6.0.json",
    )
    parser.add_argument(
        "--mappings-only",
        action="store_true",
        help="Reserved for a future separate mapping import.",
    )
    args = parser.parse_args()

    if args.mappings_only:
        parser.error("Mapping import is not implemented in this script.")

    load_dotenv()
    database_url = __import__("os").environ.get("DATABASE_URL")
    if not database_url:
        raise SystemExit("DATABASE_URL belum tersedia di .env")

    path = Path(args.input)
    items = load_d3fend(path)
    relations = load_d3fend_relations(path)

    print(f"Entitas akan diproses : {len(items)}")
    print(f"Relasi akan diproses  : {len(relations)}")

    engine = create_engine(database_url)

    with engine.begin() as conn:
        conn.execute(ITEM_SQL, items)
        conn.execute(RELATION_SQL, relations)

        item_count = conn.execute(text("""
            SELECT COUNT(*) FROM knowledge_items
            WHERE framework = 'd3fend'
        """)).scalar_one()

        relation_count = conn.execute(text("""
            SELECT COUNT(*) FROM knowledge_relations
            WHERE framework = 'd3fend'
        """)).scalar_one()

    print(f"Entitas D3FEND di DB : {item_count}")
    print(f"Relasi D3FEND di DB  : {relation_count}")


if __name__ == "__main__":
    main()
