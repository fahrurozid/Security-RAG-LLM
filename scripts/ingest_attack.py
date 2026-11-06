import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, text

from attack_pre import load_attack, load_relations

load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]
DATA_PATH = Path("data/frameworks/attack/enterprise-attack-20.0.json")


ITEM_SQL = text("""
    INSERT INTO knowledge_items (
        framework, external_id, stix_id, name, description,
        content_text, data_type, platforms, source_url, source_version,
        source_file, source_modified
    )
    VALUES (
        :framework, :external_id, :stix_id, :name, :description,
        :content_text, :data_type, :platforms, :source_url, :source_version,
        :source_file, CAST(:source_modified AS timestamptz)
    )
    ON CONFLICT (framework, external_id) DO UPDATE SET
        stix_id = EXCLUDED.stix_id,
        name = EXCLUDED.name,
        description = EXCLUDED.description,
        content_text = EXCLUDED.content_text,
        data_type = EXCLUDED.data_type,
        platforms = EXCLUDED.platforms,
        source_url = EXCLUDED.source_url,
        source_version = EXCLUDED.source_version,
        source_file = EXCLUDED.source_file,
        source_modified = EXCLUDED.source_modified
""")

RELATION_SQL = text("""
    INSERT INTO knowledge_relations (
        framework, source_id, target_id, relation_type,
        provenance_type, description, source_version, source_file
    )
    VALUES (
        :framework, :source_id, :target_id, :relation_type,
        :provenance_type, :description, :source_version, :source_file
    )
    ON CONFLICT (
        framework, source_id, target_id, relation_type, provenance_type
    ) DO UPDATE SET
        description = EXCLUDED.description,
        source_version = EXCLUDED.source_version,
        source_file = EXCLUDED.source_file
""")


def main():
    items = load_attack(DATA_PATH)
    sample = next(item for item in items if item["external_id"] == "T1003.001")
    print("DEBUG platforms:", sample.get("platforms"))
    print("DEBUG item keys:", list(sample.keys()))

    relations = load_relations(DATA_PATH)

    engine = create_engine(DATABASE_URL)

    with engine.begin() as conn:
        conn.execute(ITEM_SQL, items)
        conn.execute(RELATION_SQL, relations)

    print(f"Items processed: {len(items)}")
    print(f"Relations processed: {len(relations)}")

    with engine.connect() as conn:
        item_count = conn.execute(
            text("SELECT COUNT(*) FROM knowledge_items WHERE framework = 'attack'")
        ).scalar_one()

        relation_count = conn.execute(
            text("SELECT COUNT(*) FROM knowledge_relations WHERE framework = 'attack'")
        ).scalar_one()

    print(f"ATT&CK items in DB: {item_count}")
    print(f"ATT&CK relations in DB: {relation_count}")


if __name__ == "__main__":
    main()
