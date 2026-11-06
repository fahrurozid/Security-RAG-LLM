import json
import os
from collections import Counter
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv(dotenv_path=Path(".env"))

mapping_path = Path("data/frameworks/d3fend/d3fend-full-mappings-1.6.0.json")

if not mapping_path.exists():
    raise FileNotFoundError(f"Mapping file not found: {mapping_path}")

uri = os.environ["NEO4J_URI"]
user = os.environ["NEO4J_USER"]
password = os.environ["NEO4J_PASSWORD"]

data = json.loads(mapping_path.read_text(encoding="utf-8"))
source_rows = data["results"]["bindings"]

# Include Enterprise and ICS mappings; exclude SPARTA.
pairs = {}
for row in source_rows:
    if row.get("framework_key", {}).get("value", "").lower() == "sparta":
        continue

    attack_id = row.get("off_tech_id", {}).get("value")
    d3fend_uri = row.get("def_tech", {}).get("value")
    attack_label = row.get("off_tech_label", {}).get("value")
    d3fend_label = row.get("def_tech_label", {}).get("value")

    if not attack_id or not d3fend_uri or "#" not in d3fend_uri:
        continue

    d3fend_id = "d3f:" + d3fend_uri.rsplit("#", 1)[-1]
    key = (attack_id, d3fend_id)

    # Multiple source rows may describe the same technique pair.
    pairs[key] = {
        "attack_id": attack_id,
        "d3fend_id": d3fend_id,
        "attack_label": attack_label,
        "d3fend_label": d3fend_label,
        "source_uri": d3fend_uri,
        "mapping_source": mapping_path.name,
        "provenance_type": "official",
    }

records = list(pairs.values())
print(
    "Non-SPARTA source rows:",
    sum(
        1
        for r in source_rows
        if r.get("framework_key", {}).get("value", "").lower() != "sparta"
    ),
)
print(f"Unique ATT&CK–D3FEND pairs: {len(records)}")

with GraphDatabase.driver(uri, auth=(user, password)) as driver:
    driver.verify_connectivity()

    with driver.session() as session:
        # Match existing nodes only. Do not create framework nodes here.
        result = session.run(
            """
            UNWIND $rows AS row
            OPTIONAL MATCH (a:AttackItem {external_id: row.attack_id})
            OPTIONAL MATCH (d:D3FENDItem {stix_id: row.d3fend_id})
            RETURN
                count(*) AS checked,
                sum(CASE WHEN a IS NOT NULL THEN 1 ELSE 0 END) AS attack_found,
                sum(CASE WHEN d IS NOT NULL THEN 1 ELSE 0 END) AS d3fend_found,
                sum(CASE WHEN a IS NOT NULL AND d IS NOT NULL THEN 1 ELSE 0 END) AS both_found
        """,
            rows=records,
        ).single()

        print("ATT&CK identifiers matched:", result["attack_found"])
        print("D3FEND identifiers matched:", result["d3fend_found"])
        print("Pairs with both nodes present:", result["both_found"])

        # If either expected property doesn't match, stop before writing.
        if not result["both_found"]:
            raise RuntimeError(
                "No complete mapping pairs matched. No mapping edges were written. "
                "Check the node identifier properties before importing."
            )

        imported = session.run(
            """
            UNWIND $rows AS row
            MATCH (a:AttackItem {external_id: row.attack_id})
            MATCH (d:D3FENDItem {stix_id: row.d3fend_id})
            MERGE (a)-[r:MAPPED_TO {mapping_key: row.attack_id + '|' + row.d3fend_id}]->(d)
            SET
                r.attack_id = row.attack_id,
                r.d3fend_id = row.d3fend_id,
                r.attack_label = row.attack_label,
                r.d3fend_label = row.d3fend_label,
                r.source_uri = row.source_uri,
                r.mapping_source = row.mapping_source,
                r.provenance_type = row.provenance_type
            RETURN count(r) AS processed
        """,
            rows=records,
        ).single()

        print("Mapping pairs processed:", imported["processed"])

        totals = session.run("""
            MATCH (:AttackItem)-[r:MAPPED_TO]->(:D3FENDItem)
            RETURN count(r) AS total
        """).single()

        print("Total ATT&CK–D3FEND mapping edges now in Neo4j:", totals["total"])

        examples = session.run("""
            MATCH (a:AttackItem)-[r:MAPPED_TO]->(d:D3FENDItem)
            RETURN a.external_id AS attack_id,
                   a.name AS attack_name,
                   d.stix_id AS d3fend_id,
                   d.name AS d3fend_name,
                   r.provenance_type AS provenance
            ORDER BY attack_id, d3fend_id
            LIMIT 10
        """)

        print("\nSample imported mappings:")
        for row in examples:
            print(dict(row))
