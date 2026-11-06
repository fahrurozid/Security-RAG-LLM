import os

from neo4j import GraphDatabase


def retrieve_d3fend_mappings(
    attack_ids: list[str],
) -> list[dict]:
    """Retrieve D3FEND techniques mapped to selected ATT&CK IDs."""

    if not attack_ids:
        return []

    uri = os.environ["NEO4J_URI"]
    user = os.environ["NEO4J_USER"]
    password = os.environ["NEO4J_PASSWORD"]

    query = """
    MATCH (a:AttackItem)-[r:MAPPED_TO]->(d:D3FENDItem)
    WHERE a.external_id IN $attack_ids

    WITH
        d,
        collect(DISTINCT a.external_id) AS attack_ids,
        collect(DISTINCT {
            attack_id: a.external_id,
            relationship: type(r),
            provenance_type: coalesce(r.provenance_type, 'unknown')
        }) AS mappings

    RETURN
        d.stix_id AS stix_id,
        d.external_id AS external_id,
        d.name AS name,
        coalesce(d.description, d.content_text, '') AS description,
        d.data_type AS data_type,
        attack_ids,
        mappings
    """

    with GraphDatabase.driver(
        uri,
        auth=(user, password),
    ) as driver:
        driver.verify_connectivity()

        with driver.session() as session:
            result = session.run(
                query,
                attack_ids=attack_ids,
            )

            return [record.data() for record in result]
