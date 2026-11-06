import json
from pathlib import Path
from typing import Any

RELATION_PROPERTIES = {
    "d3f:analyzes",
    "d3f:enables",
    "d3f:hardens",
    "d3f:monitors",
    "d3f:filters",
    "d3f:restricts",
    "d3f:maps",
    "d3f:restores",
    "d3f:authenticates",
    "d3f:deletes",
    "d3f:spoofs",
    "d3f:blocks",
    "d3f:inventories",
    "d3f:validates",
    "d3f:uses",
    "d3f:verifies",
    "d3f:strengthens",
    "d3f:evaluates",
    "d3f:identifies",
    "d3f:regenerates",
    "d3f:encrypts",
    "d3f:terminates",
    "d3f:enforces",
    "d3f:modifies",
    "d3f:mediates-access-to",
    "d3f:disables",
    "d3f:reads",
    "d3f:quarantines",
    "d3f:manages",
    "d3f:configures",
}


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _id(value: Any) -> str | None:
    if isinstance(value, dict):
        return value.get("@id")
    return None


def _text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return value.get("@value") or value.get("@id")
    return None


def load_d3fend(path: str | Path) -> list[dict]:
    """Load D3FEND entities and supporting ontology concepts."""
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    items = []

    for obj in data.get("@graph", []):
        object_id = obj.get("@id")
        types = _as_list(obj.get("@type"))
        external_id = _text(obj.get("d3f:d3fend-id"))
        name = _text(obj.get("rdfs:label"))
        raw_definition = obj.get("d3f:definition")

        if isinstance(raw_definition, list):
            description = "\n".join(
                text for value in raw_definition if (text := _text(value))
            )
        else:
            description = _text(raw_definition)

        if not isinstance(object_id, str) or not object_id.startswith("d3f:"):
            continue
        if not name:
            continue

        if not description:
            description = ""
        if "owl:Class" not in types:
            continue

        # Exclude embedded ATLAS objects.
        if (
            object_id.startswith("d3f:AML.")
            or object_id.startswith("d3f:ATLAS")
            or (external_id and external_id.startswith("AML."))
        ):
            continue

        # Preserve official IDs when present. For supporting concepts,
        # create an internal key without misrepresenting it as an official ID.
        if not external_id:
            external_id = f"ONTOLOGY:{object_id}"

        items.append(
            {
                "framework": "d3fend",
                "external_id": external_id,
                "stix_id": object_id,
                "name": name,
                "description": description,
                "content_text": f"{name}\n\n{description}",
                "data_type": (
                    "ontology_entity"
                    if external_id.startswith("ONTOLOGY:")
                    else "ontology_entity"
                ),
                "source_url": _id(obj.get("rdfs:seeAlso")),
                "source_version": "1.6.0",
                "source_file": path.name,
            }
        )

    # Ontology IDs are the stable identity for deduplication.
    unique = {}
    for item in items:
        unique.setdefault(item["stix_id"], item)

    return list(unique.values())


def load_d3fend_relations(path: str | Path) -> list[dict]:
    """Extract selected D3FEND property relations from the ontology."""
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    relations = []

    for obj in data.get("@graph", []):
        source_id = obj.get("@id")
        if not isinstance(source_id, str) or not source_id.startswith("d3f:"):
            continue

        # Only extract relations originating from identified D3FEND entities.
        if not _text(obj.get("d3f:d3fend-id")):
            continue

        for prop in RELATION_PROPERTIES:
            for target in _as_list(obj.get(prop)):
                target_id = _id(target)
                if not target_id or not target_id.startswith("d3f:"):
                    continue

                # Do not treat ATLAS references as D3FEND entities.
                if source_id.startswith("d3f:AML.") or source_id.startswith(
                    "d3f:ATLAS"
                ):
                    continue
                if target_id.startswith("d3f:AML.") or target_id.startswith(
                    "d3f:ATLAS"
                ):
                    continue

                relations.append(
                    {
                        "source_id": source_id,
                        "target_id": target_id,
                        "relation_type": prop.removeprefix("d3f:"),
                        "provenance_type": "official",
                        "source_version": "1.6.0",
                        "source_file": path.name,
                    }
                )

    unique = {
        (
            r["source_id"],
            r["target_id"],
            r["relation_type"],
        ): r
        for r in relations
    }
    return list(unique.values())
