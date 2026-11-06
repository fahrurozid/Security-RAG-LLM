import json
from pathlib import Path
from typing import Any

ATTACK_TYPES = {
    "attack-pattern",
    "course-of-action",
    "x-mitre-data-component",
    "x-mitre-detection-strategy",
    "x-mitre-analytic",
    "malware",
    "tool",
    "intrusion-set",
    "campaign",
    "identity",
    "x-mitre-tactic",
}


def detect_platform(obj: dict[str, Any]) -> list[str]:
    platforms = obj.get("x_mitre_platforms", [])
    return sorted(set(platforms))

def load_attack(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)

    with path.open("r", encoding="utf-8") as file:
        bundle = json.load(file)

    objects = bundle.get("objects", [])
    items = []

    for obj in objects:
        if obj.get("type") not in ATTACK_TYPES:
            continue

        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        external_id = next(
            (
                ref["external_id"]
                for ref in obj.get("external_references", [])
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id")
            ),
            None,
        )

        external_id = external_id or obj.get("id")

        if not external_id:
            continue

        items.append(
            {
                "framework": "attack",
                "external_id": external_id,
                "stix_id": obj.get("id"),
                "name": obj.get("name") or external_id,
                "description": obj.get("description"),
                "content_text": "\n\n".join(
                    part
                    for part in [
                        obj.get("name"),
                        obj.get("description"),
                    ]
                    if part
                ),
                "data_type": obj.get("type"),
                "platforms": detect_platform(obj),
                "source_url": next(
                    (
                        ref["url"]
                        for ref in obj.get("external_references", [])
                        if ref.get("source_name") == "mitre-attack"
                        and ref.get("external_id") == external_id
                        and ref.get("url")
                    ),
                    None,
                ),
                "source_version": "20.0",
                "source_file": path.name,
                "source_modified": obj.get("modified"),
            }
        )

    return items


def load_relations(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)

    with path.open("r", encoding="utf-8") as file:
        bundle = json.load(file)

    relations = []

    for obj in bundle.get("objects", []):
        if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
            continue

        # Relasi STIX standar
        if obj.get("type") == "relationship":
            source_id = obj.get("source_ref")
            target_id = obj.get("target_ref")
            relation_type = obj.get("relationship_type")

            if not source_id or not target_id or not relation_type:
                continue

            relations.append(
                {
                    "framework": "attack",
                    "source_id": source_id,
                    "target_id": target_id,
                    "relation_type": relation_type,
                    "provenance_type": "official",
                    "description": obj.get("description"),
                    "source_version": "20.0",
                    "source_file": path.name,
                }
            )

        # Relasi resmi detection strategy -> analytic
        elif obj.get("type") == "x-mitre-detection-strategy":
            strategy_id = obj.get("id")

            if not strategy_id:
                continue

            for analytic_id in obj.get("x_mitre_analytic_refs", []):
                if not analytic_id:
                    continue

                relations.append(
                    {
                        "framework": "attack",
                        "source_id": strategy_id,
                        "target_id": analytic_id,
                        "relation_type": "has-analytic",
                        "provenance_type": "official",
                        "description": None,
                        "source_version": "20.0",
                        "source_file": path.name,
                    }
                )

    return relations
