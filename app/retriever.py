import json
import re
import subprocess
import sys
from collections import Counter

import httpx
from sqlalchemy import create_engine, text, bindparam
from pgvector.sqlalchemy import Vector

from app.config import (
    ROOT,
    DATABASE_URL,
    EMBEDDING_MODEL,
    EMBEDDING_BASE_URL,
    STOPWORDS,
    RELATIONSHIP_WEIGHTS,
    DATA_TYPE_WEIGHTS,
)


def build_retrieval_query(alert: dict) -> str:
    """Build a focused retrieval query from a normalized Wazuh alert."""

    original = alert.get("original", {})

    if isinstance(original, str):
        try:
            original = json.loads(original)
        except json.JSONDecodeError:
            original = {"raw": original}

    rule = original.get("rule", {})
    data = original.get("data", {})

    return "\n".join(
        str(value)
        for value in [
            alert.get("alert_description", ""),
            rule.get("description", ""),
            f"Wazuh rule ID: {rule.get('id', '')}",
            f"Event: {original.get('full_log', '')}",
            f"Source IP: {data.get('srcip', '')}",
            f"Destination user: {data.get('dstuser', '')}",
        ]
        if value
    )


def search_framework(
    query: str,
    framework: str,
    top_k: int = 3,
) -> dict:
    """Run the existing hybrid framework retriever."""

    script = ROOT / "scripts" / "search_knowledge.py"

    result = subprocess.run(
        [
            sys.executable,
            str(script),
            query,
            "--mode",
            "hybrid",
            "--framework",
            framework,
            "-k",
            str(top_k),
            "--json",
        ],
        cwd=ROOT,
        env={
            **__import__("os").environ,
            "PYTHONPATH": ":".join(
                [
                    str(ROOT / "src"),
                    __import__("os").environ.get("PYTHONPATH", ""),
                ]
            ),
        },
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"{framework} retrieval failed.\n"
            f"stdout: {result.stdout[-2000:]}\n"
            f"stderr: {result.stderr[-2000:]}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"{framework} retriever returned invalid JSON: "
            f"{result.stdout[:1000]!r}"
        ) from exc


def _text_for_scoring(item: dict) -> str:
    """Build searchable text from a knowledge item."""

    fields = [
        item.get("id", ""),
        item.get("name", ""),
        item.get("data_type", ""),
        item.get("description", ""),
        item.get("relationship", ""),
    ]

    return " ".join(
        str(value)
        for value in fields
        if value
    )


def _tokenize(value: str) -> list[str]:
    """Normalize text into meaningful tokens."""

    tokens = re.findall(
        r"[a-zA-Z][a-zA-Z0-9_.-]*",
        value.lower(),
    )

    return [
        token
        for token in tokens
        if len(token) > 1 and token not in STOPWORDS
    ]


def _score_candidate(
    item: dict,
    query_tokens: list[str],
    framework: str,
    alert_ids=None,
) -> tuple[float, list[str]]:
    """Calculate lexical relevance and available ranking signals."""

    candidate_text = _text_for_scoring(item)
    candidate_tokens = _tokenize(candidate_text)

    query_counts = Counter(query_tokens)
    candidate_counts = Counter(candidate_tokens)

    overlap = set(query_counts) & set(candidate_counts)

    lexical_score = sum(
        min(query_counts[token], 3)
        * min(candidate_counts[token], 2)
        for token in overlap
    )

    query_vocabulary = set(query_tokens)

    coverage = (
        len(overlap) / len(query_vocabulary)
        if query_vocabulary
        else 0.0
    )

    score = lexical_score + coverage * 5.0
    reasons = []

    if overlap:
        reasons.append(
            "lexical overlap: "
            + ", ".join(sorted(overlap)[:12])
        )

    alert_ids = set(alert_ids or [])
    candidate_id = str(item.get("id", ""))

    if framework == "attack" and candidate_id in alert_ids:
        score += 5.0
        reasons.append("exact alert ATT&CK technique match (+5.0)")

    relationship = str(
        item.get("relationship", "")
    ).lower()

    if framework == "attack" and relationship in RELATIONSHIP_WEIGHTS:
        bonus = RELATIONSHIP_WEIGHTS[relationship]
        score += bonus
        reasons.append(
            f"ATT&CK relationship '{relationship}' (+{bonus})"
        )

    data_type = str(
        item.get("data_type", "")
    ).lower()

    if framework == "attack" and data_type in DATA_TYPE_WEIGHTS:
        bonus = DATA_TYPE_WEIGHTS[data_type]
        score += bonus
        reasons.append(
            f"evidence type '{data_type}' (+{bonus})"
        )

    return score, reasons


def embed_alert_context(query: str) -> list[float]:
    """Generate a query embedding using local Ollama."""

    payload = {
        "model": EMBEDDING_MODEL,
        "input": [f"search_query: {query}"],
    }

    response = httpx.post(
        f"{EMBEDDING_BASE_URL}/api/embed",
        json=payload,
        timeout=120.0,
    )

    response.raise_for_status()

    embeddings = response.json().get("embeddings", [])

    if not embeddings:
        raise RuntimeError(
            "Ollama returned no query embedding."
        )

    embedding = embeddings[0]

    if len(embedding) != 768:
        raise ValueError(
            f"Expected 768 dimensions, received {len(embedding)}."
        )

    return embedding


def fetch_candidate_similarities(
    candidates: list[dict],
    query_embedding: list[float],
) -> dict[tuple[str, str], float]:
    """Find stored embedding similarities for candidates."""

    attack_ids = sorted({
        item["id"]
        for item in candidates
        if item.get("id")
        and item.get("framework", "attack") == "attack"
    })

    d3fend_stix_ids = sorted({
        item["id"]
        for item in candidates
        if item.get("id")
        and item.get("framework") == "d3fend"
    })

    if not attack_ids and not d3fend_stix_ids:
        return {}

    sql = text("""
        SELECT
            k.framework,
            CASE
                WHEN k.framework = 'd3fend'
                    THEN k.stix_id
                ELSE k.external_id
            END AS candidate_id,
            1 - (e.embedding <=> :query_embedding) AS similarity

        FROM knowledge_items AS k

        JOIN knowledge_embeddings AS e
          ON e.knowledge_item_id = k.id

        WHERE e.model = :model
          AND (
                (
                    k.framework = 'attack'
                    AND k.external_id = ANY(:attack_ids)
                )
             OR (
                    k.framework = 'd3fend'
                    AND k.stix_id = ANY(:d3fend_stix_ids)
                )
          )
    """).bindparams(
        bindparam(
            "query_embedding",
            type_=Vector(768),
        )
    )

    engine = create_engine(DATABASE_URL)

    try:
        with engine.connect() as conn:
            rows = (
                conn.execute(
                    sql,
                    {
                        "query_embedding": query_embedding,
                        "model": EMBEDDING_MODEL,
                        "attack_ids": attack_ids,
                        "d3fend_stix_ids": d3fend_stix_ids,
                    },
                )
                .mappings()
                .all()
            )
    finally:
        engine.dispose()

    return {
        (row["framework"], row["candidate_id"]):
            float(row["similarity"])
        for row in rows
    }


def rank_d3fend(
    query: str,
    attack_results: list[dict],
    candidates: list[dict],
    top_k: int = 3,
) -> list[dict]:
    """Rank mapped D3FEND candidates by semantic and lexical relevance."""

    if not candidates:
        return []

    context = (
        query
        + "\n"
        + "\n".join(
            f"{item.get('external_id', '')} "
            f"{item.get('name', '')} "
            f"{item.get('description', '')}"
            for item in attack_results
        )
    )

    tokens = _tokenize(context)

    embedding = embed_alert_context(context)

    similarities = fetch_candidate_similarities(
        candidates,
        embedding,
    )

    ranked = []

    for item in candidates:
        similarity = similarities.get(
            ("d3fend", item.get("id"))
        )

        lexical, reasons = _score_candidate(
            item,
            tokens,
            "d3fend",
        )

        lexical_normalized = (
            lexical / (lexical + 10.0)
            if lexical > 0
            else 0.0
        )

        semantic = (
            max(0.0, min(1.0, similarity))
            if similarity is not None
            else 0.0
        )

        score = (
            0.70 * semantic + 0.30 * lexical_normalized
            if similarity is not None
            else 0.30 * lexical_normalized
        )

        if similarity is None:
            reasons.append("semantic similarity unavailable")
        else:
            reasons.append(
                f"semantic similarity: {semantic:.4f}"
            )

        ranked.append({
            **item,
            "semantic_similarity": (
                round(semantic, 4)
                if similarity is not None
                else None
            ),
            "lexical_score": round(lexical, 4),
            "relevance_score": round(score, 4),
            "ranking_reasons": reasons,
        })

    ranked.sort(
        key=lambda item: (
            -item["relevance_score"],
            str(item.get("id", "")),
        )
    )

    return [
        item
        for item in ranked
        if item["relevance_score"] > 0
    ][:top_k]
