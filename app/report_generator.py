import json
import urllib.error
import urllib.request

from app.prompts.loader import (
    load_rag_system_prompt,
    load_relevance_prompt,
)


def _ollama_chat(
    base_url: str,
    model: str,
    messages: list[dict],
    *,
    temperature: float = 0.0,
    num_ctx: int = 8192,
    num_predict: int = 1024,
    unload_after: bool = False,
    json_mode: bool = False,
) -> tuple[str, dict]:
    """Send a chat request to Ollama."""

    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "think": False,
        "options": {
            "temperature": temperature,
            "num_ctx": num_ctx,
            "num_predict": num_predict,
        },
        "keep_alive": 0 if unload_after else "5m",
    }

    if json_mode:
        payload["format"] = "json"

    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/api/chat",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=900) as response:
            result = json.loads(response.read().decode("utf-8"))
            print("Generation status:", result.get("done"))
            print("Stop reason:", result.get("done_reason"))
            print("Prompt tokens:", result.get("prompt_eval_count"))
            print("Generated tokens:", result.get("eval_count"))

            print("Model load:", result.get("load_duration", 0) / 1e9, "s")
            print(
                "Prompt evaluation:", result.get("prompt_eval_duration", 0) / 1e9, "s"
            )
            print("Token generation:", result.get("eval_duration", 0) / 1e9, "s")
            print("Ollama total:", result.get("total_duration", 0) / 1e9, "s")

    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Ollama rejected the request " f"(HTTP {exc.code}): {error_body}"
        ) from exc

    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach Ollama at {base_url}: {exc}") from exc

    message = result.get("message", {})
    content = message.get("content", "").strip()

    if not content:
        raise RuntimeError(
            "Ollama returned empty message.content. "
            "Check whether the selected model supports think=false."
        )

    return content, result


def assess_relevance(
    base_url: str,
    model: str,
    alert: dict,
    candidates: list[dict],
    num_predict=2000,
) -> dict:
    """Assess ATT&CK and D3FEND relevance against the alert."""

    compact_candidates = []

    for item in candidates:
        compact_item = {
            "framework": item.get("framework"),
            "external_id": item.get("external_id"),
            "name": item.get("name"),
            "data_type": item.get("data_type"),
            "description": (item.get("description") or "")[:500],
        }

        if item.get("framework") == "d3fend":
            compact_item["attack_ids"] = item.get("attack_ids", [])
            compact_item["mappings"] = [
                {
                    "attack_id": mapping.get("attack_id"),
                    "relationship": mapping.get("relationship"),
                    "provenance_type": mapping.get("provenance_type"),
                }
                for mapping in item.get("mappings", [])
            ]

        compact_candidates.append(compact_item)

    context = {
        "alert": alert,
        "candidates": compact_candidates,
    }

    messages = [
        {
            "role": "system",
            "content": load_relevance_prompt(),
        },
        {
            "role": "user",
            "content": (
                "Nilai relevansi seluruh kandidat knowledge berikut "
                "berdasarkan bukti alert. Jangan membuat ID baru.\n\n"
                + json.dumps(context, ensure_ascii=False)
            ),
        },
    ]

    content, result = _ollama_chat(
        base_url,
        model,
        messages,
        temperature=0.0,
        num_ctx=8192,
        num_predict=num_predict,
        unload_after=False,
        json_mode=True,
    )

    try:
        assessment = json.loads(content)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Relevance assessment returned invalid JSON: {exc}"
        ) from exc

    if not isinstance(assessment, dict):
        raise RuntimeError("Relevance assessment must be a JSON object.")

    original_ids = {
        item.get("external_id") for item in candidates if item.get("external_id")
    }

    valid_categories = {
        "relevant",
        "partially_relevant",
        "not_relevant",
    }

    for field in ("attack_assessment", "d3fend_assessment"):
        entries = assessment.get(field)

        if not isinstance(entries, list):
            raise RuntimeError(f"Invalid relevance assessment field: {field}")

        seen = set()

        for entry in entries:
            if not isinstance(entry, dict):
                raise RuntimeError(f"Invalid entry in {field}")

            external_id = entry.get("external_id")
            relevance = entry.get("relevance")

            if external_id not in original_ids:
                raise RuntimeError(f"Assessment contains unknown ID: {external_id}")

            if external_id in seen:
                raise RuntimeError(f"Duplicate assessment ID: {external_id}")

            if relevance not in valid_categories:
                raise RuntimeError(f"Invalid relevance category for {external_id}")

            if not isinstance(entry.get("reason"), str):
                raise RuntimeError(f"Missing assessment reason for {external_id}")

            seen.add(external_id)

    attack_assessment = assessment["attack_assessment"]
    d3fend_assessment = assessment["d3fend_assessment"]

    attack_ids = {
        entry["external_id"]
        for entry in attack_assessment
        if entry["relevance"] == "relevant"
    }

    d3fend_ids = {
        entry["external_id"]
        for entry in d3fend_assessment
        if entry["relevance"] == "relevant"
    }

    selected_candidates = [
        item
        for item in candidates
        if (item.get("framework") == "attack" and item.get("external_id") in attack_ids)
        or (item.get("framework") == "d3fend" and item.get("external_id") in d3fend_ids)
    ]

    return {
        "selected_results": selected_candidates,
        "attack_assessment": attack_assessment,
        "d3fend_assessment": d3fend_assessment,
        "selected_attack_ids": sorted(attack_ids),
        "selected_d3fend_ids": sorted(d3fend_ids),
        "summary": assessment.get("summary", ""),
        "ollama_metadata": {
            "prompt_eval_count": result.get("prompt_eval_count"),
            "eval_count": result.get("eval_count"),
            "done_reason": result.get("done_reason"),
        },
    }


def build_prompt(evidence: dict) -> list[dict]:
    """Build a compact report-generation input."""

    alert = evidence["alert"]
    retrieval = evidence["retrieval"]
    assessment = evidence.get("relevance_assessment", {})

    selected_ids = set(
        assessment.get("selected_attack_ids", [])
        + assessment.get("selected_d3fend_ids", [])
    )

    selected_knowledge = []

    for item in retrieval.get("results", []):
        if item.get("external_id") not in selected_ids:
            continue

        selected_knowledge.append(
            {
                "framework": item.get("framework"),
                "external_id": item.get("external_id"),
                "name": item.get("name"),
                "description": (item.get("description") or "")[:800],
            }
        )

    print("Selected knowledge count:", len(selected_knowledge))
    print("Selected IDs:", [item["external_id"] for item in selected_knowledge])

    context = {
        "alert": alert,
        "selected_knowledge": selected_knowledge,
    }

    user_message = (
        "Analyze the supplied alert and write the incident report "
        "required by the system prompt. Use selected knowledge only "
        "as supporting context, never as proof of compromise.\n\n"
        + json.dumps(
            context,
            ensure_ascii=False,
            indent=2,
        )
    )

    return [
        {"role": "system", "content": load_rag_system_prompt()},
        {"role": "user", "content": user_message},
    ]


def generate_report(
    base_url: str,
    model: str,
    messages: list[dict],
    unload_after: bool,
) -> tuple[str, dict]:
    """Send the report-generation request to Ollama."""

    print("\n" + "=" * 80)
    print("DEBUG: EXACT MESSAGES SENT TO LLM")
    print("=" * 80)

    for i, message in enumerate(messages, start=1):
        print(f"\n--- MESSAGE {i}: {message.get('role', 'unknown')} ---")
        print(message.get("content", ""))

    print("\n" + "=" * 80)
    print("END OF LLM INPUT")
    print("=" * 80)

    return _ollama_chat(
        base_url,
        model,
        messages,
        temperature=0.2,
        num_ctx=8192,
        num_predict=1200,
        unload_after=unload_after,
    )
