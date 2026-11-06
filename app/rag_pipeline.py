import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from app.config import (
    ROOT,
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    AVAILABLE_MODELS,
)

from app.graph_retriever import retrieve_d3fend_mappings

from app.retriever import (
    build_retrieval_query,
    search_framework,
)

from app.report_generator import (
    assess_relevance,
    build_prompt,
    generate_report,
)

from app.timing import measure


def retrieve_evidence(
    alert_input: Path | dict,
    top_k: int = 3,
) -> dict:
    """Retrieve ATT&CK candidates and mapped D3FEND knowledge."""

    with measure("Alert loading"):
        if isinstance(alert_input, Path):
            alert = json.loads(alert_input.read_text(encoding="utf-8"))
        elif isinstance(alert_input, dict):
            alert = alert_input
        else:
            raise TypeError("alert_input must be a Path or dict")

    with measure("Query construction"):
        query = build_retrieval_query(alert)

    with measure("PostgreSQL ATT&CK retrieval"):
        attack = search_framework(
            query,
            framework="attack",
            top_k=top_k,
        )
        attack_results = attack.get("results", [])[:top_k]

    attack_ids = [
        item["external_id"] for item in attack_results if item.get("external_id")
    ]

    with measure("Neo4j D3FEND retrieval"):
        mapped = retrieve_d3fend_mappings(attack_ids)

    d3fend_results = [
        {
            "id": item.get("stix_id") or item.get("external_id"),
            "framework": "d3fend",
            "external_id": item.get("external_id") or item.get("stix_id"),
            "name": item.get("name"),
            "description": item.get("description"),
            "data_type": item.get("data_type"),
            "source_version": None,
            "stix_id": item.get("stix_id"),
            "attack_ids": item.get("attack_ids", []),
            "mappings": item.get("mappings", []),
        }
        for item in mapped
    ]

    combined_results = attack_results + d3fend_results

    retrieval = {
        "mode": "hybrid",
        "selection_policy": {
            "attack_method": "hybrid vector + lexical + exact-ID retrieval",
            "d3fend_method": "Neo4j MAPPED_TO using all retrieved ATT&CK IDs",
            "framework_limits": {
                "attack": top_k,
		#"d3fend": top_k,
                "d3fend": "all mapped candidates",
            },
            "retrieved_count": len(combined_results),
        },
        "results": combined_results,
    }

    return {
        "alert": alert,
        "retrieval_query": query,
        "retrieval": retrieval,
    }


def analyze_alert(
    alert: dict,
    top_k: int = 3,
    base_url: str = DEFAULT_BASE_URL,
    model: str = DEFAULT_MODEL,
    keep_loaded: bool = False,
) -> dict:
    """Run the complete RAG and LLM analysis for an alert."""

    if not isinstance(alert, dict):
        raise TypeError("alert must be a dictionary")

    # Step 1: Retrieve evidence.
    evidence = retrieve_evidence(
        alert,
        top_k=top_k,
    )

    candidates = evidence["retrieval"]["results"]

    # Step 2: Assess relevance.
    with measure("LLM relevance assessment"):
        assessment = assess_relevance(
            base_url=base_url,
            model=model,
            alert=evidence["alert"],
            candidates=candidates,
        )

    evidence["retrieval"]["selected_results"] = assessment["selected_results"]

    evidence["retrieval"]["selection_policy"][
        "relevance_method"
    ] = "LLM relevance assessment"

    evidence["relevance_assessment"] = {
        "attack_assessment": assessment["attack_assessment"],
        "d3fend_assessment": assessment["d3fend_assessment"],
        "selected_attack_ids": assessment["selected_attack_ids"],
        "selected_d3fend_ids": assessment["selected_d3fend_ids"],
        "summary": assessment["summary"],
    }

    # Step 3: Build report prompt.
    with measure("Prompt construction"):
        messages = build_prompt(evidence)

    # Step 4: Generate report.
    with measure("LLM report generation"):
        report, response = generate_report(
            base_url,
            model,
            messages,
            unload_after=not keep_loaded,
        )

    # Step 5: Return the analysis.
    metadata = {
        "model": model,
        "base_url": base_url,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "ollama_done_reason": response.get("done_reason"),
        "relevance_assessment": assessment["ollama_metadata"],
        "retrieval_mode": evidence["retrieval"].get("mode"),
        "retrieved_count": len(candidates),
        "selected_count": len(assessment["selected_results"]),
        "selected_attack_ids": assessment["selected_attack_ids"],
        "selected_d3fend_ids": assessment["selected_d3fend_ids"],
    }

    return {
        "report": report,
        "evidence": evidence,
        "metadata": metadata,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Run the hybrid Vector + Lexical RAG pipeline."
    )

    parser.add_argument(
        "--model",
        choices=AVAILABLE_MODELS,
        default=DEFAULT_MODEL,
        help="Ollama model to use.",
    )

    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="Ollama API base URL.",
    )

    parser.add_argument(
        "--alert",
        type=Path,
        default=(ROOT / "data" / "alerts" / "auth_fail_success.json"),
        help="Path to the input alert JSON file.",
    )

    parser.add_argument(
        "-k",
        type=int,
        default=3,
        help="Maximum number of ATT&CK retrieval results.",
    )

    parser.add_argument(
        "--keep-loaded",
        action="store_true",
        help="Keep the selected model loaded for up to five minutes.",
    )

    args = parser.parse_args()

    alert_path = args.alert

    if not alert_path.is_absolute():
        alert_path = ROOT / alert_path

    if not alert_path.is_file():
        parser.error(f"Alert file not found: {alert_path}")

    if args.k < 1:
        parser.error("-k must be at least 1")

    # Step 1: Retrieve candidates.
    print(f"Retrieving knowledge for: {alert_path}")

    evidence = retrieve_evidence(
        alert_path,
        top_k=args.k,
    )

    candidates = evidence["retrieval"]["results"]

    print(f"\nRetrieved {len(candidates)} candidates.")

    for item in candidates:
        print(
            f"  [{item.get('framework')}] "
            f"{item.get('external_id')} - "
            f"{item.get('name')}"
        )

    # Step 2: Assess candidate relevance.
    print("\nAssessing ATT&CK and D3FEND relevance...")

    with measure("LLM relevance assessment"):
        assessment = assess_relevance(
            base_url=args.base_url,
            model=args.model,
            alert=evidence["alert"],
            candidates=candidates,
        )

    # Keep all original candidates for audit.
    evidence["retrieval"]["selected_results"] = assessment["selected_results"]

    evidence["retrieval"]["selection_policy"][
        "relevance_method"
    ] = "LLM relevance assessment"

    evidence["relevance_assessment"] = {
        "attack_assessment": assessment["attack_assessment"],
        "d3fend_assessment": assessment["d3fend_assessment"],
        "selected_attack_ids": assessment["selected_attack_ids"],
        "selected_d3fend_ids": assessment["selected_d3fend_ids"],
        "summary": assessment["summary"],
    }

    selected = assessment["selected_results"]

    print("\nRelevance assessment completed.")
    print(f"Selected ATT&CK: " f"{len(assessment['selected_attack_ids'])}")
    print(f"Selected D3FEND: " f"{len(assessment['selected_d3fend_ids'])}")
    print(f"Selected total: {len(selected)}")

    for item in selected:
        print(
            f"  [{item.get('framework')}] "
            f"{item.get('external_id')} - "
            f"{item.get('name')}"
        )

    # Step 3: Build report-generation messages.
    print(f"\nGenerating report with: {args.model}")

    with measure("Prompt construction"):
        messages = build_prompt(evidence)

    # Step 4: Generate incident report.
    with measure("LLM report generation"):
        report, response = generate_report(
            args.base_url,
            args.model,
            messages,
            unload_after=not args.keep_loaded,
        )

    # Step 5: Save outputs.
    output_dir = ROOT / "data" / "reports"
    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    stem = f"hybrid_rag_{timestamp}"

    with measure("Saving outputs"):
        report_path = output_dir / f"{stem}.md"
        evidence_path = output_dir / f"{stem}_evidence.json"
        metadata_path = output_dir / f"{stem}_metadata.json"

    report_path.write_text(
        report.rstrip() + "\n",
        encoding="utf-8",
    )

    evidence_path.write_text(
        json.dumps(
            evidence,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    metadata_path.write_text(
        json.dumps(
            {
                "model": args.model,
                "base_url": args.base_url,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "ollama_done_reason": response.get("done_reason"),
                "relevance_assessment": assessment["ollama_metadata"],
                "retrieval_mode": evidence["retrieval"].get("mode"),
                "retrieved_count": len(candidates),
                "selected_count": len(selected),
                "selected_attack_ids": assessment["selected_attack_ids"],
                "selected_d3fend_ids": assessment["selected_d3fend_ids"],
                "alert_path": str(alert_path),
                "unload_after_request": not args.keep_loaded,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print("\n" + "=" * 72)
    print(report)
    print("=" * 72)

    print(f"Report:   {report_path.relative_to(ROOT)}")
    print(f"Evidence: {evidence_path.relative_to(ROOT)}")
    print(f"Metadata: {metadata_path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
