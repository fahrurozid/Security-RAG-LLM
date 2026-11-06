import json
from pathlib import Path

from run_graph_rag import retrieve_evidence, rank_evidence

ROOT = Path(__file__).resolve().parents[1]


def print_candidates(title, candidates):
    print(f"\n{'=' * 90}")
    print(title)
    print("=" * 90)

    if not candidates:
        print("No candidates.")
        return

    for rank, item in enumerate(candidates, start=1):
        print(f"\n[{rank}] Score: {item.get('relevance_score', 0)}")
        print(f"ID:           {item.get('id', 'N/A')}")
        print(f"Name:         {item.get('name', 'N/A')}")
        print(f"Relationship: {item.get('relationship', 'N/A')}")
        print(f"Data type:    {item.get('data_type', 'N/A')}")

        reasons = item.get("ranking_reasons", [])
        print("Reasons:")
        if reasons:
            for reason in reasons:
                print(f"  - {reason}")
        else:
            print("  - No matching terms or ranking signals")

        description = item.get("description", "")
        if description:
            print(f"Description:  {description[:350]}")


def main():
    print("Retrieving evidence from Neo4j...")
    evidence = retrieve_evidence()

    print("Ranking candidates without calling the LLM...")
    ranked = rank_evidence(evidence, top_k=3)

    alert = evidence.get("alert", {})
    print("\nALERT CONTEXT")
    print(json.dumps(alert, indent=2, ensure_ascii=False))

    print_candidates(
        "ATT&CK CANDIDATES — ALL RANKED",
        ranked["attack_candidates_ranked"],
    )

    print_candidates(
        "D3FEND CANDIDATES — ALL RANKED",
        ranked["d3fend_candidates_ranked"],
    )

    print_candidates(
        "SELECTED ATT&CK EVIDENCE",
        ranked["selected_related_attack_evidence"],
    )

    print_candidates(
        "SELECTED D3FEND EVIDENCE",
        ranked["selected_d3fend_mappings"],
    )

    output_dir = ROOT / "data" / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / "ranking_test.json"
    output_path.write_text(
        json.dumps(ranked, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"\nRanking results saved to: {output_path}")
    print("No LLM request was made.")


if __name__ == "__main__":
    main()
