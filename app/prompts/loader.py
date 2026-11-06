from pathlib import Path

PROMPT_DIR = Path(__file__).resolve().parent

PROMPT_FILE = PROMPT_DIR / "promptsid.md"
RELEVANCE_PROMPT_FILE = PROMPT_DIR / "relevance_assessment_id.md"


def _load_prompt(prompt_file: Path) -> str:
    """Load and validate a prompt file."""

    if not prompt_file.is_file():
        raise FileNotFoundError(
            f"Prompt not found: {prompt_file}"
        )

    prompt = prompt_file.read_text(
        encoding="utf-8"
    ).strip()

    if not prompt:
        raise ValueError(
            f"Prompt is empty: {prompt_file}"
        )

    return prompt


def load_rag_system_prompt() -> str:
    """Load the incident analysis prompt."""

    return _load_prompt(PROMPT_FILE)


def load_relevance_prompt() -> str:
    """Load the ATT&CK and D3FEND relevance assessment prompt."""

    return _load_prompt(RELEVANCE_PROMPT_FILE)


def load_graph_rag_system_prompt() -> str:
    """Backward-compatible alias."""

    return load_rag_system_prompt()
