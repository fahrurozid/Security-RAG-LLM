import os
from pathlib import Path

from dotenv import load_dotenv


ROOT = Path(__file__).resolve().parents[1]

load_dotenv(ROOT / ".env")


DEFAULT_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://127.0.0.1:11434",
)

DEFAULT_MODEL = os.getenv(
    "OLLAMA_CHAT_MODEL",
    "Qwen3.6-27B-Q4_K_S:latest",
)

AVAILABLE_MODELS = [
    "orcasaq-cyber:latest",
    "Qwen3.6-27B-Q4_K_S:latest",
    "qwen2.5:3b",
]

EMBEDDING_MODEL = os.getenv(
    "EMBEDDING_MODEL",
    "nomic-embed-text:latest",
)

EMBEDDING_BASE_URL = os.getenv(
    "EMBEDDING_BASE_URL",
    "http://127.0.0.1:11434",
).rstrip("/")

DATABASE_URL = os.environ["DATABASE_URL"]


STOPWORDS = {
    "a", "an", "and", "are", "as", "at",
    "be", "been", "being", "by",
    "for", "from",
    "has", "have",
    "in", "into", "is", "it", "its",
    "of", "on", "or",
    "that", "the", "their", "this", "to",
    "was", "were", "with",
    "which", "when", "where",
    "using", "used", "may", "can", "could",
    "should", "would",
    "potential", "related", "associated",
    "technique", "techniques",
    "attack", "attacks",
    "system", "security", "data", "based",
}


RELATIONSHIP_WEIGHTS = {
    "detects": 1.0,
    "has-analytic": 1.0,
    "mitigates": 0.5,
    "subtechnique-of": 0.5,
    "uses": 0.25,
    "related-to": 0.1,
}


DATA_TYPE_WEIGHTS = {
    "x-mitre-detection-strategy": 1.0,
    "x-mitre-analytic": 0.8,
    "attack-pattern": 0.5,
    "course-of-action": 0.3,
}
