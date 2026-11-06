import json
import logging
import re
from datetime import datetime, timezone

from app.rag_pipeline import analyze_alert

logger = logging.getLogger("cyber-rag-worker")


def get_alert_id(alert: dict) -> str | None:
    """Extract the alert ID from available alert fields."""

    alert_id = alert.get("alert_id") or alert.get("id") or alert.get("log_uuid")

    if alert_id:
        return str(alert_id)

    description = alert.get("alert_description", "")
    match = re.search(r"log_uuid:\s*([a-fA-F0-9-]+)", description)

    return match.group(1) if match else None


def process_alert(alert: dict) -> dict:
    """Run Cyber RAG and package the incident report."""

    if not isinstance(alert, dict):
        raise TypeError("Alert must be a dictionary")

    alert_id = get_alert_id(alert)

    logger.info("Processing alert: %s", alert_id or "unknown")

    try:
        analysis = analyze_alert(alert)

        return {
            "log_uuid": alert_id,
            "status": "completed",
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "report_format": "markdown",
            "incident_report": analysis["report"],
        }

    except Exception as exc:
        logger.exception("Alert processing failed")

        return {
            "log_uuid": alert_id,
            "status": "failed",
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "error": str(exc),
        }


def process_message(raw_message: str) -> str:
    """Process an incoming JSON message and return a JSON result."""

    try:
        alert = json.loads(raw_message)

        if not isinstance(alert, dict):
            raise ValueError("Incoming alert must be a JSON object")

        result = process_alert(alert)

    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        logger.error("Invalid incoming alert: %s", exc)

        result = {
            "status": "failed",
            "processed_at": datetime.now(timezone.utc).isoformat(),
            "error": str(exc),
        }

    return json.dumps(result, ensure_ascii=False)
