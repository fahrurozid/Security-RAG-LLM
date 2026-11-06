import asyncio
import logging
import os
import re
from datetime import datetime

import httpx

logger = logging.getLogger("cyber-rag-receiver")

ALERT_URL = os.getenv(
    "ALERT_STREAM_URL",
    "http://103.252.50.212:17771/",
)

POLL_INTERVAL = int(os.getenv("ALERT_POLL_INTERVAL", "5"))
REQUEST_TIMEOUT = 30


def get_alert_id(alert: dict) -> str | None:
    """Extract log_uuid from the enriched alert description."""

    description = alert.get("alert_description", "")
    match = re.search(r"log_uuid:\s*([a-fA-F0-9-]+)", description)

    if match:
        return match.group(1)

    return None


def get_timestamp(alert: dict) -> datetime:
    """Parse the alert timestamp."""

    value = alert.get("@timestamp")

    if not value:
        raise ValueError("Alert is missing @timestamp")

    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def get_newest_alert(alerts: list) -> dict | None:
    """Return the newest alert from the JSON array."""

    valid_alerts = []

    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        try:
            timestamp = get_timestamp(alert)
            valid_alerts.append((timestamp, alert))
        except (ValueError, TypeError):
            logger.warning("Skipping alert with invalid timestamp")

    if not valid_alerts:
        return None

    return max(valid_alerts, key=lambda item: item[0])[1]


async def receive_alerts(handler):
    """Poll Redis and process only the newest alert."""

    last_alert_id = None

    timeout = httpx.Timeout(REQUEST_TIMEOUT)

    async with httpx.AsyncClient(timeout=timeout) as client:
        while True:
            try:
                response = await client.get(ALERT_URL)
                response.raise_for_status()

                alerts = response.json()

                if not isinstance(alerts, list):
                    raise ValueError("Redis endpoint must return a JSON array")

                newest_alert = get_newest_alert(alerts)

                if newest_alert is None:
                    logger.info("No valid alerts available")

                else:
                    alert_id = get_alert_id(newest_alert)

                    if not alert_id:
                        logger.warning("Newest alert has no log_uuid; skipping")

                    elif alert_id != last_alert_id:
                        logger.info("New alert detected: %s", alert_id)

                        delivered = await handler(newest_alert)

                        if delivered:
                            last_alert_id = alert_id
                        else:
                            logger.warning("Alert %s will be retried", alert_id)

                    else:
                        logger.debug("No new alert")

            except asyncio.CancelledError:
                raise

            except Exception:
                logger.exception("Alert polling failed")

            await asyncio.sleep(POLL_INTERVAL)
