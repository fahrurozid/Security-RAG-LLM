import asyncio
import logging

from app.timing import measure
from app.workers.alert_receiver import receive_alerts
from app.workers.alert_worker import process_alert
from app.workers.result_sender import (
    publish_result,
    start_result_server,
)

logger = logging.getLogger("cyber-rag-pipeline")


async def handle_alert(alert: dict):
    """Process an alert and publish its analysis result."""

    with measure("Total pipeline execution"):
        result = await asyncio.to_thread(process_alert, alert)

        log_uuid = result.get("log_uuid", "unknown")

        logger.info(
            "RAG processing finished for log_uuid: %s",
            log_uuid,
        )

        published = await publish_result(result)

        if published:
            logger.info("Result published to stream")
        else:
            logger.warning("Result was not delivered to any stream client")

        return published


async def main():
    logger.info("Starting Cyber RAG pipeline")

    runner = await start_result_server()

    try:
        logger.info("Starting Redis alert polling")
        await receive_alerts(handle_alert)
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Cyber RAG pipeline stopped")
