import asyncio
import json
import logging
import os

from aiohttp import web

logger = logging.getLogger("cyber-rag-result-stream")

HOST = os.getenv("LLM_STREAM_HOST", "0.0.0.0")
PORT = int(os.getenv("LLM_STREAM_PORT", "17772"))
STREAM_PATH = os.getenv("LLM_STREAM_PATH", "/stream")

listeners = set()


async def stream_handler(request):
    """Keep a client connection open for incoming result events."""

    response = web.StreamResponse(
        status=200,
        headers={
            "Content-Type": "application/x-ndjson",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        },
    )

    await response.prepare(request)
    listeners.add(response)

    logger.info("Stream client connected: %s", request.remote)

    try:
        await response.write(b'{"event":"connected"}\n')

        while True:
            await asyncio.sleep(30)
            await response.write(b"\n")

    except (ConnectionResetError, asyncio.CancelledError):
        pass

    finally:
        listeners.discard(response)
        logger.info("Stream client disconnected: %s", request.remote)

    return response


async def publish_result(result: dict):
    """Publish one complete JSON result to all connected clients."""

    if not listeners:
        logger.warning("No stream clients connected; result not delivered")
        return False

    message = (
        json.dumps(result, ensure_ascii=False, default=str) + "\n"
    ).encode("utf-8")

    disconnected = []

    for listener in list(listeners):
        try:
            await listener.write(message)
        except (ConnectionResetError, RuntimeError):
            disconnected.append(listener)

    for listener in disconnected:
        listeners.discard(listener)

    logger.info(
        "Published result for alert %s to %d client(s)",
        result.get("log_uuid", "unknown"),
        len(listeners),
    )

    return len(listeners) > 0


async def start_result_server():
    """Start the HTTP result streaming server."""

    app = web.Application()
    app.router.add_get(STREAM_PATH, stream_handler)

    runner = web.AppRunner(app)
    await runner.setup()

    site = web.TCPSite(runner, HOST, PORT)
    await site.start()

    logger.info("Result stream listening on http://%s:%d%s",
                HOST, PORT, STREAM_PATH)

    return runner
