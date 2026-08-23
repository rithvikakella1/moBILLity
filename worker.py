"""Standalone reminder dispatcher.

Runs the due-job loop in a dedicated process so that scaling the web service
does not multiply outbound messages. Deployed as the `mobillity-dispatcher`
worker in render.yaml.
"""
import asyncio
import logging
import os

os.environ.setdefault("WORKFLOW_WORKER", "true")

import app as application

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("mobillity.worker")


async def main() -> None:
    application._init_db()
    application._backfill_phone_fingerprints()
    logger.info("Reminder dispatcher starting (delivery mode=%s)",
                os.getenv("COMMUNICATION_DELIVERY_MODE", "preview"))
    try:
        await application._reminder_scheduler()
    finally:
        application._close_pool()
        logger.info("Reminder dispatcher stopped")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
