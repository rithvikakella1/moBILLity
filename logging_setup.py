"""Structured JSON logging with request correlation.

One unstructured logger meant that when a patient reported a missed reminder,
there was no way to trace that appointment through scheduling, claiming,
delivery, and the provider response — so the only question that matters in that
conversation ("did we send it?") could not be answered.

Never log decrypted patient data through this module. Log identifiers instead.
"""
import contextvars
import json
import logging
import os
import sys
from datetime import UTC, datetime

# Bound per request by RequestContextMiddleware, and emitted on every record.
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")

_RESERVED = {
    "args", "asctime", "created", "exc_info", "exc_text", "filename", "funcName",
    "levelname", "levelno", "lineno", "module", "msecs", "message", "msg", "name",
    "pathname", "process", "processName", "relativeCreated", "stack_info",
    "thread", "threadName", "taskName",
}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_var.get(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        # Anything passed via logger.info(..., extra={...}) becomes a queryable
        # field rather than being interpolated into the message.
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        return json.dumps(payload, default=str)


def configure_logging() -> None:
    """Install the formatter on the root logger.

    Plain-text output stays the default locally, where a human is reading; JSON
    is used when LOG_FORMAT=json, which the deployment sets.
    """
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    handler = logging.StreamHandler(sys.stdout)
    if os.getenv("LOG_FORMAT", "text").lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s  %(message)s")
        )
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)

    # Access logs duplicate what the request middleware already records.
    logging.getLogger("uvicorn.access").setLevel(
        os.getenv("UVICORN_ACCESS_LOG_LEVEL", "WARNING").upper()
    )
