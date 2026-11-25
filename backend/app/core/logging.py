"""Structured JSON logging with secret redaction."""
from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone

_SECRET_KEYS = re.compile(r"(password|passwd|secret|token|api[_-]?key|authorization|private[_-]?key|community)", re.I)
_INLINE = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key)\s*[=:]\s*([^\s,;]+)")


def redact(value):
    """Recursively redact secret-looking keys from dicts/lists and inline k=v strings."""
    if isinstance(value, dict):
        return {k: ("***" if _SECRET_KEYS.search(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return _INLINE.sub(lambda m: f"{m.group(1)}=***", value)
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        extra = getattr(record, "extra_fields", None)
        if extra:
            payload.update(redact(extra))
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


def setup_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.handlers.clear()
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(JsonFormatter())
    root.addHandler(h)
    root.setLevel(level)
    # paramiko/netmiko can log session content at DEBUG; keep them quiet
    for noisy in ("paramiko", "netmiko", "pypsrp", "urllib3", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def log_event(logger: logging.Logger, msg: str, **fields) -> None:
    logger.info(msg, extra={"extra_fields": fields})
