"""
EnterpriseSecurityIQ — Logging
Structured logging with levels matching the PowerShell Logger.ps1.
Supports plain-text and JSON structured output (ENTERPRISESECURITYIQ_LOG_FORMAT=json).
"""

import json as _json
import logging
import os
import sys
from datetime import datetime, timezone

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


class JsonFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object (structured logging)."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info and record.exc_info[1]:
            entry["exception"] = str(record.exc_info[1])
        return _json.dumps(entry, default=str)


def setup_logger(name: str = "enterprisesecurityiq", level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        fmt = os.getenv("ENTERPRISESECURITYIQ_LOG_FORMAT", "text").lower()
        if fmt == "json":
            handler.setFormatter(JsonFormatter())
        else:
            handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt="%Y-%m-%dT%H:%M:%S"))
        logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    return logger


log = setup_logger()
