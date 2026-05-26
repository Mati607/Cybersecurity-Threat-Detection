"""Centralized logging configuration for threatpipe.

The ingestion side runs in a tight loop, so we keep the formatter cheap
and avoid touching the root logger more than once. Callers should ask
for a logger through :func:`get_logger` rather than calling
``logging.getLogger`` directly, so we can swap the backend (e.g. to
``structlog``) later without rewriting every module.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional

_DEFAULT_FORMAT = (
    "%(asctime)s %(levelname)-7s [%(name)s] %(message)s"
)
_DATEFMT = "%Y-%m-%dT%H:%M:%S"

_CONFIGURED = False


def configure_logging(
    level: str | int = "INFO",
    log_file: Optional[str | os.PathLike[str]] = None,
    fmt: str = _DEFAULT_FORMAT,
    datefmt: str = _DATEFMT,
    rotate_bytes: int = 25 * 1024 * 1024,
    rotate_backups: int = 5,
) -> None:
    """Install the root handlers exactly once."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    root = logging.getLogger()
    root.setLevel(level if isinstance(level, int) else level.upper())

    formatter = logging.Formatter(fmt=fmt, datefmt=datefmt)

    stream = logging.StreamHandler(stream=sys.stderr)
    stream.setFormatter(formatter)
    root.addHandler(stream)

    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            filename=str(path),
            maxBytes=rotate_bytes,
            backupCount=rotate_backups,
            encoding="utf-8",
        )
        handler.setFormatter(formatter)
        root.addHandler(handler)

    # The transformers + torch stack is extremely noisy at INFO.
    for noisy in ("urllib3", "filelock", "transformers", "torch"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a module-scoped logger, configuring root on first use."""
    if not _CONFIGURED:
        configure_logging()
    return logging.getLogger(name)
