"""Logging setup + run-ID scheme.

Every probe run gets a timestamped, collision-resistant run ID so results,
logs and committed snapshots can be tied back to a single invocation.
"""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime

from rich.logging import RichHandler

_CONFIGURED = False


def new_run_id() -> str:
    """e.g. 'run-20261125T154212Z-a1b2c3'. Sortable by time, unique per run."""
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"run-{ts}-{secrets.token_hex(3)}"


def setup_logging(level: str = "INFO") -> None:
    """Idempotent logging config with Rich formatting."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    logging.basicConfig(
        level=level.upper(),
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )
    _CONFIGURED = True


def get_logger(name: str = "agent_probe") -> logging.Logger:
    return logging.getLogger(name)
