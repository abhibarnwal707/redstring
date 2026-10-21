"""JSONL audit log of every MCP tool call: tool, arguments, duration, result size, error.

The same log later measures tool-call accuracy (did the call succeed, did it return rows)."""

import json
import os
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from redstring_cti.config import PROCESSED_DIR

DEFAULT_PATH = Path(os.environ.get("REDSTRING_AUDIT_LOG", PROCESSED_DIR / "audit.jsonl"))
MAX_ARG_CHARS = 400


def _clip(value: Any) -> Any:
    text = json.dumps(value, default=str)
    return value if len(text) <= MAX_ARG_CHARS else text[:MAX_ARG_CHARS] + "...[truncated]"


def result_size(result: Any) -> int | None:
    """Row/result count of a tool response, for the log."""
    if isinstance(result, dict):
        for key in ("results", "neighbors", "paths", "rows", "candidates"):
            if isinstance(result.get(key), list):
                return len(result[key])
        return 1 if result.get("found", True) else 0
    return len(result) if isinstance(result, list) else None


class AuditLog:
    def __init__(self, path: Path | None = DEFAULT_PATH) -> None:
        self.path = path
        self._lock = threading.Lock()

    def write(self, entry: dict[str, Any]) -> None:
        if self.path is None:
            return
        line = json.dumps(entry, default=str) + "\n"
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as f:
                f.write(line)

    def record(self, tool: str, args: dict[str, Any], call: Callable[[], Any]) -> Any:
        """Run `call`, log the outcome (including errors), and return or re-raise."""
        started = time.perf_counter()
        entry: dict[str, Any] = {"ts": datetime.now(UTC).isoformat(timespec="milliseconds"), "tool": tool, "args": _clip(args)}
        try:
            result = call()
        except Exception as exc:
            entry.update(ok=False, error=f"{type(exc).__name__}: {str(exc)[:300]}", rows=None)
            raise
        else:
            entry.update(ok=True, error=None, rows=result_size(result))
            return result
        finally:
            entry["duration_ms"] = round((time.perf_counter() - started) * 1000, 1)
            self.write(entry)
