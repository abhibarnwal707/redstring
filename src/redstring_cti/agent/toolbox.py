"""How the agent reaches the graph tools. One interface, two implementations:

* `McpToolbox`: launches the MCP server as a stdio subprocess and keeps one session open (the real
  architecture: the same server Claude Desktop/Code can use).
* `DirectToolbox`: calls the same tool functions in-process (fast; used by tests and quick experiments).

Both raise `ToolCallError` when a tool reports an error, so the agent never has to guess from text.
"""

import asyncio
import json
import os
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from redstring_cti.mcp_server import tools
from redstring_cti.mcp_server.guardrails import CypherExecutionError, GuardrailError

REPO_ROOT = Path(__file__).resolve().parents[3]


class ToolCallError(RuntimeError):
    """A tool rejected the call or failed; the message says why and is safe to show to a model."""


class Toolbox(Protocol):
    def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]: ...
    def close(self) -> None: ...


class DirectToolbox:
    """In-process calls to the tool functions behind the MCP server."""

    def __init__(self, ctx: tools.Context) -> None:
        self.ctx = ctx
        self._table: dict[str, Callable[..., dict[str, Any]]] = {
            "semantic_search": tools.semantic_search, "resolve_entity": tools.resolve_entity, "get_entity": tools.get_entity,
            "get_neighbors": tools.get_neighbors, "find_paths": tools.find_paths, "cypher_query": tools.cypher_query,
            "cve_lookup": tools.cve_lookup,
        }

    def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        fn = self._table.get(name)
        if fn is None:
            raise ToolCallError(f"unknown tool {name!r}")
        try:
            return fn(self.ctx, **args)
        except tools.ToolInputError as exc:
            raise ToolCallError(str(exc)) from exc
        except GuardrailError as exc:
            raise ToolCallError(f"query rejected: {exc}") from exc
        except CypherExecutionError as exc:
            raise ToolCallError(f"query failed: {exc}") from exc
        except TypeError as exc:  # wrong argument names
            raise ToolCallError(f"bad arguments for {name}: {exc}") from exc

    def close(self) -> None:
        self.ctx.driver.close()


class McpToolbox:
    """A persistent stdio session to the RedString MCP server, driven from synchronous code.

    The session lives in one long-running task on a background event loop (anyio cancel scopes must be
    entered and exited by the same task), and calls are submitted to that loop from the caller's thread."""

    def __init__(self, *, cwd: Path = REPO_ROOT, env: dict[str, str] | None = None, call_timeout_s: float = 90.0, start_timeout_s: float = 120.0) -> None:
        self._cwd, self._timeout = cwd, call_timeout_s
        base = {k: os.environ[k] for k in ("PATH", "HOME", "REDSTRING_AUDIT_LOG") if k in os.environ}
        self._env = {**base, **(env or {})}
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, name="mcp-toolbox", daemon=True)
        self._thread.start()
        self._ready = threading.Event()
        self._stop: asyncio.Event | None = None
        self._session: Any = None
        self._error: BaseException | None = None
        self._main_future = asyncio.run_coroutine_threadsafe(self._main(), self._loop)
        if not self._ready.wait(start_timeout_s) or self._error is not None:
            self.close()
            raise ToolCallError(f"MCP server did not start: {self._error!r}")

    async def _main(self) -> None:
        from langchain_mcp_adapters.client import MultiServerMCPClient

        self._stop = asyncio.Event()
        config = {"redstring": {"transport": "stdio", "command": sys.executable, "args": ["-m", "redstring_cti.mcp_server.server"],
                                "cwd": str(self._cwd), "env": self._env}}
        try:
            async with MultiServerMCPClient(config).session("redstring") as session:  # type: ignore[arg-type]
                self._session = session
                self._ready.set()
                await self._stop.wait()
        except BaseException as exc:  # noqa: BLE001  (surface start-up failures to the constructor)
            self._error = exc
            self._ready.set()

    def call(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        future = asyncio.run_coroutine_threadsafe(self._session.call_tool(name, args), self._loop)
        try:
            result = future.result(self._timeout)
        except TimeoutError as exc:
            future.cancel()
            raise ToolCallError(f"tool {name} timed out after {self._timeout:.0f}s") from exc
        text = " ".join(getattr(block, "text", "") for block in result.content)
        if result.isError:
            raise ToolCallError(text or f"tool {name} failed")
        if result.structuredContent is not None:
            return dict(result.structuredContent)
        try:
            return dict(json.loads(text))
        except (ValueError, TypeError) as exc:
            raise ToolCallError(f"tool {name} returned something that is not JSON: {text[:120]}") from exc

    def langchain_tools(self) -> list[Any]:
        """The same tools as LangChain `BaseTool`s, for LLM tool-calling variants of the agent."""
        from langchain_mcp_adapters.tools import load_mcp_tools

        return list(asyncio.run_coroutine_threadsafe(load_mcp_tools(self._session), self._loop).result(self._timeout))

    def close(self) -> None:
        if self._stop is not None:
            self._loop.call_soon_threadsafe(self._stop.set)
        try:
            self._main_future.result(15)
        except BaseException:  # noqa: BLE001, S110
            pass
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(5)
