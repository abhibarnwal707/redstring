"""Read-only guardrails for model-written Cypher (Text2Cypher now, the MCP `cypher_query` tool later).

Neo4j Community has no role-based access control, so enforcement is layered:
  1. every query runs in a *read* transaction (`execute_read`), where writes fail in the server;
  2. a deny-list rejects write / admin / unbounded constructs before the query is sent;
  3. a per-transaction timeout and a row cap bound the cost.
Layers 1 and 2 are the enforcement. The deny-list alone is not trusted.
"""

import re
from typing import Any

from neo4j import Driver, ManagedTransaction, unit_of_work
from neo4j.exceptions import ClientError, DatabaseError, Neo4jError

MAX_ROWS = 200
MAX_HOPS = 4
TIMEOUT_S = 5.0

_STRINGS = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|`[^`]*`")
_COMMENTS = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_DENY = re.compile(
    r"\b(?:CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|FOREACH|LOAD\s+CSV|PERIODIC|"
    r"GRANT|DENY|REVOKE|START|STOP|TERMINATE)\b|\bCALL\s*\{|\b(?:apoc|dbms)\s*\.",
    re.IGNORECASE,
)
_CALL = re.compile(r"\bCALL\s+([\w.]+)", re.IGNORECASE)
_ALLOWED_PROCEDURES = {"db.index.vector.queryNodes", "db.index.fulltext.queryNodes"}
_BRACKET = re.compile(r"\[[^\[\]]*\]")
_VARLEN = re.compile(r"\*\s*(\d+)?\s*(\.\.)?\s*(\d+)?")
_FINAL_LIMIT = re.compile(r"\bLIMIT\s+(\d+|\$\w+)\s*$", re.IGNORECASE)  # a number or a bound parameter


class GuardrailError(ValueError):
    """The query was rejected before it ran."""


class CypherExecutionError(RuntimeError):
    """The query was allowed but failed in Neo4j (syntax error, timeout, ...)."""


def _skeleton(cypher: str) -> str:
    return _STRINGS.sub("''", _COMMENTS.sub(" ", cypher))


def validate(cypher: str) -> str:
    """Return a safe version of `cypher` (trailing ';' removed, row cap enforced) or raise."""
    text = cypher.strip()
    if not text:
        raise GuardrailError("empty query")
    skeleton = _skeleton(text)
    body = skeleton.rstrip().rstrip(";").rstrip()
    if ";" in body:
        raise GuardrailError("multiple statements are not allowed")
    if (bad := _DENY.search(body)) is not None:
        raise GuardrailError(f"write or admin construct not allowed: {bad.group(0).strip()}")
    for proc in _CALL.findall(body):
        if proc not in _ALLOWED_PROCEDURES:
            raise GuardrailError(f"procedure not allowed: {proc}")
    for bracket in _BRACKET.findall(body):
        if (star := _VARLEN.search(bracket)) is None or "*" not in bracket:
            continue
        low, dots, high = star.groups()
        if dots:
            if high is None:
                raise GuardrailError("variable-length path needs an upper bound")
            bound = int(high)
        elif low is None:
            raise GuardrailError("unbounded variable-length path (*)")
        else:
            bound = int(low)
        if bound > MAX_HOPS:
            raise GuardrailError(f"variable-length path longer than {MAX_HOPS} hops")
    # Row cap, applied to the original text so string literals are preserved.
    original = text.rstrip().rstrip(";").rstrip()
    if (m := _FINAL_LIMIT.search(original)) is None:
        return f"{original} LIMIT {MAX_ROWS}"
    if not m.group(1).startswith("$") and int(m.group(1)) > MAX_ROWS:  # parameterised limits are set by our own tools
        return original[: m.start()] + f"LIMIT {MAX_ROWS}"
    return original


def run_read(
    driver: Driver, cypher: str, *, params: dict[str, Any] | None = None, timeout_s: float = TIMEOUT_S
) -> tuple[list[dict[str, Any]], str]:
    """Validate then execute in a read transaction with a timeout. Returns (rows, executed query)."""
    safe = validate(cypher)

    @unit_of_work(timeout=timeout_s)
    def work(tx: ManagedTransaction) -> list[dict[str, Any]]:
        return [dict(r) for r in tx.run(safe, params or {})]

    try:
        with driver.session() as session:
            return session.execute_read(work), safe
    except (ClientError, DatabaseError, Neo4jError) as exc:
        raise CypherExecutionError(str(exc).splitlines()[0][:300]) from exc
