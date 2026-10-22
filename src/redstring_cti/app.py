"""The demo UI (Gradio): ask the agent, extract from a report, read the benchmark tables.

Everything with logic is a plain function so it can be tested without a browser. The demo is read-only: the Extract tab
links entities against the graph but never writes to it. Configuration comes from the environment:
  REDSTRING_EXTRACTOR  hf | ollama | llama:<path-to-gguf>   (default hf)
  REDSTRING_RATE_LIMIT questions per visitor per hour (default 10)
  REDSTRING_MAX_CHUNKS report chunks processed per extraction (default 3)"""

import os
import time
from collections import defaultdict, deque
from collections.abc import Callable
from pathlib import Path
from typing import Any

from redstring_cti.extractor import upsert
from redstring_cti.extractor.schema import TASK_FULL

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "evals" / "results"
BENCHMARK_FILES = [("Extractor comparison", "extractor_comparison.md"), ("Fine-tuning verdict", "extractor_verdict.md"),
                   ("Retrieval baselines", "baselines.md"), ("Data quality", "data_quality.md")]
EXAMPLES = ["Which techniques does APT29 use?", "Which actively exploited (KEV) CVEs are weakness-linked, through CAPEC and CWE, to the techniques of Sandworm Team?",
            "What are the sub-techniques of T1059?", "Which groups share at least 21 techniques with APT29?", "What does the Royal advisory add beyond ATT&CK about Royal?"]
SAMPLE_REPORT = ("Royal ransomware actors gained initial access through phishing emails and used Cobalt Strike and Mimikatz for credential theft. "
                 "They moved laterally over RDP with PsExec and encrypted files with a custom encryptor, after exfiltrating data with Rclone.")


class RateLimiter:
    """Sliding window per visitor, so one person cannot spend the shared free-tier token budget."""

    def __init__(self, limit: int, window_s: float = 3600.0, clock: Callable[[], float] = time.monotonic) -> None:
        self.limit, self.window, self._clock = limit, window_s, clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, visitor: str) -> tuple[bool, int]:
        """(allowed, seconds until the next slot frees up when refused)."""
        now = self._clock()
        hits = self._hits[visitor]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            return False, int(self.window - (now - hits[0])) + 1
        hits.append(now)
        return True, 0


def format_answer(result: Any) -> tuple[str, str]:
    """(markdown answer, markdown trace) from an AgentResult."""
    answer = result.answer.strip() or "No answer."
    trace = [f"**Route:** {result.route}" + (f" / {result.pattern}" if result.pattern else ""), (f"**Model calls:** {result.llm_calls}, **tool calls:** {result.tool_calls}, "
             f"**tokens:** {result.tokens:,}, **cost:** ${result.cost_usd:.5f}, **time:** {result.latency_ms / 1000:.1f}s")]
    if result.entities:
        trace.append("**Resolved:** " + ", ".join(f"{e.get('name') or ''} {e['id']}".strip() for e in result.entities))
    if result.verdict != "pass":
        trace.append(f"**Self-check:** {result.verdict}")
    if result.paths:
        shown = [f"{t[0]} -[{t[1]}]-> {t[2]}" for t in result.paths[:12]]
        trace.append("**Evidence paths:**\n" + "\n".join(f"- {s}" for s in shown))
    return answer, "\n\n".join(trace)


def format_extraction(report: upsert.IngestReport, extractions: list[Any]) -> str:
    lines = [f"**{report.chunks} chunk(s)**, {report.invalid_chunks} unusable, {report.pruned_entities} entities pruned (not in the text)."]
    if report.linked:
        lines += ["", "| Entity | Linked to | How |", "|---|---|---|"]
        for text, link in report.linked.items():
            lines.append(f"| {text} | " + (f"**{link.node_id}** ({link.label})" if link.curated else "not in the graph (would be provisional)") + f" | {link.method} |")
    if report.techniques:
        lines += ["", "**ATT&CK techniques:** " + ", ".join(f"{t} (x{n})" for t, n in sorted(report.techniques.items()))]
    if report.unknown_techniques:
        lines.append("Dropped, not live ATT&CK ids: " + ", ".join(report.unknown_techniques))
    if report.asserted:
        lines += ["", "**Relations:** " + "; ".join(f"{h} {r} {t}" for h, r, t in report.asserted)]
    return "\n".join(lines)


def run_extraction(text: str, extractor: upsert.Extractor, driver: Any, live_techniques: set[str], max_chunks: int) -> str:
    """Extract from the first `max_chunks` chunks and link against the graph, without writing anything."""
    text = text.strip()
    if not text:
        return "Paste some report text first."
    chunks = upsert.chunk_text(text)
    note = f"\n\n_Only the first {max_chunks} of {len(chunks)} chunks were processed (the demo runs on CPU)._" if len(chunks) > max_chunks else ""
    extractions, n_chunks, invalid, pruned = upsert.extract_report("\n\n".join(chunks[:max_chunks]), extractor, TASK_FULL)
    report = upsert.ingest(driver, "demo", "demo", "demo", text, extractions, n_chunks, invalid, live_techniques, dry_run=True, pruned=pruned)
    return format_extraction(report, extractions) + note


def benchmarks_markdown(results_dir: Path = RESULTS) -> dict[str, str]:
    return {title: (results_dir / name).read_text() if (results_dir / name).exists() else f"_{name} has not been generated yet._" for title, name in BENCHMARK_FILES}


def live_technique_ids(driver: Any) -> set[str]:
    """Every Technique node in the graph is a live ATT&CK technique (revoked and deprecated ones are never loaded), so the
    graph itself is the source of truth and the Space does not need the raw ATT&CK bundle."""
    rows, _, _ = driver.execute_query("MATCH (t:Technique) RETURN t.attack_id AS id")
    return {r["id"] for r in rows}


def build_extractor(kind: str, live_ids: set[str]) -> upsert.Extractor:
    from redstring_cti.extractor import backends

    if kind == "ollama":
        return backends.OllamaExtractor(os.environ.get("REDSTRING_OLLAMA_MODEL", "redstring-extractor-q8"), os.environ.get("REDSTRING_OLLAMA_URL", "http://localhost:11434"), live_ids=live_ids)
    if kind.startswith("llama:"):
        return backends.LlamaCppExtractor(kind.split(":", 1)[1], live_ids)
    return backends.HFExtractor(constrain=True)


def build_app() -> Any:
    import gradio as gr

    from redstring_cti.agent.graph import Agent
    from redstring_cti.agent.toolbox import McpToolbox
    from redstring_cti.graph.loader import get_driver
    from redstring_cti.llm import LLMClient

    limiter = RateLimiter(int(os.environ.get("REDSTRING_RATE_LIMIT", "10")))
    max_chunks = int(os.environ.get("REDSTRING_MAX_CHUNKS", "3"))
    lazy: dict[str, Any] = {}

    def agent() -> Any:
        if "agent" not in lazy:
            lazy["agent"] = Agent(LLMClient(), McpToolbox())
        return lazy["agent"]

    def extractor() -> Any:
        if "extractor" not in lazy:
            lazy["extractor"] = build_extractor(os.environ.get("REDSTRING_EXTRACTOR", "hf"), live_technique_ids(get_driver()))
        return lazy["extractor"]

    def ask(question: str, request: gr.Request) -> tuple[str, str]:
        if not question.strip():
            return "Type a question.", ""
        ok, wait = limiter.allow(request.client.host if request and request.client else "anonymous")
        if not ok:
            return f"Rate limit reached for this demo: try again in about {wait // 60 + 1} minute(s).", ""
        try:
            return format_answer(agent().run(question))
        except Exception as exc:  # noqa: BLE001  the UI must show a failure, not crash
            return f"The agent failed: {type(exc).__name__}: {exc}", ""

    def extract(text: str) -> str:
        try:
            return run_extraction(text, extractor(), get_driver(), live_technique_ids(get_driver()), max_chunks)
        except Exception as exc:  # noqa: BLE001
            return f"Extraction failed: {type(exc).__name__}: {exc}"

    with gr.Blocks(title="RedString-CTI") as demo:
        gr.Markdown("# RedString-CTI\nAgentic GraphRAG over MITRE ATT&CK, CAPEC, CWE, NVD and CISA KEV, plus a fine-tuned 1.7B threat-report extractor. "
                    "Answers cite graph IDs; report claims are automatic extractions and unverified.")
        with gr.Tab("Ask"):
            q = gr.Textbox(label="Question", lines=2)
            gr.Examples(EXAMPLES, inputs=q)
            btn = gr.Button("Ask", variant="primary")
            ans, trace = gr.Markdown(label="Answer"), gr.Markdown(label="How it was answered")
            btn.click(ask, q, [ans, trace])
        with gr.Tab("Extract"):
            txt = gr.Textbox(label="Threat report text", lines=8, value=SAMPLE_REPORT)
            go = gr.Button("Extract and link", variant="primary")
            out = gr.Markdown()
            go.click(extract, txt, out)
        for title, body in benchmarks_markdown().items():
            with gr.Tab(title):
                gr.Markdown(body)
    return demo


def main() -> None:
    build_app().launch(server_name="0.0.0.0", server_port=int(os.environ.get("PORT", "7860")))


if __name__ == "__main__":
    main()
