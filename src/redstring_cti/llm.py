"""Chat client for Groq and OpenRouter: disk cache, proactive throttling, same-model rate-limit
retries, and fallback to the next model only on hard failures. Every result records the model that
answered, so a run can never silently mix models.

Models are written as specs: `groq:openai/gpt-oss-120b` or `openrouter:minimax/minimax-m3.1-flash:free`.
A bare name means Groq (this keeps old cache entries and tests valid).
"""

import hashlib
import json
import logging
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import httpx

from redstring_cti.config import (
    LLM_MODELS,
    PROCESSED_DIR,
    REFERENCE_PRICES_USD_PER_M,
    get_settings,
)

log = logging.getLogger(__name__)

CACHE_DIR = PROCESSED_DIR / "llm_cache"
OPENROUTER_BUDGET_PATH = PROCESSED_DIR / "openrouter_usage.json"
MAX_RATE_LIMIT_RETRIES = 12
MAX_UPSTREAM_RETRIES = 3  # OpenRouter free models: upstream 429s are common; fail over quickly
MAX_SERVER_RETRIES = 3
MAX_TRANSPORT_RETRIES = 2
READ_TIMEOUT_S = 40.0  # answers take 1-15s; a longer silence means the connection is stuck
MAX_WAIT_S = 90.0
UPSTREAM_WAIT_S = 8.0
CHARS_PER_TOKEN = 3.0  # conservative estimate used only for throttling
_THINK = re.compile(r"<think>.*?</think>", re.DOTALL)
_DURATION = re.compile(r"(?:(\d+(?:\.\d+)?)h)?(?:(\d+(?:\.\d+)?)m(?!s))?(?:(\d+(?:\.\d+)?)s)?(?:(\d+(?:\.\d+)?)ms)?")
_TRY_AGAIN = re.compile(r"try again in ((?:\d+(?:\.\d+)?(?:ms|h|m|s))+)", re.IGNORECASE)


@dataclass(frozen=True)
class Provider:
    name: str
    url: str
    min_interval_s: float = 0.0  # spacing between requests (OpenRouter free: 20 requests/minute)
    extra_headers: dict[str, str] = field(default_factory=dict)


PROVIDERS = {
    "groq": Provider("groq", "https://api.groq.com/openai/v1/chat/completions"),
    "openrouter": Provider(
        "openrouter",
        "https://openrouter.ai/api/v1/chat/completions",
        min_interval_s=3.2,
        extra_headers={"HTTP-Referer": "https://github.com/abhibarnwal707/redstring", "X-Title": "RedString-CTI"},
    ),
}


def record_name(spec: str) -> str:
    """The name stored in results: bare for Groq, the full spec for other providers."""
    provider, model = split_spec(spec)
    return model if provider == "groq" else spec


def split_spec(spec: str) -> tuple[str, str]:
    """'openrouter:a/b:free' -> ('openrouter', 'a/b:free'); a bare name is a Groq model."""
    for name in PROVIDERS:
        if spec.startswith(f"{name}:"):
            return name, spec[len(name) + 1 :]
    return "groq", spec


class LLMError(RuntimeError):
    """No model could answer."""


class RequestTooLarge(LLMError):
    """The prompt plus the completion budget exceeds the per-request limit; shrink the prompt."""


class HardFailure(LLMError):
    """This model cannot answer right now (quota exhausted, removed, repeated server errors)."""


@dataclass
class LLMResult:
    text: str
    model: str  # the full spec that answered
    prompt_tokens: int
    completion_tokens: int
    reasoning_tokens: int
    latency_s: float
    cached: bool = False
    fallback_from: list[str] | None = None  # models that failed before this one answered
    waited_s: float = 0.0  # time spent sleeping for rate limits and retries (not part of service time)
    truncated: bool = False  # the reply hit max_tokens, so it may be cut off mid-list

    @property
    def cost_usd(self) -> float:
        """Reference cost at Groq list prices; free OpenRouter models are $0."""
        price_in, price_out = REFERENCE_PRICES_USD_PER_M.get(self.model, (0.0, 0.0))
        return (self.prompt_tokens * price_in + self.completion_tokens * price_out) / 1_000_000


class DailyBudget:
    """Persistent per-day request counter, so free-tier allowances survive process restarts."""

    def __init__(self, path: Path | None, limit: int, today: Callable[[], date] = date.today) -> None:
        self.path, self.limit, self._today = path, limit, today

    def _read(self) -> dict[str, Any]:
        if self.path is not None and self.path.exists():
            data = json.loads(self.path.read_text())
            if data.get("date") == self._today().isoformat():
                return data
        return {"date": self._today().isoformat(), "count": 0}

    def used(self) -> int:
        return int(self._read()["count"])

    def take(self) -> bool:
        """Count one request; False (and no count) when the day's allowance is spent."""
        data = self._read()
        if data["count"] >= self.limit:
            return False
        data["count"] += 1
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(data))
        return True


def parse_duration(text: str) -> float:
    """'1m26.4s' -> 86.4, '2.07s' -> 2.07, '350ms' -> 0.35."""
    m = _DURATION.fullmatch(text.strip())
    if not m or not any(m.groups()):
        return 0.0
    h, mi, s, ms = (float(g) if g else 0.0 for g in m.groups())
    return h * 3600 + mi * 60 + s + ms / 1000


def estimate_tokens(messages: Sequence[dict[str, str]], max_tokens: int) -> int:
    """Groq reserves prompt + max_completion_tokens against the per-minute budget up front."""
    return int(sum(len(m["content"]) for m in messages) / CHARS_PER_TOKEN) + 30 + max_tokens


class LLMClient:
    def __init__(
        self,
        models: Sequence[str] = LLM_MODELS,
        api_key: str | None = None,
        cache_dir: Path | None = CACHE_DIR,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        openrouter_key: str | None = None,
        openrouter_budget: DailyBudget | None = None,
    ) -> None:
        settings = get_settings()
        self.models = tuple(models)
        self._keys = {
            "groq": api_key if api_key is not None else settings.groq_api_key,
            "openrouter": openrouter_key if openrouter_key is not None else settings.openrouter_api_key,
        }
        self._budget_limit = openrouter_budget or DailyBudget(OPENROUTER_BUDGET_PATH, settings.openrouter_daily_limit)
        self._cache_dir = cache_dir
        if cache_dir is not None:
            cache_dir.mkdir(parents=True, exist_ok=True)
        self._client = client or httpx.Client(timeout=httpx.Timeout(READ_TIMEOUT_S, connect=15.0))
        self._sleep = sleep
        # spec -> (remaining tokens, tokens-per-second refill, observed at); Groq reports this in headers
        self._budget: dict[str, tuple[float, float, float]] = {}
        self._last_request: dict[str, float] = {}

    # ------------------------------------------------------------------ public
    def complete(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int = 800,
        reasoning_effort: str = "low",
        temperature: float = 0.0,
        models: Sequence[str] | None = None,
    ) -> LLMResult:
        chain = tuple(models or self.models)
        key = self._cache_key(messages, max_tokens, reasoning_effort, temperature, chain)
        cached = self._read_cache(key)
        if cached is not None:
            return cached
        failed: list[str] = []
        errors: list[str] = []
        for spec in chain:
            try:
                result = self._call(spec, messages, max_tokens, reasoning_effort, temperature)
            except HardFailure as exc:
                log.warning("model %s failed hard (%s); trying the next one", spec, exc)
                failed.append(spec)
                errors.append(f"{spec}: {exc}")
                continue
            result.fallback_from = failed or None
            self._write_cache(key, result)
            return result
        raise LLMError("all models failed: " + "; ".join(errors))

    # ------------------------------------------------------------------ cache
    @staticmethod
    def _cache_key(messages: Any, max_tokens: int, effort: str, temperature: float, chain: Sequence[str]) -> str:
        blob = json.dumps(
            {"m": messages, "mt": max_tokens, "re": effort, "t": temperature, "c": list(chain)}, sort_keys=True
        )
        return hashlib.sha256(blob.encode()).hexdigest()

    def _read_cache(self, key: str) -> LLMResult | None:
        if self._cache_dir is None:
            return None
        path = self._cache_dir / f"{key}.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        data["cached"] = True
        return LLMResult(**data)

    def _write_cache(self, key: str, result: LLMResult) -> None:
        if self._cache_dir is not None:
            data = asdict(result)
            data["cached"] = False
            (self._cache_dir / f"{key}.json").write_text(json.dumps(data))

    # ------------------------------------------------------------------ throttling
    def _throttle(self, spec: str, provider: Provider, needed: int) -> float:
        """Sleep until the request fits the provider's limits. Returns the seconds slept."""
        slept = 0.0
        if provider.min_interval_s:
            last = self._last_request.get(provider.name)
            if last is not None:
                wait = provider.min_interval_s - (time.monotonic() - last)
                if wait > 0:
                    self._sleep(wait)
                    slept += wait
            self._last_request[provider.name] = time.monotonic()
        state = self._budget.get(spec)
        if state is not None:
            remaining, rate, observed = state
            available = min(remaining + rate * (time.monotonic() - observed), rate * 60)
            if available < needed:
                wait = min((needed - available) / rate + 0.25, MAX_WAIT_S)
                log.info("throttling %.1fs for %s (need ~%d tokens, have ~%d)", wait, spec, needed, available)
                self._sleep(wait)
                slept += wait
        return slept

    def _remember_budget(self, spec: str, headers: httpx.Headers) -> None:
        try:
            limit = float(headers["x-ratelimit-limit-tokens"])
            remaining = float(headers["x-ratelimit-remaining-tokens"])
        except (KeyError, ValueError):
            return
        self._budget[spec] = (remaining, limit / 60.0, time.monotonic())

    # ------------------------------------------------------------------ transport
    @staticmethod
    def _body(provider: str, model: str, messages: list[dict[str, str]], max_tokens: int, effort: str, temperature: float) -> dict[str, Any]:
        if provider == "openrouter":
            return {"model": model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens, "reasoning": {"effort": effort}}
        return {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_completion_tokens": max_tokens,
            # gpt-oss models reason before answering (those tokens are billed and rate-limited);
            # Qwen is told not to think.
            "reasoning_effort": effort if "gpt-oss" in model else "none",
        }

    def _call(self, spec: str, messages: list[dict[str, str]], max_tokens: int, effort: str, temperature: float) -> LLMResult:
        provider_name, model = split_spec(spec)
        provider = PROVIDERS[provider_name]
        token_field = "max_tokens" if provider_name == "openrouter" else "max_completion_tokens"
        body = self._body(provider_name, model, messages, max_tokens, effort, temperature)
        headers = {"Authorization": f"Bearer {self._keys[provider_name]}", "Content-Type": "application/json", **provider.extra_headers}
        rate_limited = server_errors = transport_errors = 0
        doubled = False
        waited = 0.0
        while True:
            if provider_name == "openrouter" and not self._budget_limit.take():
                raise HardFailure(f"OpenRouter daily request budget spent ({self._budget_limit.limit})")
            waited += self._throttle(spec, provider, estimate_tokens(messages, body[token_field]))
            started = time.perf_counter()
            try:
                resp = self._client.post(provider.url, headers=headers, json=body)
            except httpx.TransportError as exc:
                transport_errors += 1
                log.warning("%s: %s (attempt %d/%d)", spec, type(exc).__name__, transport_errors, MAX_TRANSPORT_RETRIES + 1)
                if transport_errors > MAX_TRANSPORT_RETRIES:
                    raise HardFailure(f"transport errors: {exc!r}") from exc
                waited += 2.0**transport_errors
                self._sleep(2.0**transport_errors)
                continue
            latency = time.perf_counter() - started
            self._remember_budget(spec, resp.headers)
            if resp.status_code == 200:
                data = resp.json()
                if "choices" not in data:  # OpenRouter can return 200 with an error body
                    raise HardFailure(f"no choices in response: {str(data)[:120]}")
                choice = data["choices"][0]
                text = _THINK.sub("", choice["message"].get("content") or "").strip()
                if not text and choice.get("finish_reason") == "length" and not doubled:
                    body[token_field] = min(body[token_field] * 2, 4000)  # reasoning ate the budget
                    doubled = True
                    continue
                if not text:
                    raise HardFailure(f"empty completion (finish_reason={choice.get('finish_reason')})")
                usage = data.get("usage") or {}
                details = usage.get("completion_tokens_details") or {}
                return LLMResult(
                    text=text,
                    model=model if provider_name == "groq" else spec,
                    prompt_tokens=int(usage.get("prompt_tokens", 0)),
                    completion_tokens=int(usage.get("completion_tokens", 0)),
                    reasoning_tokens=int(details.get("reasoning_tokens", 0) or 0),
                    latency_s=latency,
                    waited_s=waited,
                    truncated=choice.get("finish_reason") == "length",
                )
            message = self._error_message(resp)
            lowered = message.lower()
            if resp.status_code == 429:
                if "per day" in lowered or "per-day" in lowered or "daily" in lowered:
                    raise HardFailure(f"daily quota: {message[:400]}")
                rate_limited += 1
                limit = MAX_UPSTREAM_RETRIES if provider_name == "openrouter" else MAX_RATE_LIMIT_RETRIES
                if rate_limited > limit:
                    raise HardFailure("rate limited too many times")
                wait = UPSTREAM_WAIT_S if provider_name == "openrouter" else self._retry_after(resp, message)
                log.info("429 on %s, sleeping %.1fs", spec, wait)
                waited += wait
                self._sleep(wait)
                continue
            if resp.status_code == 413 or (resp.status_code == 400 and "too large" in lowered):
                raise RequestTooLarge(message[:200])
            if resp.status_code == 401:
                raise LLMError(f"authentication error 401: {message[:120]}")
            if resp.status_code in (402, 403, 404, 410) or "decommission" in lowered:
                raise HardFailure(f"model unavailable ({resp.status_code}): {message[:120]}")
            server_errors += 1
            if resp.status_code >= 500 and server_errors <= MAX_SERVER_RETRIES:
                waited += 2.0**server_errors
                self._sleep(2.0**server_errors)
                continue
            raise HardFailure(f"HTTP {resp.status_code}: {message[:120]}")

    @staticmethod
    def _error_message(resp: httpx.Response) -> str:
        try:
            error = resp.json().get("error", {})
        except ValueError:
            return resp.text
        if not isinstance(error, dict):
            return str(error)
        raw = (error.get("metadata") or {}).get("raw", "")  # OpenRouter hides the real reason here
        return f"{error.get('message', resp.text)} {raw}".strip()

    @staticmethod
    def _retry_after(resp: httpx.Response, message: str) -> float:
        header = resp.headers.get("retry-after")
        if header:
            try:
                return min(float(header) + 0.5, MAX_WAIT_S)
            except ValueError:
                pass
        m = _TRY_AGAIN.search(message)
        return min(parse_duration(m.group(1)) + 0.5, MAX_WAIT_S) if m else 5.0


# Backwards-compatible name: the first version only spoke to Groq.
GroqLLM = LLMClient
