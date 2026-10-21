import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from redstring_cti.llm import (
    GroqLLM,
    LLMError,
    RequestTooLarge,
    estimate_tokens,
    parse_duration,
)

MSGS = [{"role": "user", "content": "hi"}]


def ok(text: str = "hello", model: str = "m", prompt: int = 10, completion: int = 5, reasoning: int = 0) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": prompt, "completion_tokens": completion, "completion_tokens_details": {"reasoning_tokens": reasoning}},
        },
        headers={"x-ratelimit-limit-tokens": "8000", "x-ratelimit-remaining-tokens": "7000"},
    )


def err(status: int, message: str, **headers: str) -> httpx.Response:
    return httpx.Response(status, json={"error": {"message": message}}, headers=headers)


def make(handler: Callable[[httpx.Request], httpx.Response], tmp_path: Path | None, models: tuple[str, ...] = ("a", "b")) -> tuple[GroqLLM, list[float]]:
    sleeps: list[float] = []
    llm = GroqLLM(models=models, api_key="k", cache_dir=tmp_path, client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=sleeps.append)
    return llm, sleeps


def test_parse_duration() -> None:
    assert parse_duration("2.07s") == pytest.approx(2.07)
    assert parse_duration("1m26.4s") == pytest.approx(86.4)
    assert parse_duration("350ms") == pytest.approx(0.35)
    assert parse_duration("1h2m3s") == 3723
    assert parse_duration("garbage") == 0.0


def test_estimate_reserves_the_completion_budget() -> None:
    assert estimate_tokens(MSGS, 500) >= 500


def test_success_records_usage_cost_and_model(tmp_path: Path) -> None:
    llm, _ = make(lambda r: ok("<think>x</think>answer", prompt=1000, completion=500, reasoning=100), tmp_path, ("openai/gpt-oss-120b",))
    r = llm.complete(MSGS)
    assert r.text == "answer" and r.model == "openai/gpt-oss-120b" and r.reasoning_tokens == 100 and not r.cached
    assert r.cost_usd == pytest.approx((1000 * 0.15 + 500 * 0.60) / 1e6)


def test_request_sends_reasoning_effort_only_to_gpt_oss(tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        seen[body["model"]] = body["reasoning_effort"]
        return ok()

    llm, _ = make(handler, None, ("openai/gpt-oss-120b", "qwen/qwen3.8-27b"))
    llm.complete(MSGS, reasoning_effort="medium")
    llm.complete(MSGS, reasoning_effort="medium", models=("qwen/qwen3.8-27b",))
    assert seen == {"openai/gpt-oss-120b": "medium", "qwen/qwen3.8-27b": "none"}


def test_second_identical_call_is_served_from_cache(tmp_path: Path) -> None:
    calls: list[int] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(1)
        return ok()

    llm, _ = make(handler, tmp_path)
    first = llm.complete(MSGS)
    second = llm.complete(MSGS)
    assert len(calls) == 1 and second.cached and second.text == first.text
    llm.complete(MSGS, max_tokens=123)  # different parameters -> different key
    assert len(calls) == 2


def test_rate_limit_waits_and_retries_the_same_model(tmp_path: Path) -> None:
    attempts: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        attempts.append(json.loads(req.content)["model"])
        return err(429, "Rate limit reached for tokens per minute. Please try again in 7.5s.") if len(attempts) < 3 else ok()

    llm, sleeps = make(handler, None)
    r = llm.complete(MSGS)
    assert attempts == ["a", "a", "a"] and r.model == "a" and r.fallback_from is None
    assert sleeps == [pytest.approx(8.0), pytest.approx(8.0)]  # waited, did not switch models


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Rate limit reached ... Please try again in 7.5s. Need more tokens?", 8.0),
        ("Please try again in 1m26.4s.", 86.9),
        ("Please try again in 350ms.", 0.85),
        ("no hint here", 5.0),
    ],
)
def test_real_groq_message_formats_are_parsed(message: str, expected: float) -> None:
    n = [0]

    def handler(req: httpx.Request) -> httpx.Response:
        n[0] += 1
        return err(429, message) if n[0] == 1 else ok()

    llm, sleeps = make(handler, None)
    llm.complete(MSGS)
    assert sleeps == [pytest.approx(expected)]


def test_retry_after_header_wins() -> None:
    n = [0]

    def handler(req: httpx.Request) -> httpx.Response:
        n[0] += 1
        return err(429, "slow down", **{"retry-after": "3"}) if n[0] == 1 else ok()

    llm, sleeps = make(handler, None)
    llm.complete(MSGS)
    assert sleeps == [pytest.approx(3.5)]


def test_daily_quota_falls_back_to_the_next_model() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if json.loads(req.content)["model"] == "a":
            return err(429, "Rate limit reached for requests per day (RPD): Limit 1000")
        return ok()

    llm, _ = make(handler, None)
    r = llm.complete(MSGS)
    assert r.model == "b" and r.fallback_from == ["a"]


def test_removed_model_falls_back() -> None:
    llm, _ = make(lambda r: err(400, "The model `a` has been decommissioned") if json.loads(r.content)["model"] == "a" else ok(), None)
    assert llm.complete(MSGS).model == "b"


def test_server_errors_retry_then_fall_back() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return err(503, "overloaded") if json.loads(req.content)["model"] == "a" else ok()

    llm, sleeps = make(handler, None)
    r = llm.complete(MSGS)
    assert r.model == "b" and len(sleeps) == 3


def test_too_large_request_does_not_fall_back() -> None:
    llm, _ = make(lambda r: err(413, "Request too large for model: tokens per minute limit 8000"), None)
    with pytest.raises(RequestTooLarge):
        llm.complete(MSGS)


def test_bad_key_is_not_masked_by_fallback() -> None:
    llm, _ = make(lambda r: err(401, "Invalid API Key"), None)
    with pytest.raises(LLMError, match="authentication"):
        llm.complete(MSGS)


def test_reasoning_that_eats_the_budget_is_retried_with_more_tokens() -> None:
    budgets: list[int] = []

    def handler(req: httpx.Request) -> httpx.Response:
        budgets.append(json.loads(req.content)["max_completion_tokens"])
        if len(budgets) == 1:
            return httpx.Response(200, json={"choices": [{"message": {"content": ""}, "finish_reason": "length"}], "usage": {}})
        return ok("done")

    llm, _ = make(handler, None)
    assert llm.complete(MSGS, max_tokens=300).text == "done" and budgets == [300, 600]


def test_all_models_failing_raises() -> None:
    llm, _ = make(lambda r: err(429, "Rate limit reached for requests per day"), None)
    with pytest.raises(LLMError, match="all models failed"):
        llm.complete(MSGS)


def test_throttle_sleeps_when_the_budget_is_nearly_spent() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        resp = ok()
        resp.headers["x-ratelimit-remaining-tokens"] = "100"  # almost nothing left after the first call
        return resp

    llm, sleeps = make(handler, None, ("a",))
    llm.complete(MSGS, max_tokens=800)
    assert sleeps == []  # first call: nothing known yet
    llm.complete([{"role": "user", "content": "different"}], max_tokens=800)
    assert sleeps and sleeps[0] > 1.0


# ------------------------------------------------------------------ OpenRouter
from datetime import date

from redstring_cti.config import LLM_CHAINS, LLM_MODELS, OPENROUTER_FREE_MODELS
from redstring_cti.llm import DailyBudget, split_spec

OR = "openrouter:minimax/minimax-m3.1-flash:free"
OR2 = "openrouter:nvidia/nemotron-3-super-120b-a12b:free"


def or_client(handler: Callable[[httpx.Request], httpx.Response], models: tuple[str, ...], tmp_path: Path, limit: int = 45) -> tuple[GroqLLM, list[float], DailyBudget]:
    sleeps: list[float] = []
    budget = DailyBudget(tmp_path / "usage.json", limit)
    llm = GroqLLM(
        models=models, api_key="gk", openrouter_key="ok", cache_dir=None,
        client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=sleeps.append, openrouter_budget=budget,
    )
    return llm, sleeps, budget


def or_error(status: int, raw: str) -> httpx.Response:
    return httpx.Response(status, json={"error": {"message": "Provider returned error", "code": status, "metadata": {"raw": raw}}})


def test_split_spec() -> None:
    assert split_spec("openrouter:a/b:free") == ("openrouter", "a/b:free")
    assert split_spec("groq:openai/gpt-oss-120b") == ("groq", "openai/gpt-oss-120b")
    assert split_spec("openai/gpt-oss-120b") == ("groq", "openai/gpt-oss-120b")  # bare = Groq


def test_chains_are_wired_safely() -> None:
    assert LLM_CHAINS["groq"] == LLM_MODELS and all(":" not in m or m.startswith("openrouter:") for m in LLM_MODELS)
    assert all(m.startswith("openrouter:") and m.endswith(":free") for m in OPENROUTER_FREE_MODELS)
    assert not any(m.endswith("openrouter/free") for m in OPENROUTER_FREE_MODELS)  # the random router breaks reproducibility
    assert LLM_CHAINS["groq+openrouter"] == (*LLM_MODELS, *OPENROUTER_FREE_MODELS)


def test_openrouter_request_shape_and_result(tmp_path: Path) -> None:
    seen: dict[str, Any] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["url"], seen["headers"], seen["body"] = str(req.url), dict(req.headers), json.loads(req.content)
        return ok("done", prompt=50, completion=5)

    llm, _, budget = or_client(handler, (OR,), tmp_path)
    r = llm.complete(MSGS, max_tokens=300, reasoning_effort="low")
    assert seen["url"] == "https://openrouter.ai/api/v1/chat/completions"
    assert seen["headers"]["authorization"] == "Bearer ok" and seen["headers"]["x-title"] == "RedString-CTI"
    assert seen["body"]["model"] == "minimax/minimax-m3.1-flash:free"  # prefix stripped
    assert seen["body"]["max_tokens"] == 300 and seen["body"]["reasoning"] == {"effort": "low"}
    assert "max_completion_tokens" not in seen["body"] and "reasoning_effort" not in seen["body"]
    assert r.model == OR and r.cost_usd == 0.0 and budget.used() == 1


def test_groq_requests_still_go_to_groq(tmp_path: Path) -> None:
    urls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        urls.append(str(req.url))
        return ok()

    llm, _, budget = or_client(handler, ("openai/gpt-oss-120b",), tmp_path)
    assert llm.complete(MSGS).model == "openai/gpt-oss-120b"
    assert urls == ["https://api.groq.com/openai/v1/chat/completions"] and budget.used() == 0  # Groq never touches the OpenRouter budget


def test_openrouter_requests_are_spaced_for_20_per_minute(tmp_path: Path) -> None:
    llm, sleeps, _ = or_client(lambda r: ok(), (OR,), tmp_path)
    llm.complete(MSGS)
    assert sleeps == []
    llm.complete([{"role": "user", "content": "second"}])
    assert len(sleeps) == 1 and sleeps[0] == pytest.approx(3.2, abs=0.2)


def test_daily_budget_stops_requests_and_falls_back_to_the_next_provider(tmp_path: Path) -> None:
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url).split("/")[2])
        return ok()

    llm, _, budget = or_client(handler, (OR, "openai/gpt-oss-120b"), tmp_path, limit=1)
    first = llm.complete(MSGS)
    assert first.model == OR and budget.used() == 1
    second = llm.complete([{"role": "user", "content": "again"}])  # budget spent -> never contacts OpenRouter
    assert second.model == "openai/gpt-oss-120b" and second.fallback_from == [OR]
    assert calls == ["openrouter.ai", "api.groq.com"]


def test_daily_budget_all_openrouter_exhausted_raises(tmp_path: Path) -> None:
    llm, _, _ = or_client(lambda r: ok(), (OR, OR2), tmp_path, limit=0)
    with pytest.raises(LLMError, match="daily request budget"):
        llm.complete(MSGS)


def test_daily_budget_persists_and_resets_each_day(tmp_path: Path) -> None:
    day = [date(2026, 10, 21)]
    path = tmp_path / "u.json"
    b1 = DailyBudget(path, 3, today=lambda: day[0])
    assert [b1.take() for _ in range(4)] == [True, True, True, False]
    assert DailyBudget(path, 3, today=lambda: day[0]).used() == 3  # survives a restart
    day[0] = date(2026, 10, 22)
    assert DailyBudget(path, 3, today=lambda: day[0]).used() == 0 and DailyBudget(path, 3, today=lambda: day[0]).take()


def test_provider_404_fails_over_immediately(tmp_path: Path) -> None:
    """Seen live: nvidia/nemotron returned 404 'Function ... Not found for account'."""
    def handler(req: httpx.Request) -> httpx.Response:
        return or_error(404, "Function 'abc': Not found for account") if json.loads(req.content)["model"].startswith("nvidia") else ok()

    llm, sleeps, _ = or_client(handler, (OR2, OR), tmp_path)
    r = llm.complete(MSGS)
    assert r.model == OR and r.fallback_from == [OR2]
    assert all(w < 4 for w in sleeps)  # only the 20-requests-per-minute pacing, no retry backoff on a 404


def test_upstream_rate_limit_waits_then_fails_over(tmp_path: Path) -> None:
    """Seen live: google/gemma 429 'temporarily rate-limited upstream' from a shared pool."""
    def handler(req: httpx.Request) -> httpx.Response:
        if json.loads(req.content)["model"].startswith("google"):
            return or_error(429, "google/gemma is temporarily rate-limited upstream. Please retry shortly")
        return ok()

    gemma = "openrouter:google/gemma-4-31b-it:free"
    llm, sleeps, _ = or_client(handler, (gemma, OR), tmp_path)
    r = llm.complete(MSGS)
    assert r.model == OR and r.fallback_from == [gemma]
    assert sleeps.count(8.0) == 3  # three patient retries, then move on


def test_upstream_rate_limit_that_clears_is_retried_on_the_same_model(tmp_path: Path) -> None:
    n = [0]

    def handler(req: httpx.Request) -> httpx.Response:
        n[0] += 1
        return or_error(429, "temporarily rate-limited upstream") if n[0] == 1 else ok()

    llm, _, _ = or_client(handler, (OR, OR2), tmp_path)
    r = llm.complete(MSGS)
    assert r.model == OR and r.fallback_from is None


def test_free_models_per_day_limit_is_a_hard_failure(tmp_path: Path) -> None:
    llm, sleeps, _ = or_client(lambda r: or_error(429, "Rate limit exceeded: free-models-per-day"), (OR,), tmp_path)
    with pytest.raises(LLMError, match="all models failed"):
        llm.complete(MSGS)
    assert sleeps == []  # no point waiting out a daily limit


def test_openrouter_200_with_an_error_body_fails_over(tmp_path: Path) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"error": {"message": "x", "code": 502}}) if json.loads(req.content)["model"].startswith("minimax") else ok()

    llm, _, _ = or_client(handler, (OR, OR2), tmp_path)
    assert llm.complete(MSGS).model == OR2


def test_a_reply_cut_off_by_max_tokens_is_flagged_not_retried() -> None:
    calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(200, json={"choices": [{"message": {"content": "M1040, M10"}, "finish_reason": "length"}], "usage": {"prompt_tokens": 5, "completion_tokens": 9}})

    llm, _ = make(handler, None)
    r = llm.complete(MSGS)
    assert r.truncated and r.text == "M1040, M10" and len(calls) == 1  # the caller decides whether to retry
    ok_llm, _ = make(lambda req: ok(), None)
    assert not ok_llm.complete(MSGS).truncated
