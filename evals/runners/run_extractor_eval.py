"""Score a fine-tuned extractor on the Apple GPU (MPS) or CPU: `make eval-extractor SPLIT=val`.

Loads the base model in 16-bit and applies the LoRA adapter from the Hub (the adapter was trained on the 4-bit
base, so scores can differ slightly from the Kaggle numbers; that difference is itself worth knowing).
Generations are cached per example id in evals/results/extractor/<name>-<split>.jsonl so a run is resumable."""

import argparse
import hashlib
import json
import time
from pathlib import Path
from typing import Any

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

from redstring_cti.config import ATTACK_VERSION, RAW_DIR
from redstring_cti.extractor import metrics
from redstring_cti.extractor.attack_ids import load_attack_ids
from redstring_cti.extractor.constrain import extraction_schema

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "finetune" / "data"
OUT = ROOT / "evals" / "results" / "extractor"
BASE = "Qwen/Qwen3-1.7B"


def prompt(tok: Any, messages: list[dict[str, str]], shots: list[list[dict[str, str]]] | None = None) -> str:
    """System + (optional few-shot user/assistant pairs) + user, ending in the empty think block."""
    turns = [messages[0]]
    for shot in shots or []:
        turns += [shot[1], shot[2]]
    turns.append(messages[1])
    return str(tok.apply_chat_template(turns, tokenize=False, add_generation_prompt=True, enable_thinking=False))


def pick_shots(k: int) -> dict[str, list[list[dict[str, str]]]]:
    """k short, non-empty TRAIN examples per task, chosen deterministically (never from val or test)."""
    out: dict[str, list[list[dict[str, str]]]] = {"full": [], "entities_techniques": []}
    rows = [json.loads(line) for line in (DATA / "train.jsonl").read_text().splitlines()]
    for r in sorted(rows, key=lambda r: (len(r["messages"][1]["content"]), r["id"])):
        gold = json.loads(r["messages"][2]["content"])
        if r["source"] == "annoctr" and len(r["messages"][1]["content"]) < 700:
            continue  # keep shots short; the chunk-sized ones would swamp the context
        if gold["entities"] and gold["techniques"] and len(out[r["task"]]) < k:
            out[r["task"]].append(r["messages"])
    # AnnoCTR-style (no relations) examples are all long, so relax the length cut for that task
    for r in sorted(rows, key=lambda r: (len(r["messages"][1]["content"]), r["id"])):
        gold = json.loads(r["messages"][2]["content"])
        if r["task"] == "entities_techniques" and len(out["entities_techniques"]) < k and gold["entities"] and gold["techniques"] and r["messages"] not in out["entities_techniques"]:
            out["entities_techniques"].append(r["messages"])
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", default="abhibarnwal707/redstring-cti-extractor-qwen3-1.7b-lora", help="Hub id or local folder; 'none' = base model")
    ap.add_argument("--split", default="val", choices=["val", "test_annoctr", "test_procedures"])
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--batch", type=int, default=8)
    ap.add_argument("--name", default="qwen3-1.7b-qlora")
    ap.add_argument("--shots", type=int, default=0, help="few-shot examples per task taken from the training file")
    ap.add_argument("--repetition-penalty", type=float, default=1.0)
    ap.add_argument("--max-new-tokens", type=int, default=700)
    ap.add_argument("--api", default="", help="score an API model instead (e.g. groq-120b); outputs are cut to the outermost {...}")
    ap.add_argument("--constrain", action="store_true", help="schema-constrained decoding (batch size 1)")
    ap.add_argument("--sample", type=int, default=0, help="score a fixed, seeded subset of this many rows (the same rows for every system)")
    args = ap.parse_args()

    rows = [json.loads(line) for line in (DATA / f"{args.split}.jsonl").read_text().splitlines()]
    rows = [r for r in rows if len(r["messages"][1]["content"]) <= 3000]
    if args.sample and len(rows) > args.sample:
        rows = sorted(rows, key=lambda r: hashlib.sha1(("extractor-eval-sample" + r["id"]).encode()).hexdigest())[: args.sample]
    if args.limit:
        rows = rows[: args.limit]
    OUT.mkdir(parents=True, exist_ok=True)
    cache_path = OUT / f"{args.name}-{args.split}.jsonl"
    cache = {json.loads(line)["id"]: json.loads(line) for line in cache_path.read_text().splitlines()} if cache_path.exists() else {}
    todo = [r for r in rows if r["id"] not in cache]
    print(f"{len(rows)} rows, {len(cache)} cached, {len(todo)} to generate", flush=True)

    if todo and args.api:
        from redstring_cti.config import LLM_CHAINS
        from redstring_cti.llm import LLMClient

        client = LLMClient()
        chain = LLM_CHAINS.get(args.api, (args.api,))
        with cache_path.open("a") as f:
            for n, r in enumerate(todo, 1):
                res = client.complete(r["messages"][:2], max_tokens=1500, reasoning_effort="low", models=chain)
                text = res.text.strip()
                if "{" in text and "}" in text:
                    text = text[text.index("{") : text.rindex("}") + 1]
                rec = {"id": r["id"], "source": r["source"], "task": r["task"], "output": text, "gold": r["messages"][2]["content"], "latency_s": round(res.latency_s, 2),
                       "prompt_tokens": res.prompt_tokens, "completion_tokens": res.completion_tokens, "reasoning_tokens": res.reasoning_tokens, "cost_usd": res.cost_usd, "model": res.model}
                cache[r["id"]] = rec
                f.write(json.dumps(rec) + "\n")
                f.flush()
                print(f"{n}/{len(todo)} done ({res.prompt_tokens + res.completion_tokens} tokens)", flush=True)
    elif todo:
        device = "mps" if torch.backends.mps.is_available() else "cpu"
        tok = AutoTokenizer.from_pretrained(BASE, padding_side="left")
        model = AutoModelForCausalLM.from_pretrained(BASE, dtype=torch.float16 if device == "mps" else torch.float32).to(device)  # type: ignore[arg-type]
        if args.adapter != "none":
            model = PeftModel.from_pretrained(model, args.adapter)  # type: ignore[arg-type]
        model.eval()
        shots = pick_shots(args.shots) if args.shots else {}
        live_ids = load_attack_ids(RAW_DIR / f"enterprise-attack-{ATTACK_VERSION}.json").live
        if args.constrain:
            args.batch = 1
            import transformers
            import transformers.tokenization_utils as _tu  # type: ignore[import-not-found]

            if not hasattr(_tu, "PreTrainedTokenizerBase"):  # lm-format-enforcer 0.11 predates transformers 5
                _tu.PreTrainedTokenizerBase = transformers.PreTrainedTokenizerBase  # type: ignore[attr-defined]
            from lmformatenforcer import JsonSchemaParser
            from lmformatenforcer.integrations.transformers import (
                build_token_enforcer_tokenizer_data,
                build_transformers_prefix_allowed_tokens_fn,
            )

            token_data = build_token_enforcer_tokenizer_data(tok)
        todo.sort(key=lambda r: len(r["messages"][1]["content"]))
        started = time.time()
        with cache_path.open("a") as f:
            for i in range(0, len(todo), args.batch):
                batch = todo[i : i + args.batch]
                enc = tok([prompt(tok, r["messages"], shots.get(r["task"])) for r in batch], return_tensors="pt", padding=True).to(device)
                t0 = time.time()
                extra: dict[str, Any] = {}
                if args.constrain:
                    parser = JsonSchemaParser(extraction_schema(batch[0]["task"], live_ids))
                    extra["prefix_allowed_tokens_fn"] = build_transformers_prefix_allowed_tokens_fn(token_data, parser)
                with torch.no_grad():
                    out = model.generate(**enc, max_new_tokens=args.max_new_tokens, do_sample=False, repetition_penalty=args.repetition_penalty, **extra)
                dt = time.time() - t0
                for r, seq in zip(batch, out, strict=True):
                    text = str(tok.decode(seq[enc["input_ids"].shape[1]:], skip_special_tokens=True)).strip()
                    rec = {"id": r["id"], "source": r["source"], "task": r["task"], "output": text, "gold": r["messages"][2]["content"], "batch_seconds": round(dt, 2)}
                    cache[r["id"]] = rec
                    f.write(json.dumps(rec) + "\n")
                f.flush()
                print(f"{min(i + args.batch, len(todo))}/{len(todo)} done, {time.time() - started:.0f}s elapsed", flush=True)

    live = load_attack_ids(RAW_DIR / f"enterprise-attack-{ATTACK_VERSION}.json").live
    recs = [cache[r["id"]] for r in rows]
    result = {"system": args.name, "split": args.split, "adapter": args.adapter, "overall": metrics.score([(c["output"], c["gold"]) for c in recs], live).summary()}
    for source in sorted({c["source"] for c in recs}):
        result[source] = metrics.score([(c["output"], c["gold"]) for c in recs if c["source"] == source], live).summary()
    if args.api:
        result["api_usage"] = {"model": recs[0].get("model"), "total_cost_usd": round(sum(c.get("cost_usd", 0.0) for c in recs), 5),
                               "cost_per_1k_docs_usd": round(1000 * sum(c.get("cost_usd", 0.0) for c in recs) / len(recs), 3),
                               "median_latency_s": sorted(c["latency_s"] for c in recs)[len(recs) // 2],
                               "total_tokens": sum(c.get("prompt_tokens", 0) + c.get("completion_tokens", 0) for c in recs)}
    (OUT / f"{args.name}-{args.split}.metrics.json").write_text(json.dumps(result, indent=1))
    print(json.dumps(result, indent=1))


if __name__ == "__main__":
    main()
