"""Ways to run the fine-tuned extractor: a local Ollama server (the deployment path) or the Hub adapter via transformers."""

from typing import Any

import httpx

from redstring_cti.extractor.schema import SYSTEM_PROMPTS

DEFAULT_ADAPTER = "abhibarnwal707/redstring-cti-extractor-qwen3-1.7b-lora-v2"
BASE_MODEL = "Qwen/Qwen3-1.7B"


class OllamaExtractor:
    """Calls an Ollama server: `ollama create redstring-extractor -f Modelfile` must have been run (Phase 11 step 1)."""

    def __init__(self, model: str = "redstring-extractor", url: str = "http://localhost:11434", client: httpx.Client | None = None) -> None:
        self.model, self.url = model, url.rstrip("/")
        self._client = client or httpx.Client(timeout=httpx.Timeout(120.0, connect=5.0))

    def __call__(self, task: str, chunk: str) -> str:
        resp = self._client.post(f"{self.url}/api/chat", json={
            "model": self.model, "stream": False, "think": False, "options": {"temperature": 0, "num_predict": 700},
            "messages": [{"role": "system", "content": SYSTEM_PROMPTS[task]}, {"role": "user", "content": chunk}],
        })
        resp.raise_for_status()
        return str(resp.json()["message"]["content"]).strip()


class HFExtractor:
    """The Hub adapter on the 16-bit base model (Apple GPU if available). Slower to start than Ollama, no conversion needed."""

    def __init__(self, adapter: str = DEFAULT_ADAPTER, constrain: bool = False) -> None:
        import torch
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer

        self._torch = torch
        self.device = "mps" if torch.backends.mps.is_available() else "cpu"
        self.tok: Any = AutoTokenizer.from_pretrained(BASE_MODEL)
        base: Any = AutoModelForCausalLM.from_pretrained(BASE_MODEL, dtype=torch.float16 if self.device == "mps" else torch.float32).to(self.device)  # type: ignore[arg-type]
        self.model: Any = PeftModel.from_pretrained(base, adapter).eval()  # type: ignore[arg-type]
        self.constrain = constrain
        if constrain:
            import transformers
            import transformers.tokenization_utils as tu  # type: ignore[import-not-found]

            if not hasattr(tu, "PreTrainedTokenizerBase"):  # lm-format-enforcer 0.11 predates transformers 5
                tu.PreTrainedTokenizerBase = transformers.PreTrainedTokenizerBase
            from lmformatenforcer.integrations.transformers import (
                build_token_enforcer_tokenizer_data,
            )

            from redstring_cti.config import ATTACK_VERSION, RAW_DIR
            from redstring_cti.extractor.attack_ids import load_attack_ids

            self._token_data = build_token_enforcer_tokenizer_data(self.tok)
            self._live = load_attack_ids(RAW_DIR / f"enterprise-attack-{ATTACK_VERSION}.json").live

    def __call__(self, task: str, chunk: str) -> str:
        prompt = self.tok.apply_chat_template([{"role": "system", "content": SYSTEM_PROMPTS[task]}, {"role": "user", "content": chunk}],
                                              tokenize=False, add_generation_prompt=True, enable_thinking=False)
        enc = self.tok(prompt, return_tensors="pt").to(self.device)
        extra: dict[str, Any] = {}
        if self.constrain:
            from lmformatenforcer import JsonSchemaParser
            from lmformatenforcer.integrations.transformers import (
                build_transformers_prefix_allowed_tokens_fn,
            )

            from redstring_cti.extractor.constrain import extraction_schema

            extra["prefix_allowed_tokens_fn"] = build_transformers_prefix_allowed_tokens_fn(self._token_data, JsonSchemaParser(extraction_schema(task, self._live)))
        with self._torch.no_grad():
            out = self.model.generate(**enc, max_new_tokens=700, do_sample=False, **extra)
        return str(self.tok.decode(out[0][enc["input_ids"].shape[1]:], skip_special_tokens=True)).strip()
