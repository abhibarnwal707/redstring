# Recovery: load the checkpoint saved by a training run whose evaluation crashed, evaluate it, push it to the Hub.
# Kaggle: GPU T4 x2, Internet ON; Add Input -> (1) the private dataset redstring-cti-finetune,
# (2) "Notebook Output Files" -> your failed train_qlora version. Secret HF_TOKEN. Then edit the cell below.

# %%
HF_REPO = "YOUR_HF_USERNAME/redstring-cti-extractor-qwen3-1.7b-lora"  # <- edit
DATA_DIR = "/kaggle/input/redstring-cti-finetune"                      # <- check
CKPT = "/kaggle/input/train-qlora/ckpt/checkpoint-518"                 # <- check in the right-hand file tree

# %%
# !pip install -q unsloth

# %%
from unsloth import FastLanguageModel  # unsloth must be imported before trl / transformers

import json

import torch
from datasets import load_dataset

load_kw = dict(max_seq_length=2048, load_in_4bit=True)
try:
    model, tok = FastLanguageModel.from_pretrained(CKPT, dtype=torch.float16, **load_kw)
except TypeError:
    model, tok = FastLanguageModel.from_pretrained(CKPT, torch_dtype=torch.float16, **load_kw)
print(type(model).__name__)

# %%
def prompt_of(messages):
    return tok.apply_chat_template(messages[:2], tokenize=False, add_generation_prompt=True, enable_thinking=False)


FastLanguageModel.for_inference(model)


def generate(messages):
    ids = tok(prompt_of(messages), return_tensors="pt").to("cuda")
    out = model.generate(**ids, max_new_tokens=700, do_sample=False)
    return tok.decode(out[0][ids["input_ids"].shape[1]:], skip_special_tokens=True).strip()


def parse(s):
    try:
        d = json.loads(s)
        ents = {(e["text"], e["type"]) for e in d["entities"]}
        techs = {t["attack_id"] for t in d["techniques"]}
        rels = {(r["head"], r["relation"], r["tail"]) for r in d.get("relations") or []}
        return ents, techs, rels
    except Exception:
        return None


def prf(pred, gold):
    tp = len(pred & gold)
    p, r = tp / len(pred) if pred else 0.0, tp / len(gold) if gold else 0.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


def micro(pairs):
    tp = sum(len(p & g) for p, g in pairs); np_ = sum(len(p) for p, _ in pairs); ng = sum(len(g) for _, g in pairs)
    p, r = tp / np_ if np_ else 0.0, tp / ng if ng else 0.0
    return round(p, 3), round(r, 3), round(2 * p * r / (p + r), 3) if p + r else 0.0


def evaluate(rows, label):
    valid, ent, tech, rel, bad = 0, [], [], [], []
    for row in rows:
        out = generate(row["messages"])
        gold = parse(row["messages"][2]["content"]); got = parse(out)
        if got is None:
            bad.append(out[:200]); got = (set(), set(), set())
        else:
            valid += 1
        ent.append((got[0], gold[0])); tech.append((got[1], gold[1]))
        if row["task"] == "full":
            rel.append((got[2], gold[2]))
    res = {"split": label, "n": len(rows), "json_valid": round(valid / len(rows), 3),
           "entity_PRF": micro(ent), "technique_PRF": micro(tech), "relation_PRF": micro(rel) if rel else None}
    print(res); [print("INVALID:", b) for b in bad[:3]]
    return res


val_raw = load_dataset("json", data_files={"validation": f"{DATA_DIR}/val.jsonl"})["validation"]
val_rows = [r for r in val_raw if len(r["messages"][1]["content"]) <= 3000]
print(len(val_rows), "of", len(val_raw), "validation rows scored")
results = [evaluate(val_rows, "validation")]
json.dump(results, open("/kaggle/working/validation_metrics.json", "w"), indent=1)

# %%
from kaggle_secrets import UserSecretsClient

token = UserSecretsClient().get_secret("HF_TOKEN")
model.push_to_hub(HF_REPO, token=token); tok.push_to_hub(HF_REPO, token=token)
print("pushed", HF_REPO)
