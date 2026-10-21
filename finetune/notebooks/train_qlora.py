# Phase 9: QLoRA fine-tune of Qwen3-1.7B for CTI extraction. Written as percent-cells; `make kaggle-notebook` turns it
# into train_qlora.ipynb. NOT RUN YET (needs a Kaggle GPU): start with DEBUG = True.

# %% [markdown]
# # RedString-CTI extractor: QLoRA on Qwen3-1.7B
# Kaggle settings: Accelerator GPU T4 x2 (or P100), Internet ON, attach the private dataset `redstring-cti-finetune`,
# add Kaggle Secret `HF_TOKEN` (write token). Run with DEBUG = True first, then DEBUG = False via Save & Run All (Commit).

# %%
DEBUG = True  # True: 200 examples, 50 steps. False: the full run.
HF_REPO = "YOUR_HF_USERNAME/redstring-cti-extractor-qwen3-1.7b-lora"  # <- edit
DATA_DIR = "/kaggle/input/redstring-cti-finetune"  # <- check the folder name in the right-hand panel
EPOCHS, LR, RANK, SEED = 2, 2e-4, 16, 42

# %%
# !pip install -q unsloth

# %%
import json

from datasets import load_dataset
from trl import SFTConfig, SFTTrainer
from unsloth import FastLanguageModel
from unsloth.chat_templates import train_on_responses_only

model, tok = FastLanguageModel.from_pretrained("unsloth/Qwen3-1.7B-unsloth-bnb-4bit", max_seq_length=2048, load_in_4bit=True)
model = FastLanguageModel.get_peft_model(
    model, r=RANK, lora_alpha=2 * RANK, lora_dropout=0, random_state=SEED,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    use_gradient_checkpointing="unsloth",
)

# %% [markdown]
# ## Data
# The prompt is rendered exactly as it will be at inference (`add_generation_prompt=True, enable_thinking=False`, which
# ends in an empty think block). The target and `<|im_end|>` are appended, so training and inference see the same prefix.

# %%
RESPONSE_PART = "<|im_start|>assistant\n<think>\n\n</think>\n\n"


def prompt_of(messages):
    return tok.apply_chat_template(messages[:2], tokenize=False, add_generation_prompt=True, enable_thinking=False)


def to_text(ex):
    return {"text": prompt_of(ex["messages"]) + ex["messages"][2]["content"] + "<|im_end|>\n"}


raw = load_dataset("json", data_files={"train": f"{DATA_DIR}/train.jsonl", "validation": f"{DATA_DIR}/val.jsonl"})
train_raw, val_raw = raw["train"], raw["validation"]
if DEBUG:
    train_raw, val_raw = train_raw.shuffle(seed=SEED).select(range(200)), val_raw.select(range(40))
train_ds, val_ds = train_raw.map(to_text), val_raw.map(to_text)
assert RESPONSE_PART in train_ds[0]["text"], "response marker not found: check the chat template"
print(len(train_ds), len(val_ds)); print(train_ds[0]["text"][-400:])

# %%
trainer = SFTTrainer(
    model=model, tokenizer=tok, train_dataset=train_ds, eval_dataset=val_ds,
    args=SFTConfig(
        dataset_text_field="text", max_seq_length=2048, per_device_train_batch_size=4, gradient_accumulation_steps=4,
        num_train_epochs=EPOCHS, max_steps=50 if DEBUG else -1, learning_rate=LR, warmup_ratio=0.03,
        fp16=True, bf16=False,  # T4 / P100 have no bf16
        logging_steps=5 if DEBUG else 20, eval_strategy="steps", eval_steps=25 if DEBUG else 100,
        save_steps=25 if DEBUG else 100, save_total_limit=2, output_dir="/kaggle/working/ckpt",
        report_to="none", seed=SEED,
    ),
)
trainer = train_on_responses_only(trainer, instruction_part="<|im_start|>user\n", response_part=RESPONSE_PART)
trainer.train()  # after a timeout: trainer.train(resume_from_checkpoint=True)

# %% [markdown]
# ## Validation F1 (the number Phase 9 must record)
# Greedy decoding on the validation set; JSON validity, entity F1 (exact text + type), technique F1 (ids).

# %%
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


val_rows = list(val_raw)
results = [evaluate(val_rows, "validation")]
json.dump(results, open("/kaggle/working/validation_metrics.json", "w"), indent=1)

# %% [markdown]
# ## Save: adapter to the Hub (full run only)

# %%
if not DEBUG:
    from kaggle_secrets import UserSecretsClient
    token = UserSecretsClient().get_secret("HF_TOKEN")
    model.push_to_hub(HF_REPO, token=token); tok.push_to_hub(HF_REPO, token=token)
    print("pushed", HF_REPO)
else:
    print("DEBUG run: loss should fall and JSON should mostly parse; nothing was pushed.")
