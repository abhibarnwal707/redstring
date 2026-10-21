"""Compare embedding models on retrieval tasks built from the real graph.

Task A: ATT&CK procedure sentence  -> technique        (400 real USES descriptions)
Task B: CVE description            -> its Primary CWE   (400 real CVEs)
Task C: 20 hand-written analyst questions over all non-CVE nodes (small, so noisy)
Task D: alias lookup, e.g. 'Cozy Bear' -> APT29 (200 real aliases of groups and software)

Usage: uv run python evals/runners/compare_embedders.py [--out evals/results/embedding_model_choice.md]
"""

import argparse
import random
import time
from dataclasses import dataclass
from typing import Any

import numpy as np
import torch
from sentence_transformers import SentenceTransformer

from redstring_cti.graph.embeddings import embedding_text
from redstring_cti.graph.loader import get_driver

SEED = 42
N_A = N_B = 400
N_D = 200
MAX_SEQ = 256


@dataclass(frozen=True)
class Spec:
    name: str
    query_prefix: str = ""
    doc_prefix: str = ""
    with_aliases: bool = True


BGE_Q = "Represent this sentence for searching relevant passages: "
SPECS = [
    Spec("BAAI/bge-small-en-v1.5", query_prefix=BGE_Q),
    Spec("BAAI/bge-small-en-v1.5", query_prefix=BGE_Q, with_aliases=False),
    Spec("BAAI/bge-small-en-v1.5"),
    Spec("sentence-transformers/all-MiniLM-L6-v2"),
    Spec("thenlper/gte-small"),
    Spec("intfloat/e5-small-v2", query_prefix="query: ", doc_prefix="passage: "),
    Spec("BAAI/bge-base-en-v1.5", query_prefix=BGE_Q),
]

# (question, uid prefixes that count as correct, node names that count as correct)
TASK_C: list[tuple[str, list[str], list[str]]] = [
    ("How do attackers abuse scheduled tasks for persistence?", ["Technique:T1053"], []),
    ("adversaries send emails with malicious attachments to gain access", ["Technique:T1566"], []),
    ("stealing credentials from the memory of the LSASS process", ["Technique:T1003"], []),
    ("attackers use PowerShell to execute commands", ["Technique:T1059.001"], []),
    ("encrypting victim files to demand a ransom", ["Technique:T1486"], []),
    ("SQL injection through unsanitized user input", ["CWE:CWE-89", "CAPEC:CAPEC-66"], []),
    ("writing past the end of a buffer in memory", ["CWE:CWE-787", "CWE:CWE-120", "CWE:CWE-121", "CWE:CWE-122", "CWE:CWE-119"], []),
    ("cross-site scripting where script runs in the victim's browser", ["CWE:CWE-79", "CAPEC:CAPEC-63", "CAPEC:CAPEC-591", "CAPEC:CAPEC-592"], []),
    ("tricking people into clicking a malicious link in a message", ["Technique:T1566.002", "CAPEC:CAPEC-98", "CAPEC:CAPEC-163"], []),
    ("Cozy Bear", ["Group:G0016"], []),
    ("Russian SVR espionage group also called Midnight Blizzard", ["Group:G0016"], []),
    ("North Korean state-sponsored hackers stealing cryptocurrency", [], ["Lazarus Group", "APT38", "Andariel"]),
    ("logging in with stolen valid accounts", ["Technique:T1078"], []),
    ("deleting event logs to hide intrusion activity", ["Technique:T1070"], []),
    ("injecting code into the memory of another running process", ["Technique:T1055"], []),
    ("sending stolen data out over the network", ["Technique:T1041", "Technique:T1048", "Technique:T1567"], []),
    ("hard-coded or default passwords in software", ["CWE:CWE-798", "CWE:CWE-259", "CWE:CWE-1392", "CWE:CWE-1393"], []),
    ("path traversal reading files outside the intended directory", ["CWE:CWE-22", "CAPEC:CAPEC-126"], []),
    ("server makes requests to internal systems on an attacker's behalf", ["CWE:CWE-918", "CAPEC:CAPEC-664"], []),
    ("training users to spot phishing as a defensive measure", [], ["User Training"]),
]


def fetch(driver: Any, cypher: str, **params: Any) -> list[dict[str, Any]]:
    with driver.session() as session:
        return [dict(r) for r in session.run(cypher, **params)]


def load_data(driver: Any) -> dict[str, Any]:
    nodes = fetch(
        driver,
        """MATCH (n:Searchable) WHERE NOT n:CVE
           RETURN n.uid AS uid, [l IN labels(n) WHERE l <> 'Searchable'][0] AS label, n.name AS name,
                  n.description AS description, coalesce(n.aliases, []) AS aliases""",
    )
    rng = random.Random(SEED)
    edges = fetch(
        driver,
        """MATCH (a)-[u:USES]->(t:Technique) WHERE (a:Group OR a:Software OR a:Campaign)
             AND size(u.description) > 40 RETURN t.uid AS gold, u.description AS text""",
    )
    cves = fetch(
        driver,
        """MATCH (v:CVE)-[h:HAS_WEAKNESS {type: 'Primary'}]->(w:CWE) WHERE size(v.description) > 40
           RETURN w.uid AS gold, v.description AS text""",
    )
    owners: dict[str, set[str]] = {}
    for n in nodes:
        if n["label"] in ("Group", "Software"):
            for alias in n["aliases"]:
                if alias and alias.lower() != (n["name"] or "").lower():
                    owners.setdefault(alias, set()).add(n["uid"])
    unambiguous = sorted((a, next(iter(u))) for a, u in owners.items() if len(u) == 1)
    return {
        "nodes": nodes,
        "A": rng.sample(edges, N_A),
        "B": rng.sample(cves, N_B),
        "D": [{"text": a, "gold": u} for a, u in rng.sample(unambiguous, N_D)],
    }


def metrics(ranked: np.ndarray, gold_sets: list[set[int]]) -> dict[str, float]:
    """ranked: (n_queries, n_docs) doc indices sorted best-first."""
    r1 = r5 = r10 = mrr = 0.0
    for row, gold in zip(ranked, gold_sets, strict=True):
        ranks = [i for i, d in enumerate(row, start=1) if d in gold]
        first = ranks[0] if ranks else 10**9
        r1 += first <= 1
        r5 += first <= 5
        r10 += first <= 10
        mrr += 1.0 / first if first < 10**9 else 0.0
    n = len(gold_sets)
    return {"R@1": r1 / n, "R@5": r5 / n, "R@10": r10 / n, "MRR": mrr / n}


def evaluate(spec: Spec, data: dict[str, Any], device: str) -> dict[str, Any]:
    model = SentenceTransformer(spec.name, device=device)
    model.max_seq_length = MAX_SEQ

    def enc(texts: list[str]) -> np.ndarray:
        return model.encode(
            texts, batch_size=64, normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False
        )

    def search(queries: list[str], docs: list[str]) -> np.ndarray:
        q = enc([spec.query_prefix + t for t in queries])
        d = enc([spec.doc_prefix + t for t in docs])
        return np.argsort(-(q @ d.T), axis=1)

    nodes = data["nodes"]
    doc_text = {
        n["uid"]: embedding_text(n["label"], n["name"], n["description"], n["aliases"], with_aliases=spec.with_aliases)
        for n in nodes
    }
    out: dict[str, Any] = {"dim": model.get_sentence_embedding_dimension()}

    # Task A: pool = techniques
    pool = [n["uid"] for n in nodes if n["uid"].startswith("Technique:")]
    ranked = search([x["text"] for x in data["A"]], [doc_text[u] for u in pool])
    out["A"] = metrics(ranked, [{pool.index(x["gold"])} for x in data["A"]])

    # Task B: pool = CWE
    pool = [n["uid"] for n in nodes if n["uid"].startswith("CWE:")]
    ranked = search([x["text"] for x in data["B"]], [doc_text[u] for u in pool])
    out["B"] = metrics(ranked, [{pool.index(x["gold"])} for x in data["B"]])

    # Task C: pool = all non-CVE nodes; time the document encoding for a throughput figure
    pool = [n["uid"] for n in nodes]
    names = {n["uid"]: (n["name"] or "").lower() for n in nodes}
    gold_sets: list[set[int]] = []
    for question, prefixes, wanted in TASK_C:
        gold = {
            i for i, u in enumerate(pool)
            if any(u.startswith(p) for p in prefixes) or names[u] in {w.lower() for w in wanted}
        }
        assert gold, f"no gold nodes found for: {question}"
        gold_sets.append(gold)
    t0 = time.perf_counter()
    d = enc([spec.doc_prefix + doc_text[u] for u in pool])
    docs_per_s = len(pool) / (time.perf_counter() - t0)
    q = enc([spec.query_prefix + t for t, _, _ in TASK_C])
    out["C"] = metrics(np.argsort(-(q @ d.T), axis=1), gold_sets)

    # Task D: alias lookup against the same document matrix (Group + Software nodes only)
    idx = {u: i for i, u in enumerate(pool)}
    keep = [i for i, u in enumerate(pool) if u.startswith(("Group:", "Software:"))]
    qd = enc([spec.query_prefix + x["text"] for x in data["D"]])
    sub = qd @ d[keep].T
    out["D"] = metrics(np.argsort(-sub, axis=1), [{keep.index(idx[x["gold"]])} for x in data["D"]])
    out["docs_per_s"] = docs_per_s
    if device == "mps":
        torch.mps.empty_cache()
    return out


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    device = "mps" if torch.backends.mps.is_available() else "cpu"
    driver = get_driver()
    try:
        data = load_data(driver)
    finally:
        driver.close()
    print(f"device={device}  corpus={len(data['nodes'])} non-CVE nodes  A={len(data['A'])} B={len(data['B'])} C={len(TASK_C)} D={len(data['D'])}")

    rows = []
    for spec in SPECS:
        label = spec.name.split("/")[-1]
        if "bge" in spec.name and not spec.query_prefix:
            label += " [no query prefix]"
        if not spec.with_aliases:
            label += " [no aliases]"
        t0 = time.perf_counter()
        res = evaluate(spec, data, device)
        rows.append((label, res))
        print(f"{label:48} done in {time.perf_counter() - t0:5.1f}s")

    lines = [
        "| Model | dim | A R@1 | A R@5 | A MRR | B R@5 | B R@10 | B MRR | C R@1 | C R@5 | D R@1 | D R@5 | docs/s |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for label, r in rows:
        lines.append(
            f"| {label} | {r['dim']} | {r['A']['R@1']:.3f} | {r['A']['R@5']:.3f} | {r['A']['MRR']:.3f} | "
            f"{r['B']['R@5']:.3f} | {r['B']['R@10']:.3f} | {r['B']['MRR']:.3f} | "
            f"{r['C']['R@1']:.2f} | {r['C']['R@5']:.2f} | {r['D']['R@1']:.3f} | {r['D']['R@5']:.3f} | "
            f"{r['docs_per_s']:.0f} |"
        )
    table = "\n".join(lines)
    print("\n" + table)
    if args.out:
        with open(args.out, "w") as f:
            f.write(table + "\n")


if __name__ == "__main__":
    main()
