"""Phase 11: turn extractor output into graph updates, without ever touching curated data.

Flow: report text -> chunks -> extractor (any callable returning JSON) -> schema validation -> entity linking
(exact name or alias in the graph, then optional vector similarity) -> upsert.

Separation of curated and extracted knowledge:
* curated nodes (ATT&CK, CAPEC, CWE, NVD, KEV) are only ever MATCHed, never modified, and get no new properties;
* entities with no match become `:ProvisionalEntity` nodes (no `:Searchable` / `:Reference` label, so the existing
  indexes, embeddings and MCP tools do not see them);
* everything a report says hangs off a `:Report` node: `(:Report)-[:MENTIONS]->(node)` and `(:Report)-[:ASSERTS_TECHNIQUE]->(:Technique)`;
* relations between two entities become `(a)-[:ASSERTED {relation, report_id, confidence}]->(b)`, a different relationship
  type from the curated `USES`, so a query can never mistake a report's claim for ATT&CK's.
A report can be removed again with `drop_report`."""

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from neo4j import Driver

from redstring_cti.extractor.schema import SYSTEM_PROMPTS, TASK_FULL, Extraction
from redstring_cti.graph.ids import key_expr

Extractor = Callable[[str, str], str]  # (task, chunk text) -> raw model output
VECTOR_THRESHOLD = 0.85
_LUCENE = re.compile(r'([+\-&|!(){}\[\]^"~*?:\\/])')
LABELS_FOR = {"THREAT_ACTOR": ["Group"], "MALWARE": ["Software"], "TOOL": ["Software"], "CAMPAIGN": ["Campaign"], "CVE": ["CVE"], "INFRASTRUCTURE": []}


@dataclass(frozen=True)
class Link:
    node_id: str  # curated id (G0016) or provisional uid
    label: str
    curated: bool
    method: str  # exact | alias | vector | cve | new
    confidence: float


@dataclass
class IngestReport:
    report_id: str
    chunks: int = 0
    invalid_chunks: int = 0
    linked: dict[str, Link] = field(default_factory=dict)  # surface text -> link
    techniques: dict[str, int] = field(default_factory=dict)  # attack id -> chunks asserting it
    unknown_techniques: list[str] = field(default_factory=list)
    asserted: list[tuple[str, str, str]] = field(default_factory=list)
    skipped_relations: int = 0
    pruned_entities: int = 0

    def summary(self) -> str:
        curated = [(t, ln) for t, ln in self.linked.items() if ln.curated]
        new = [(t, ln) for t, ln in self.linked.items() if not ln.curated]
        lines = [f"report {self.report_id}: {self.chunks} chunks ({self.invalid_chunks} unusable output, {self.pruned_entities} entities pruned: not in the text or not a CVE id)",
                 f"  linked to curated nodes: {len(curated)}"] + [f"    {t!r} -> {ln.node_id} ({ln.method}, {ln.confidence:.2f})" for t, ln in curated]
        lines += [f"  provisional (not in the graph): {len(new)}"] + [f"    {t!r} -> {ln.node_id}" for t, ln in new]
        lines += [f"  techniques asserted: {', '.join(f'{k} (x{v})' for k, v in sorted(self.techniques.items())) or 'none'}"]
        if self.unknown_techniques:
            lines.append(f"  ids the model produced that are not ATT&CK techniques (dropped): {', '.join(self.unknown_techniques)}")
        lines.append(f"  relations stored: {len(self.asserted)} ({self.skipped_relations} skipped: an endpoint was not an extracted entity or technique)")
        return "\n".join(lines)


# ---------------------------------------------------------------------------- text and chunks
def chunk_text(text: str, max_chars: int = 1400) -> list[str]:
    """Paragraph-aware chunks of at most `max_chars` (the size the extractor was trained on).
    A single sentence longer than the limit is cut at word boundaries so no input is lost."""
    pieces: list[str] = []
    for para in re.split(r"\n\s*\n", text.strip()):
        para = para.strip()
        if not para:
            continue
        for sent in re.split(r"(?<=[.!?])\s+", para):
            while len(sent) > max_chars:
                cut = sent.rfind(" ", 0, max_chars)
                cut = cut if cut > 0 else max_chars
                pieces.append(sent[:cut])
                sent = sent[cut:].lstrip()
            if sent:
                pieces.append(sent)
    chunks: list[str] = []
    current = ""
    for piece in pieces:
        if current and len(current) + 1 + len(piece) > max_chars:
            chunks.append(current)
            current = piece
        else:
            current = f"{current} {piece}".strip()
    if current:
        chunks.append(current)
    return chunks


def report_id_for(source: str) -> str:
    return "report-" + hashlib.sha1(source.encode()).hexdigest()[:12]


def norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", name.lower()).strip()


# ---------------------------------------------------------------------------- linking
def link_entity(driver: Driver, text: str, etype: str, embedder: Callable[[str], list[float]] | None = None) -> Link:
    """Curated match if one exists, else a provisional uid. Never creates anything."""
    if etype == "CVE":
        rows, _, _ = driver.execute_query("MATCH (v:CVE {cve_id: $id}) RETURN v.cve_id AS id", id=text.upper())
        if rows:
            return Link(rows[0]["id"], "CVE", True, "cve", 1.0)
        return Link(provisional_uid(etype, text), "ProvisionalEntity", False, "new", 0.5)
    labels = LABELS_FOR.get(etype, [])
    if labels:
        escaped = _LUCENE.sub(r"\\\1", text.strip())
        rows, _, _ = driver.execute_query(
            "CALL db.index.fulltext.queryNodes('text_search', $q, {limit: 10}) YIELD node, score "
            "WITH node, score WHERE any(l IN labels(node) WHERE l IN $labels) "
            "RETURN " + key_expr("node") + " AS id, [l IN labels(node) WHERE l IN $labels][0] AS label, node.name AS name, "
            "coalesce(node.aliases, []) AS aliases, score",
            q=f'"{escaped}"', labels=labels,
        )
        target = norm(text)
        matches = [(r["id"], r["label"], "exact" if norm(r["name"] or "") == target else "alias") for r in rows
                   if norm(r["name"] or "") == target or any(norm(a) == target for a in r["aliases"])]
        if matches:
            ids = {m[0] for m in matches}
            if len(ids) == 1:  # an ambiguous name is not linked: guessing would corrupt curated knowledge
                node_id, label, how = matches[0]
                return Link(node_id, label, True, how, 1.0 if how == "exact" else 0.95)
        elif embedder is not None:
            hit, _, _ = driver.execute_query(
                "CALL db.index.vector.queryNodes('ref_vec', 5, $v) YIELD node, score "
                "WHERE any(l IN labels(node) WHERE l IN $labels) "
                "RETURN " + key_expr("node") + " AS id, [l IN labels(node) WHERE l IN $labels][0] AS label, score ORDER BY score DESC LIMIT 1",
                v=embedder(text), labels=labels,
            )
            if hit and float(hit[0]["score"]) >= VECTOR_THRESHOLD:
                return Link(hit[0]["id"], hit[0]["label"], True, "vector", round(float(hit[0]["score"]), 3))
    return Link(provisional_uid(etype, text), "ProvisionalEntity", False, "new", 0.5)


def provisional_uid(etype: str, text: str) -> str:
    return f"prov:{etype.lower()}:{norm(text).replace(' ', '-')}"


# ---------------------------------------------------------------------------- extraction over chunks
_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def prune(parsed: Extraction, chunk: str) -> tuple[Extraction, int]:
    """Drop what the chunk cannot support: entities whose text is not in the chunk (the prompt says to copy it
    exactly), and CVE entities that are not CVE ids. Relations that lose an endpoint go with them."""
    kept = [e for e in parsed.entities if e.text in chunk and (e.type != "CVE" or _CVE_ID.match(e.text))]
    names = {e.text for e in kept} | {t.attack_id for t in parsed.techniques}
    relations = None if parsed.relations is None else [r for r in parsed.relations if r.head in names and r.tail in names]
    return Extraction(entities=kept, techniques=parsed.techniques, relations=relations), len(parsed.entities) - len(kept)


def extract_report(text: str, extractor: Extractor, task: str = TASK_FULL) -> tuple[list[Extraction], int, int, int]:
    """Run the extractor over every chunk; returns (extractions kept after salvage and pruning, chunk count, count with nothing usable, pruned entity count)."""
    from redstring_cti.extractor import metrics

    assert task in SYSTEM_PROMPTS
    chunks = chunk_text(text)
    out: list[Extraction] = []
    pruned = 0
    for chunk in chunks:
        raw = extractor(task, chunk)
        parsed = metrics.parse(raw) or metrics.salvage(raw)
        if parsed is not None:
            clean, dropped = prune(parsed, chunk)
            out.append(clean)
            pruned += dropped
    return out, len(chunks), len(chunks) - len(out), pruned


# ---------------------------------------------------------------------------- upsert
def ingest(driver: Driver, report_id: str, title: str, source: str, text: str, extractions: list[Extraction], chunks: int, invalid: int,
           live_techniques: set[str], embedder: Callable[[str], list[float]] | None = None, dry_run: bool = False, pruned: int = 0) -> IngestReport:
    rep = IngestReport(report_id=report_id, chunks=chunks, invalid_chunks=invalid, pruned_entities=pruned)
    mentions: dict[str, int] = {}
    types: dict[str, str] = {}
    for ex in extractions:
        for ent in ex.entities:
            key = ent.text
            types.setdefault(key, ent.type)
            mentions[key] = mentions.get(key, 0) + 1
            if key not in rep.linked:
                rep.linked[key] = link_entity(driver, ent.text, ent.type, embedder)
        for tech in ex.techniques:
            if tech.attack_id in live_techniques:
                rep.techniques[tech.attack_id] = rep.techniques.get(tech.attack_id, 0) + 1
            elif tech.attack_id not in rep.unknown_techniques:
                rep.unknown_techniques.append(tech.attack_id)
        for rel in ex.relations or []:
            if rel.head not in rep.linked or not (rel.tail in rep.techniques or rel.tail in rep.linked):
                rep.skipped_relations += 1
                continue
            rep.asserted.append((rel.head, rel.relation, rel.tail))
    rep.asserted = sorted(set(rep.asserted))
    if dry_run:
        return rep

    now = datetime.now(UTC).isoformat(timespec="seconds")
    with driver.session() as session:
        session.run("MERGE (r:Report {report_id: $id}) SET r.title = $title, r.source = $source, r.ingested_at = $now, r.chars = $chars",
                    id=report_id, title=title, source=source, now=now, chars=len(text))
        for surface, link in rep.linked.items():
            if link.curated:
                label, prop, _ = _ref(link)
                session.run(f"MATCH (r:Report {{report_id: $rid}}), (n:{label} {{{prop}: $id}}) "
                            "MERGE (r)-[m:MENTIONS]->(n) SET m.count = $count, m.method = $method, m.confidence = $conf, m.surface = $surface",
                            rid=report_id, id=link.node_id, count=mentions[surface], method=link.method, conf=link.confidence, surface=surface)
            else:
                session.run("MERGE (p:ProvisionalEntity {uid: $uid}) ON CREATE SET p.name = $name, p.entity_type = $etype, p.first_seen_report = $rid, p.created_at = $now "
                            "WITH p MATCH (r:Report {report_id: $rid}) "
                            "MERGE (r)-[m:MENTIONS]->(p) SET m.count = $count, m.method = 'new', m.confidence = 0.5, m.surface = $surface",
                            uid=link.node_id, name=surface, etype=types[surface], rid=report_id, now=now, count=mentions[surface], surface=surface)
        for tech_id, count in rep.techniques.items():
            session.run("MATCH (r:Report {report_id: $rid}), (t:Technique {attack_id: $tid}) MERGE (r)-[a:ASSERTS_TECHNIQUE]->(t) SET a.chunks = $count",
                        rid=report_id, tid=tech_id, count=count)
        for head, relation, tail in rep.asserted:
            h = rep.linked[head]
            hl, hp, hid = _ref(h)
            if tail in rep.techniques:
                tl, tp, tid, conf_tail = "Technique", "attack_id", tail, 1.0
            else:
                t = rep.linked[tail]
                (tl, tp, tid), conf_tail = _ref(t), t.confidence
            session.run(f"MATCH (h:{hl} {{{hp}: $hid}}), (t:{tl} {{{tp}: $tid}}) "
                        "MERGE (h)-[a:ASSERTED {relation: $rel, report_id: $rid}]->(t) SET a.confidence = $conf, a.source = 'report'",
                        hid=hid, tid=tid, rel=relation, rid=report_id, conf=min(h.confidence, conf_tail))
    return rep


def _ref(link: Link) -> tuple[str, str, str]:
    """(label, key property, key) that MATCHes the node a link points at."""
    if not link.curated:
        return "ProvisionalEntity", "uid", link.node_id
    return link.label, "cve_id" if link.label == "CVE" else "attack_id", link.node_id


def drop_report(driver: Driver, report_id: str) -> dict[str, int]:
    """Remove a report, its ASSERTED edges, and any provisional entity that no other report mentions."""
    with driver.session() as session:
        asserted = session.run("MATCH ()-[a:ASSERTED {report_id: $rid}]->() DELETE a RETURN count(a) AS n", rid=report_id).single()
        orphans = session.run("MATCH (r:Report {report_id: $rid})-[:MENTIONS]->(p:ProvisionalEntity) WHERE NOT exists { MATCH (o:Report)-[:MENTIONS]->(p) WHERE o.report_id <> $rid } "
                              "DETACH DELETE p RETURN count(p) AS n", rid=report_id).single()
        reports = session.run("MATCH (r:Report {report_id: $rid}) DETACH DELETE r RETURN count(r) AS n", rid=report_id).single()
    return {"asserted_edges": asserted["n"] if asserted else 0, "provisional_entities": orphans["n"] if orphans else 0, "reports": reports["n"] if reports else 0}
