"""Schema-derived multi-hop templates for `find_paths`.

A metapath is a route through the node *types* of the graph, e.g.
Group -USES-> Technique <-MAPS_TO- CAPEC -EXPLOITS-> CWE <-HAS_WEAKNESS- CVE.
Routes are enumerated from a fixed whitelist of relationships, and the Cypher built from them contains
only labels and relationship types from that whitelist plus one parameter (the start node), so no
model-written Cypher is involved. Hierarchy edges (CHILD_OF, SUBTECHNIQUE_OF) stay out of templates:
they are one-hop questions for `get_neighbors`.
"""

from dataclasses import dataclass

# (source label, relationship, target label)
SCHEMA_EDGES: tuple[tuple[str, str, str], ...] = (
    ("Group", "USES", "Technique"),
    ("Software", "USES", "Technique"),
    ("Campaign", "USES", "Technique"),
    ("Group", "USES", "Software"),
    ("Campaign", "USES", "Software"),
    ("Campaign", "ATTRIBUTED_TO", "Group"),
    ("Mitigation", "MITIGATES", "Technique"),
    ("Technique", "IN_TACTIC", "Tactic"),
    ("CAPEC", "MAPS_TO", "Technique"),
    ("CAPEC", "EXPLOITS", "CWE"),
    ("CVE", "HAS_WEAKNESS", "CWE"),
)
WEAKNESS_LEVEL_LABELS = frozenset({"CAPEC", "CWE"})
MAX_HOPS = 4


@dataclass(frozen=True)
class Step:
    rel: str
    forward: bool  # True: (current)-[rel]->(next); False: (current)<-[rel]-(next)


@dataclass(frozen=True)
class Metapath:
    labels: tuple[str, ...]
    steps: tuple[Step, ...]

    @property
    def hops(self) -> int:
        return len(self.steps)

    @property
    def weakness_level(self) -> bool:
        """True when the route passes through CAPEC or CWE: an association, not observed behaviour."""
        return bool(WEAKNESS_LEVEL_LABELS & set(self.labels[1:-1])) or bool(WEAKNESS_LEVEL_LABELS & {self.labels[0], self.labels[-1]})

    def describe(self) -> str:
        out = self.labels[0]
        for step, label in zip(self.steps, self.labels[1:], strict=True):
            out += f" -{step.rel}-> {label}" if step.forward else f" <-{step.rel}- {label}"
        return out


def _moves(label: str) -> list[tuple[str, Step]]:
    moves = []
    for src, rel, dst in SCHEMA_EDGES:
        if src == label:
            moves.append((dst, Step(rel, True)))
        if dst == label:
            moves.append((src, Step(rel, False)))
    return moves


def enumerate_metapaths(src: str, dst: str, max_hops: int = MAX_HOPS) -> list[Metapath]:
    """All simple routes from node type `src` to `dst` with at most `max_hops` relationships, shortest first."""
    if src == dst or max_hops < 1:
        return []
    found: list[Metapath] = []

    def walk(labels: tuple[str, ...], steps: tuple[Step, ...]) -> None:
        if len(steps) >= max_hops:
            return
        for nxt, step in _moves(labels[-1]):
            if nxt in labels:  # simple paths only: never revisit a node type
                continue
            if nxt == dst:
                found.append(Metapath((*labels, nxt), (*steps, step)))
            else:
                walk((*labels, nxt), (*steps, step))

    walk((src,), ())
    return sorted(found, key=lambda m: (m.hops, m.describe()))


_KEY = "coalesce({v}.attack_id, {v}.capec_id, {v}.cwe_id, {v}.cve_id)"
_LABEL = "[l IN labels({v}) WHERE NOT l IN ['Searchable', 'Reference']][0]"


def metapath_cypher(path: Metapath, *, kev_only: bool = False) -> str:
    """Parameterised Cypher for one route. Start node is `$uid`; use with LIMIT supplied by the caller."""
    parts = ["(n0:Searchable {uid: $uid})"]
    for i, (step, label) in enumerate(zip(path.steps, path.labels[1:], strict=True), start=1):
        rel = f"-[r{i}:{step.rel}]->" if step.forward else f"<-[r{i}:{step.rel}]-"
        parts.append(f"{rel}(n{i}:{label})")
    last = f"n{path.hops}"
    where = f" WHERE {last}.kev = true" if kev_only and path.labels[-1] == "CVE" else ""
    nodes = f"[{', '.join('{id: ' + _KEY.format(v=f'n{i}') + ', label: ' + _LABEL.format(v=f'n{i}') + ', name: n' + str(i) + '.name}' for i in range(path.hops + 1))}]"
    triples = f"[{', '.join('[' + _KEY.format(v=f'startNode(r{i})') + ', type(r' + str(i) + '), ' + _KEY.format(v=f'endNode(r{i})') + ']' for i in range(1, path.hops + 1))}]"
    return f"MATCH {''.join(parts)}{where} RETURN {nodes} AS nodes, {triples} AS triples"
