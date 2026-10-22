"""`make ingest-report URL=https://... [DRY=1]`: read a public threat report, extract, link, and upsert it into the graph."""

import argparse
import re
from html.parser import HTMLParser
from pathlib import Path

import httpx

from redstring_cti.config import ATTACK_VERSION, RAW_DIR
from redstring_cti.extractor import upsert
from redstring_cti.extractor.attack_ids import load_attack_ids
from redstring_cti.extractor.backends import HFExtractor, OllamaExtractor
from redstring_cti.graph.loader import get_driver

_SKIP = {"script", "style", "nav", "header", "footer", "aside", "form", "noscript", "svg"}
_BLOCK = {"p", "div", "br", "li", "h1", "h2", "h3", "h4", "h5", "tr", "section", "article", "pre"}


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.title = ""
        self._skip = 0
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIP:
            self._skip += 1
        self._in_title = tag == "title"
        if tag in _BLOCK:
            self.parts.append("\n\n" if tag.startswith("h") or tag == "p" else "\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP and self._skip:
            self._skip -= 1
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()
        elif not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> tuple[str, str]:
    """(title, readable text) from an HTML page: navigation, scripts and footers are dropped."""
    parser = _Text()
    parser.feed(html)
    text = re.sub(r"[ \t\r\f\v]+", " ", "".join(parser.parts))
    text = re.sub(r"\n[ \t]+", "\n", text)
    return parser.title, re.sub(r"\n{3,}", "\n\n", text).strip()


def load_source(source: str) -> tuple[str, str]:
    if source.startswith(("http://", "https://")):
        resp = httpx.get(source, follow_redirects=True, timeout=30.0, headers={"User-Agent": "RedString-CTI research (github.com/abhibarnwal707/redstring)"})
        resp.raise_for_status()
        return html_to_text(resp.text) if "html" in resp.headers.get("content-type", "") else (source, resp.text)
    path = Path(source)
    return path.name, path.read_text()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source", help="URL or local text file")
    ap.add_argument("--extractor", choices=["ollama", "hf"], default="ollama")
    ap.add_argument("--constrain", action="store_true", help="hf only: schema-constrained decoding")
    ap.add_argument("--dry-run", action="store_true", help="extract and link but write nothing")
    ap.add_argument("--drop", action="store_true", help="remove this report (and provisional entities only it mentioned) instead")
    ap.add_argument("--max-chunks", type=int, default=0, help="stop after this many chunks (for a quick look)")
    args = ap.parse_args()

    report_id = upsert.report_id_for(args.source)
    driver = get_driver()
    if args.drop:
        print(upsert.drop_report(driver, report_id))
        return
    title, text = load_source(args.source)
    extractor = HFExtractor(constrain=args.constrain) if args.extractor == "hf" else OllamaExtractor()
    if args.max_chunks:
        chunks = upsert.chunk_text(text)[: args.max_chunks]
        text = "\n\n".join(chunks)
    extractions, n_chunks, invalid, pruned = upsert.extract_report(text, extractor)
    live = load_attack_ids(RAW_DIR / f"enterprise-attack-{ATTACK_VERSION}.json").live
    report = upsert.ingest(driver, report_id, title or args.source, args.source, text, extractions, n_chunks, invalid, live, dry_run=args.dry_run, pruned=pruned)
    print(("DRY RUN, nothing written\n" if args.dry_run else "") + report.summary())


if __name__ == "__main__":
    main()
