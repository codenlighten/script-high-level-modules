#!/usr/bin/env python3
"""The paper as a PDF, from the same two files the repository checks.

    python3 tools/paper_pdf.py            writes paper/paper.pdf

paper/paper.md is the prose and paper/tables.md is generated from results.json,
so the PDF is those two, in that order, and nothing typed in between. A PDF made
any other way is a copy of the paper as it was on the day someone made it, which
is the thing tools/paper.js exists to prevent.

Needs python-markdown and WeasyPrint.
"""

import pathlib
import re
import subprocess

import markdown
from weasyprint import HTML

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAPER = ROOT / "paper" / "paper.md"
TABLES = ROOT / "paper" / "tables.md"
OUT = ROOT / "paper" / "paper.pdf"
AUTHOR = "codenlighten"

CSS = """
@page {
  size: A4;
  margin: 22mm 20mm 24mm 20mm;
  @bottom-center { content: counter(page); font: 9pt 'DejaVu Serif', serif; color: #555; }
}
body { font: 10.5pt/1.45 'DejaVu Serif', 'Liberation Serif', serif; color: #111; }
h1 { font-size: 19pt; line-height: 1.2; margin: 0 0 4pt; }
h1 + h3 { font-weight: normal; font-style: italic; margin-top: 0; color: #333; }
h2 { font-size: 13.5pt; margin: 18pt 0 6pt; page-break-after: avoid; }
h3 { font-size: 11.5pt; margin: 14pt 0 4pt; page-break-after: avoid; }
p, li { text-align: left; hyphens: auto; }
code { font: 8.8pt 'DejaVu Sans Mono', monospace; }
pre {
  font: 8.2pt/1.35 'DejaVu Sans Mono', monospace;
  background: #f5f5f3; border-left: 2pt solid #bbb;
  padding: 6pt 8pt; white-space: pre-wrap; word-break: break-all;
  page-break-inside: avoid;
}
pre code { font-size: inherit; }
table { border-collapse: collapse; margin: 8pt 0; font-size: 9pt; }
tr { page-break-inside: avoid; }
thead { display: table-header-group; }
th, td { border-bottom: 0.5pt solid #ccc; padding: 2.5pt 6pt; vertical-align: top; }
th { border-bottom: 1pt solid #666; text-align: left; }
td:not(:first-child) { word-break: break-word; }
blockquote { margin: 8pt 16pt; color: #333; font-style: italic; }
hr { border: 0; border-top: 0.5pt solid #bbb; margin: 14pt 0; }
.appendix { page-break-before: always; }
.meta { color: #555; font-size: 9pt; margin-bottom: 12pt; }
"""


def commit():
    """The commit the PDF was built from — and whether the tree had moved on from it.

    "Built from commit X" on a PDF made from uncommitted files would name a
    version of the paper that does not say what the PDF says.
    """
    try:
        head = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, text=True).strip()
        dirty = subprocess.check_output(
            ["git", "status", "--porcelain", "--", "paper", "results.json", "src", "tools"], cwd=ROOT, text=True
        ).strip()
        return f"{head} with uncommitted changes" if dirty else head
    except Exception:
        return "an unknown commit"


def render(text):
    # Markdown table cells escape a pipe as \| — python-markdown leaves the
    # backslash in, so take it out before the text is rendered.
    text = text.replace("\\|", "&#124;")
    return markdown.markdown(text, extensions=["tables", "fenced_code", "sane_lists"])


def main():
    paper = PAPER.read_text(encoding="utf-8")
    tables = TABLES.read_text(encoding="utf-8")
    # The tables file carries HTML comments saying it is generated; the PDF
    # states its provenance once, in its own words.
    tables = re.sub(r"<!--.*?-->", "", tables, flags=re.S)
    tables = tables.replace("# Tables", "# Appendix — the tables, generated from results.json", 1)

    title = paper.splitlines()[0].lstrip("# ").strip()
    body = render(paper)
    meta = f'<p class="meta">{AUTHOR} · built from commit {commit()} · tables generated from results.json</p>'
    body = body.replace("</h3>", "</h3>" + meta, 1)

    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>{title}</title>
<meta name="author" content="{AUTHOR}">
<meta name="description" content="BLS12-381, Groth16 verification, and an inverted cryptographic cost model">
<style>{CSS}</style></head>
<body>{body}<div class="appendix">{render(tables)}</div></body></html>"""
    HTML(string=html, base_url=str(ROOT / "paper")).write_pdf(OUT)
    print(f"paper: wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
