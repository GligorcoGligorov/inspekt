#!/usr/bin/env python3
"""Evaluate Inspekt against a labelled corpus and gate on regressions.

Examples
--------
Sample corpus shipped with the repo:

    python3 eval/evaluate.py --labels testdata/labels.csv

Public corpora (see docs/WEEKEND_PLAN.md, step 4):

    python3 eval/evaluate.py --ham data/ham --phish data/phish \
        --min-recall 0.80 --max-fpr 0.02 --out eval/report

The scanner is invoked through the CLI in JSONL mode, in batches, so the
evaluation runs offline and needs nothing but a Go toolchain.
Exit code 1 means a quality gate failed, which is what CI keys on.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from metrics import confusion, signal_counts, split_of  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
BATCH = 200


def load_labels(args) -> list[tuple[Path, str, str]]:
    """Returns (path, label, split) per message."""
    items: list[tuple[Path, str, str]] = []
    if args.labels:
        base = Path(args.labels).parent
        with open(args.labels, newline="") as f:
            for row in csv.DictReader(f):
                items.append((base / row["file"], row["label"], split_of(row["file"])))
    for d, label in ((args.ham, "ham"), (args.phish, "phish")):
        if d:
            root = Path(d)
            items += [(p, label, split_of(f"{label}/{p.relative_to(root)}"))
                      for p in sorted(root.rglob("*")) if p.is_file()]
    if args.split:
        items = [it for it in items if it[2] == args.split]
    if args.limit:
        items = items[: args.limit]
    return items


def build_cli() -> Path:
    out = ROOT / "bin" / "inspekt"
    subprocess.run(["go", "build", "-o", str(out), "./cmd/inspekt"], cwd=ROOT, check=True)
    return out


def scan(cli: Path, files: list[Path]) -> dict[str, dict]:
    """Run the CLI over files in batches; return reports keyed by path."""
    reports: dict[str, dict] = {}
    for i in range(0, len(files), BATCH):
        chunk = [str(p) for p in files[i : i + BATCH]]
        proc = subprocess.run([str(cli), "scan", "--json", *chunk], capture_output=True, text=True)
        for line in proc.stdout.splitlines():
            rep = json.loads(line)
            reports[rep["file"]] = rep
        # Files the parser rejected are reported on stderr; they become
        # "error" rows rather than silently disappearing from the metrics.
    return reports


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--labels", help="CSV with columns file,label (label: ham|phish)")
    ap.add_argument("--ham", help="directory of legitimate messages")
    ap.add_argument("--phish", help="directory of phishing / malicious messages")
    ap.add_argument("--positive-at", default="suspicious", choices=["suspicious", "malicious"])
    ap.add_argument("--min-recall", type=float, default=0.0)
    ap.add_argument("--max-fpr", type=float, default=1.0)
    ap.add_argument("--max-parse-errors", type=int, default=-1,
                    help="fail if more messages than this are rejected by the parser (-1: no limit)")
    ap.add_argument("--limit", type=int, default=0, help="evaluate only the first N messages")
    ap.add_argument("--split", choices=["dev", "holdout"],
                    help="evaluate only this split; design changes with --split dev, and measure "
                         "holdout once, after the change is final")
    ap.add_argument("--out", help="write <out>.json and <out>.md")
    args = ap.parse_args()

    items = load_labels(args)
    if not items:
        ap.error("no messages: pass --labels and/or --ham/--phish")

    # The public corpora must never be sent to an external LLM (licences and
    # privacy): with the grey-zone review configured, only our own samples
    # may be evaluated.
    llm = os.environ.get("INSPEKT_LLM_ENABLED") == "true"
    data_dir = (ROOT / "data").resolve()
    if llm and any(p.resolve().is_relative_to(data_dir) for p, _, _ in items):
        ap.error("refusing to send public-corpus messages to an LLM: unset INSPEKT_LLM_ENABLED "
                 "or evaluate only testdata/ (e.g. --labels testdata/bec/labels.csv)")

    cli = build_cli()
    t0 = time.perf_counter()
    reports = scan(cli, [p for p, _, _ in items])
    elapsed = time.perf_counter() - t0

    results, errors = [], []
    for path, label, split in items:
        rep = reports.get(str(path))
        if rep is None:
            errors.append(str(path))
            continue
        results.append({
            "file": str(path),
            "label": label,
            "split": split,
            "verdict": rep["verdict"],
            "score": rep["score"],
            "signals": [s["id"] for s in rep["signals"]],
            # Kept for the grey-zone review: the model's reasons, or why it
            # was unavailable (e.g. a malformed answer).
            "review": [f'{s["id"]}: {"; ".join(s["evidence"])}' for s in rep["signals"] if s["id"].startswith("llm_")],
        })

    cm = confusion(results, args.positive_at)
    summary = {
        "engine": next(iter(reports.values()))["engine"] if reports else "n/a",
        "llm_review": os.environ.get("INSPEKT_LLM_MODEL", "?") if os.environ.get("INSPEKT_LLM_ENABLED") == "true" else "off",
        "messages": len(items),
        "parse_errors": len(errors),
        "positive_at": args.positive_at,
        "throughput_msgs_per_s": round(len(results) / elapsed, 1) if elapsed else None,
        **cm.summary(),
        "splits": {
            name: {"messages": len(part), **confusion(part, args.positive_at).summary()}
            for name in ("dev", "holdout")
            if (part := [r for r in results if r["split"] == name])
        },
        "signals_on_ham": signal_counts(results, "ham").most_common(10),
        "signals_on_phish": signal_counts(results, "phish").most_common(10),
        "missed": [r["file"] for r in results if r["label"] == "phish" and r["verdict"] == "clean"][:20],
        "false_positives": [r["file"] for r in results if r["label"] == "ham" and r["verdict"] != "clean"][:20],
    }

    print(json.dumps(summary, indent=2))
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out + ".json").write_text(json.dumps({"summary": summary, "results": results}, indent=2))
        Path(args.out + ".md").write_text(to_markdown(summary))

    failed = []
    if cm.recall < args.min_recall:
        failed.append(f"recall {cm.recall:.3f} < {args.min_recall}")
    if cm.fpr > args.max_fpr:
        failed.append(f"false-positive rate {cm.fpr:.3f} > {args.max_fpr}")
    # A message the parser rejects drops out of the confusion matrix, which
    # would quietly inflate recall; on a curated corpus that must fail.
    if 0 <= args.max_parse_errors < len(errors):
        failed.append(f"parse errors {len(errors)} > {args.max_parse_errors}")
    if failed:
        print("QUALITY GATE FAILED: " + "; ".join(failed), file=sys.stderr)
        return 1
    return 0


def to_markdown(s: dict) -> str:
    rows = "\n".join(f"| {k} | {s[k]} |" for k in
                     ("messages", "precision", "recall", "f1", "false_positive_rate", "throughput_msgs_per_s"))
    ham = "\n".join(f"- `{sig}`: {n}" for sig, n in s["signals_on_ham"]) or "- none"
    return f"""# Inspekt evaluation ({s['engine']})

| metric | value |
|---|---|
{rows}

Confusion: TP {s['tp']} · FP {s['fp']} · TN {s['tn']} · FN {s['fn']} (positive = verdict ≥ {s['positive_at']})

## Signals firing on legitimate mail (false-positive drivers)
{ham}
"""


if __name__ == "__main__":
    sys.exit(main())
