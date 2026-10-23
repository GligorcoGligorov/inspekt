#!/usr/bin/env python3
"""Explain an evaluation report: what drives false positives, why phish is missed.

    python3 eval/explain.py eval/report.json            # dev split (default)
    python3 eval/explain.py eval/report.json --split all

Look at the dev split when deciding what to change; holdout is for checking
the change afterwards, so it must not shape the change.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("report")
    ap.add_argument("--split", default="dev", choices=["dev", "holdout", "all"])
    ap.add_argument("--top", type=int, default=12)
    args = ap.parse_args()

    results = json.load(open(args.report))["results"]
    if args.split != "all":
        results = [r for r in results if r["split"] == args.split]
    ham = [r for r in results if r["label"] == "ham"]
    phish = [r for r in results if r["label"] == "phish"]
    fps = [r for r in ham if r["verdict"] != "clean"]
    fns = [r for r in phish if r["verdict"] == "clean"]
    print(f"split={args.split}: {len(ham)} ham, {len(phish)} phish, {len(fps)} false positives, {len(fns)} missed")

    section("False positives: signal combinations")
    for combo, n in Counter(" + ".join(sorted(r["signals"])) for r in fps).most_common(args.top):
        print(f"{n:5}  {combo}")
    section("False positives: by ham source")
    for src, n in Counter(r["file"].split("/")[2] for r in fps).most_common():
        print(f"{n:5}  {src}")

    section("Missed phish: score buckets")
    for bucket, n in sorted(Counter(min(r["score"] // 10 * 10, 90) for r in fns).items()):
        print(f"{n:5}  score {bucket:2}-{bucket + 9}")
    section("Missed phish: signal combinations")
    for combo, n in Counter(" + ".join(sorted(r["signals"])) or "(no signals)" for r in fns).most_common(args.top):
        print(f"{n:5}  {combo}")
    section("Missed phish: by year")
    by_year = Counter(r["file"].split("/")[2] for r in fns)
    all_year = Counter(r["file"].split("/")[2] for r in phish)
    for y in sorted(all_year):
        print(f"{by_year[y]:5} / {all_year[y]:4}  {y}")

    section("Signal precision on this split (fires on phish / fires at all)")
    fired = Counter()
    on_phish = Counter()
    for r in results:
        for s in set(r["signals"]):
            fired[s] += 1
            on_phish[s] += r["label"] == "phish"
    for s, n in fired.most_common():
        print(f"{on_phish[s] / n:6.1%}  {on_phish[s]:5} / {n:5}  {s}")


def section(title: str) -> None:
    print(f"\n## {title}")


if __name__ == "__main__":
    main()
