#!/usr/bin/env python3
"""Measure campaign clustering offline on the labelled public corpora.

    make eval                     # writes eval/report.json (labels, splits, verdicts)
    python3 eval/campaigns.py     # clusters dev and holdout, prints the numbers

Clustering uses the same Go code as GET /v1/campaigns (cmd/inspekt-campaigns,
internal/campaign); each split is one window. This measures, it does not
tune: nothing here changes a score or a verdict.

Per split it reports:
  campaigns                 groups of 2+ messages that share an indicator
  phish in campaigns        share of phishing that sits in a multi-email campaign
  campaign-assisted recall  phishing the rules MISSED that shares a campaign
                            with phishing the rules CAUGHT (what correlation
                            could add, if an analyst followed the campaign)
  ham contamination         legitimate mail in a campaign that contains phishing
  guard                     indicator values dropped as too common, per kind
  oversized                 clusters above --max-size, marked "likely shared
                            infrastructure": reported separately and NOT counted
                            in the two numbers above
  largest campaigns         to check they are real campaigns, not infrastructure

Run dev first and holdout once, with nothing changed in between:
    python3 eval/campaigns.py --split dev
    python3 eval/campaigns.py --split holdout
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--report", default=str(ROOT / "eval" / "report.json"), help="evaluate.py --out report (JSON)")
    ap.add_argument("--max-shared", type=int, default=20)
    ap.add_argument("--max-share", type=float, default=0.05)
    ap.add_argument("--max-size", type=int, default=500)
    ap.add_argument("--split", choices=["dev", "holdout"], help="measure one split only")
    ap.add_argument("--out", default=str(ROOT / "eval" / "out" / "campaigns.json"))
    args = ap.parse_args()

    report = json.load(open(args.report))
    wanted = (args.split,) if args.split else ("dev", "holdout")
    results = [r for r in report["results"] if r["split"] in wanted]
    if not results:
        sys.exit("no dev/holdout results in the report; run `make eval` first")
    meta = {r["file"]: r for r in results}

    # The LLM must never see corpus mail: run the clustering with it off.
    env = {k: v for k, v in os.environ.items() if not k.startswith("INSPEKT_LLM_")}
    subprocess.run(["go", "build", "-o", str(ROOT / "bin" / "inspekt-campaigns"), "./cmd/inspekt-campaigns"], cwd=ROOT, check=True)
    feed = "\n".join(json.dumps({"file": r["file"], "split": r["split"]}) for r in results)
    proc = subprocess.run([str(ROOT / "bin" / "inspekt-campaigns"), f"-max-shared={args.max_shared}",
                           f"-max-share={args.max_share}", f"-max-size={args.max_size}"],
                          input=feed, capture_output=True, text=True, cwd=ROOT, env=env, check=True)
    clusters = json.loads(proc.stdout)

    summary = {}
    for split in wanted:
        c = clusters.get(split)
        if not c:
            continue
        rows = [r for r in results if r["split"] == split]
        phish = [r for r in rows if r["label"] == "phish"]
        ham = [r for r in rows if r["label"] == "ham"]
        caught = {r["file"] for r in phish if r["verdict"] != "clean"}
        missed = {r["file"] for r in phish if r["verdict"] == "clean"}
        in_campaign, assisted, contaminated = set(), set(), set()
        mixed = pure_phish = 0
        largest, oversized, largest_phish = [], [], []
        for camp in c["campaigns"] or []:
            files = camp["scan_ids"]
            labels = Counter(meta[f]["label"] for f in files if f in meta)
            if len(largest) < 5:
                top = (camp.get("indicators") or [{}])[0]
                largest.append({"size": camp["size"], "phish": labels["phish"], "ham": labels["ham"],
                                "oversized": bool(camp.get("oversized")),
                                "top_indicator": f'{top.get("kind")}={top.get("value")} ({top.get("scans")} scans)',
                                "example_subject": (camp.get("subjects") or [""])[0]})
            if labels["phish"] and len(largest_phish) < 5:
                top = (camp.get("indicators") or [{}])[0]
                largest_phish.append({"size": camp["size"], "phish": labels["phish"], "ham": labels["ham"],
                                      "top_indicator": f'{top.get("kind")}={top.get("value")} ({top.get("scans")} scans)',
                                      "example_subject": (camp.get("subjects") or [""])[0]})
            if camp.get("oversized"):
                # Likely shared infrastructure: reported, never counted as a campaign.
                oversized.append({"size": camp["size"], "phish": labels["phish"], "ham": labels["ham"]})
                continue
            if labels["phish"] and not labels["ham"]:
                pure_phish += 1
            in_campaign.update(files)
            if any(f in caught for f in files):
                assisted.update(f for f in files if f in missed)
            if labels["phish"]:
                contaminated.update(f for f in files if f in meta and meta[f]["label"] == "ham")
            if labels["phish"] and labels["ham"]:
                mixed += 1
        phish_in = sum(1 for r in phish if r["file"] in in_campaign)
        tp = len(caught)
        summary[split] = {
            "scans": c["scans"], "phish": len(phish), "ham": len(ham),
            "campaigns": len(c["campaigns"] or []) - len(oversized),
            "campaigns_all_phish": pure_phish,
            "oversized": oversized,
            "phish_in_campaigns": phish_in, "phish_in_campaigns_share": round(phish_in / len(phish), 4) if phish else 0,
            "missed_phish": len(missed),
            "campaign_assisted": len(assisted),
            "campaign_assisted_share_of_phish": round(len(assisted) / len(phish), 4) if phish else 0,
            "campaign_assisted_share_of_missed": round(len(assisted) / len(missed), 4) if missed else 0,
            "recall_rules": round(tp / len(phish), 4) if phish else 0,
            "recall_if_followed": round((tp + len(assisted)) / len(phish), 4) if phish else 0,
            "ham_contaminated": len(contaminated),
            "ham_contamination_share": round(len(contaminated) / len(ham), 4) if ham else 0,
            "mixed_campaigns": mixed,
            "guard_limit": c["guard_limit"], "guard_dropped": c["guard_dropped"],
            "distinct_indicators": c["indicators_by_kind"],
            "largest": largest,
            "largest_with_phish": largest_phish,
        }

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(summary, indent=2))
    for split, s in summary.items():
        print(f"== {split}: {s['scans']} messages ({s['phish']} phishing, {s['ham']} ham), guard limit {s['guard_limit']}")
        print(f"   campaigns (2+ messages):        {s['campaigns']} ({s['campaigns_all_phish']} are 100% phishing), plus {len(s['oversized'])} oversized")
        for o in s["oversized"]:
            print(f"     oversized: {o['size']} messages ({o['phish']} phish, {o['ham']} ham), not counted below")
        print(f"   phishing in campaigns:          {s['phish_in_campaigns']} of {s['phish']} ({s['phish_in_campaigns_share']:.2%})")
        print(f"   campaign-assisted recall:       {s['campaign_assisted']} missed phishing share a campaign with caught phishing "
              f"({s['campaign_assisted_share_of_missed']:.2%} of {s['missed_phish']} missed; "
              f"recall {s['recall_rules']} -> {s['recall_if_followed']} if every one were followed up)")
        print(f"   ham contamination:              {s['ham_contaminated']} of {s['ham']} ham share a campaign with phishing "
              f"({s['ham_contamination_share']:.2%}); mixed campaigns: {s['mixed_campaigns']}")
        print(f"   guard dropped (values/kind):    {s['guard_dropped'] or 'none'}  of distinct {s['distinct_indicators']}")
        print("   largest campaigns:")
        for c in s["largest"]:
            flag = " OVERSIZED" if c["oversized"] else ""
            print(f"     size {c['size']:4} ({c['phish']} phish, {c['ham']} ham){flag}  top {c['top_indicator']}  e.g. {c['example_subject'][:60]!r}")
        print("   largest campaigns containing phishing:")
        for c in s["largest_with_phish"]:
            print(f"     size {c['size']:4} ({c['phish']} phish, {c['ham']} ham)  top {c['top_indicator']}  e.g. {c['example_subject'][:60]!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
