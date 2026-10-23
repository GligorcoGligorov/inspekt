#!/usr/bin/env python3
"""Pick a fixed evaluation subset from the fetched corpora for the CI gate.

    python3 eval/make_subset.py data/ > data/subset.csv
    python3 eval/evaluate.py --labels data/subset.csv ...

Only holdout messages are eligible, so the gate is measured on mail that no
tuning decision looked at. Within the holdout, messages are ordered by a hash
of their path and the first N of each label are taken: the same subset on
every machine, with no list of files to maintain. The SpamAssassin texts may
not be redistributed, so CI rebuilds the subset from the pinned downloads
(eval/fetch_corpora.sh) instead of committing it.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from metrics import split_of  # noqa: E402

PER_LABEL = 100


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    data = Path(sys.argv[1])
    print("file,label")
    for label in ("ham", "phish"):
        keys = [f"{label}/{p.relative_to(data / label)}" for p in (data / label).rglob("*") if p.is_file()]
        keys = [k for k in keys if split_of(k) == "holdout"]
        keys.sort(key=lambda k: hashlib.sha256(("subset:" + k).encode()).hexdigest())
        if len(keys) < PER_LABEL:
            sys.exit(f"only {len(keys)} holdout {label} messages; run eval/fetch_corpora.sh")
        for k in keys[:PER_LABEL]:
            print(f"{k},{label}")


if __name__ == "__main__":
    main()
