#!/usr/bin/env python3
"""Split an mbox file into one .eml file per message.

    python3 eval/split_mbox.py data/raw/phishing-2024 data/phish/phishing-2024

Messages are written byte-for-byte as stored (minus the mbox "From " separator
line), not re-serialised by the email package: re-serialising would change
headers and line endings, which matters for DKIM and for the parser under test.
"""

from __future__ import annotations

import mailbox
import sys
from pathlib import Path


def split(mbox_path: str, out_dir: str) -> int:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    box = mailbox.mbox(mbox_path, create=False)
    n = 0
    for n, key in enumerate(box.iterkeys(), start=1):
        (out / f"{n:05d}.eml").write_bytes(box.get_bytes(key))
    box.close()
    return n


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    count = split(sys.argv[1], sys.argv[2])
    print(f"{sys.argv[1]}: {count} messages -> {sys.argv[2]}")
