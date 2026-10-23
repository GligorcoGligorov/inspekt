"""Detection metrics. Pure functions, no I/O, so they are trivially testable."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class Confusion:
    tp: int = 0  # phish flagged
    fp: int = 0  # ham flagged   <- the number customers complain about
    tn: int = 0  # ham passed
    fn: int = 0  # phish missed  <- the number attackers exploit

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0

    def summary(self) -> dict:
        return {
            **asdict(self),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.fpr, 4),
        }


VERDICT_RANK = {"clean": 0, "suspicious": 1, "malicious": 2}


def is_flagged(verdict: str, positive_at: str) -> bool:
    """A message counts as flagged if its verdict is at or above positive_at."""
    return VERDICT_RANK[verdict] >= VERDICT_RANK[positive_at]


def confusion(results: list[dict], positive_at: str = "suspicious") -> Confusion:
    """results: [{"label": "ham"|"phish", "verdict": ...}, ...]"""
    tp = fp = tn = fn = 0
    for r in results:
        flagged = is_flagged(r["verdict"], positive_at)
        phish = r["label"] == "phish"
        if phish and flagged:
            tp += 1
        elif phish:
            fn += 1
        elif flagged:
            fp += 1
        else:
            tn += 1
    return Confusion(tp, fp, tn, fn)


def signal_counts(results: list[dict], label: str) -> Counter:
    """How often each signal fired on messages with the given label.

    Run on ham, this is the list of rules causing false positives:
    the first place to look when tuning.
    """
    c: Counter = Counter()
    for r in results:
        if r["label"] == label:
            c.update(set(r.get("signals", [])))
    return c
