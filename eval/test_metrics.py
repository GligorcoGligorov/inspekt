import unittest

from metrics import confusion, is_flagged, signal_counts, split_of


class MetricsTest(unittest.TestCase):
    def test_confusion_and_rates(self):
        results = [
            {"label": "phish", "verdict": "malicious"},   # tp
            {"label": "phish", "verdict": "suspicious"},  # tp at suspicious, fn at malicious
            {"label": "phish", "verdict": "clean"},       # fn
            {"label": "ham", "verdict": "clean"},         # tn
            {"label": "ham", "verdict": "suspicious"},    # fp at suspicious
        ]
        cm = confusion(results, "suspicious")
        self.assertEqual((cm.tp, cm.fp, cm.tn, cm.fn), (2, 1, 1, 1))
        self.assertAlmostEqual(cm.precision, 2 / 3)
        self.assertAlmostEqual(cm.recall, 2 / 3)
        self.assertAlmostEqual(cm.fpr, 0.5)

        strict = confusion(results, "malicious")
        self.assertEqual((strict.tp, strict.fp, strict.tn, strict.fn), (1, 0, 2, 2))

    def test_empty_is_safe(self):
        cm = confusion([])
        self.assertEqual((cm.precision, cm.recall, cm.f1, cm.fpr), (0.0, 0.0, 0.0, 0.0))

    def test_is_flagged(self):
        self.assertTrue(is_flagged("malicious", "suspicious"))
        self.assertFalse(is_flagged("clean", "suspicious"))

    def test_signal_counts_counts_each_signal_once_per_message(self):
        results = [{"label": "ham", "signals": ["a", "a", "b"]}, {"label": "ham", "signals": ["a"]}]
        self.assertEqual(signal_counts(results, "ham")["a"], 2)


if __name__ == "__main__":
    unittest.main()


class SplitTest(unittest.TestCase):
    def test_stable_and_about_one_fifth(self):
        keys = [f"ham/easy_ham/{i:05d}" for i in range(5000)]
        splits = [split_of(k) for k in keys]
        self.assertEqual(splits, [split_of(k) for k in keys])  # deterministic
        share = splits.count("holdout") / len(splits)
        self.assertTrue(0.18 < share < 0.22, share)
