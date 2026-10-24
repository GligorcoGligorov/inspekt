# Inspekt evaluation (inspekt-rules/0.2.0)

| metric | value |
|---|---|
| messages | 5001 |
| precision | 0.9489 |
| recall | 0.351 |
| f1 | 0.5125 |
| false_positive_rate | 0.0092 |
| throughput_msgs_per_s | 1776.6 |

Confusion: TP 576 · FP 31 · TN 3326 · FN 1065 (positive = verdict ≥ suspicious)

## Signals firing on legitimate mail (false-positive drivers)
- `return_path_mismatch`: 2306
- `reply_to_mismatch`: 618
- `html_form_in_email`: 71
- `link_text_mismatch`: 18
- `ip_literal_url`: 4
- `url_shortener`: 4
- `missing_from`: 2
- `display_name_spoof`: 2
- `lookalike_link`: 1
- `html_attachment`: 1
