# Inspekt evaluation (inspekt-rules/0.2.0)

| metric | value |
|---|---|
| messages | 1201 |
| precision | 0.95 |
| recall | 0.326 |
| f1 | 0.4854 |
| false_positive_rate | 0.0088 |
| throughput_msgs_per_s | 1407.3 |

Confusion: TP 133 · FP 7 · TN 786 · FN 275 (positive = verdict ≥ suspicious)

## Signals firing on legitimate mail (false-positive drivers)
- `return_path_mismatch`: 559
- `reply_to_mismatch`: 139
- `html_form_in_email`: 16
- `link_text_mismatch`: 6
- `ip_literal_url`: 2
- `url_shortener`: 1
