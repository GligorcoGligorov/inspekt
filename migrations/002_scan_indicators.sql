-- Correlation indicators per scan (internal/campaign): link hosts,
-- attachment hashes, the sending IP and a subject fingerprint. One row per
-- distinct (kind, value); rewritten with the scan's result, so a
-- redelivered message never duplicates rows. Scans sharing a value belong
-- to the same campaign.
CREATE TABLE scan_indicators (
    scan_id    CHAR(64)     NOT NULL,
    kind       VARCHAR(32)  NOT NULL,
    value      VARCHAR(255) COLLATE utf8mb4_bin NOT NULL,  -- exact, case-sensitive matches
    created_at DATETIME(3)  NOT NULL,  -- the scan's received_at: the campaign window is arrival time
    PRIMARY KEY (scan_id, kind, value),
    KEY idx_indicators_kind_value (kind, value),
    KEY idx_indicators_created (created_at),
    CONSTRAINT fk_indicators_scan FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;  -- scan_id must match scans.id for the foreign key
