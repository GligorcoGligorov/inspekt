-- Scan results. One row per distinct message (id = SHA-256 of the raw
-- message), so re-scans update the row instead of adding one.
CREATE TABLE scans (
    id          CHAR(64)          NOT NULL,
    received_at DATETIME(3)       NOT NULL,  -- accepted by the API
    scanned_at  DATETIME(3)       NOT NULL,  -- analysed by a worker
    verdict     ENUM('clean', 'suspicious', 'malicious') NOT NULL,
    score       TINYINT UNSIGNED  NOT NULL,
    engine      VARCHAR(64)       NOT NULL,  -- rule-set version, e.g. inspekt-rules/0.1.0
    from_domain VARCHAR(255)      NULL,
    report      JSON              NOT NULL,  -- full explainable report
    PRIMARY KEY (id),
    KEY idx_scans_received (received_at),
    KEY idx_scans_verdict_received (verdict, received_at),
    KEY idx_scans_from_domain (from_domain, received_at)
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;

-- One row per signal per scan, so questions like "how often does
-- reply_to_mismatch fire on clean mail this week" are a plain SQL query
-- instead of a scan over JSON documents.
CREATE TABLE signals (
    scan_id   CHAR(64)         NOT NULL,
    signal_id VARCHAR(64)      NOT NULL,
    score     TINYINT UNSIGNED NOT NULL,
    PRIMARY KEY (scan_id, signal_id),
    KEY idx_signals_signal (signal_id, scan_id),
    CONSTRAINT fk_signals_scan FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;
