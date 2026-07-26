-- fd0-witness schema. See TRANSLOG.md §8.2.

-- One row per (server_url, chain_id, tree_size, root_hash). The
-- four-key primary key lets two distinct STHs at the same tree_size
-- coexist as equivocation evidence — DetectEquivocationAt surfaces
-- such pairs by counting distinct root_hash per (server, chain, size).
CREATE TABLE IF NOT EXISTS witness_sths (
    server_url        TEXT    NOT NULL,
    chain_id          TEXT    NOT NULL,
    tree_size         INTEGER NOT NULL,
    root_hash         BLOB    NOT NULL CHECK (length(root_hash) = 32),
    timestamp         INTEGER NOT NULL,
    signature         BLOB    NOT NULL CHECK (length(signature) = 64),
    fetched_at        INTEGER NOT NULL,
    -- witness_signature: ed25519 cosign by THIS witness over
    -- ("fd0-witness-cosign-v1" || cbor({sth, server_url})). NULL
    -- only on rows from before the cosign keypair was provisioned.
    witness_signature BLOB             CHECK (witness_signature IS NULL OR length(witness_signature) = 64),
    PRIMARY KEY (server_url, chain_id, tree_size, root_hash)
);
CREATE INDEX IF NOT EXISTS witness_sths_size
    ON witness_sths(server_url, chain_id, tree_size);

-- The witness's own cosign pubkey, cached so a startup mismatch
-- with the on-disk keyfile is FATAL (operator pointing at the wrong
-- DB or having swapped only one side would silently invalidate
-- every client's witness pin). Single row (id=1) by convention.
CREATE TABLE IF NOT EXISTS witness_keypair (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    pub       BLOB    NOT NULL CHECK (length(pub) = 32),
    pinned_at INTEGER NOT NULL
);

-- Operator-supplied pubkey pin per server URL. Single row per URL;
-- a rotation requires deleting the row first (ceremony).
CREATE TABLE IF NOT EXISTS witness_pins (
    server_url   TEXT    PRIMARY KEY,
    server_pub   BLOB    NOT NULL CHECK (length(server_pub) = 32),
    pinned_at    INTEGER NOT NULL
);

-- Durable record of consistency-proof failures (TRANSLOG.md §8.1
-- step 3). One row per (server, chain, from_size, to_size,
-- fetched_at) — fetched_at in the key so retries against the same
-- forked pair don't dedup the evidence. `reason` is "fetch_failed"
-- (proof endpoint refused / network) or "verify_failed" (proof
-- bytes did not validate).
--
-- These rows make the "different-size fork" detection durable across
-- log rotation and witness restart; status/verify scan this table
-- alongside the same-size multi-root check in witness_sths.
CREATE TABLE IF NOT EXISTS witness_consistency_failures (
    server_url   TEXT    NOT NULL,
    chain_id     TEXT    NOT NULL,
    from_size    INTEGER NOT NULL,
    from_root    BLOB    NOT NULL CHECK (length(from_root) = 32),
    to_size      INTEGER NOT NULL,
    to_root      BLOB    NOT NULL CHECK (length(to_root) = 32),
    reason       TEXT    NOT NULL,
    fetched_at   INTEGER NOT NULL,
    PRIMARY KEY (server_url, chain_id, from_size, to_size, fetched_at)
);
CREATE INDEX IF NOT EXISTS witness_cfail_chain
    ON witness_consistency_failures(server_url, chain_id);

CREATE TABLE IF NOT EXISTS witness_chain_summary (
    server_url                TEXT    NOT NULL,
    chain_id                  TEXT    NOT NULL,
    max_tree_size             INTEGER NOT NULL,
    row_count                 INTEGER NOT NULL,
    has_equiv                 INTEGER NOT NULL DEFAULT 0,
    consistency_failure_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (server_url, chain_id)
);

CREATE TABLE IF NOT EXISTS witness_schema_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS witness_summary_sth_insert
AFTER INSERT ON witness_sths
BEGIN
    INSERT INTO witness_chain_summary (
        server_url, chain_id, max_tree_size, row_count,
        has_equiv, consistency_failure_count
    ) VALUES (
        NEW.server_url, NEW.chain_id, NEW.tree_size, 1, 0, 0
    )
    ON CONFLICT(server_url, chain_id) DO UPDATE SET
        max_tree_size = MAX(max_tree_size, NEW.tree_size),
        row_count = row_count + 1;

    UPDATE witness_chain_summary
       SET has_equiv = 1
     WHERE server_url = NEW.server_url
       AND chain_id = NEW.chain_id
       AND (
           SELECT COUNT(DISTINCT root_hash)
             FROM witness_sths
            WHERE server_url = NEW.server_url
              AND chain_id = NEW.chain_id
              AND tree_size = NEW.tree_size
       ) > 1;
END;

CREATE TRIGGER IF NOT EXISTS witness_summary_failure_insert
AFTER INSERT ON witness_consistency_failures
BEGIN
    INSERT INTO witness_chain_summary (
        server_url, chain_id, max_tree_size, row_count,
        has_equiv, consistency_failure_count
    ) VALUES (
        NEW.server_url, NEW.chain_id, 0, 0, 0, 1
    )
    ON CONFLICT(server_url, chain_id) DO UPDATE SET
        consistency_failure_count = consistency_failure_count + 1;
END;
