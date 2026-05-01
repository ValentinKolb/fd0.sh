-- fd0-witness schema. See TRANSLOG.md §8.2.

-- One row per (server_url, chain_id, tree_size, root_hash). The
-- four-key primary key lets two distinct STHs at the same tree_size
-- coexist as equivocation evidence — DetectEquivocationAt surfaces
-- such pairs by counting distinct root_hash per (server, chain, size).
CREATE TABLE IF NOT EXISTS witness_sths (
    server_url   TEXT    NOT NULL,
    chain_id     TEXT    NOT NULL,
    tree_size    INTEGER NOT NULL,
    root_hash    BLOB    NOT NULL CHECK (length(root_hash) = 32),
    timestamp    INTEGER NOT NULL,
    signature    BLOB    NOT NULL CHECK (length(signature) = 64),
    fetched_at   INTEGER NOT NULL,
    PRIMARY KEY (server_url, chain_id, tree_size, root_hash)
);
CREATE INDEX IF NOT EXISTS witness_sths_size
    ON witness_sths(server_url, chain_id, tree_size);

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
