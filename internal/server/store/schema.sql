-- fd0 server schema. Mirrors STORAGE.md §2.

CREATE TABLE IF NOT EXISTS events (
    chain_id    TEXT    NOT NULL,
    seq         INTEGER NOT NULL,
    event_id    TEXT    NOT NULL UNIQUE,
    prev_hash   BLOB,
    kind        TEXT    NOT NULL,
    cbor        BLOB    NOT NULL,
    stored_at   INTEGER NOT NULL,
    PRIMARY KEY (chain_id, seq)
);

CREATE INDEX IF NOT EXISTS events_by_chain_seq ON events(chain_id, seq);

CREATE TABLE IF NOT EXISTS chains (
    chain_id  TEXT    PRIMARY KEY,
    tip_seq   INTEGER NOT NULL,
    tip_hash  BLOB    NOT NULL,
    metadata  BLOB
);

CREATE TABLE IF NOT EXISTS auth_nonces (
    pk    BLOB    NOT NULL,
    nonce BLOB    NOT NULL,
    ts    INTEGER NOT NULL,
    PRIMARY KEY (pk, nonce)
);

CREATE INDEX IF NOT EXISTS auth_nonces_by_ts ON auth_nonces(ts);

-- Transparency log per TRANSLOG.md §7.2.
--
-- translog_nodes stores every "complete aligned subtree" hash. A subtree
-- at (level L, index_at_level k) covers leaves [k*2^L, (k+1)*2^L - 1] and
-- is inserted only when fully populated. Inclusion proofs and consistency
-- proofs read these nodes; incomplete-spine subtrees are recomputed on
-- demand from stored complete subtrees.
CREATE TABLE IF NOT EXISTS translog_nodes (
    chain_id        TEXT    NOT NULL,
    level           INTEGER NOT NULL,
    index_at_level  INTEGER NOT NULL,
    hash            BLOB    NOT NULL,
    PRIMARY KEY (chain_id, level, index_at_level)
);
CREATE INDEX IF NOT EXISTS translog_nodes_chain ON translog_nodes(chain_id, level);

-- translog_sths archives every signed tree head. The latest row per
-- chain_id is the current STH. Older rows let witnesses backfill and
-- enable a future /v1/sth/{cid}?at_size={n} endpoint.
CREATE TABLE IF NOT EXISTS translog_sths (
    chain_id    TEXT    NOT NULL,
    tree_size   INTEGER NOT NULL,
    root_hash   BLOB    NOT NULL,
    timestamp   INTEGER NOT NULL,
    signature   BLOB    NOT NULL,
    PRIMARY KEY (chain_id, tree_size)
);

-- translog_server_key caches the operator-supplied translog signing
-- pubkey. Single-row table (id=1). On boot the server cross-checks this
-- against the keyfile contents (TRANSLOG.md §4.1 startup matrix); a
-- mismatch is fatal — the operator either swapped the wrong key or
-- pointed at the wrong DB.
CREATE TABLE IF NOT EXISTS translog_server_key (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    pub             BLOB    NOT NULL CHECK (length(pub) = 32),
    pub_pinned_at   INTEGER NOT NULL
);
