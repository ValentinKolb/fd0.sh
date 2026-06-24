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

-- Registered users. Codex audit (🔴 auth.go:87, server.go:279):
-- without this table, authenticated endpoints accepted any
-- self-signed pk (anyone could call /sync without registering)
-- AND POST /users could register the same user_super_pub multiple
-- times under different shortIds. The PRIMARY KEY (super_pub) +
-- UNIQUE (short_id) close both.
CREATE TABLE IF NOT EXISTS users (
    super_pub     BLOB    PRIMARY KEY CHECK (length(super_pub) = 32),
    short_id      TEXT    NOT NULL UNIQUE,
    registered_at INTEGER NOT NULL
);

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

-- peers caches each configured replica's resolved identity. The peer
-- resolver runs `GET /v1/server-info` against each FD0_PEERS entry on
-- boot and on a periodic schedule; on first success it TOFU-pins the
-- peer's signing pubkey and stores the peer's self-declared label.
-- Subsequent resolves refuse to overwrite a pinned pubkey — divergence
-- means the peer either rotated its key (operator must wipe the row to
-- re-pin) or is being impersonated.
--
-- url is the canonical peer URL (scheme://host[:port], no trailing
-- slash) — same form the publishing server uses in its /v1/server-info
-- response. label is the peer's self-declared FD0_LABEL, validated
-- against [a-z0-9-]{0,32} at write time so it's safe to render in
-- client UI.
CREATE TABLE IF NOT EXISTS peers (
    url             TEXT    PRIMARY KEY,
    pub             BLOB    NOT NULL CHECK (length(pub) = 32),
    label           TEXT    NOT NULL DEFAULT '',
    first_seen      INTEGER NOT NULL,
    last_verified   INTEGER NOT NULL
);

-- Replication backup (REPLICATION.md Phase 0 — DR cold standby).
--
-- A replica pulls a full, verbatim copy of another server's (the
-- "source", identified by its translog pubkey) chains and stores them
-- here UNCHANGED. These tables are a write-once archive: the live
-- serving / signing path (events, chains, translog_*) never reads or
-- writes them, and the server never re-signs a backup chain. This is the
-- structural guard that a mirrored, foreign-anchored chain can never be
-- mistaken for one this server itself anchors (the one-anchor invariant,
-- REPLICATION.md §2). Promotion to primary is a separate, operator-driven
-- restore that copies a backup chain into the live tables under a fenced
-- identity (REPLICATION.md §5 Phase 3) — not done automatically here.
--
-- source_pub namespaces every row by the anchoring server's pubkey, so
-- one replica can back up several sources without collision.
CREATE TABLE IF NOT EXISTS backup_events (
    source_pub  BLOB    NOT NULL CHECK (length(source_pub) = 32),
    chain_id    TEXT    NOT NULL,
    seq         INTEGER NOT NULL,
    event_id    TEXT    NOT NULL,
    prev_hash   BLOB,
    kind        TEXT    NOT NULL,
    cbor        BLOB    NOT NULL,
    stored_at   INTEGER NOT NULL,
    PRIMARY KEY (source_pub, chain_id, seq)
);

CREATE TABLE IF NOT EXISTS backup_sths (
    source_pub  BLOB    NOT NULL CHECK (length(source_pub) = 32),
    chain_id    TEXT    NOT NULL,
    tree_size   INTEGER NOT NULL,
    root_hash   BLOB    NOT NULL,
    timestamp   INTEGER NOT NULL,
    signature   BLOB    NOT NULL,
    PRIMARY KEY (source_pub, chain_id, tree_size)
);
