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
