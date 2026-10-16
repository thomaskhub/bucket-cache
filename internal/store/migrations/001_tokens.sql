CREATE TABLE api_keys (
    id           TEXT PRIMARY KEY,
    hash         TEXT NOT NULL UNIQUE,
    name         TEXT NOT NULL,
    role         TEXT NOT NULL,              -- admin | token-issuer
    ceiling      TEXT NOT NULL DEFAULT '{}', -- JSON: scope and max TTL this key may issue
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at   INTEGER
);

CREATE TABLE tokens (
    id           TEXT PRIMARY KEY,
    hash         TEXT NOT NULL UNIQUE,
    kind         TEXT NOT NULL,              -- ci | personal
    description  TEXT NOT NULL DEFAULT '',
    labels       TEXT NOT NULL DEFAULT '{}', -- JSON object
    scope        TEXT NOT NULL,              -- JSON: buckets, prefixes, git
    created_by   TEXT NOT NULL,              -- api key id, "bootstrap" or user id
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    revoked_at   INTEGER,
    last_used_at INTEGER,
    requests     INTEGER NOT NULL DEFAULT 0,
    bytes        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX tokens_expires_at ON tokens(expires_at);
