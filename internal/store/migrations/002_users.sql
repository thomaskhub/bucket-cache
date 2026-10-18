CREATE TABLE users (
    id                   TEXT PRIMARY KEY,
    username             TEXT NOT NULL UNIQUE COLLATE NOCASE,
    role                 TEXT NOT NULL,              -- admin | user
    password_hash        TEXT NOT NULL,              -- Argon2id, PHC string format
    must_change_password INTEGER NOT NULL DEFAULT 0,
    totp_secret          TEXT,                       -- AES-GCM sealed, NULL until enrolled
    totp_pending         TEXT,                       -- sealed secret shown during enrolment
    totp_last_step       INTEGER NOT NULL DEFAULT 0, -- last accepted TOTP step (replay protection)
    failed_logins        INTEGER NOT NULL DEFAULT 0, -- consecutive failures
    locked_until         INTEGER,
    disabled_at          INTEGER,
    created_at           INTEGER NOT NULL,
    last_login_at        INTEGER
);

CREATE TABLE sessions (
    id_hash      TEXT PRIMARY KEY,                   -- SHA-256 of the cookie value
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mfa          INTEGER NOT NULL DEFAULT 0,         -- 1 once a TOTP code was verified
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL                    -- absolute lifetime
);
CREATE INDEX sessions_user_id ON sessions(user_id);
