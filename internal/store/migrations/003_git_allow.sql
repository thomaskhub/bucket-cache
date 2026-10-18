-- Git allowlist entries added at runtime (web UI or API), on top of the
-- patterns in the config file.
CREATE TABLE git_allow (
    remote     TEXT NOT NULL,
    pattern    TEXT NOT NULL COLLATE NOCASE, -- owner/repo or owner/*
    created_by TEXT NOT NULL,                -- api key id, "bootstrap" or user id
    created_at INTEGER NOT NULL,
    PRIMARY KEY (remote, pattern)
);
