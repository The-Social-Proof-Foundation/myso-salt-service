CREATE TABLE IF NOT EXISTS zklogin_salts (
    user_identifier TEXT PRIMARY KEY,
    salt TEXT NOT NULL,
    iss TEXT NOT NULL,
    aud TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
