-- The application permits one administrator account, created from the first-run setup page.
CREATE TABLE IF NOT EXISTS public.admin_account (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
