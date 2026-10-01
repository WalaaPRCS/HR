-- Record the one allowed Excel import. A single fixed key prevents repeat imports.
CREATE TABLE IF NOT EXISTS public.employee_import_control (
    id              SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    source_filename TEXT NOT NULL,
    sha256          CHAR(64) NOT NULL UNIQUE,
    imported_rows   INTEGER NOT NULL CHECK (imported_rows > 0),
    imported_by     TEXT NOT NULL,
    imported_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
