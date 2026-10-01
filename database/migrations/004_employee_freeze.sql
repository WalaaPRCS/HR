-- Track whether an employee file is frozen and who froze it.
ALTER TABLE public.employees
    ADD COLUMN IF NOT EXISTS is_frozen BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS frozen_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS frozen_by TEXT;

CREATE INDEX IF NOT EXISTS employees_frozen_idx
    ON public.employees (is_frozen);
