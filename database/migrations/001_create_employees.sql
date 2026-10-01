-- HR employees table: initial schema
-- Source workbook contains 1,876 employee rows. Import is intentionally separate.
-- Apply to the HR PostgreSQL database only after it has been provisioned.

CREATE TABLE IF NOT EXISTS public.employees (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    employee_number     TEXT NOT NULL UNIQUE,
    employee_name       TEXT NOT NULL,
    work_center         TEXT NOT NULL,
    directorate         TEXT,
    department          TEXT,
    job_title           TEXT NOT NULL,
    cadre_type          TEXT NOT NULL,
    employment_status   TEXT NOT NULL,
    salary              NUMERIC(12, 2),
    next_grade_due_date DATE,
    coverage_percentage NUMERIC(6, 2),
    project             TEXT,
    grade               TEXT,
    employee_code       TEXT NOT NULL UNIQUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT employees_coverage_nonnegative
      CHECK (coverage_percentage IS NULL OR coverage_percentage >= 0),
    CONSTRAINT employees_salary_nonnegative
      CHECK (salary IS NULL OR salary >= 0)
);

CREATE INDEX IF NOT EXISTS employees_name_idx
    ON public.employees (employee_name);
CREATE INDEX IF NOT EXISTS employees_work_center_idx
    ON public.employees (work_center);
CREATE INDEX IF NOT EXISTS employees_directorate_idx
    ON public.employees (directorate);
CREATE INDEX IF NOT EXISTS employees_department_idx
    ON public.employees (department);
CREATE INDEX IF NOT EXISTS employees_job_title_idx
    ON public.employees (job_title);
CREATE INDEX IF NOT EXISTS employees_status_idx
    ON public.employees (employment_status);
CREATE INDEX IF NOT EXISTS employees_project_idx
    ON public.employees (project);

-- Row Level Security is enabled from the start. Policies will be added
-- alongside the authentication and role model, before any app access is granted.
ALTER TABLE public.employees ENABLE ROW LEVEL SECURITY;

COMMENT ON TABLE public.employees IS
  'Employee master records imported from the PRCS HR workbook.';
