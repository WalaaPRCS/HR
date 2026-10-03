CREATE TABLE IF NOT EXISTS public.projects (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  start_date DATE,
  end_date DATE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT projects_dates_order CHECK (start_date IS NULL OR end_date IS NULL OR end_date >= start_date)
);

CREATE TABLE IF NOT EXISTS public.project_positions (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  project_id BIGINT NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  job_title_id BIGINT REFERENCES public.ref_job_titles(id) ON DELETE SET NULL,
  title_label TEXT NOT NULL,
  planned_count INTEGER NOT NULL DEFAULT 0 CHECK (planned_count >= 0),
  budget_amount NUMERIC(14,2) NOT NULL DEFAULT 0 CHECK (budget_amount >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT project_positions_title_unique UNIQUE(project_id, title_label)
);

CREATE INDEX IF NOT EXISTS project_positions_project_idx
  ON public.project_positions(project_id);
CREATE INDEX IF NOT EXISTS project_positions_title_idx
  ON public.project_positions(job_title_id);
