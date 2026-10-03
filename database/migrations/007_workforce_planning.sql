CREATE TABLE IF NOT EXISTS public.workforce_requirements (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  service_line TEXT NOT NULL CHECK (service_line IN ('hospitals','primary_care','emergency')),
  location_name TEXT NOT NULL,
  work_center_id BIGINT REFERENCES public.ref_work_centers(id) ON DELETE SET NULL,
  directorate_id BIGINT REFERENCES public.ref_directorates(id) ON DELETE SET NULL,
  department_id BIGINT REFERENCES public.ref_departments(id) ON DELETE SET NULL,
  job_title_id BIGINT REFERENCES public.ref_job_titles(id) ON DELETE SET NULL,
  source_directorate TEXT NOT NULL DEFAULT '',
  source_department TEXT NOT NULL DEFAULT '',
  source_job_title TEXT NOT NULL,
  required_count INTEGER NOT NULL DEFAULT 0 CHECK (required_count >= 0),
  source_file TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT workforce_requirements_source_unique
    UNIQUE (service_line, location_name, source_directorate, source_department, source_job_title)
);
CREATE INDEX IF NOT EXISTS workforce_requirements_filter_idx
  ON public.workforce_requirements(service_line, location_name);
CREATE INDEX IF NOT EXISTS workforce_requirements_title_idx
  ON public.workforce_requirements(job_title_id);

CREATE TABLE IF NOT EXISTS public.workforce_requirement_seed_control (
  id SMALLINT PRIMARY KEY CHECK (id = 1),
  imported_rows INTEGER NOT NULL DEFAULT 0,
  imported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
