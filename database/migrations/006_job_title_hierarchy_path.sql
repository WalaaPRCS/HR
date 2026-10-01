-- Keep job-title associations at the exact directorate -> department path.
CREATE TABLE IF NOT EXISTS public.ref_directorate_department_job_titles (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  directorate_id BIGINT NOT NULL,
  department_id BIGINT NOT NULL,
  job_title_id BIGINT NOT NULL REFERENCES public.ref_job_titles(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT ref_directorate_department_job_titles_unique
    UNIQUE (directorate_id, department_id, job_title_id),
  CONSTRAINT ref_directorate_department_job_titles_path_fk
    FOREIGN KEY (directorate_id, department_id)
    REFERENCES public.ref_directorate_departments(directorate_id, department_id)
    ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS ref_directorate_department_job_titles_title_idx
  ON public.ref_directorate_department_job_titles(job_title_id);

-- Seed actual paths from employee records. Keep the older department/title relation
-- for compatibility while the app uses this path-specific mapping.
INSERT INTO public.ref_directorate_department_job_titles(directorate_id,department_id,job_title_id)
SELECT DISTINCT d.id,p.id,j.id
FROM public.employees e
JOIN public.ref_directorates d ON d.name=btrim(e.directorate)
JOIN public.ref_departments p ON p.name=btrim(e.department)
JOIN public.ref_job_titles j ON j.name=btrim(e.job_title)
JOIN public.ref_directorate_departments dp ON dp.directorate_id=d.id AND dp.department_id=p.id
WHERE nullif(btrim(e.directorate),'') IS NOT NULL
  AND nullif(btrim(e.department),'') IS NOT NULL
  AND nullif(btrim(e.job_title),'') IS NOT NULL
ON CONFLICT (directorate_id,department_id,job_title_id) DO NOTHING;

CREATE OR REPLACE FUNCTION public.sync_employee_job_title_path()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  directorate_key BIGINT;
  department_key BIGINT;
  job_title_key BIGINT;
BEGIN
  IF nullif(btrim(NEW.directorate),'') IS NULL
     OR nullif(btrim(NEW.department),'') IS NULL
     OR nullif(btrim(NEW.job_title),'') IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT id INTO directorate_key FROM public.ref_directorates WHERE name=btrim(NEW.directorate);
  SELECT id INTO department_key FROM public.ref_departments WHERE name=btrim(NEW.department);
  SELECT id INTO job_title_key FROM public.ref_job_titles WHERE name=btrim(NEW.job_title);
  IF directorate_key IS NOT NULL AND department_key IS NOT NULL AND job_title_key IS NOT NULL THEN
    INSERT INTO public.ref_directorate_department_job_titles(directorate_id,department_id,job_title_id)
    SELECT directorate_key,department_key,job_title_key
    WHERE EXISTS (
      SELECT 1 FROM public.ref_directorate_departments
      WHERE directorate_id=directorate_key AND department_id=department_key
    )
    ON CONFLICT (directorate_id,department_id,job_title_id) DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS employees_sync_job_title_path ON public.employees;
CREATE TRIGGER employees_sync_job_title_path
AFTER INSERT OR UPDATE OF directorate,department,job_title
ON public.employees FOR EACH ROW EXECUTE FUNCTION public.sync_employee_job_title_path();
