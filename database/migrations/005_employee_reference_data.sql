-- HR reference data extracted from the imported employee records.
-- Names are global dictionaries; associations are many-to-many.
CREATE TABLE IF NOT EXISTS public.ref_work_centers (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS public.ref_directorates (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS public.ref_departments (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS public.ref_job_titles (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS public.ref_employment_statuses (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS public.ref_cadre_types (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS public.ref_center_directorates (
  center_id BIGINT NOT NULL REFERENCES public.ref_work_centers(id) ON DELETE CASCADE,
  directorate_id BIGINT NOT NULL REFERENCES public.ref_directorates(id) ON DELETE CASCADE,
  PRIMARY KEY (center_id, directorate_id)
);
CREATE TABLE IF NOT EXISTS public.ref_directorate_departments (
  directorate_id BIGINT NOT NULL REFERENCES public.ref_directorates(id) ON DELETE CASCADE,
  department_id BIGINT NOT NULL REFERENCES public.ref_departments(id) ON DELETE CASCADE,
  PRIMARY KEY (directorate_id, department_id)
);
CREATE TABLE IF NOT EXISTS public.ref_department_job_titles (
  department_id BIGINT NOT NULL REFERENCES public.ref_departments(id) ON DELETE CASCADE,
  job_title_id BIGINT NOT NULL REFERENCES public.ref_job_titles(id) ON DELETE CASCADE,
  PRIMARY KEY (department_id, job_title_id)
);

-- Re-running at container startup is safe. Preserve the source labels as entered.
INSERT INTO public.ref_work_centers(name)
SELECT DISTINCT btrim(work_center) FROM public.employees
WHERE nullif(btrim(work_center), '') IS NOT NULL
ON CONFLICT (name) DO NOTHING;
INSERT INTO public.ref_directorates(name)
SELECT DISTINCT btrim(directorate) FROM public.employees
WHERE nullif(btrim(directorate), '') IS NOT NULL
ON CONFLICT (name) DO NOTHING;
INSERT INTO public.ref_departments(name)
SELECT DISTINCT btrim(department) FROM public.employees
WHERE nullif(btrim(department), '') IS NOT NULL
ON CONFLICT (name) DO NOTHING;
INSERT INTO public.ref_job_titles(name)
SELECT DISTINCT btrim(job_title) FROM public.employees
WHERE nullif(btrim(job_title), '') IS NOT NULL
ON CONFLICT (name) DO NOTHING;
INSERT INTO public.ref_employment_statuses(name)
SELECT DISTINCT btrim(employment_status) FROM public.employees
WHERE nullif(btrim(employment_status), '') IS NOT NULL
ON CONFLICT (name) DO NOTHING;
INSERT INTO public.ref_cadre_types(name)
SELECT DISTINCT btrim(cadre_type) FROM public.employees
WHERE nullif(btrim(cadre_type), '') IS NOT NULL
ON CONFLICT (name) DO NOTHING;

INSERT INTO public.ref_center_directorates(center_id, directorate_id)
SELECT DISTINCT c.id, d.id
FROM public.employees e
JOIN public.ref_work_centers c ON c.name = btrim(e.work_center)
JOIN public.ref_directorates d ON d.name = btrim(e.directorate)
WHERE nullif(btrim(e.work_center), '') IS NOT NULL
  AND nullif(btrim(e.directorate), '') IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO public.ref_directorate_departments(directorate_id, department_id)
SELECT DISTINCT d.id, p.id
FROM public.employees e
JOIN public.ref_directorates d ON d.name = btrim(e.directorate)
JOIN public.ref_departments p ON p.name = btrim(e.department)
WHERE nullif(btrim(e.directorate), '') IS NOT NULL
  AND nullif(btrim(e.department), '') IS NOT NULL
ON CONFLICT DO NOTHING;

INSERT INTO public.ref_department_job_titles(department_id, job_title_id)
SELECT DISTINCT p.id, j.id
FROM public.employees e
JOIN public.ref_departments p ON p.name = btrim(e.department)
JOIN public.ref_job_titles j ON j.name = btrim(e.job_title)
WHERE nullif(btrim(e.department), '') IS NOT NULL
  AND nullif(btrim(e.job_title), '') IS NOT NULL
ON CONFLICT DO NOTHING;

-- Keep the initial dictionaries complete when employees are imported or edited later.
CREATE OR REPLACE FUNCTION public.sync_employee_reference_data()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  center_key BIGINT;
  directorate_key BIGINT;
  department_key BIGINT;
  job_key BIGINT;
BEGIN
  INSERT INTO public.ref_work_centers(name) VALUES (btrim(NEW.work_center))
    ON CONFLICT(name) DO NOTHING;
  SELECT id INTO center_key FROM public.ref_work_centers WHERE name=btrim(NEW.work_center);

  IF nullif(btrim(NEW.directorate), '') IS NOT NULL THEN
    INSERT INTO public.ref_directorates(name) VALUES (btrim(NEW.directorate))
      ON CONFLICT(name) DO NOTHING;
    SELECT id INTO directorate_key FROM public.ref_directorates WHERE name=btrim(NEW.directorate);
    INSERT INTO public.ref_center_directorates(center_id,directorate_id)
      VALUES(center_key,directorate_key) ON CONFLICT DO NOTHING;
  END IF;

  IF nullif(btrim(NEW.department), '') IS NOT NULL THEN
    INSERT INTO public.ref_departments(name) VALUES (btrim(NEW.department))
      ON CONFLICT(name) DO NOTHING;
    SELECT id INTO department_key FROM public.ref_departments WHERE name=btrim(NEW.department);
    IF directorate_key IS NOT NULL THEN
      INSERT INTO public.ref_directorate_departments(directorate_id,department_id)
        VALUES(directorate_key,department_key) ON CONFLICT DO NOTHING;
    END IF;
  END IF;

  INSERT INTO public.ref_job_titles(name) VALUES (btrim(NEW.job_title))
    ON CONFLICT(name) DO NOTHING;
  SELECT id INTO job_key FROM public.ref_job_titles WHERE name=btrim(NEW.job_title);
  IF department_key IS NOT NULL THEN
    INSERT INTO public.ref_department_job_titles(department_id,job_title_id)
      VALUES(department_key,job_key) ON CONFLICT DO NOTHING;
  END IF;

  INSERT INTO public.ref_employment_statuses(name) VALUES (btrim(NEW.employment_status))
    ON CONFLICT(name) DO NOTHING;
  INSERT INTO public.ref_cadre_types(name) VALUES (btrim(NEW.cadre_type))
    ON CONFLICT(name) DO NOTHING;
  RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS employees_sync_reference_data ON public.employees;
CREATE TRIGGER employees_sync_reference_data
AFTER INSERT OR UPDATE OF work_center,directorate,department,job_title,cadre_type,employment_status
ON public.employees FOR EACH ROW EXECUTE FUNCTION public.sync_employee_reference_data();
