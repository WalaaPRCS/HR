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
