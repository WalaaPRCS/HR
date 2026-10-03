-- The planning workbook is the authoritative source for employee job titles.
CREATE TABLE IF NOT EXISTS public.planning_job_title_catalog (
  name TEXT PRIMARY KEY,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO public.planning_job_title_catalog(name)
SELECT DISTINCT BTRIM(p.source_job_title)
FROM public.workforce_requirements p
WHERE NULLIF(BTRIM(p.source_job_title), '') IS NOT NULL
ON CONFLICT(name) DO NOTHING;

INSERT INTO public.ref_job_titles (name)
SELECT DISTINCT BTRIM(c.name)
FROM public.planning_job_title_catalog c
WHERE NULLIF(BTRIM(c.name), '') IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM public.ref_job_titles jt
      WHERE LOWER(BTRIM(jt.name)) = LOWER(BTRIM(c.name))
  );

UPDATE public.workforce_requirements p
SET job_title_id = jt.id
FROM public.ref_job_titles jt
WHERE LOWER(BTRIM(jt.name)) = LOWER(BTRIM(p.source_job_title))
  AND p.job_title_id IS DISTINCT FROM jt.id;

INSERT INTO public.ref_directorate_department_job_titles
    (directorate_id, department_id, job_title_id)
SELECT DISTINCT p.directorate_id, p.department_id, p.job_title_id
FROM public.workforce_requirements p
JOIN public.ref_directorate_departments dd
  ON dd.directorate_id = p.directorate_id
 AND dd.department_id = p.department_id
WHERE p.directorate_id IS NOT NULL
  AND p.department_id IS NOT NULL
  AND p.job_title_id IS NOT NULL
ON CONFLICT DO NOTHING;

UPDATE public.employees e
SET job_title = p.source_job_title
FROM public.workforce_requirements p
WHERE LOWER(BTRIM(e.job_title)) = LOWER(BTRIM(p.source_job_title))
  AND e.job_title IS DISTINCT FROM p.source_job_title;
