-- Keep job-title definitions complete with titles used in the employee roster.
-- Idempotent: database startup reapplies migration files.
INSERT INTO public.ref_job_titles (name)
SELECT DISTINCT BTRIM(e.job_title)
FROM public.employees e
WHERE NULLIF(BTRIM(e.job_title), '') IS NOT NULL
  AND NOT EXISTS (
      SELECT 1
      FROM public.ref_job_titles jt
      WHERE LOWER(BTRIM(jt.name)) = LOWER(BTRIM(e.job_title))
  );
