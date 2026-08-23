-- FOOTGUN 04 -- view without security_invoker
-- Views default to running as their OWNER. On Supabase the owner is postgres,
-- which bypasses RLS -- so the view happily returns every tenant's rows to
-- anyone allowed to select from it, including the anon role.
drop view public.project_overview;
create view public.project_overview as
  select p.id, p.name, p.org_id, o.name as org_name, p.created_at
  from public.projects p
  join public.organizations o on o.id = p.org_id;
