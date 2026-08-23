-- FOOTGUN 05 -- the copy-pasted SECURITY DEFINER
-- Someone flips an RPC to SECURITY DEFINER "to fix a permissions error".
-- Two holes at once: the function now bypasses RLS with no access check of
-- its own, and the search_path is no longer pinned.
create or replace function public.get_org_projects(p_org_id uuid)
returns setof public.projects
language sql
stable
security definer
as $$
  select * from public.projects where org_id = p_org_id;
$$;
