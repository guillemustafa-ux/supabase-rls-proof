-- FOOTGUN 02 -- UPDATE policy that validates the wrong thing
-- Postgres reuses USING as the WITH CHECK when you omit it, so the naive
-- "forgot WITH CHECK" is actually safe. The version that ships to production
-- looks like this instead: the check validates OWNERSHIP ("it is still my
-- row") but not the TENANT COLUMN, so a member can `update ... set org_id`
-- and move their rows into an org they do not belong to.
drop policy "projects_update_member" on public.projects;
create policy "projects_update_member"
  on public.projects for update to authenticated
  using (public.is_org_member(org_id))
  with check (created_by = (select auth.uid()));
