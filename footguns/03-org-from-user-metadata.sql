-- FOOTGUN 03 -- trusting user_metadata
-- user_metadata is writable by the END USER via supabase.auth.updateUser().
-- A policy that reads the org from it (say, to support a "current org"
-- switcher) lets any user grant themselves access to any org by editing
-- their own profile. Tenant claims belong in app_metadata or in a table.
create policy "projects_select_metadata_org"
  on public.projects for select to authenticated
  using (org_id = ((select auth.jwt()) -> 'user_metadata' ->> 'org_id')::uuid);
