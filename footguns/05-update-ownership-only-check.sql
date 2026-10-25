-- FOOTGUN 05 -- ownership-only WITH CHECK
-- An UPDATE policy that checks OWNERSHIP ("it is still my row") instead of the
-- TENANT COLUMN lets a member move a row into an org they don't belong to:
--
--     using (public.is_org_member(org_id))            -- old row: passes
--     with check (created_by = (select auth.uid()))    -- new row: ALSO passes (!)
--
-- The filtered move test stays green under this policy: its PATCH and its RPC
-- both read projects.id, so Postgres also checks the new row against the
-- SELECT policy (CREATE POLICY docs, "Policies Applied by Command Type") and
-- is_org_member(orgB) still aborts them. An unfiltered PATCH never reaches the
-- policy either: Supabase's Postgres image loads pg-safeupdate for the
-- authenticator role, so an UPDATE with no WHERE fails with 21000 first. The
-- leak needs an UPDATE whose WHERE, SET and RETURNING reference none of the
-- table's own columns, run past safeupdate. The SQL-level move test runs
-- exactly that as `authenticated` with alice's claims, and it is the test
-- that goes red here.
drop policy "projects_update_member" on public.projects;
create policy "projects_update_member"
  on public.projects for update to authenticated
  using (public.is_org_member(org_id))
  with check (created_by = (select auth.uid()));
