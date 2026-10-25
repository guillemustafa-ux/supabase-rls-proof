-- CASE STUDY (not a matrix footgun) -- defense in depth beats a broken policy
--
-- The finding this re-creates is real and common: an UPDATE policy that checks
-- OWNERSHIP ("it is still my row") instead of the TENANT COLUMN, which on paper
-- lets a member move a row into an org they don't belong to:
--
--     using (public.is_org_member(org_id))            -- old row: passes
--     with check (created_by = (select auth.uid()))    -- new row: ALSO passes (!)
--
-- What makes it a *case study* rather than a matrix footgun: with this hole
-- applied, the suite still stays GREEN, because the cross-tenant moves it
-- tests are blocked by a SECOND layer the broken policy never touches:
--
--   Both test paths (a PATCH through PostgREST and the SECURITY INVOKER RPC
--   public.move_project) run an UPDATE whose WHERE reads projects.id. When an
--   UPDATE reads the table, Postgres also checks the NEW row against the
--   SELECT policy (CREATE POLICY docs, "Policies Applied by Command Type").
--   is_org_member(orgB) is false for the attacker, so both abort with 42501
--   regardless of WITH CHECK. An UPDATE whose WHERE, SET and RETURNING
--   reference none of the table's own columns gets no such check, and the
--   broken WITH CHECK alone would decide it; the suite has no test of that
--   shape.
--
-- The lesson for a client reading this repo: a single broken policy did NOT
-- open a hole in the two paths the suite tests, because tenant identity is
-- enforced in more than one place.
-- That is the point of `move_project` and the two-pronged move test in
-- tests/tenant-isolation.test.ts -- they PASS on the baseline AND with this
-- policy applied, which is exactly what "defense in depth" looks like when you
-- can measure it.
--
-- Apply it yourself to watch the suite stay green under a genuinely broken
-- policy:
--     npx supabase db reset --yes
--     psql "$(npx supabase status -o env | grep DB_URL | cut -d= -f2- | tr -d '\"')" \
--       -f footguns/case-study/update-cross-tenant-defense-in-depth.sql
--     npm test
drop policy "projects_update_member" on public.projects;
create policy "projects_update_member"
  on public.projects for update to authenticated
  using (public.is_org_member(org_id))
  with check (created_by = (select auth.uid()));
