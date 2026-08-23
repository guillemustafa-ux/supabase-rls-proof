-- Multi-tenant baseline: organizations -> memberships -> projects.
-- Deny-by-default: RLS on everywhere, no policy = no rows.

create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

create table public.memberships (
  user_id uuid not null references auth.users (id) on delete cascade,
  org_id uuid not null references public.organizations (id) on delete cascade,
  role text not null default 'member' check (role in ('owner', 'member')),
  created_at timestamptz not null default now(),
  primary key (user_id, org_id)
);

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.organizations (id) on delete cascade,
  name text not null,
  created_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now()
);

create index memberships_org_id_idx on public.memberships (org_id);
create index projects_org_id_idx on public.projects (org_id);

-- Membership check used by every tenant policy.
--
-- SECURITY DEFINER on purpose: an INVOKER version evaluated from a policy on
-- memberships itself would recurse. Three guardrails make DEFINER safe here:
--   1. search_path pinned to '' (no schema hijacking);
--   2. it only answers about the CALLING user (auth.uid()), so it cannot be
--      used to probe other users' memberships;
--   3. it returns a boolean, never rows.
create or replace function public.is_org_member(p_org_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.memberships m
    where m.org_id = p_org_id
      and m.user_id = (select auth.uid())
  );
$$;

alter table public.organizations enable row level security;
alter table public.memberships enable row level security;
alter table public.projects enable row level security;

-- organizations: members read their own orgs. Creating orgs stays server-side.
create policy "organizations_select_member"
  on public.organizations for select to authenticated
  using (public.is_org_member(id));

-- memberships: users see their own membership rows. Granting membership is a
-- server-side operation; there is deliberately NO insert/update/delete policy.
create policy "memberships_select_own"
  on public.memberships for select to authenticated
  using (user_id = (select auth.uid()));

-- projects: full CRUD for members of the owning org.
-- WITH CHECK on write policies is what stops a member from MOVING a row into
-- a tenant they don't belong to (update ... set org_id = <someone else's org>).
create policy "projects_select_member"
  on public.projects for select to authenticated
  using (public.is_org_member(org_id));

create policy "projects_insert_member"
  on public.projects for insert to authenticated
  with check (public.is_org_member(org_id));

create policy "projects_update_member"
  on public.projects for update to authenticated
  using (public.is_org_member(org_id))
  with check (public.is_org_member(org_id));

create policy "projects_delete_member"
  on public.projects for delete to authenticated
  using (public.is_org_member(org_id));

-- A view over tenant data MUST be security_invoker. Without it the view runs
-- with its owner's privileges (postgres on Supabase = bypasses RLS) and turns
-- into a read-everything hole for whoever can select from it.
create view public.project_overview
  with (security_invoker = true) as
  select p.id, p.name, p.org_id, o.name as org_name, p.created_at
  from public.projects p
  join public.organizations o on o.id = p.org_id;

-- RPC surface: SECURITY INVOKER so the caller's RLS still applies.
-- If you ever flip one of these to DEFINER, you own the access check yourself.
create or replace function public.get_org_projects(p_org_id uuid)
returns setof public.projects
language sql
stable
security invoker
set search_path = ''
as $$
  select * from public.projects where org_id = p_org_id;
$$;
