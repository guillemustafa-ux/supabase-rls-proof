# supabase-rls-proof

**A green RLS test suite proves nothing until you have watched it go red.**

This repo is a multi-tenant Supabase schema with hand-written Row Level
Security, a test suite that exercises it with **real authenticated user
tokens** (not the anon key), plus one SQL-level check run as `authenticated`
where PostgREST cannot reach, and — the part that matters — a catalog of five
**footguns**: SQL scripts that deliberately re-introduce real-world audit
findings. Apply any of them and the suite must fail, on the exact test the
README says it will. CI enforces both directions: baseline green, every
footgun red. The fifth, `05`, is a policy that looked safe for as long as
other layers covered every path the suite tried; it joined the matrix once
the suite tested the policy without them.

```
npx supabase start   # local stack (Docker)
npm ci
npm test             # baseline: 17 tests, all green
npm run footgun 02-org-from-user-metadata   # break it on purpose: suite goes red
```

No `.env` to configure — the tests read local credentials from
`supabase status` themselves. Nothing here is a secret: local development
keys only.

## The schema

Three tables, one tenant boundary:

```
organizations ──< memberships >── auth.users
      └────────< projects
```

- RLS enabled on every table, deny-by-default. Policies grant members of an
  org full CRUD on that org's `projects`, read on their own `memberships`
  and `organizations`. Nothing else.
- Membership is resolved by `is_org_member(org_id)` — a `SECURITY DEFINER`
  helper with `search_path` pinned to `''`, that only ever answers about the
  **calling** user (`auth.uid()`). Tenant identity lives in a table the user
  cannot write, **never** in `user_metadata`.
- `project_overview` is a `security_invoker` view; `get_org_projects()` is a
  `SECURITY INVOKER` RPC. Both inherit the caller's RLS instead of the
  owner's superpowers.

## What the suite verifies

`tests/tenant-isolation.test.ts` — two real users (created through the admin
API, signed in with email+password), one org and one project each:

| # | Test | Why it exists |
|---|------|---------------|
| 1 | Tokens are real user JWTs (`role=authenticated`, `sub=user.id`) | RLS behaves differently for anon and authenticated. Testing with the anon key only is how leaks ship. |
| 2–3 | Each user reads their org's rows and nothing else | The core isolation claim, both directions. |
| 4 | INSERT into the other org is rejected (`42501`) | `WITH CHECK` on insert. |
| 5 | UPDATE on the other org's row affects 0 rows, data intact | RLS filters silently — asserting "no error" would pass on a leak. |
| 6 | A **filtered** UPDATE cannot move a row into the other org, through a PATCH and through a writing RPC | Both paths read `projects.id`, so the SELECT policy also checks the new row: doubly guarded. Stays green under footgun 05 — see #7. |
| 7 | An UPDATE that reads **no column** of the table cannot move a row into the other org | The one shape with no SELECT check: `WITH CHECK` alone decides. Runs in SQL as `authenticated` with alice's claims, because through the API `pg-safeupdate` refuses an UPDATE with no `WHERE` first. See footgun 05. |
| 8 | DELETE on the other org's row deletes nothing | Verified against the DB with service_role, not by the API response. |
| 9 | A user cannot insert their own membership into another org | Privilege escalation via the membership table itself. |
| 10 | Forging `org_id` in own `user_metadata` grants nothing | The test really mints a fresh JWT carrying the forged claim, then proves it is worthless. See footgun 02. |
| 11 | The anon key reads zero rows from every table and view | The public surface. |
| 12 | service_role sees everything | Documents WHY that key must never reach a client. |
| 13 | The view only returns the caller's tenant | Views are a classic RLS bypass. See footgun 03. |
| 14 | The RPC returns nothing for a foreign org | RPCs are the other classic bypass. See footgun 04. |

`tests/catalog.test.ts` — structural checks straight from the Postgres
catalog, so the schema cannot regress silently:

| # | Check |
|---|-------|
| 15 | Every table in `public` has RLS enabled |
| 16 | Every view in `public` is `security_invoker` |
| 17 | Every `SECURITY DEFINER` function in `public` pins `search_path` |

## The footgun catalog

Each file in `footguns/` re-introduces one real audit finding.
`npm run footgun <name>` resets to the clean baseline, applies it, runs the
suite, and **exits non-zero unless every documented test fails**. The
baseline is restored afterwards.

| Footgun | What it re-creates | Caught by |
|---------|--------------------|-----------|
| `01-rls-disabled` | RLS never enabled (or disabled while debugging, and shipped) | #2, #11, #15 |
| `02-org-from-user-metadata` | Policy trusts `org_id` from `user_metadata`, which the end user can edit via `auth.updateUser()` | #10 |
| `03-view-without-security-invoker` | View recreated without `security_invoker` — runs as owner, bypasses RLS | #13, #16 |
| `04-security-definer-leak` | RPC flipped to `SECURITY DEFINER` "to fix a permissions error": no access check, no pinned `search_path` | #14, #17 |
| `05-update-ownership-only-check` | UPDATE policy whose `WITH CHECK` validates *ownership* ("the row is still mine") instead of the tenant column — a row can be moved into another org | #7 |

### Footgun 05: the hole other layers were hiding

`05-update-ownership-only-check` re-creates a genuinely broken UPDATE policy.
For a while it lived outside the matrix as a case study, because the suite
stayed green with it applied: the moves it tried were stopped by a second
layer the broken policy never touches.

- Both paths of test #6 run an UPDATE that filters on `projects.id`: the
  PATCH through PostgREST and the `SECURITY INVOKER` RPC `move_project`. When
  an UPDATE reads a column of the table, Postgres also checks the **new** row
  against the SELECT policy ([CREATE POLICY](https://www.postgresql.org/docs/current/sql-createpolicy.html),
  "Policies Applied by Command Type"). `is_org_member(orgB)` is false for the
  attacker, so both abort with `42501` regardless of `WITH CHECK`. Under 05,
  test #6 stays green.
- That second layer exists only because the statement reads the table. An
  UPDATE whose `WHERE`, `SET` and `RETURNING` reference none of the table's
  own columns gets no SELECT check; there `WITH CHECK` is the only wall.
  Through the API a PATCH with no filters and no `select` would be that
  shape, but it never reaches the policy: Supabase's Postgres image sets
  `session_preload_libraries = supautils, safeupdate` on the `authenticator`
  role, so PostgREST's UPDATE without a `WHERE` fails with `21000` first.
  Test #7 runs the statement in SQL as `authenticated` with alice's claims,
  inside a transaction it always rolls back, and under 05 it goes red.

The lesson survived the promotion: in the two API paths the suite drives, a
single broken policy did not leak data, because the SELECT policy also checks
the new row. The unfiltered PATCH is stopped by a different guard,
`pg-safeupdate`, which is extension configuration rather than tenant
identity: drop it, or add a write path that runs as `authenticated` and
whose UPDATE reads no column of `projects` but still has a `WHERE` (a
`SECURITY INVOKER` RPC whose `WHERE` tests only its own parameters, say),
and `WITH CHECK` is the only wall. The suite now tests the policy on its
own, where `WITH CHECK` is already the only wall.

## CI

Two jobs, and both have to hold:

- **`baseline: suite must pass`** — spins up the Supabase stack in the
  runner and runs the 17 tests.
- **`footgun NN: suite must fail`** — a 5-way matrix. Each leg applies one
  footgun and fails the build if the suite *stays green* or if any of the
  documented tests still passes.

The second job is the point of the repo: it is the difference between "my
tests pass" and "my tests have been shown to catch the bugs they claim to
catch".

## Layout

```
supabase/migrations/   the baseline schema + RLS (one migration, commented)
tests/                 tenant-isolation.test.ts, catalog.test.ts
footguns/              five .sql footguns + manifest.json
scripts/footgun.mjs    reset -> apply footgun -> run suite -> verify it bit
.github/workflows/     baseline-green + footgun-matrix-red
```

## License

MIT
