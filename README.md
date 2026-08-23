# supabase-rls-proof

**A green RLS test suite proves nothing until you have watched it go red.**

This repo is a multi-tenant Supabase schema with hand-written Row Level
Security, a test suite that exercises it with **real authenticated user
tokens** (not the anon key), and — the part that matters — a catalog of five
**footguns**: migrations that deliberately re-introduce real-world audit
findings. Apply any of them and the suite must fail, on the exact test the
README says it will. CI enforces both directions: baseline green, every
footgun red.

```
npx supabase start   # local stack (Docker)
npm ci
npm test             # baseline: 16 tests, all green
npm run footgun 03-org-from-user-metadata   # break it on purpose: suite goes red
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
| 6 | UPDATE cannot **move** a row into the other org | The `WITH CHECK` half of the update policy. See footgun 02. |
| 7 | DELETE on the other org's row deletes nothing | Verified against the DB with service_role, not by the API response. |
| 8 | A user cannot insert their own membership into another org | Privilege escalation via the membership table itself. |
| 9 | Forging `org_id` in own `user_metadata` grants nothing | The test really mints a fresh JWT carrying the forged claim, then proves it is worthless. See footgun 03. |
| 10 | The anon key reads zero rows from every table and view | The public surface. |
| 11 | service_role sees everything | Documents WHY that key must never reach a client. |
| 12 | The view only returns the caller's tenant | Views are a classic RLS bypass. See footgun 04. |
| 13 | The RPC returns nothing for a foreign org | RPCs are the other classic bypass. See footgun 05. |

`tests/catalog.test.ts` — structural checks straight from the Postgres
catalog, so the schema cannot regress silently:

| # | Check |
|---|-------|
| 14 | Every table in `public` has RLS enabled |
| 15 | Every view in `public` is `security_invoker` |
| 16 | Every `SECURITY DEFINER` function in `public` pins `search_path` |

## The footgun catalog

Each file in `footguns/` re-introduces one real audit finding.
`npm run footgun <name>` resets to the clean baseline, applies it, runs the
suite, and **exits non-zero unless every documented test fails**. The
baseline is restored afterwards.

| Footgun | What it re-creates | Caught by |
|---------|--------------------|-----------|
| `01-rls-disabled` | RLS never enabled (or disabled while debugging, and shipped) | #2, #10, #14 |
| `02-update-without-tenant-check` | UPDATE policy checks *ownership* but not the *tenant column* — rows can be moved across orgs | #6 |
| `03-org-from-user-metadata` | Policy trusts `org_id` from `user_metadata`, which the end user can edit via `auth.updateUser()` | #9 |
| `04-view-without-security-invoker` | View recreated without `security_invoker` — runs as owner, bypasses RLS | #12, #15 |
| `05-security-definer-leak` | RPC flipped to `SECURITY DEFINER` "to fix a permissions error": no access check, no pinned `search_path` | #13, #16 |

A note on 02, because it is the subtle one: Postgres reuses `USING` as the
`WITH CHECK` when you omit it, so the naive "forgot WITH CHECK" is actually
safe. The version that ships to production is a check that validates the
wrong thing — "the row is still mine" — while `org_id` quietly changes.

## CI

Two jobs, and both have to hold:

- **`baseline: suite must pass`** — spins up the Supabase stack in the
  runner and runs the 16 tests.
- **`footgun NN: suite must fail`** — a 5-way matrix. Each leg applies one
  footgun and fails the build if the suite *stays green* or fails anywhere
  other than the documented tests.

The second job is the point of the repo: it is the difference between "my
tests pass" and "my tests have been shown to catch the bugs they claim to
catch".

## Layout

```
supabase/migrations/   the baseline schema + RLS (one migration, commented)
tests/                 tenant-isolation.test.ts, catalog.test.ts
footguns/              five .sql footguns + manifest.json (footgun -> expected failures)
scripts/footgun.mjs    reset -> apply footgun -> run suite -> verify it bit
.github/workflows/     baseline-green + footgun-matrix-red
```

## License

MIT
