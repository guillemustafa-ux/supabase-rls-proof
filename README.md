# supabase-rls-proof

**A green RLS test suite proves nothing until you have watched it go red.**

This repo is a multi-tenant Supabase schema with hand-written Row Level
Security, a test suite that exercises it with **real authenticated user
tokens** (not the anon key), and — the part that matters — a catalog of four
**footguns**: migrations that deliberately re-introduce real-world audit
findings. Apply any of them and the suite must fail, on the exact test the
README says it will. CI enforces both directions: baseline green, every
footgun red. A fifth finding lives in `footguns/case-study/` — a broken
policy that the suite proves is *not* enough to leak data, because tenant
identity is enforced in more than one place.

```
npx supabase start   # local stack (Docker)
npm ci
npm test             # baseline: 16 tests, all green
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
| 6 | UPDATE cannot **move** a row into the other org | Passes on the baseline AND with the ownership-only policy applied — see the case study below. |
| 7 | DELETE on the other org's row deletes nothing | Verified against the DB with service_role, not by the API response. |
| 8 | A user cannot insert their own membership into another org | Privilege escalation via the membership table itself. |
| 9 | Forging `org_id` in own `user_metadata` grants nothing | The test really mints a fresh JWT carrying the forged claim, then proves it is worthless. See footgun 02. |
| 10 | The anon key reads zero rows from every table and view | The public surface. |
| 11 | service_role sees everything | Documents WHY that key must never reach a client. |
| 12 | The view only returns the caller's tenant | Views are a classic RLS bypass. See footgun 03. |
| 13 | The RPC returns nothing for a foreign org | RPCs are the other classic bypass. See footgun 04. |

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
| `02-org-from-user-metadata` | Policy trusts `org_id` from `user_metadata`, which the end user can edit via `auth.updateUser()` | #9 |
| `03-view-without-security-invoker` | View recreated without `security_invoker` — runs as owner, bypasses RLS | #12, #15 |
| `04-security-definer-leak` | RPC flipped to `SECURITY DEFINER` "to fix a permissions error": no access check, no pinned `search_path` | #13, #16 |

### Case study: a broken policy that *didn't* open a hole

`footguns/case-study/update-cross-tenant-defense-in-depth.sql` re-creates a
genuinely broken UPDATE policy — it validates *ownership* ("the row is still
mine") instead of the *tenant column*, so on paper a member could move a row
into another org. It lives outside the matrix on purpose: with it applied,
the suite **stays green**, because the move is stopped by a second layer the
broken policy never touches.

- A PATCH through PostgREST is blocked by the internal `RETURNING`: the new
  row must pass a SELECT policy, and `is_org_member(orgB)` is false for the
  attacker, so it aborts with `42501` regardless of `WITH CHECK`.
- A `SECURITY INVOKER` RPC that writes inside its body (`move_project`) is
  still blocked in practice on this stack.

That is why test #6 fires the move through **two** paths and expects both to
fail — and why it passes on the baseline *and* under the broken policy. A
single broken policy did not leak data here because tenant identity is
enforced in more than one place. Apply it yourself (instructions are in the
file header) and watch the suite stay green under a policy that looks broken.

## CI

Two jobs, and both have to hold:

- **`baseline: suite must pass`** — spins up the Supabase stack in the
  runner and runs the 16 tests.
- **`footgun NN: suite must fail`** — a 4-way matrix. Each leg applies one
  footgun and fails the build if the suite *stays green* or fails anywhere
  other than the documented tests.

The second job is the point of the repo: it is the difference between "my
tests pass" and "my tests have been shown to catch the bugs they claim to
catch".

## Layout

```
supabase/migrations/   the baseline schema + RLS (one migration, commented)
tests/                 tenant-isolation.test.ts, catalog.test.ts
footguns/              four .sql footguns + manifest.json; case-study/ holds the defense-in-depth finding
scripts/footgun.mjs    reset -> apply footgun -> run suite -> verify it bit
.github/workflows/     baseline-green + footgun-matrix-red
```

## License

MIT
