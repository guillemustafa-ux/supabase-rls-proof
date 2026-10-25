import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import {
  addMember,
  admin,
  anonClient,
  createOrg,
  createProject,
  createUser,
  deleteOrg,
  deleteUser,
  env,
  jwtPayload,
  type TestUser,
} from './helpers';

/**
 * Two tenants, two real users, one project each:
 *
 *   org A -- alice (member) -- project "Apollo"
 *   org B -- bob   (member) -- project "Borealis"
 *
 * Every test below runs with a real authenticated user token obtained via
 * email+password sign-in -- not with the anon key. RLS behaves differently
 * for the two, and testing with anon only is how leaks slip through.
 */
describe('tenant isolation', () => {
  let alice: TestUser;
  let bob: TestUser;
  let orgA: string;
  let orgB: string;
  let projectA: string;
  let projectB: string;

  beforeAll(async () => {
    [alice, bob] = await Promise.all([createUser('alice'), createUser('bob')]);
    [orgA, orgB] = await Promise.all([createOrg('Org A'), createOrg('Org B')]);
    await Promise.all([addMember(orgA, alice.id), addMember(orgB, bob.id)]);
    projectA = await createProject(orgA, 'Apollo', alice.id);
    projectB = await createProject(orgB, 'Borealis', bob.id);
  });

  afterAll(async () => {
    await Promise.all([deleteOrg(orgA), deleteOrg(orgB)]);
    await Promise.all([deleteUser(alice), deleteUser(bob)]);
  });

  it('tokens: both users authenticate with real user JWTs, not the anon key', () => {
    for (const user of [alice, bob]) {
      expect(user.accessToken).not.toBe(env.anonKey);
      const payload = jwtPayload(user.accessToken);
      expect(payload.role).toBe('authenticated');
      expect(payload.sub).toBe(user.id);
    }
  });

  it("select: alice sees org A's projects and nothing from org B", async () => {
    const { data, error } = await alice.client.from('projects').select('id, org_id');
    expect(error).toBeNull();
    expect(data!.map((p) => p.id)).toEqual([projectA]);
    expect(data!.every((p) => p.org_id === orgA)).toBe(true);
  });

  it("select: bob sees org B's projects and nothing from org A", async () => {
    const { data, error } = await bob.client.from('projects').select('id, org_id');
    expect(error).toBeNull();
    expect(data!.map((p) => p.id)).toEqual([projectB]);
  });

  it('insert: alice cannot create a project in org B', async () => {
    const { data, error } = await alice.client
      .from('projects')
      .insert({ org_id: orgB, name: 'smuggled', created_by: alice.id })
      .select();
    expect(error).not.toBeNull();
    expect(error!.code).toBe('42501'); // row-level security violation
    expect(data).toBeNull();
  });

  it("update: alice cannot touch bob's project (0 rows affected, data intact)", async () => {
    const { data, error } = await alice.client
      .from('projects')
      .update({ name: 'defaced' })
      .eq('id', projectB)
      .select();
    // RLS filters the row out of the UPDATE's scope: no error, no rows.
    expect(error).toBeNull();
    expect(data).toEqual([]);
    const { data: check } = await admin.from('projects').select('name').eq('id', projectB).single();
    expect(check!.name).toBe('Borealis');
  });

  it('update: alice cannot move her project into org B through a filtered UPDATE (PATCH and RPC)', async () => {
    try {
      // Prong 1 -- plain PATCH. This path is DOUBLY guarded: the UPDATE's WHERE
      // reads projects.id, so Postgres also checks the new row against the
      // SELECT policy, which aborts a cross-tenant move even with a broken
      // WITH CHECK. Passing proves the move is blocked, not which layer did it.
      const { error } = await alice.client
        .from('projects')
        .update({ org_id: orgB })
        .eq('id', projectA);
      expect(error).not.toBeNull();
      expect(error!.code).toBe('42501');

      // Prong 2 -- the same move through a SECURITY INVOKER RPC that writes.
      // Its UPDATE also filters on id, so the same SELECT check applies.
      // Neither prong isolates WITH CHECK; the next test does, which is why
      // footgun 05 (an ownership-only WITH CHECK) leaves this one green.
      const { error: rpcError } = await alice.client.rpc('move_project', {
        p_project_id: projectA,
        p_org_id: orgB,
      });
      expect(rpcError).not.toBeNull();
      expect(rpcError!.code).toBe('42501');

      const { data: check } = await admin.from('projects').select('org_id').eq('id', projectA).single();
      expect(check!.org_id).toBe(orgA);
    } finally {
      // Repair in case a footgun let the move through, so later tests stay meaningful.
      await admin.from('projects').update({ org_id: orgA }).eq('id', projectA);
    }
  });

  it("update: an UPDATE that reads no column cannot move alice's project into org B (WITH CHECK is the only wall)", async () => {
    // Through the API, the one request with this shape -- a PATCH with no
    // filters -- never reaches the policy: Supabase's Postgres image loads
    // pg-safeupdate for the authenticator role, so it is refused with 21000
    // ("UPDATE requires a WHERE clause") first. So the statement runs in SQL
    // as `authenticated` with alice's claims. No WHERE, no RETURNING, nothing
    // on the right of SET reads projects, so Postgres applies no SELECT check
    // to the new row: USING narrows it to alice's rows and WITH CHECK alone
    // decides. This is the shape footgun 05 opens, and the test that catches
    // it. Rolled back either way.
    const db = new pg.Client({ connectionString: env.dbUrl });
    try {
      await db.connect();
      await db.query('begin');
      await db.query('set local role authenticated');
      await db.query("select set_config('request.jwt.claims', $1, true), set_config('request.jwt.claim.sub', $2, true)", [
        JSON.stringify({ sub: alice.id, role: 'authenticated' }),
        alice.id,
      ]);
      // Precondition that keeps footgun 05 detectable: the rows alice can see
      // (the SELECT policy uses the same is_org_member(org_id) predicate as the
      // UPDATE policy's USING) are exactly her own, so an ownership-only WITH
      // CHECK would let every one of them through.
      const { rows: visible } = await db.query('select id, created_by from public.projects order by id');
      expect(visible, 'precondition: alice must see exactly her own project').toEqual([
        { id: projectA, created_by: alice.id },
      ]);
      const errorCode = await db.query('update public.projects set org_id = $1', [orgB]).then(
        () => null,
        (e: { code?: string }) => e.code,
      );
      expect(errorCode, 'policy leak: the no-column UPDATE was not refused').toBe('42501');
    } finally {
      // Roll back no matter what, without hiding the assertion that failed.
      await db.query('rollback').catch(() => undefined);
      await db.end().catch(() => undefined);
    }
  });

  it("delete: alice cannot delete bob's project", async () => {
    const { data, error } = await alice.client.from('projects').delete().eq('id', projectB).select();
    expect(error).toBeNull();
    expect(data).toEqual([]);
    const { count } = await admin.from('projects').select('*', { count: 'exact', head: true }).eq('id', projectB);
    expect(count).toBe(1);
  });

  it('memberships: alice cannot grant herself membership in org B', async () => {
    const { error } = await alice.client.from('memberships').insert({ user_id: alice.id, org_id: orgB });
    expect(error).not.toBeNull();
    expect(error!.code).toBe('42501');
  });

  it('user_metadata: forging org_id = org B in her own metadata grants alice nothing', async () => {
    // The attack: any user can edit their OWN user_metadata...
    const { error: updateError } = await alice.client.auth.updateUser({ data: { org_id: orgB } });
    expect(updateError).toBeNull();
    // ...and mint a fresh JWT that carries the forged claim.
    const { data: refreshed, error: refreshError } = await alice.client.auth.refreshSession();
    expect(refreshError).toBeNull();
    const claims = jwtPayload(refreshed.session!.access_token);
    expect(claims.user_metadata?.org_id).toBe(orgB); // the forgery really is in the token
    // A policy that trusts user_metadata would now leak org B. Ours must not.
    const { data, error } = await alice.client.from('projects').select('id, org_id');
    expect(error).toBeNull();
    expect(data!.map((p) => p.id)).toEqual([projectA]);
  });

  it('anon: the anon key reads zero rows from every table and view', async () => {
    const anon = anonClient();
    for (const relation of ['organizations', 'memberships', 'projects', 'project_overview']) {
      const { data } = await anon.from(relation).select('*');
      // Empty result or permission error are both fine; rows are not.
      expect(data ?? []).toEqual([]);
    }
  });

  it('service_role: sees all rows across tenants (server-side only)', async () => {
    const { data, error } = await admin.from('projects').select('id').in('id', [projectA, projectB]);
    expect(error).toBeNull();
    expect(data).toHaveLength(2);
  });

  it("view: project_overview only returns the caller's tenant", async () => {
    const { data, error } = await alice.client.from('project_overview').select('id, org_id, org_name');
    expect(error).toBeNull();
    expect(data!.map((p) => p.id)).toEqual([projectA]);
    expect(data![0].org_name).toBe('Org A');
  });

  it('rpc: get_org_projects(org B) returns nothing for alice', async () => {
    const { data: own, error: ownError } = await alice.client.rpc('get_org_projects', { p_org_id: orgA });
    expect(ownError).toBeNull();
    expect(own!.map((p: { id: string }) => p.id)).toEqual([projectA]);
    const { data: foreign, error } = await alice.client.rpc('get_org_projects', { p_org_id: orgB });
    expect(error).toBeNull();
    expect(foreign).toEqual([]);
  });
});
