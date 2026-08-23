import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { supabaseEnv } from './env';

/**
 * Structural checks straight from the Postgres catalog. Behavioral tests prove
 * what today's rows do; these prove the SHAPE of the schema can't regress
 * silently -- a new table without RLS fails CI before it leaks anything.
 */
describe('catalog', () => {
  let db: pg.Client;

  beforeAll(async () => {
    db = new pg.Client({ connectionString: supabaseEnv().dbUrl });
    await db.connect();
  });

  afterAll(async () => {
    await db.end();
  });

  it('every table in public has RLS enabled', async () => {
    const { rows } = await db.query(`
      select c.relname
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public' and c.relkind = 'r' and not c.relrowsecurity
      order by c.relname
    `);
    expect(rows.map((r) => r.relname)).toEqual([]);
  });

  it('every view in public is security_invoker', async () => {
    const { rows } = await db.query(`
      select c.relname
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      where n.nspname = 'public' and c.relkind = 'v'
        and not exists (
          select 1 from unnest(coalesce(c.reloptions, '{}')) o
          where o in ('security_invoker=true', 'security_invoker=on', 'security_invoker=1')
        )
      order by c.relname
    `);
    expect(rows.map((r) => r.relname)).toEqual([]);
  });

  it('every SECURITY DEFINER function in public pins search_path', async () => {
    const { rows } = await db.query(`
      select p.proname
      from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
      where n.nspname = 'public' and p.prosecdef
        and not exists (
          select 1 from unnest(coalesce(p.proconfig, '{}')) c
          where c like 'search_path=%'
        )
      order by p.proname
    `);
    expect(rows.map((r) => r.proname)).toEqual([]);
  });
});
