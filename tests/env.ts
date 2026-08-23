import { execSync } from 'node:child_process';

export interface SupabaseEnv {
  url: string;
  anonKey: string;
  serviceRoleKey: string;
  dbUrl: string;
}

let cached: SupabaseEnv | null = null;

/**
 * Resolve local Supabase credentials. Explicit env vars win (CI can inject
 * them); otherwise we ask the CLI, so `npm test` needs zero configuration
 * beyond a running `npx supabase start`.
 */
export function supabaseEnv(): SupabaseEnv {
  if (!cached) cached = fromProcessEnv() ?? fromCli();
  return cached;
}

function fromProcessEnv(): SupabaseEnv | null {
  const { SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_DB_URL } = process.env;
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) return null;
  return {
    url: strip(SUPABASE_URL),
    anonKey: strip(SUPABASE_ANON_KEY),
    serviceRoleKey: strip(SUPABASE_SERVICE_ROLE_KEY),
    dbUrl: strip(SUPABASE_DB_URL ?? 'postgresql://postgres:postgres@127.0.0.1:54322/postgres'),
  };
}

function fromCli(): SupabaseEnv {
  let out: string;
  try {
    out = execSync('npx supabase status -o env', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (cause) {
    throw new Error('Could not read local Supabase credentials. Is `npx supabase start` running?', { cause });
  }
  const vars: Record<string, string> = {};
  for (const line of out.split(/\r?\n/)) {
    const m = line.match(/^([A-Z0-9_]+)=(.*)$/);
    if (m) vars[m[1]] = strip(m[2]);
  }
  const url = vars.API_URL;
  const anonKey = vars.ANON_KEY ?? vars.PUBLISHABLE_KEY;
  const serviceRoleKey = vars.SERVICE_ROLE_KEY ?? vars.SECRET_KEY;
  const dbUrl = vars.DB_URL;
  if (!url || !anonKey || !serviceRoleKey || !dbUrl) {
    throw new Error('`supabase status -o env` did not return API_URL / ANON_KEY / SERVICE_ROLE_KEY / DB_URL');
  }
  return { url, anonKey, serviceRoleKey, dbUrl };
}

/** Values quoted in .env files are read back WITH the quotes on Linux -- strip defensively. */
function strip(value: string): string {
  return value.trim().replace(/^"|"$/g, '');
}
