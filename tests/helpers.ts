import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { supabaseEnv } from './env';

export const env = supabaseEnv();

const clientOptions = { auth: { persistSession: false, autoRefreshToken: false } };

/** service_role client -- server-side only in real life. Bypasses RLS. */
export const admin = createClient(env.url, env.serviceRoleKey, clientOptions);

/** Fresh client holding only the anon key -- no user session. */
export function anonClient(): SupabaseClient {
  return createClient(env.url, env.anonKey, clientOptions);
}

export interface TestUser {
  id: string;
  email: string;
  client: SupabaseClient;
  accessToken: string;
}

/**
 * Create a real user through the admin API and sign in with email+password.
 * Every tenant test runs with the resulting USER access token -- never with
 * the anon key pretending to be a user.
 */
export async function createUser(label: string): Promise<TestUser> {
  const email = `${label}-${crypto.randomUUID()}@rls-proof.test`;
  const password = `pw-${crypto.randomUUID()}`;
  const { data: created, error } = await admin.auth.admin.createUser({ email, password, email_confirm: true });
  if (error) throw error;
  const client = anonClient();
  const { data: signIn, error: signInError } = await client.auth.signInWithPassword({ email, password });
  if (signInError) throw signInError;
  if (!signIn.session) throw new Error('signInWithPassword returned no session');
  return { id: created.user.id, email, client, accessToken: signIn.session.access_token };
}

export async function deleteUser(user: TestUser | undefined): Promise<void> {
  if (user) await admin.auth.admin.deleteUser(user.id);
}

export function jwtPayload(token: string): Record<string, any> {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
}

export async function createOrg(name: string): Promise<string> {
  const { data, error } = await admin.from('organizations').insert({ name }).select('id').single();
  if (error) throw error;
  return data.id;
}

export async function addMember(orgId: string, userId: string, role = 'member'): Promise<void> {
  const { error } = await admin.from('memberships').insert({ org_id: orgId, user_id: userId, role });
  if (error) throw error;
}

export async function createProject(orgId: string, name: string, createdBy: string): Promise<string> {
  const { data, error } = await admin.from('projects').insert({ org_id: orgId, name, created_by: createdBy }).select('id').single();
  if (error) throw error;
  return data.id;
}

export async function deleteOrg(orgId: string | undefined): Promise<void> {
  if (orgId) await admin.from('organizations').delete().eq('id', orgId);
}
