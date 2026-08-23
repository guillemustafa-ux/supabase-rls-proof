#!/usr/bin/env node
/**
 * Apply ONE footgun on top of the clean baseline and run the test suite.
 *
 * The suite is only worth trusting if it goes red when the schema is broken
 * the way real audits find it broken. So:
 *
 *   exit 0  -> the suite CAUGHT the hole (every documented test failed)
 *   exit 1  -> the hole went unnoticed, or the runner itself broke
 *
 * The database is reset to the clean baseline before and after.
 */
import { readFileSync, existsSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import pg from 'pg';

const shell = process.platform === 'win32';
const manifest = JSON.parse(readFileSync(fileURLToPath(new URL('../footguns/manifest.json', import.meta.url)), 'utf8'));

const name = process.argv[2];
if (!name || !manifest[name]) {
  console.error('Usage: npm run footgun <name>\n\nAvailable footguns:');
  for (const [key, value] of Object.entries(manifest)) console.error(`  ${key}\n      ${value.description}`);
  process.exit(1);
}
const entry = manifest[name];

run('npx', ['supabase', 'db', 'reset', '--yes'], 'resetting to the clean baseline');
await applySql(fileURLToPath(new URL(`../footguns/${name}.sql`, import.meta.url)));

console.log(`\n--- footgun applied: ${name} -- ${entry.description}`);
console.log('--- running the suite; it MUST fail now ---\n');

const reportFile = '.footgun-report.json';
spawnSync('npx', ['vitest', 'run', '--reporter=default', '--reporter=json', `--outputFile=${reportFile}`], {
  stdio: 'inherit',
  shell,
});
if (!existsSync(reportFile)) {
  console.error('vitest produced no report -- infrastructure failure, not a verdict.');
  process.exit(1);
}
const report = JSON.parse(readFileSync(reportFile, 'utf8'));
rmSync(reportFile);

const failed = [];
for (const file of report.testResults ?? []) {
  for (const test of file.assertionResults ?? []) {
    if (test.status === 'failed') failed.push(test.fullName ?? test.title);
  }
}

run('npx', ['supabase', 'db', 'reset', '--yes'], 'restoring the clean baseline');

if (failed.length === 0) {
  console.error(`\nFOOTGUN NOT CAUGHT: the suite stayed green with ${name} applied.`);
  process.exit(1);
}

console.log(`\nSuite failures with ${name} applied:`);
for (const f of failed) console.log(`  x ${f}`);

const missing = entry.expectedFailures.filter((expected) => !failed.some((f) => f.includes(expected)));
if (missing.length > 0) {
  console.error('\nFOOTGUN ONLY PARTIALLY CAUGHT -- these documented tests should have failed too:');
  for (const m of missing) console.error(`  - ${m}`);
  process.exit(1);
}

console.log(`\nCAUGHT: ${name} makes the suite fail exactly where the README says it will.`);

async function applySql(file) {
  const sql = readFileSync(file, 'utf8');
  const client = new pg.Client({ connectionString: dbUrl() });
  await client.connect();
  try {
    await client.query(sql);
  } finally {
    await client.end();
  }
}

function dbUrl() {
  if (process.env.SUPABASE_DB_URL) return process.env.SUPABASE_DB_URL.replace(/"/g, '');
  const out = spawnSync('npx', ['supabase', 'status', '-o', 'env'], { encoding: 'utf8', shell });
  const match = (out.stdout ?? '').match(/^DB_URL="?([^"\r\n]+)"?/m);
  if (!match) throw new Error('Cannot resolve DB_URL from `supabase status`. Is `npx supabase start` running?');
  return match[1];
}

function run(cmd, args, label) {
  console.log(`--- ${label} ---`);
  const result = spawnSync(cmd, args, { stdio: 'inherit', shell });
  if (result.status !== 0) {
    console.error(`Command failed: ${cmd} ${args.join(' ')}`);
    process.exit(1);
  }
}
