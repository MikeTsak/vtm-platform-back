/**
 * Run pending database migrations on PRODUCTION, with progress bars.
 *
 * Uses the same deploy.config.json / FTPS credentials as `npm run deploy`:
 *   1. Writes a one-time token to tmp/deploy-backup.token over FTPS (the same
 *      trust mechanism the pre-deploy backup uses; no admin login needed).
 *   2. Asks the server what's pending (dry run) and lists it.
 *   3. Takes a game-data database backup (skip with --no-backup).
 *   4. Applies the pending migrations, streaming progress per migration.
 *
 * The server code must already be deployed: migration files live on the
 * server, so a new migration has to be uploaded with `npm run deploy` first.
 * Note that a normal deploy restarts the app, and boot already applies
 * pending migrations, so right after a deploy this usually reports
 * "up to date". It's the tool to confirm that, and to retry a boot-time
 * migration that failed (boot only logs the error and keeps running).
 *
 * Usage:
 *   npm run migrations                Show status, back up, apply pending
 *   npm run migrations:status         Read-only report: prod vs local code version,
 *                                     server vs local migration files, recently
 *                                     applied, pending, and any mismatch warnings
 *   npm run migrations -- --no-backup Skip the pre-migration backup
 *   npm run migrations -- --yes       Don't ask for confirmation
 */
import { Client } from 'basic-ftp';
import cliProgress from 'cli-progress';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline/promises';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/* ------------------------------------------------------------------ colors --- */
const color = !process.env.NO_COLOR && (Boolean(process.stdout.isTTY) || Boolean(process.env.FORCE_COLOR));
const wrap = (code) => (s) => (color ? `\x1b[${code}m${s}\x1b[0m` : String(s));
const c = {
  red: wrap('31'), green: wrap('32'), yellow: wrap('33'), cyan: wrap('36'), dim: wrap('2'), bold: wrap('1'),
  boldRed: wrap('1;31'), boldGreen: wrap('1;32'), boldYellow: wrap('1;33'), boldCyan: wrap('1;36'),
};
const RULE = '========================================================================';

function banner(paint, title, lines = []) {
  console.log('\n' + paint(RULE));
  console.log(paint(`  ${title}`));
  console.log(paint(RULE));
  for (const l of lines) console.log(`  ${l}`);
  console.log(paint(RULE) + '\n');
}
function die(title, lines = []) {
  banner(c.boldRed, `ERROR: ${title}`, lines);
  process.exit(1);
}

/* -------------------------------------------------------------------- args --- */
const argv = process.argv.slice(2);
const has = (...names) => names.some((n) => argv.includes(n));
const STATUS_ONLY = has('--status', '--dry-run', '-n');
const NO_BACKUP = has('--no-backup', '--skip-backup');
const YES = has('--yes', '-y');

/* ------------------------------------------------------------------ config --- */
const CONFIG_FILE = path.join(ROOT, 'deploy.config.json');
if (!fs.existsSync(CONFIG_FILE)) die('no deploy.config.json found', ['Create back/deploy.config.json with your FTP credentials (same file npm run deploy uses).']);
let fileCfg;
try {
  fileCfg = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
} catch (err) {
  die(`deploy.config.json is not valid JSON: ${err.message}`);
}
const ftpCfg = fileCfg.ftp || {};
const pick = (envKey, key, fallback) => process.env[envKey] ?? ftpCfg[key] ?? fileCfg[key] ?? fallback;
const asBool = (v, d) => (v === undefined || v === '' ? d : !/^(0|false|no|off)$/i.test(String(v)));

const HOST = pick('FTP_HOST', 'host');
const PORT = Number(pick('FTP_PORT', 'port', 21));
const USER = pick('FTP_USER', 'user');
const PASSWORD = pick('FTP_PASSWORD', 'password');
const secureRaw = String(pick('FTP_SECURE', 'secure', 'true'));
const SECURE = /^implicit$/i.test(secureRaw) ? 'implicit' : asBool(secureRaw, true);
const TLS_STRICT = asBool(pick('FTP_TLS_STRICT', 'tlsStrict', 'false'), false);
const REMOTE_ROOT = '/' + String(pick('FTP_REMOTE_DIR', 'remoteDir', '/')).replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
const API = (process.env.DEPLOY_API_BASE || fileCfg.apiBase || 'https://api.attlarp.gr').replace(/\/+$/, '');

for (const [k, v] of Object.entries({ host: HOST, user: USER, password: PASSWORD })) {
  if (!v) die(`"${k}" is empty in deploy.config.json or FTP_* environment variables.`);
}

/* --------------------------------------------------------------------- ftp --- */
const client = new Client(30_000);

async function connect() {
  process.stdout.write(`  connecting to ${c.boldCyan(`${USER}@${HOST}:${PORT}`)}... `);
  try {
    await client.access({ host: HOST, port: PORT, user: USER, password: PASSWORD, secure: SECURE, secureOptions: { rejectUnauthorized: TLS_STRICT } });
    console.log(c.green('connected'));
  } catch (err) {
    console.log(c.boldRed('failed'));
    die(`FTP connection failed: ${err.message}`, ['Check host, user, password, port, and TLS options in deploy.config.json.']);
  }
}

// The server accepts a token only once and only for 5 minutes, so every
// request gets a fresh one.
async function issueToken() {
  const token = crypto.randomBytes(32).toString('hex');
  const remote = path.posix.join(REMOTE_ROOT, 'tmp/deploy-backup.token');
  const upload = async () => {
    await client.ensureDir(path.posix.dirname(remote));
    await client.cd(REMOTE_ROOT);
    await client.uploadFrom(Readable.from(`${token}:${Date.now()}`), remote);
  };
  try {
    await upload();
  } catch {
    // The control connection can time out while a backup streams; reconnect once.
    await connect();
    await upload();
  }
  return token;
}

/* --------------------------------------------------------------------- sse --- */
async function streamSse(url, onEvent) {
  const token = await issueToken();
  const res = await fetch(url, { headers: { 'x-deploy-token': token, Accept: 'text/event-stream' } });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    const err = new Error(`HTTP ${res.status}${text ? `: ${text.slice(0, 200)}` : ''}`);
    err.status = res.status;
    throw err;
  }
  const decoder = new TextDecoder('utf-8');
  let buffer = '';
  const flush = (block) => {
    let event = 'message';
    let data = '';
    for (const raw of block.split(/\r?\n/)) {
      const line = raw.trim();
      if (line.startsWith('event:')) event = line.slice(6).trim();
      else if (line.startsWith('data:')) data += line.slice(5).trim();
    }
    if (!data) return;
    let parsed = data;
    try { parsed = JSON.parse(data); } catch { /* plain-text event */ }
    onEvent(event, parsed);
  };
  for await (const chunk of res.body) {
    buffer += decoder.decode(chunk, { stream: true });
    const parts = buffer.split(/\r?\n\r?\n/);
    buffer = parts.pop() || '';
    parts.forEach(flush);
  }
  if (buffer.trim()) flush(buffer);
}

function makeBar(format, total) {
  if (!process.stdout.isTTY) return null;
  const bar = new cliProgress.SingleBar(
    { format, barCompleteChar: '█', barIncompleteChar: '░', hideCursor: true, clearOnComplete: false },
    cliProgress.Presets.shades_grey,
  );
  bar.start(Math.max(total, 1), 0, { item: 'starting...' });
  return bar;
}

/* ------------------------------------------------------------------- steps --- */
async function checkPending() {
  process.stdout.write('  checking production schema... ');
  let info = null;
  try {
    await streamSse(`${API}/api/admin/schema-versions/stream?dry=true`, (event, data) => {
      if (event === 'start') info = data;
      if (event === 'done' && data && data.ok === false) throw new Error(data.error);
    });
  } catch (err) {
    console.log(c.boldRed('failed'));
    if (err.status === 401 || err.status === 403 || err.status === 404) {
      die('production does not have the migration stream route yet', [
        'This command needs the server-side route added alongside it.',
        `Deploy the backend once first: ${c.boldCyan('npm run deploy')}`,
        'That restart also applies any pending migrations automatically.',
      ]);
    }
    die(`could not read production schema: ${err.message}`);
  }
  if (!info) die('server closed the stream without reporting schema status');
  console.log(c.green('ok'));
  return info;
}

async function runBackup() {
  console.log(`\n  ${c.bold('Step 1/2')} database backup ${c.dim('(game data, same as npm run deploy:backup)')}`);
  let bar = null;
  let total = 0;
  let table = '';
  let result = null;
  await streamSse(`${API}/api/admin/backup/stream?full=false`, (event, data) => {
    if (event === 'start' && data?.total) {
      total = data.total;
      bar = makeBar(`  backup:    [{bar}] {percentage}% | {value}/{total} tables | ${c.dim('{item}')}`, total);
    } else if (event === 'log' && typeof data === 'string') {
      const m = data.match(/^([A-Za-z0-9_]+):/);
      if (m) table = m[1];
    } else if (event === 'progress' && data) {
      if (bar) bar.update(data.current, { item: table });
      else process.stdout.write(`\r  backup: ${data.current}/${data.total} tables`);
    } else if (event === 'done') {
      result = data;
    }
  });
  if (bar) { bar.update(total, { item: 'complete' }); bar.stop(); } else process.stdout.write('\n');
  if (!result || result.failed) die('backup failed, nothing was migrated', [result?.message || 'The backup stream ended without a result.', `Retry, or skip the backup with ${c.cyan('--no-backup')} if you are sure.`]);
  console.log(`  ${c.green('saved')} ${c.boldCyan(result.file || '')} ${c.dim(`(${result.message || ''})`)}`);
  return result.file;
}

async function runMigrations(total) {
  console.log(`\n  ${c.bold(NO_BACKUP ? 'Step 1/1' : 'Step 2/2')} applying migrations`);
  const bar = makeBar(`  migrating: [{bar}] {percentage}% | {value}/{total} | ${c.dim('{item}')}`, total);
  const started = Date.now();
  let result = null;
  const timings = [];
  let stepStart = started;
  await streamSse(`${API}/api/admin/schema-versions/stream`, (event, data) => {
    if (event === 'applying') {
      stepStart = Date.now();
      if (bar) bar.update(data.index, { item: data.name });
      else console.log(`    applying ${data.name}...`);
    } else if (event === 'progress') {
      timings.push({ name: data.name, ms: Date.now() - stepStart });
      if (bar) bar.update(data.current, { item: data.name });
    } else if (event === 'done') {
      result = data;
    }
  });
  if (bar) { bar.update(result?.ok ? total : bar.value, { item: result?.ok ? 'complete' : 'FAILED' }); bar.stop(); }
  return { result, timings, secs: ((Date.now() - started) / 1000).toFixed(1) };
}

/* ------------------------------------------------------------------ report --- */
const RECENT = 5;
const stripJs = (f) => f.replace(/\.js$/, '');

async function prodVersion() {
  try {
    const r = await fetch(`${API}/api/health?_=${Date.now()}`, { headers: { accept: 'application/json' } });
    return r.ok ? (await r.json()).version || null : null;
  } catch {
    return null;
  }
}

// Migration names equal their filenames (checked across the whole list), so
// "applied" = files on the server minus what the server says is pending, and
// schema_migrations rows beyond that are applied names with no file on disk.
async function printReport(info) {
  const serverFiles = (await client.list(path.posix.join(REMOTE_ROOT, 'migrations/list')))
    .filter((e) => e.isFile && e.name.endsWith('.js'))
    .map((e) => stripJs(e.name))
    .sort();
  const localFiles = fs.readdirSync(path.join(ROOT, 'migrations/list')).filter((f) => f.endsWith('.js')).map(stripJs).sort();
  const pending = new Set(info.pending);
  const applied = serverFiles.filter((n) => !pending.has(n));
  const localOnly = localFiles.filter((n) => !serverFiles.includes(n));
  const serverOnly = serverFiles.filter((n) => !localFiles.includes(n));
  const orphanRows = info.appliedCount - applied.length;
  const [prod, local] = [await prodVersion(), JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version];

  const ok = (s) => c.green(s);
  const warn = (s) => c.boldYellow(s);
  console.log(`  database: ${c.boldCyan(info.database || 'unknown')} | ${info.appliedCount} applied, ${info.total ? warn(`${info.total} pending`) : ok('0 pending')}`);
  console.log(`  code:     prod ${c.boldCyan(`v${prod || '?'}`)} | local ${c.boldCyan(`v${local}`)} ${prod === local ? ok('(same)') : warn('(differ)')}`);
  console.log(`  files:    server ${serverFiles.length} | local ${localFiles.length} ${!localOnly.length && !serverOnly.length ? ok('(in sync)') : warn('(differ)')}`);

  console.log(`\n  most recent applied on production:`);
  if (!applied.length) console.log(`    ${c.dim('none')}`);
  for (const n of applied.slice(-RECENT)) console.log(`    ${c.green('✓')} ${n}`);
  if (info.total) {
    console.log(`\n  pending on production:`);
    for (const n of info.pending) console.log(`    ${c.yellow('•')} ${n}`);
  }

  const warnings = [];
  if (localOnly.length) warnings.push(`local only, not on the server yet (needs a deploy): ${localOnly.join(', ')}`);
  if (serverOnly.length) warnings.push(`on the server but not in your local repo: ${serverOnly.join(', ')}`);
  if (orphanRows > 0) warnings.push(`${orphanRows} applied row(s) in schema_migrations with no file on the server (deleted or renamed migration)`);
  if (prod && prod !== local) warnings.push(`production runs v${prod}, local is v${local}: code on the server may not match your checkout`);
  if (warnings.length) {
    console.log(`\n  ${warn('warnings:')}`);
    for (const w of warnings) console.log(`    ${c.yellow('!')} ${w}`);
  }
  console.log('');
}

/* -------------------------------------------------------------------- main --- */
console.log(`\n  ${c.boldCyan('PRODUCTION MIGRATIONS')}  ${c.dim(API)}${STATUS_ONLY ? c.dim('  (status only)') : ''}\n`);
await connect();

let exitCode = 0;
try {
  const info = await checkPending();
  await printReport(info);

  if (STATUS_ONLY) {
    console.log(`  ${c.dim(info.total ? 'status only; run npm run migrations to apply.' : 'status only; nothing to apply.')}\n`);
  } else if (!info.total) {
    banner(c.boldGreen, 'SCHEMA UP TO DATE', ['Production has every migration applied. Nothing to do.']);
  } else {
    if (!YES && process.stdin.isTTY) {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      const answer = await rl.question(`\n  Apply ${info.total} migration(s) to ${c.boldRed('PRODUCTION')}? [y/N] `);
      rl.close();
      if (!/^y(es)?$/i.test(answer.trim())) {
        console.log(`  ${c.yellow('aborted, nothing changed.')}\n`);
        client.close();
        process.exit(0);
      }
    }

    const backupFile = NO_BACKUP ? null : await runBackup();
    const { result, timings, secs } = await runMigrations(info.total);

    if (result?.ok) {
      banner(c.boldGreen, 'MIGRATIONS APPLIED', [
        ...timings.map((t) => `${c.green('✓')} ${t.name} ${c.dim(`(${t.ms} ms)`)}`),
        '',
        `${c.bold('total:')}  ${result.ran.length} migration(s) in ${secs}s`,
        `${c.bold('backup:')} ${backupFile ? c.cyan(backupFile) : c.yellow('skipped (--no-backup)')}`,
      ]);
    } else {
      exitCode = 1;
      banner(c.boldRed, 'MIGRATION FAILED', [
        ...timings.map((t) => `${c.green('✓')} ${t.name}`),
        `${c.red('✗')} ${result?.failedMigration || 'unknown migration'}`,
        '',
        `${c.bold('error:')}  ${result?.error || 'stream ended without a result'}`,
        'The failed migration was NOT recorded as applied; it will retry on the next run or restart.',
        backupFile ? `Pre-migration backup on the server: ${c.cyan(`backups/${backupFile}`)}` : 'No backup was taken (--no-backup).',
      ]);
    }
  }
} catch (err) {
  exitCode = 1;
  banner(c.boldRed, 'ERROR', [err.message]);
} finally {
  client.close();
}
process.exit(exitCode);
