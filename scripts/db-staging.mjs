/**
 * scripts/db-staging.mjs — mirror production's latest backup into the LOCAL database.
 *
 *   npm run db:staging            newest complete backup from prod /backups
 *   npm run db:staging -- --file vtm-20261006-033000-nomedia.sql.gz   a specific one
 *
 * 1. Lists /backups on the server over FTPS (creds from deploy.config.json).
 * 2. Downloads the newest one into back/backups/ (skipped if already there, same size).
 * 3. Verifies it gunzips cleanly and ends with the dump footer — prod has a few
 *    truncated dumps from interrupted runs; those are skipped for the next newest.
 * 4. DROPs and re-CREATEs the local DB_NAME (from .env), then pipes the dump into
 *    the mariadb/mysql client of the running server (found via @@basedir — WAMP).
 *
 * Refuses to run unless DB_HOST is local, so a misconfigured .env can't wipe prod.
 * Nightly prod backups are -nomedia: premonition_media/news_media come over empty.
 */
import { Client } from 'basic-ftp';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { spawn } from 'node:child_process';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
require('dotenv').config({ path: path.join(ROOT, '.env'), quiet: true });
const mysql = require('mysql2/promise');
const { ftp } = require(path.join(ROOT, 'deploy.config.json'));

const LOCAL_DIR = path.join(ROOT, 'backups');
const REMOTE_DIR = '/backups';
const FOOTER = 'SET FOREIGN_KEY_CHECKS = 1;';
const { DB_HOST = '127.0.0.1', DB_PORT = '3306', DB_USER = 'root', DB_PASS = '', DB_NAME } = process.env;

const die = (msg) => { console.error(`\n  ✖ ${msg}`); process.exit(1); };
const mb = (n) => `${(n / 1048576).toFixed(1)} MB`;
const argOf = (f) => { const i = process.argv.indexOf(f); return i === -1 ? undefined : process.argv[i + 1]; };

if (!DB_NAME) die('DB_NAME is not set in back/.env');
if (!['127.0.0.1', 'localhost', '::1'].includes(DB_HOST)) {
  die(`DB_HOST is "${DB_HOST}" — this script only overwrites a local database.`);
}

// Gunzip the whole file and check the dump's last statement is there.
async function isComplete(file) {
  let tail = '';
  try {
    for await (const chunk of fs.createReadStream(file).pipe(zlib.createGunzip())) {
      tail = (tail + chunk.toString('latin1')).slice(-200);
    }
  } catch {
    return false;
  }
  return tail.trimEnd().endsWith(FOOTER);
}

// ---------------------------------------------------------------- download --
const client = new Client(60_000);
await client.access({
  host: ftp.host, port: ftp.port, user: ftp.user, password: ftp.password,
  secure: ftp.secure, secureOptions: { rejectUnauthorized: !!ftp.tlsStrict },
});

const wanted = argOf('--file');
// Names embed the server-local timestamp, so name order = age order.
const remote = (await client.list(REMOTE_DIR))
  .filter((f) => f.isFile && f.name.endsWith('.sql.gz') && (!wanted || f.name === wanted))
  .sort((a, b) => b.name.localeCompare(a.name));
if (!remote.length) die(wanted ? `${wanted} not found in ${REMOTE_DIR}` : `no backups in ${REMOTE_DIR}`);

fs.mkdirSync(LOCAL_DIR, { recursive: true });
let picked = null;
for (const f of remote.slice(0, 5)) {
  const local = path.join(LOCAL_DIR, f.name);
  if (fs.existsSync(local) && fs.statSync(local).size === f.size) {
    console.log(`  ${f.name}  already downloaded`);
  } else {
    client.trackProgress((info) => {
      process.stdout.write(`\r  downloading ${f.name}  ${mb(info.bytes)} / ${mb(f.size)}   `);
    });
    await client.downloadTo(local, `${REMOTE_DIR}/${f.name}`);
    client.trackProgress();
    console.log();
  }
  process.stdout.write('  verifying... ');
  if (await isComplete(local)) { console.log('ok'); picked = local; break; }
  console.log('INCOMPLETE dump, trying the previous one');
  fs.unlinkSync(local);
}
client.close();
if (!picked) die('no complete backup among the 5 newest');

// ------------------------------------------------------------------ import --
const conn = await mysql.createConnection({ host: DB_HOST, port: DB_PORT, user: DB_USER, password: DB_PASS });
const [[{ basedir, packet }]] = await conn.query('SELECT @@basedir AS basedir, @@global.max_allowed_packet AS packet');
const bin = ['mariadb.exe', 'mysql.exe', 'mariadb', 'mysql']
  .map((b) => path.join(basedir, 'bin', b))
  .find((p) => fs.existsSync(p));
if (!bin) { await conn.end(); die(`no mysql/mariadb client in ${basedir}/bin`); }

console.log(`  recreating local database \`${DB_NAME}\` on ${DB_HOST}:${DB_PORT}`);
await conn.query(`DROP DATABASE IF EXISTS \`${DB_NAME}\``);
await conn.query(`CREATE DATABASE \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
// Some prod rows are single INSERTs bigger than WAMP's 64 MB default (users.push_settings
// has a 70+ MB value), so lift the server limit to its 1 GB max for the import only.
await conn.query('SET GLOBAL max_allowed_packet = 1073741824');

console.log(`  importing ${path.basename(picked)}  (${path.basename(bin)})`);
const started = Date.now();
const proc = spawn(
  bin,
  ['-h', DB_HOST, '-P', String(DB_PORT), '-u', DB_USER, '--default-character-set=utf8mb4', '--max-allowed-packet=1G', DB_NAME],
  // stdout ignored: on error the client echoes the failed statement, which can be 70+ MB.
  { env: { ...process.env, MYSQL_PWD: DB_PASS }, stdio: ['pipe', 'ignore', 'pipe'] },
);
let stderr = '';
proc.stderr.on('data', (d) => { stderr = (stderr + d).slice(-2000); });
const exited = new Promise((res) => proc.on('close', res));
await pipeline(fs.createReadStream(picked), zlib.createGunzip(), proc.stdin).catch(() => {});
const code = await exited;
await conn.query(`SET GLOBAL max_allowed_packet = ${Number(packet)}`);
await conn.end();
if (code !== 0) die(`import failed (exit ${code}): ${stderr.trim().slice(0, 500)}\n    Local DB is partial, re-run to retry.`);

const verify = await mysql.createConnection({ host: DB_HOST, port: DB_PORT, user: DB_USER, password: DB_PASS, database: DB_NAME });
const [[{ n }]] = await verify.query('SELECT COUNT(*) AS n FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()');
const [[{ users }]] = await verify.query('SELECT COUNT(*) AS users FROM users');
await verify.end();
console.log(`\n  ✔ ${DB_NAME} now mirrors ${path.basename(picked)}: ${n} tables, ${users} users (${((Date.now() - started) / 1000).toFixed(0)}s)`);
console.log('    Local-only migrations apply on the next dev server start (npm run dev).');
