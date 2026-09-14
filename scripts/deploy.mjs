/**
 * Production backend FTP deployment and restart watcher with auto-versioning
 * and remote dependency cross-referencing.
 *
 * Direct FTP deployment to Plesk server:
 *   1. Connects to FTPS and cross-references local package.json dependencies against remote
 *      If new packages were installed locally, blocks deploy with instructions to install on server
 *   2. Bumps semantic version in package.json and generates version.json
 *   3. Generates the latest OpenAPI spec (swagger autogen) with new version
 *   4. Scans files respecting .gitignore and safety exclusions (.env, node_modules, etc.)
 *   5. Uploads changed/new files to the server via FTPS (basic-ftp)
 *   6. Restarts Phusion Passenger (touching tmp/restart.txt over FTP)
 *   7. Verifies the production API health endpoint responds with database connected and target version live
 *
 * Usage:
 *   npm run deploy            Upload changed files, bump patch version, restart server, verify health
 *   npm run deploy:dry        Dry run preview (upload nothing, no bump, no restart)
 *   npm run deploy:force      Re-upload all candidate files regardless of cached hash
 *   npm run deploy:restart    Restart the production server directly and verify health
 *
 * Flags:
 *   --dry-run, -n          Preview actions without uploading or restarting
 *   --force,   -f          Re-upload all files regardless of manifest/size match
 *   --restart-only         Only restart the server and verify health
 *   --no-restart           Upload files but skip triggering server restart
 *   --no-swagger           Skip running swagger autogen before deployment
 *   --no-bump              Skip auto-incrementing version in package.json
 *   --bump <type>          Bump type: patch (default), minor, or major
 *   --skip-deps-check      Bypass remote package.json dependency cross-reference check
 *   --verbose, -v          Enable detailed FTP command and response logging
 */
import { Client } from 'basic-ftp';
import cliProgress from 'cli-progress';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { Writable } from 'node:stream';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import ignore from 'ignore';

const execFileP = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

/* ------------------------------------------------------------------ colors --- */
const isColorSupported =
  !process.env.NO_COLOR && (Boolean(process.stdout.isTTY) || Boolean(process.env.FORCE_COLOR));

const c = {
  red: (s) => (isColorSupported ? `\x1b[31m${s}\x1b[0m` : s),
  green: (s) => (isColorSupported ? `\x1b[32m${s}\x1b[0m` : s),
  yellow: (s) => (isColorSupported ? `\x1b[33m${s}\x1b[0m` : s),
  cyan: (s) => (isColorSupported ? `\x1b[36m${s}\x1b[0m` : s),
  bold: (s) => (isColorSupported ? `\x1b[1m${s}\x1b[0m` : s),
  dim: (s) => (isColorSupported ? `\x1b[2m${s}\x1b[0m` : s),
  boldRed: (s) => (isColorSupported ? `\x1b[1;31m${s}\x1b[0m` : s),
  boldYellow: (s) => (isColorSupported ? `\x1b[1;33m${s}\x1b[0m` : s),
  boldGreen: (s) => (isColorSupported ? `\x1b[1;32m${s}\x1b[0m` : s),
  boldCyan: (s) => (isColorSupported ? `\x1b[1;36m${s}\x1b[0m` : s),
};

function printError(title, lines = []) {
  console.error('\n' + c.boldRed('========================================================================'));
  console.error(c.boldRed(`  ERROR: ${title}`));
  console.error(c.boldRed('========================================================================'));
  for (const line of lines) {
    console.error(`  ${line}`);
  }
  console.error(c.boldRed('========================================================================\n'));
}

function printWarning(title, lines = []) {
  console.warn('\n' + c.boldYellow('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'));
  console.warn(c.boldYellow(`  WARNING: ${title}`));
  console.warn(c.boldYellow('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'));
  for (const line of lines) {
    console.warn(`  ${line}`);
  }
  console.warn(c.boldYellow('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n'));
}

/* ------------------------------------------------------------------ args --- */
const argv = process.argv.slice(2);
const has = (...names) => names.some((n) => argv.includes(n));
const DRY_RUN = has('--dry-run', '-n');
const FORCE = has('--force', '-f');
const RESTART_ONLY = has('--restart-only');
const NO_RESTART = has('--no-restart');
const NO_SWAGGER = has('--no-swagger');
const NO_BUMP = has('--no-bump');
const SKIP_DEPS_CHECK = has('--skip-deps-check', '--ignore-deps');
const BACKUP_ONLY = has('--backup-only');
const NO_BACKUP = has('--no-backup', '--skip-backup');
const FULL_BACKUP = has('--full-backup');
const VERBOSE = has('--verbose', '-v');

const bumpIndex = argv.findIndex((x) => x === '--bump');
const BUMP_TYPE =
  bumpIndex !== -1 && argv[bumpIndex + 1] ? argv[bumpIndex + 1].toLowerCase() : 'patch';

/* ---------------------------------------------------------------- config --- */
const CONFIG_FILE = path.join(ROOT, 'deploy.config.json');
let fileCfg = {};
if (fs.existsSync(CONFIG_FILE)) {
  try {
    fileCfg = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  } catch (err) {
    die(`deploy.config.json is not valid JSON: ${err.message}`);
  }
} else {
  die('no deploy.config.json found. Create back/deploy.config.json with your FTP credentials.');
}

const ftpCfg = fileCfg.ftp || {};
const pick = (envKey, ftpKey, rootKey, fallback) => {
  if (process.env[envKey] !== undefined) return process.env[envKey];
  if (ftpCfg[ftpKey] !== undefined) return ftpCfg[ftpKey];
  if (fileCfg[rootKey] !== undefined) return fileCfg[rootKey];
  return fallback;
};
const asBool = (v, dflt) =>
  v === undefined || v === '' ? dflt : !/^(0|false|no|off)$/i.test(String(v));

const HOST = pick('FTP_HOST', 'host', 'host');
const PORT = Number(pick('FTP_PORT', 'port', 'port', 21));
const USER = pick('FTP_USER', 'user', 'user');
const PASSWORD = pick('FTP_PASSWORD', 'password', 'password');
const SECURE = /^implicit$/i.test(String(pick('FTP_SECURE', 'secure', 'secure', 'true')))
  ? 'implicit'
  : asBool(pick('FTP_SECURE', 'secure', 'secure', 'true'), true);
const TLS_STRICT = asBool(pick('FTP_TLS_STRICT', 'tlsStrict', 'tlsStrict', 'false'), false);
const REMOTE_ROOT =
  '/' + String(pick('FTP_REMOTE_DIR', 'remoteDir', 'remoteDir', '/')).replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
const RESTART_FILE =
  '/' + String(pick('FTP_RESTART_FILE', 'restartFile', 'restartFile', '/tmp/restart.txt')).replace(/\\/g, '/').replace(/^\/+/, '');
const API = (process.env.DEPLOY_API_BASE || fileCfg.apiBase || 'https://api.attlarp.gr').replace(/\/+$/, '');
const RESTART_EXPECT_S = Number(fileCfg.expectRestartSec || 25);
const WAIT_TIMEOUT_MS = Number(fileCfg.waitTimeoutSec || 120) * 1000;

function die(msg, lines = []) {
  printError(msg, lines);
  process.exit(1);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const mb = (b) => `${(b / 1048576).toFixed(2)} MB`;
const kb = (b) => `${(b / 1024).toFixed(1)} KB`;
const nowIso = () => new Date().toISOString();

function bumpVersion(current, type = 'patch') {
  const clean = String(current || '1.0.0').trim().replace(/^v/i, '');
  const parts = clean.split('.').map((p) => parseInt(p, 10));
  while (parts.length < 3) parts.push(0);
  let [major, minor, patch] = parts.map((n) => (isNaN(n) ? 0 : n));
  if (type === 'major') {
    major += 1;
    minor = 0;
    patch = 0;
  } else if (type === 'minor') {
    minor += 1;
    patch = 0;
  } else {
    patch += 1;
  }
  return `${major}.${minor}.${patch}`;
}

/* ------------------------------------------------------------- preflight --- */
for (const [k, v] of Object.entries({ host: HOST, user: USER, password: PASSWORD })) {
  if (!v) die(`"${k}" is empty in deploy.config.json or FTP_* environment variables.`);
}

/* --------------------------------------------------------- restart-only --- */
if (RESTART_ONLY) {
  await runRestartFlow();
  process.exit(0);
}

/* -------------------------------------------------- read local package.json --- */
const PKG_FILE = path.join(ROOT, 'package.json');
let pkgData = {};
try {
  pkgData = JSON.parse(fs.readFileSync(PKG_FILE, 'utf8'));
} catch (err) {
  die(`Could not read package.json: ${err.message}`);
}

const currentVersion = pkgData.version || '1.0.0';
const localDependencies = pkgData.dependencies || {};

/* ------------------------------------------------------------- ftp client -- */
const client = new Client(30_000);
client.ftp.verbose = VERBOSE;

const remotePathFor = (rel) => path.posix.join(REMOTE_ROOT || '/', rel);

try {
  process.stdout.write(`  connecting to ${c.boldCyan(`${USER}@${HOST}:${PORT}`)}... `);
  await client.access({
    host: HOST,
    port: PORT,
    user: USER,
    password: PASSWORD,
    secure: SECURE,
    secureOptions: { rejectUnauthorized: TLS_STRICT },
  });
  console.log(c.green('connected'));
} catch (err) {
  die(`FTP connection failed: ${err.message}`, [
    'Check host, user, password, port, and TLS options in deploy.config.json.',
  ]);
}

/* ------------------------------- cross-reference remote package.json --- */
async function fetchRemotePackageJson() {
  const remotePkgPath = remotePathFor('package.json');
  const chunks = [];
  const writer = new Writable({
    write(chunk, encoding, cb) {
      chunks.push(chunk);
      cb();
    }
  });

  try {
    await client.downloadTo(writer, remotePkgPath);
    const content = Buffer.concat(chunks).toString('utf8');
    return JSON.parse(content);
  } catch (err) {
    return null;
  }
}

if (!SKIP_DEPS_CHECK) {
  process.stdout.write('  cross referencing dependencies with remote server... ');
  const remotePkg = await fetchRemotePackageJson();

  if (!remotePkg) {
    console.log(c.yellow('remote package.json not found (skipped diff)'));
  } else {
    const remoteDependencies = remotePkg.dependencies || {};
    const missingOnServer = [];
    const updatedOnServer = [];

    for (const [pkgName, localVer] of Object.entries(localDependencies)) {
      if (!remoteDependencies[pkgName]) {
        missingOnServer.push({ name: pkgName, localVersion: localVer });
      } else if (remoteDependencies[pkgName] !== localVer) {
        updatedOnServer.push({
          name: pkgName,
          localVersion: localVer,
          remoteVersion: remoteDependencies[pkgName],
        });
      }
    }

    if (missingOnServer.length > 0) {
      console.log(c.boldRed('FAILED'));
      client.close();
      printError('DEPLOY BLOCKED: New packages detected in local package.json', [
        c.boldYellow('The following packages are in your local dependencies but NOT installed on production:'),
        '',
        ...missingOnServer.map(
          (item) => `  * ${c.boldCyan(item.name)}: local requires ${c.bold(item.localVersion)} (remote: not installed)`
        ),
        '',
        c.yellow('Because node_modules is ignored during upload, deploying now would crash the production server'),
        c.yellow('when Node tries to require missing dependencies.'),
        '',
        c.bold('ACTION REQUIRED ON SERVER:'),
        '  1. Log into your production server (via Plesk Terminal or SSH)',
        '  2. In the application root directory, install the new packages:',
        `     ${c.boldCyan(`npm install ${missingOnServer.map((item) => `${item.name}@${item.localVersion}`).join(' ')}`)}`,
        '  3. Then re-run: npm run deploy',
        '',
        c.dim('To bypass this safeguard in an emergency, run with flag: --skip-deps-check'),
      ]);
      process.exit(1);
    }

    if (updatedOnServer.length > 0) {
      console.log(c.yellow('matches with version differences'));
      printWarning('Existing dependencies have version differences on remote server', [
        ...updatedOnServer.map(
          (item) => `  * ${item.name}: local ${item.localVersion}, remote ${item.remoteVersion}`
        ),
        'Remember to run npm install on the server if features depend on updated versions.',
      ]);
    } else {
      console.log(c.green(`ok (${Object.keys(localDependencies).length} packages in sync)`));
    }
  }
} else {
  printWarning('Skipped remote dependency cross reference check (--skip-deps-check flag set)');
}

/* ------------------------------------------- production database backup --- */
async function triggerProductionBackup({ full = false } = {}) {
  const token = crypto.randomBytes(32).toString('hex');
  const payload = `${token}:${Date.now()}`;
  const remoteTokenPath = remotePathFor('tmp/deploy-backup.token');

  process.stdout.write('  authorizing backup token via FTPS... ');
  try {
    const dir = path.posix.dirname(remoteTokenPath);
    if (dir && dir !== '/') {
      await client.ensureDir(dir);
      await client.cd(REMOTE_ROOT || '/');
    }
    const { Readable } = await import('node:stream');
    await client.uploadFrom(Readable.from(payload), remoteTokenPath);
    console.log(c.green('authorized'));
  } catch (err) {
    console.log(c.yellow(`warning: could not write token file (${err.message})`));
    return { ok: false, error: err.message };
  }

  process.stdout.write(`  running database backup on production (${full ? 'FULL' : 'game data'})... `);
  const streamUrl = `${API}/api/admin/backup/stream?full=${full ? 'true' : 'false'}`;

  try {
    const res = await fetch(streamUrl, {
      headers: {
        'x-deploy-token': token,
        'Accept': 'text/event-stream',
      },
    });

    if (res.status === 401 || res.status === 403) {
      console.log(c.yellow('skipped (server requires new code update)'));
      printWarning('Pre deploy database backup skipped on first run', [
        'The remote server is running an earlier release without x-deploy-token support.',
        'This deployment will install the required route on production.',
        'Future deployments and "npm run deploy:backup" will perform the backup automatically.',
      ]);
      return { ok: false, skipped: true };
    }

    if (!res.ok) {
      console.log(c.boldRed(`HTTP ${res.status}`));
      const text = await res.text();
      printWarning('Database backup returned an unexpected response', [
        `Status: ${res.status} ${res.statusText}`,
        `Response: ${text.slice(0, 300)}`,
      ]);
      return { ok: false, error: text };
    }

    console.log(c.green('started'));

    const decoder = new TextDecoder('utf-8');
    const useBars = Boolean(process.stdout.isTTY);
    let bar = null;
    let totalTables = 52;
    let currentTable = 'initializing...';

    if (useBars) {
      bar = new cliProgress.SingleBar(
        {
          format: '  backup: [{bar}] {percentage}% | {value}/{total} tables | ' + c.dim('{table}'),
          barCompleteChar: '█',
          barIncompleteChar: '░',
          hideCursor: true,
          clearOnComplete: false,
        },
        cliProgress.Presets.shades_grey,
      );
      bar.start(totalTables, 0, { table: currentTable });
    }

    let backupFile = '';
    let backupMessage = '';
    let isFailed = false;
    let buffer = '';

    for await (const chunk of res.body) {
      buffer += typeof chunk === 'string' ? chunk : decoder.decode(chunk, { stream: true });
      const parts = buffer.split(/\r?\n\r?\n/);
      buffer = parts.pop() || '';

      for (const block of parts) {
        let eventName = 'message';
        let dataStr = '';
        for (const rawLine of block.split(/\r?\n/)) {
          const line = rawLine.trim();
          if (line.startsWith('event:')) eventName = line.slice(6).trim();
          else if (line.startsWith('data:')) dataStr = line.slice(5).trim();
        }

        if (!dataStr) continue;
        let parsed = null;
        try {
          parsed = JSON.parse(dataStr);
        } catch {
          parsed = dataStr;
        }

        if (eventName === 'start' && parsed && typeof parsed === 'object') {
          if (parsed.total) {
            totalTables = parsed.total;
            if (bar) bar.setTotal(totalTables);
          }
        } else if (eventName === 'log' && typeof parsed === 'string') {
          const match = parsed.match(/^([a-zA-Z0-9_]+):/);
          if (match) {
            currentTable = match[1];
            if (bar) bar.update({ table: currentTable });
          }
        } else if (eventName === 'progress' && parsed && typeof parsed === 'object') {
          if (parsed.total && parsed.total !== totalTables) {
            totalTables = parsed.total;
            if (bar) bar.setTotal(totalTables);
          }
          if (bar) {
            bar.update(parsed.current, { table: currentTable || 'exporting' });
          } else {
            process.stdout.write(`\r  backup: ${parsed.current} / ${parsed.total} tables (${currentTable})`);
          }
        } else if (eventName === 'done' && parsed && typeof parsed === 'object') {
          backupMessage = parsed.message || '';
          backupFile = parsed.file || '';
          if (parsed.failed) isFailed = true;
        }
      }
    }

    if (buffer.trim()) {
      let eventName = 'message';
      let dataStr = '';
      for (const rawLine of buffer.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (line.startsWith('event:')) eventName = line.slice(6).trim();
        else if (line.startsWith('data:')) dataStr = line.slice(5).trim();
      }
      if (dataStr) {
        try {
          const parsed = JSON.parse(dataStr);
          if (eventName === 'done' && parsed && typeof parsed === 'object') {
            backupMessage = parsed.message || '';
            backupFile = parsed.file || '';
            if (parsed.failed) isFailed = true;
          }
        } catch {}
      }
    }

    if (bar) {
      bar.update(totalTables, { table: 'complete' });
      bar.stop();
      process.stdout.write('\n');
    } else {
      process.stdout.write('\n');
    }

    if (isFailed) {
      console.log(`  ${c.boldRed('backup failed on server:')} ${backupMessage}`);
      return { ok: false, error: backupMessage };
    }

    if (!backupFile) {
      try {
        const backupEntries = await client.list(remotePathFor('backups'));
        const sqlGzFiles = backupEntries
          .filter((f) => f.name && f.name.endsWith('.sql.gz'))
          .sort((a, b) => {
            const timeA = a.modifiedAt ? new Date(a.modifiedAt).getTime() : (a.rawModifiedAt ? new Date(a.rawModifiedAt).getTime() : 0);
            const timeB = b.modifiedAt ? new Date(b.modifiedAt).getTime() : (b.rawModifiedAt ? new Date(b.rawModifiedAt).getTime() : 0);
            if (timeB !== timeA) return timeB - timeA;
            return b.name.localeCompare(a.name);
          });
        if (sqlGzFiles.length > 0) {
          const newest = sqlGzFiles[0];
          backupFile = newest.name;
          const mb = (newest.size / (1024 * 1024)).toFixed(1);
          if (!backupMessage) {
            backupMessage = `saved ${mb} MB`;
          }
        }
      } catch {}
    }

    console.log(
      `  ${c.boldGreen('backup complete:')} ${backupFile ? c.boldCyan(backupFile) : ''} ${backupMessage ? c.dim(`(${backupMessage})`) : ''}`
    );
    return { ok: true, file: backupFile, message: backupMessage };
  } catch (err) {
    console.log(c.boldYellow(`\n  warning: backup stream interrupted (${err.message})`));
    return { ok: false, error: err.message };
  }
}

if (BACKUP_ONLY) {
  console.log(
    `\n  ${c.boldYellow('DATABASE BACKUP:')} running ${FULL_BACKUP ? 'FULL' : 'game data'} backup on production\n` +
      `  api:    ${c.boldCyan(API)}\n` +
      `  target: ${c.cyan(`${USER}@${HOST}:${PORT}${REMOTE_ROOT || '/'}`)}\n`,
  );
  await triggerProductionBackup({ full: FULL_BACKUP });
  client.close();
} else {

if (!NO_BACKUP && !DRY_RUN) {
  await triggerProductionBackup({ full: FULL_BACKUP });
} else if (DRY_RUN && !NO_BACKUP) {
  console.log(`  dry run: would execute database backup on production (${FULL_BACKUP ? 'FULL' : 'game data'})`);
}

/* -------------------------------------------------- auto-version bump --- */
let targetVersion = currentVersion;

if (!NO_BUMP && !DRY_RUN) {
  targetVersion = bumpVersion(currentVersion, BUMP_TYPE);
  pkgData.version = targetVersion;
  fs.writeFileSync(PKG_FILE, JSON.stringify(pkgData, null, 2) + '\n');

  const versionRecord = {
    version: targetVersion,
    bump: BUMP_TYPE,
    deployed_at: nowIso(),
    environment: 'production',
  };
  fs.writeFileSync(path.join(ROOT, 'version.json'), JSON.stringify(versionRecord, null, 2) + '\n');
  console.log(`  version: ${c.dim(currentVersion)} updated to ${c.boldCyan(targetVersion)}`);
} else if (DRY_RUN && !NO_BUMP) {
  const previewVersion = bumpVersion(currentVersion, BUMP_TYPE);
  console.log(`  dry run: version would update from ${c.dim(currentVersion)} to ${c.boldCyan(previewVersion)}`);
} else {
  console.log(`  version: ${c.boldCyan(currentVersion)} (auto bump skipped)`);
}

/* ----------------------------------------------------- swagger generator --- */
if (!NO_SWAGGER && !DRY_RUN) {
  try {
    process.stdout.write('  generating swagger spec... ');
    await execFileP('node', ['swagger-autogen.js'], { cwd: ROOT });
    console.log(c.green('done'));
  } catch (err) {
    console.log(c.yellow(`skipped (warning: ${err.message})`));
  }
}

/* --------------------------------------------------------- scan files --- */
const HARD_IGNORES = [
  '.git',
  '.git/**',
  'node_modules',
  'node_modules/**',
  '.env',
  '.env.*',
  '**/.env*',
  'deploy.config.json',
  '.deploy-manifest.json',
  '.restart.tmp',
  'backups',
  'backups/**',
  'logs',
  'logs/**',
  'dist',
  'dist/**',
  'build',
  'build/**',
  'coverage',
  'coverage/**',
  '.vscode',
  '.vscode/**',
  '.idea',
  '.idea/**',
  'tmp',
  'tmp/**',
  '*.log',
  '*.tmp',
  '.DS_Store',
  'Thumbs.db',
];

const ig = ignore();
const gitignorePath = path.join(ROOT, '.gitignore');
if (fs.existsSync(gitignorePath)) {
  ig.add(fs.readFileSync(gitignorePath, 'utf8'));
}
ig.add(HARD_IGNORES);

async function walk(dir, baseDir) {
  const entries = await fsp.readdir(dir, { withFileTypes: true });
  const results = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    const rel = path.relative(baseDir, full).split(path.sep).join('/');
    const relForIgnore = entry.isDirectory() ? `${rel}/` : rel;

    if (ig.ignores(relForIgnore) || ig.ignores(rel)) continue;

    if (entry.isDirectory()) {
      results.push(...(await walk(full, baseDir)));
    } else if (entry.isFile()) {
      const stat = await fsp.stat(full);
      results.push({
        rel,
        local: full,
        size: stat.size,
        mtime: stat.mtimeMs,
      });
    }
  }
  return results;
}

const localFiles = await walk(ROOT, ROOT);
if (localFiles.length === 0) die('No backend files found to deploy.');

// Local manifest for accurate delta caching
const MANIFEST_FILE = path.join(ROOT, '.deploy-manifest.json');
let manifest = {};
if (fs.existsSync(MANIFEST_FILE) && !FORCE) {
  try {
    manifest = JSON.parse(fs.readFileSync(MANIFEST_FILE, 'utf8'));
  } catch {
    manifest = {};
  }
}

// Compute sha1 hash for each file
async function fileHash(filePath) {
  const content = await fsp.readFile(filePath);
  return crypto.createHash('sha1').update(content).digest('hex');
}

console.log(
  `\n  ${DRY_RUN ? c.boldYellow('DRY RUN: ') : ''}deploying backend files\n` +
    `  version: ${c.boldCyan(targetVersion)}\n` +
    `  source:  ${c.dim(ROOT)}\n` +
    `  target:  ${c.cyan(`${USER}@${HOST}:${PORT}${REMOTE_ROOT || '/'}`)} (${SECURE === true ? 'FTPS' : SECURE === 'implicit' ? 'FTPS implicit' : 'plain FTP'})\n` +
    `  api:     ${c.cyan(API)}\n`,
);

let uploaded = 0;
let skipped = 0;
let sentBytes = 0;
const startedAt = Date.now();

try {
  // Query remote directory listing per folder
  process.stdout.write('  checking remote files... ');
  const remoteSizes = new Map();
  const listedDirs = new Set();
  async function remoteSizeOf(remoteAbs) {
    const dir = path.posix.dirname(remoteAbs);
    if (!listedDirs.has(dir)) {
      listedDirs.add(dir);
      try {
        for (const item of await client.list(dir)) {
          if (item.isFile) remoteSizes.set(path.posix.join(dir, item.name), item.size);
        }
      } catch {
        /* remote directory does not exist yet */
      }
    }
    return remoteSizes.get(remoteAbs) ?? -1;
  }

  const plan = [];
  const currentHashes = new Map();

  for (const f of localFiles) {
    const hash = await fileHash(f.local);
    currentHashes.set(f.rel, hash);
    const remote = remotePathFor(f.rel);
    const remoteSize = !FORCE ? await remoteSizeOf(remote) : -1;

    const matchesRemote = remoteSize === f.size;
    const matchesManifest = manifest[f.rel] && manifest[f.rel].hash === hash;

    if (!FORCE && matchesRemote && matchesManifest) {
      skipped++;
    } else {
      plan.push({ ...f, remote, hash });
    }
  }

  console.log(`${c.green(`${skipped} unchanged`)}, ${c.boldCyan(`${plan.length} to upload`)}\n`);

  const plannedBytes = plan.reduce((n, f) => n + f.size, 0);

  if (plan.length === 0) {
    console.log('  nothing to upload: remote files are already up to date.\n');
  } else if (DRY_RUN) {
    for (const f of plan) {
      console.log(`  would upload: ${f.rel} (${kb(f.size)})`);
    }
    console.log(`\n  dry run total: ${plan.length} files, ${mb(plannedBytes)}\n`);
  } else {
    const useBars = Boolean(process.stdout.isTTY);
    let bar = null;
    if (useBars) {
      bar = new cliProgress.SingleBar(
        {
          format: '  uploading: [{bar}] {percentage}% | {value_mb}/{total_mb} MB | ' + c.dim('{file}'),
          barCompleteChar: '█',
          barIncompleteChar: '░',
          hideCursor: true,
          clearOnComplete: false,
        },
        cliProgress.Presets.shades_grey,
      );
      bar.start(1000, 0, {
        value_mb: '0.00',
        total_mb: (plannedBytes / 1048576).toFixed(2),
        file: 'starting...',
      });
    }

    const ensured = new Set();
    let currentUploadedBytes = 0;

    for (const f of plan) {
      const dir = path.posix.dirname(f.remote);
      if (dir && dir !== '/' && !ensured.has(dir)) {
        await client.ensureDir(dir);
        await client.cd(REMOTE_ROOT || '/');
        ensured.add(dir);
      }

      if (!useBars) {
        process.stdout.write(`  uploading: ${f.rel} ... `);
      } else if (bar) {
        const base = currentUploadedBytes;
        client.trackProgress((info) => {
          const currentTransferred = base + (info.bytesOverall || 0);
          const frac = plannedBytes > 0 ? Math.min(1, currentTransferred / plannedBytes) : 1;
          bar.update(Math.round(frac * 1000), {
            value_mb: (currentTransferred / 1048576).toFixed(2),
            total_mb: (plannedBytes / 1048576).toFixed(2),
            file: f.rel,
          });
        });
      }

      await client.uploadFrom(f.local, f.remote);

      if (useBars && bar) {
        client.trackProgress();
      }

      uploaded++;
      sentBytes += f.size;
      currentUploadedBytes += f.size;
      manifest[f.rel] = { hash: f.hash, size: f.size, uploadedAt: nowIso() };

      if (useBars && bar) {
        const frac = plannedBytes > 0 ? Math.min(1, currentUploadedBytes / plannedBytes) : 1;
        bar.update(Math.round(frac * 1000), {
          value_mb: (currentUploadedBytes / 1048576).toFixed(2),
          total_mb: (plannedBytes / 1048576).toFixed(2),
          file: f.rel,
        });
      } else {
        console.log(c.green('done'));
      }
    }

    if (useBars && bar) {
      bar.update(1000, {
        value_mb: (plannedBytes / 1048576).toFixed(2),
        total_mb: (plannedBytes / 1048576).toFixed(2),
        file: 'complete',
      });
      bar.stop();
      process.stdout.write('\n');
    }

    // Save updated manifest
    try {
      fs.writeFileSync(MANIFEST_FILE, JSON.stringify(manifest, null, 2));
    } catch {
      /* non-fatal */
    }
  }
} catch (err) {
  client.close();
  die(`deploy upload failed: ${err.message}`);
}

client.close();

const uploadSecs = ((Date.now() - startedAt) / 1000).toFixed(1);
console.log(
  `  upload complete: ` +
    `${c.boldGreen(`${uploaded} uploaded`)} (${mb(sentBytes)}), ${c.green(`${skipped} unchanged`)}, ${uploadSecs}s\n`,
);

/* ----------------------------------------------------- server restart --- */
if (DRY_RUN || NO_RESTART) {
  if (NO_RESTART) console.log('  server restart skipped (--no-restart flag set).\n');
  process.exit(0);
}

await runRestartFlow(targetVersion);

/* ------------------------------------------------------------- helpers --- */
async function health() {
  try {
    const r = await fetch(`${API}/api/health?_=${Date.now()}`, {
      headers: { accept: 'application/json' },
    });
    if (!r.ok) return null;
    const b = await r.json();
    return {
      ok: b.ok === true,
      db: Boolean(b.db),
      version: b.version || null,
      uptime: b.uptime_sec ?? 0,
      startedAt: b.started_at,
      env: b.env || 'unknown',
    };
  } catch {
    return null;
  }
}

function restarted(base, h) {
  if (!h) return false;
  if (!base) return h.ok;
  if (base.startedAt && h.startedAt) return h.startedAt !== base.startedAt;
  return h.uptime < base.uptime;
}

async function waitFor(startedAtMs, maxMs, check) {
  while (Date.now() - startedAtMs < maxMs) {
    let done = false;
    try {
      done = await check();
    } catch {
      /* ignore poll errors */
    }
    if (done) return true;
    await sleep(2000);
  }
  return false;
}

function mkRestartBar(expectS = 25) {
  const tty = Boolean(process.stdout.isTTY);
  let b = null;
  if (tty) {
    b = new cliProgress.SingleBar(
      {
        format: '  restarting: [{bar}] {pct}% | {note}',
        barCompleteChar: '█',
        barIncompleteChar: '░',
        hideCursor: true,
        linewrap: false,
      },
      cliProgress.Presets.shades_grey,
    );
    b.start(1000, 0, { pct: '0', note: 'touching restart file' });
  } else {
    console.log('  restarting server...');
  }
  let lastNote = '';
  return {
    tick(elapsedMs, note) {
      lastNote = note || lastNote;
      const frac = Math.min(0.96, elapsedMs / 1000 / expectS);
      if (tty) {
        b.update(Math.round(frac * 1000), {
          pct: String(Math.round(frac * 100)),
          note: lastNote,
        });
      } else {
        process.stdout.write(`    ${Math.round(elapsedMs / 1000)}s: ${lastNote}\n`);
      }
    },
    done(good) {
      if (tty) {
        b.update(1000, {
          pct: good ? '100' : 'timed out',
          note: good ? lastNote : 'timed out',
        });
        b.stop();
        process.stdout.write('\n');
      } else {
        console.log(`    ${good ? 'restart verified' : 'timed out'}: ${lastNote}`);
      }
    },
  };
}

async function touchRestartFile() {
  const cFtp = new Client(20_000);
  const tmpFile = path.join(ROOT, '.restart.tmp');
  try {
    await cFtp.access({
      host: HOST,
      port: PORT,
      user: USER,
      password: PASSWORD,
      secure: SECURE,
      secureOptions: { rejectUnauthorized: TLS_STRICT },
    });
    await cFtp.ensureDir(path.posix.dirname(RESTART_FILE));
    await cFtp.cd(REMOTE_ROOT || '/');
    fs.writeFileSync(tmpFile, `restart ${nowIso()}\n`);
    await cFtp.uploadFrom(tmpFile, RESTART_FILE);
  } finally {
    cFtp.close();
    try {
      fs.unlinkSync(tmpFile);
    } catch {
      /* ignore */
    }
  }
}

async function runRestartFlow(expectedVersion = null) {
  const baseHealth = await health();
  console.log(
    `  api baseline: ${baseHealth ? `v${baseHealth.version || 'legacy'}, up ${baseHealth.uptime}s (started ${baseHealth.startedAt})` : 'not responding'}`,
  );
  process.stdout.write('  touching restart file over FTP... ');
  await touchRestartFile();
  console.log(c.green('done'));

  const restartBar = mkRestartBar(RESTART_EXPECT_S);
  const t0 = Date.now();

  const restartSuccess = await waitFor(t0, WAIT_TIMEOUT_MS, async () => {
    const h = await health();
    const isRestarted = restarted(baseHealth, h);
    const isTargetVer = !expectedVersion || (h && h.version === expectedVersion);
    const back = h && h.ok && h.db && isRestarted && isTargetVer;
    const note = h
      ? back
        ? `v${h.version || expectedVersion}, up ${h.uptime}s, db: ok`
        : `restarting, v${h.version || '...'}, up ${h.uptime}s`
      : 'restarting...';
    restartBar.tick(Date.now() - t0, note);
    return back;
  });

  restartBar.done(restartSuccess);

  const finalHealth = await health();
  const totalElapsed = Math.round((Date.now() - t0) / 1000);

  if (restartSuccess && finalHealth) {
    console.log(
      '\n' +
        c.boldGreen('========================================================================\n') +
        c.boldGreen('  DEPLOY SUCCESSFUL\n') +
        c.boldGreen('========================================================================\n') +
        `  ${c.bold('version:')}        ${c.boldCyan(finalHealth.version || expectedVersion || '1.0.0')}\n` +
        `  ${c.bold('server restart:')} ${c.green(`verified in ${totalElapsed}s`)}\n` +
        `  ${c.bold('health status:')}  ${c.boldGreen('ok')}\n` +
        `  ${c.bold('database:')}       ${c.boldGreen('ok')}\n` +
        `  ${c.bold('uptime:')}         ${finalHealth.uptime}s\n` +
        `  ${c.bold('started at:')}     ${finalHealth.startedAt}\n` +
        `  ${c.bold('environment:')}    ${finalHealth.env}\n` +
        `  ${c.bold('live url:')}       ${c.cyan(`${API}/api/health`)}\n` +
        c.boldGreen('========================================================================\n'),
    );
  } else {
    printError('Server did not report healthy restart', [
      `Waited ${totalElapsed}s without confirmation of healthy restart.`,
      `Check ${API}/api/health and Plesk Passenger error logs.`,
    ]);
    process.exit(2);
  }
}
}

