/**
 * Production backend FTP deployment and restart watcher with auto-versioning.
 *
 * Direct FTP deployment to Plesk server:
 *   1. Bumps semantic version in package.json and generates version.json
 *   2. Generates the latest OpenAPI spec (swagger autogen) with new version
 *   3. Scans files respecting .gitignore and safety exclusions (.env, node_modules, etc.)
 *   4. Uploads changed/new files to the server via FTPS (basic-ftp)
 *   5. Restarts Phusion Passenger (touching tmp/restart.txt over FTP)
 *   6. Verifies the production API health endpoint responds with database connected and target version live
 *
 * Usage:
 *   npm run deploy            Upload changed files, bump patch version, restart server, verify health
 *   npm run deploy:dry        Dry run preview (upload nothing, no bump, no restart)
 *   npm run deploy:force      Re-upload all candidate files regardless of cached hash
 *   npm run deploy:restart    Restart the production server directly and verify health
 *
 * Flags:
 *   --dry-run, -n    Preview actions without uploading or restarting
 *   --force,   -f    Re-upload all files regardless of manifest/size match
 *   --restart-only   Only restart the server and verify health
 *   --no-restart     Upload files but skip triggering server restart
 *   --no-swagger     Skip running swagger autogen before deployment
 *   --no-bump        Skip auto-incrementing version in package.json
 *   --bump <type>    Bump type: patch (default), minor, or major
 *   --verbose, -v    Enable detailed FTP command and response logging
 */
import { Client } from 'basic-ftp';
import cliProgress from 'cli-progress';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import ignore from 'ignore';

const execFileP = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');

/* ------------------------------------------------------------------ args --- */
const argv = process.argv.slice(2);
const has = (...names) => names.some((n) => argv.includes(n));
const DRY_RUN = has('--dry-run', '-n');
const FORCE = has('--force', '-f');
const RESTART_ONLY = has('--restart-only');
const NO_RESTART = has('--no-restart');
const NO_SWAGGER = has('--no-swagger');
const NO_BUMP = has('--no-bump');
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

function die(msg) {
  console.error(`\n  deploy error: ${msg}\n`);
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

/* -------------------------------------------------- auto-version bump --- */
const PKG_FILE = path.join(ROOT, 'package.json');
let pkgData = {};
try {
  pkgData = JSON.parse(fs.readFileSync(PKG_FILE, 'utf8'));
} catch (err) {
  die(`Could not read package.json: ${err.message}`);
}

const currentVersion = pkgData.version || '1.0.0';
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
  console.log(`\n  version: updated from ${currentVersion} to ${targetVersion}`);
} else if (DRY_RUN && !NO_BUMP) {
  const previewVersion = bumpVersion(currentVersion, BUMP_TYPE);
  console.log(`\n  dry run: version would update from ${currentVersion} to ${previewVersion}`);
} else {
  console.log(`\n  version: ${currentVersion} (auto bump skipped)`);
}

/* ----------------------------------------------------- swagger generator --- */
if (!NO_SWAGGER && !DRY_RUN) {
  try {
    process.stdout.write('  generating swagger spec... ');
    await execFileP('node', ['swagger-autogen.js'], { cwd: ROOT });
    console.log('done');
  } catch (err) {
    console.log(`skipped (warning: ${err.message})`);
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

/* ------------------------------------------------------------- ftp client -- */
const client = new Client(30_000);
client.ftp.verbose = VERBOSE;

const remotePathFor = (rel) => path.posix.join(REMOTE_ROOT || '/', rel);

console.log(
  `\n  ${DRY_RUN ? 'DRY RUN: ' : ''}deploying backend files\n` +
    `  version: ${targetVersion}\n` +
    `  source:  ${ROOT}\n` +
    `  target:  ${USER}@${HOST}:${PORT}${REMOTE_ROOT || '/'} (${SECURE === true ? 'FTPS' : SECURE === 'implicit' ? 'FTPS implicit' : 'plain FTP'})\n` +
    `  api:     ${API}\n`,
);

let uploaded = 0;
let skipped = 0;
let sentBytes = 0;
const startedAt = Date.now();

try {
  await client.access({
    host: HOST,
    port: PORT,
    user: USER,
    password: PASSWORD,
    secure: SECURE,
    secureOptions: { rejectUnauthorized: TLS_STRICT },
  });

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

  console.log(`${skipped} unchanged, ${plan.length} to upload\n`);

  const plannedBytes = plan.reduce((n, f) => n + f.size, 0);

  if (plan.length === 0) {
    console.log('  nothing to upload: remote files are already up to date.\n');
  } else if (DRY_RUN) {
    for (const f of plan) {
      console.log(`  would upload: ${f.rel} (${kb(f.size)})`);
    }
    console.log(`\n  dry run total: ${plan.length} files, ${mb(plannedBytes)}\n`);
  } else {
    const useBars = process.stdout.isTTY;
    const bars = useBars
      ? new cliProgress.MultiBar(
          {
            format: '  {bar} {percentage}% | {value_mb}/{total_mb} MB | {name}',
            barCompleteChar: '█',
            barIncompleteChar: '░',
            hideCursor: true,
            clearOnComplete: false,
            autopadding: true,
          },
          cliProgress.Presets.shades_grey,
        )
      : null;

    const fmtBar = (b, val, total, name) =>
      b?.update(val, {
        name,
        value_mb: (val / 1048576).toFixed(2),
        total_mb: (total / 1048576).toFixed(2),
      });

    const overall = bars?.create(plannedBytes, 0, {
      name: 'TOTAL',
      value_mb: '0.00',
      total_mb: (plannedBytes / 1048576).toFixed(2),
    });

    const ensured = new Set();
    let fileBar = null;
    let currentRel = '';
    let currentSize = 0;
    let baseBytes = 0;

    client.trackProgress((info) => {
      if (info.type !== 'upload') return;
      const n = Math.min(info.bytes, currentSize || info.bytes);
      fmtBar(fileBar, n, currentSize || info.bytes, currentRel);
      fmtBar(overall, baseBytes + n, plannedBytes, 'TOTAL');
    });

    for (const f of plan) {
      currentRel = f.rel;
      currentSize = f.size;
      const dir = path.posix.dirname(f.remote);
      if (dir && dir !== '/' && !ensured.has(dir)) {
        await client.ensureDir(dir);
        await client.cd(REMOTE_ROOT || '/');
        ensured.add(dir);
      }

      if (useBars) {
        fileBar = bars.create(f.size, 0, {
          name: f.rel,
          value_mb: '0.00',
          total_mb: (f.size / 1048576).toFixed(2),
        });
      } else {
        process.stdout.write(`  uploading: ${f.rel} ... `);
      }

      await client.uploadFrom(f.local, f.remote);

      uploaded++;
      sentBytes += f.size;
      baseBytes += f.size;
      manifest[f.rel] = { hash: f.hash, size: f.size, uploadedAt: nowIso() };

      if (useBars) {
        fmtBar(fileBar, f.size, f.size, f.rel);
        fmtBar(overall, baseBytes, plannedBytes, 'TOTAL');
        bars.remove(fileBar);
        fileBar = null;
      } else {
        console.log('done');
      }
    }

    client.trackProgress();
    fmtBar(overall, plannedBytes, plannedBytes, 'TOTAL');
    bars?.stop();

    // Save updated manifest
    try {
      fs.writeFileSync(MANIFEST_FILE, JSON.stringify(manifest, null, 2));
    } catch {
      /* non-fatal */
    }
  }
} catch (err) {
  client.trackProgress?.();
  console.error(`\n  deploy upload failed: ${err.message}\n`);
  client.close();
  process.exit(1);
}

client.close();

const uploadSecs = ((Date.now() - startedAt) / 1000).toFixed(1);
console.log(
  `\n  upload complete: ` +
    `${uploaded} uploaded (${mb(sentBytes)}), ${skipped} unchanged, ${uploadSecs}s\n`,
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
      db: !!b.db,
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
  const tty = process.stdout.isTTY;
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
      } else {
        console.log(`    ${good ? 'restart verified' : 'timed out'}: ${lastNote}`);
      }
    },
  };
}

async function touchRestartFile() {
  const c = new Client(20_000);
  const tmpFile = path.join(ROOT, '.restart.tmp');
  try {
    await c.access({
      host: HOST,
      port: PORT,
      user: USER,
      password: PASSWORD,
      secure: SECURE,
      secureOptions: { rejectUnauthorized: TLS_STRICT },
    });
    await c.ensureDir(path.posix.dirname(RESTART_FILE));
    await c.cd(REMOTE_ROOT || '/');
    fs.writeFileSync(tmpFile, `restart ${nowIso()}\n`);
    await c.uploadFrom(tmpFile, RESTART_FILE);
  } finally {
    c.close();
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
  console.log('done');

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
      `\n  DEPLOY SUCCESSFUL\n` +
        `  version:        ${finalHealth.version || expectedVersion || '1.0.0'}\n` +
        `  server restart: verified in ${totalElapsed}s\n` +
        `  health status:  ok\n` +
        `  database:       ok\n` +
        `  uptime:         ${finalHealth.uptime}s\n` +
        `  started at:     ${finalHealth.startedAt}\n` +
        `  environment:    ${finalHealth.env}\n` +
        `  live url:       ${API}/api/health\n`,
    );
  } else {
    console.error(
      `\n  deploy warning: server did not report healthy restart after ${totalElapsed}s.\n` +
        `  Check ${API}/api/health and Plesk Passenger error logs.\n`,
    );
    process.exit(2);
  }
}
