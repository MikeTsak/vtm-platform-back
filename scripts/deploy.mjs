/**
 * Backend deploy watcher.
 *
 * You push manually (`git push`). This then:
 *   1. tells the Plesk server to pull       (Git webhook, or you click "Pull")
 *   2. waits for the pull + npm + restart    (deploy/after-pull.sh does these)
 *   3. verifies the API came back healthy on the new commit
 * with a progress bar for each phase.
 *
 *   npm run deploy               trigger pull, watch it land
 *   npm run deploy -- --no-trigger   skip step 1 (you'll pull in Plesk yourself)
 *   npm run deploy:restart       just bounce the app (FTP touch tmp/restart.txt)
 *
 * There is no build step; migrations self-apply on boot.
 * Config: back/deploy.config.json (gitignored) — see deploy.config.example.json.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import cliProgress from 'cli-progress';

const execFileP = promisify(execFile);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/* ------------------------------------------------------------------ args --- */
const argv = process.argv.slice(2);
const has = (...n) => n.some((x) => argv.includes(x));
const NO_TRIGGER = has('--no-trigger');
const RESTART_ONLY = has('--restart-only');

/* ---------------------------------------------------------------- config --- */
const CFG = path.join(ROOT, 'deploy.config.json');
if (!fs.existsSync(CFG)) {
  die('no deploy.config.json — copy deploy.config.example.json to deploy.config.json and fill it in.');
}
let cfg;
try {
  cfg = JSON.parse(fs.readFileSync(CFG, 'utf8'));
} catch (e) {
  die(`deploy.config.json is not valid JSON: ${e.message}`);
}
const API = (process.env.DEPLOY_API_BASE || cfg.apiBase || 'https://api.attlarp.gr').replace(/\/+$/, '');
const BRANCH = process.env.DEPLOY_BRANCH || cfg.branch || 'main';
const WEBHOOK = process.env.PLESK_WEBHOOK_URL || cfg.pleskWebhookUrl || '';
const DEPLOY_EXPECT_S = Number(cfg.expectDeploySec || 100); // pull + npm + swagger
const RESTART_EXPECT_S = Number(cfg.expectRestartSec || 25);
const HARD_TIMEOUT_MS = Number(cfg.waitTimeoutSec || 360) * 1000;

function die(msg) {
  console.error(`\n  deploy: ${msg}\n`);
  process.exit(1);
}
const git = async (...a) => (await execFileP('git', a, { cwd: ROOT })).stdout.trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const nowIso = () => new Date().toISOString();

/* --------------------------------------------------------- restart-only --- */
if (RESTART_ONLY) {
  process.stdout.write('  FTP: touching restart file … ');
  await ftpRestart();
  console.log('done');
  const t0 = Date.now();
  const bar = mkBar('restart');
  const good = await waitFor(RESTART_EXPECT_S, t0, async () => {
    const h = await health();
    bar.tick(Date.now() - t0, h ? `up ${h.uptime}s · db ${h.db ? 'ok' : '…'}` : 'restarting…');
    return h && h.ok && h.db && h.startedAt && new Date(h.startedAt).getTime() > t0 - 8000;
  });
  bar.done(good);
  console.log(good ? '\n  restarted and healthy.\n' : '\n  no healthy response yet — check the API.\n');
  process.exit(good ? 0 : 2);
}

/* ------------------------------------------------------------- preflight --- */
const branchNow = await git('rev-parse', '--abbrev-ref', 'HEAD');
if (branchNow !== BRANCH) die(`on branch "${branchNow}", expected "${BRANCH}" (set "branch" in deploy.config.json to change).`);

const localSha = await git('rev-parse', 'HEAD');
let originSha = '';
try {
  await execFileP('git', ['fetch', 'origin', BRANCH, '--quiet'], { cwd: ROOT });
  originSha = await git('rev-parse', `origin/${BRANCH}`);
} catch {
  console.log('  (could not fetch origin — assuming your push already landed)');
}
const target = (originSha || localSha).slice(0, 7);

console.log(`\n  ${API}   branch ${BRANCH}`);
console.log(`  local  ${localSha.slice(0, 7)}${localSha === originSha ? '  (matches origin)' : ''}`);
if (originSha) console.log(`  origin ${originSha.slice(0, 7)}  <- this is what will deploy`);
if (originSha && originSha !== localSha) {
  const ahead = await git('rev-list', '--count', `origin/${BRANCH}..HEAD`).catch(() => '?');
  if (ahead !== '0') console.log(`\n  ! you have ${ahead} unpushed commit(s). Run "git push" first if you want them live.`);
}
console.log('');

/* ----------------------------------------------------------- 1: trigger --- */
const triggeredAt = Date.now();

if (NO_TRIGGER) {
  console.log('  1/3  trigger        skipped (--no-trigger)');
} else if (WEBHOOK) {
  process.stdout.write('  1/3  trigger        POST Plesk webhook … ');
  const r = await fetch(WEBHOOK, { method: 'POST' }).catch((e) => ({ ok: false, _err: e.message }));
  if (r._err) { console.log('failed'); die(`could not reach the webhook: ${r._err}`); }
  console.log(r.ok ? 'accepted' : `HTTP ${r.status} (Plesk often replies non-2xx here — continuing)`);
} else {
  console.log('  1/3  trigger        no pleskWebhookUrl set');
  if (process.stdin.isTTY) {
    await prompt('       → open Plesk › Websites & Domains › Git, click "Pull Updates", then press Enter…');
  } else {
    console.log('       → click "Pull Updates" in Plesk now.');
  }
}

/* ------------------------------------------------ 2: wait for the deploy --- */
console.log('');
const deployStart = Date.now();
const bar1 = mkBar('2/3  deploying');
let sawMarker = null;
let sawRestart = false;

const deployOk = await waitFor(DEPLOY_EXPECT_S, deployStart, async () => {
  const [h, m] = await Promise.all([health(), marker()]);
  if (m && new Date(m.at).getTime() > triggeredAt - 15000) sawMarker = m;
  if (h && h.startedAt && new Date(h.startedAt).getTime() > triggeredAt - 8000) sawRestart = true;
  const note = sawMarker
    ? `pulled ${sawMarker.short} · deps ${sawMarker.deps}`
    : h ? `waiting… (api up ${h.uptime}s)` : 'waiting…';
  bar1.tick(Date.now() - deployStart, note);
  return !!sawMarker || sawRestart;
});
bar1.done(deployOk);

if (!deployOk) {
  fail(`the server never reported a pull after ${Math.round((Date.now() - deployStart) / 1000)}s.\n` +
    `  Check the Plesk Git deploy log. If "Additional deployment actions" isn't set to\n` +
    `  "sh deploy/after-pull.sh", set that and retry.`);
}

/* --------------------------------------------------- 3: wait for restart --- */
console.log('');
const restartStart = Date.now();
const bar2 = mkBar('3/3  restarting');
let ftpKicked = false;

const restartOk = await waitFor(RESTART_EXPECT_S, restartStart, async () => {
  const h = await health();
  const back = h && h.ok && h.db && h.startedAt && new Date(h.startedAt).getTime() > triggeredAt - 8000;
  bar2.tick(Date.now() - restartStart, h ? (back ? `up ${h.uptime}s · db ok` : `restarting… (${h.uptime}s)`) : 'restarting…');
  // Fallback: after-pull.sh should have touched tmp/restart.txt. If we've
  // waited well past normal and it hasn't restarted, do it ourselves.
  if (!back && !ftpKicked && Date.now() - restartStart > (RESTART_EXPECT_S + 20) * 1000) {
    ftpKicked = true;
    ftpRestart().then(() => bar2.note('sent restart over FTP')).catch(() => {});
  }
  return back;
});
bar2.done(restartOk);

/* ---------------------------------------------------------------- verify --- */
const h = await health();
const m = await marker();
const took = Math.round((Date.now() - triggeredAt) / 1000);
console.log('');
if (restartOk && h) {
  const sha = m?.short || 'unknown';
  const match = originSha ? (sha === target || sha === 'unknown') : true;
  console.log(`  deployed in ${took}s`);
  console.log(`    commit   ${sha}${sha !== 'unknown' && originSha && sha !== target ? `  ! expected ${target}` : ''}`);
  console.log(`    health   ok · db ${h.db ? 'ok' : 'DOWN'} · uptime ${h.uptime}s`);
  console.log(`    api      ${API}/\n`);
  process.exit(match && h.db ? 0 : 2);
}
fail(`API did not come back healthy within ${Math.round(HARD_TIMEOUT_MS / 1000)}s. Check ${API}/ and the Plesk logs.`);

/* -------------------------------------------------------------- helpers --- */
function fail(msg) {
  console.error(`\n  deploy incomplete: ${msg}\n`);
  process.exit(2);
}

async function prompt(q) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  await new Promise((res) => rl.question(q + ' ', () => { rl.close(); res(); }));
}

async function health() {
  try {
    const r = await fetch(`${API}/api/health?_=${Date.now()}`, { headers: { accept: 'application/json' } });
    const b = await r.json();
    return { ok: b.ok === true, db: !!b.db, uptime: b.uptime_sec ?? 0, startedAt: b.started_at };
  } catch {
    return null;
  }
}

async function marker() {
  try {
    const r = await fetch(`${API}/public/deploy-status.json?_=${Date.now()}`);
    if (!r.ok) return null;
    const b = await r.json();
    return b && b.at ? b : null;
  } catch {
    return null;
  }
}

// Poll `check()` every 2s until it returns true or the hard timeout hits.
// `expectS` only drives how the progress bar fills.
async function waitFor(expectS, startedAt, check) {
  while (Date.now() - startedAt < HARD_TIMEOUT_MS && Date.now() - triggeredAt < HARD_TIMEOUT_MS) {
    let done = false;
    try { done = await check(); } catch { /* keep waiting */ }
    if (done) return true;
    await sleep(2000);
  }
  return false;
}

// A progress bar that fills toward `expectS` but never completes until you
// call .done() — so a slow phase keeps crawling instead of sitting at 100%.
function mkBar(label) {
  const tty = process.stdout.isTTY;
  let b;
  if (tty) {
    b = new cliProgress.SingleBar(
      { format: `  ${label}  [{bar}] {pct}%  {note}`, barCompleteChar: '█', barIncompleteChar: '░', hideCursor: true, linewrap: false },
      cliProgress.Presets.shades_grey,
    );
    b.start(1000, 0, { pct: '0', note: '' });
  } else {
    console.log(`  ${label} …`);
  }
  let lastNote = '';
  return {
    tick(elapsedMs, note) {
      lastNote = note || lastNote;
      const frac = Math.min(0.96, elapsedMs / 1000 / expectS);
      if (tty) b.update(Math.round(frac * 1000), { pct: String(Math.round(frac * 100)), note: lastNote });
      else process.stdout.write(`    ${Math.round(elapsedMs / 1000)}s  ${lastNote}\n`);
    },
    note(n) { lastNote = n; if (tty) b.update({ note: n }); else console.log(`    ${n}`); },
    done(good) {
      if (tty) { b.update(1000, { pct: good ? '100' : '—', note: good ? lastNote : 'timed out' }); b.stop(); }
      else console.log(`    ${good ? 'done' : 'timed out'} — ${lastNote}`);
    },
  };
}

async function ftpRestart() {
  const f = cfg.ftp || {};
  for (const k of ['host', 'user', 'password']) {
    if (!f[k]) die(`ftp.${k} missing in deploy.config.json.`);
  }
  let Client;
  try {
    ({ Client } = await import('basic-ftp'));
  } catch {
    die('needs "basic-ftp": run  npm i -D basic-ftp  in back/.');
  }
  const restartFile = ('/' + (f.restartFile || '/tmp/restart.txt').replace(/^\/+/, ''));
  const c = new Client(20_000);
  const tmpFile = path.join(ROOT, '.restart.tmp');
  try {
    await c.access({
      host: f.host, port: f.port || 21, user: f.user, password: f.password,
      secure: f.secure !== false, secureOptions: { rejectUnauthorized: !!f.tlsStrict },
    });
    await c.ensureDir(path.posix.dirname(restartFile));
    await c.cd('/');
    fs.writeFileSync(tmpFile, `restart ${nowIso()}\n`);
    await c.uploadFrom(tmpFile, restartFile);
  } finally {
    c.close();
    try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
  }
}
