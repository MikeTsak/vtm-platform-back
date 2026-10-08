// scripts/backup-db.js
//
// Full logical backup of the MariaDB database, written as a gzipped .sql file.
//
// Implemented with mysql2 rather than shelling out to mysqldump on purpose:
// mysqldump is not installed on every machine this runs from (it isn't on the
// dev box), and depending on a binary that may be missing is how a backup job
// silently stops working. This needs nothing the API doesn't already have.
//
// The output is an ordinary SQL script — you can import it straight into
// phpMyAdmin (Import ▸ choose file; it reads .sql and .sql.gz), or pipe it to
// the mysql client on a host that has one:
//
//     gunzip -c vtm-20260909-033000.sql.gz | mysql -u USER -p DBNAME
//
// Usage:
//     npm run backup                 # write a new backup, then prune old ones
//     npm run backup -- --list       # list existing backups
//     npm run backup -- --out DIR    # write somewhere other than back/backups
//
// Size note: premonition_media and news_media hold full-resolution images as
// BLOBs and are ~370 MB of a ~383 MB database — 97% of it, in 74 rows. Every
// other table combined is about 12 MB. So:
//
//     npm run backup                 full dump, ~400 MB      -> vtm-<stamp>.sql.gz
//     npm run backup -- --no-media   game data only, ~12 MB  -> vtm-<stamp>-nomedia.sql.gz
//
// The filename and the file's own header always say which one you're holding,
// so a partial backup can't be mistaken for a full one. The nightly job uses
// --no-media by default (see jobs/index.js) because those images are static;
// take a full one before anything risky.
//
// Configuration (.env):
//     BACKUP_DIR              default: <back>/backups
//     BACKUP_RETENTION_DAYS   default: 14   (0 disables pruning)
//     BACKUP_MEDIA_TABLES     default: premonition_media,news_media

// Load .env from the application root, not the current working directory, so
// this works from a cron entry, a Plesk scheduled task, or any other cwd.
require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const mysql = require('mysql2/promise');

const DEFAULT_DIR = path.join(__dirname, '..', 'backups');
const RETENTION_DAYS = Number(process.env.BACKUP_RETENTION_DAYS ?? 14);
const MEDIA_TABLES = (process.env.BACKUP_MEDIA_TABLES || 'premonition_media,news_media')
  .split(',').map((t) => t.trim()).filter(Boolean);

const argOf = (flag) => {
  const i = process.argv.indexOf(flag);
  return i !== -1 ? process.argv[i + 1] : undefined;
};

function backupDir() {
  return path.resolve(argOf('--out') || process.env.BACKUP_DIR || DEFAULT_DIR);
}

function stamp(d = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

const fmtBytes = (n) =>
  n > 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(1)} MB` : `${(n / 1024).toFixed(0)} KB`;

// mysql2 gives back JS values; turn each one back into SQL literal syntax.
function sqlValue(v) {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'number') return Number.isFinite(v) ? String(v) : 'NULL';
  if (typeof v === 'boolean') return v ? '1' : '0';
  if (v instanceof Date) {
    const p = (n) => String(n).padStart(2, '0');
    return `'${v.getFullYear()}-${p(v.getMonth() + 1)}-${p(v.getDate())} ${p(v.getHours())}:${p(v.getMinutes())}:${p(v.getSeconds())}'`;
  }
  if (Buffer.isBuffer(v)) return `X'${v.toString('hex')}'`;
  if (typeof v === 'object') return escapeString(JSON.stringify(v));
  return escapeString(String(v));
}

function escapeString(s) {
  return `'${s.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\0/g, '\\0').replace(/\x1a/g, '\\Z')}'`;
}

async function listBackups() {
  const dir = backupDir();
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.sql.gz'))
    .map((f) => {
      const st = fs.statSync(path.join(dir, f));
      return { file: f, size: st.size, mtime: st.mtime };
    })
    .sort((a, b) => b.mtime - a.mtime);
}

function prune(dir) {
  if (!RETENTION_DAYS || RETENTION_DAYS <= 0) return [];
  const cutoff = Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000;
  const removed = [];
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith('.sql.gz')) continue;
    const full = path.join(dir, f);
    if (fs.statSync(full).mtimeMs < cutoff) {
      fs.unlinkSync(full);
      removed.push(f);
    }
  }
  return removed;
}

// onProgress({ phase, table, rows, index, total, skipped }) is called as each
// table completes, so callers (the admin SSE runner) can stream progress.
async function backup({ quiet = false, skipMedia = false, onProgress } = {}) {
  const say = quiet ? () => {} : (...a) => console.log(...a);
  const report = typeof onProgress === 'function' ? onProgress : () => {};
  const skipData = new Set(skipMedia ? MEDIA_TABLES : []);
  const dir = backupDir();
  fs.mkdirSync(dir, { recursive: true });

  const dbName = process.env.DB_NAME;
  const conn = await mysql.createConnection({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: dbName,
    charset: 'utf8mb4',
    // Keep BLOBs as Buffers and dates as Date objects so sqlValue() can round-trip them
    dateStrings: false,
  });

  const suffix = skipMedia ? '-nomedia' : '';
  const outFile = path.join(dir, `${dbName}-${stamp()}${suffix}.sql.gz`);
  const gzip = zlib.createGzip({ level: 9 });
  const out = fs.createWriteStream(outFile);
  gzip.pipe(out);

  let writeError = null;
  gzip.on('error', (e) => { writeError = e; });
  out.on('error', (e) => { writeError = e; });

  // Respects backpressure: resolves immediately when the buffer has room,
  // otherwise waits for 'drain'. Without this a large table is buffered
  // entirely in memory before gzip can consume it.
  const write = (s) =>
    new Promise((res, rej) => {
      if (writeError) return rej(writeError);
      if (gzip.write(s)) return res();
      gzip.once('drain', res);
    });

  await write(
    `-- Erebus Portal backup\n` +
    `-- database: ${dbName}\n` +
    `-- taken:    ${new Date().toISOString()}\n` +
    `-- restore:  import this file in phpMyAdmin, or\n` +
    `--           gunzip -c <file> | mysql -u USER -p ${dbName}\n` +
    (skipMedia
      ? `--\n-- *** PARTIAL BACKUP ***\n` +
        `-- Structure only, NO ROW DATA, for: ${MEDIA_TABLES.join(', ')}\n` +
        `-- Restoring this alone loses those images. Use a full backup for those.\n`
      : `-- contents: complete (all tables, all rows)\n`) +
    `\n` +
    `SET NAMES utf8mb4;\n` +
    `SET FOREIGN_KEY_CHECKS = 0;\n` +
    `SET SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO';\n\n`,
  );

  // System-versioned tables (migrations/sql/0051) report TABLE_TYPE 'SYSTEM VERSIONED', not
  // 'BASE TABLE' — filtering on the latter alone would silently drop them from the backup.
  const [tableRows] = await conn.query(
    `SELECT TABLE_NAME AS n, TABLE_TYPE AS t FROM information_schema.TABLES
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE IN ('BASE TABLE', 'SYSTEM VERSIONED') ORDER BY TABLE_NAME`,
  );
  const tables = tableRows.map((r) => r.n);
  const versioned = new Set(tableRows.filter((r) => r.t === 'SYSTEM VERSIONED').map((r) => r.n));
  // Dumping history needs @@system_versioning_insert_history on restore (MariaDB 10.11+/11.x).
  // Without it we can still write the current rows, but history would not survive a restore.
  let canDumpHistory = false;
  if (versioned.size) {
    try { await conn.query('SELECT @@system_versioning_insert_history'); canDumpHistory = true; } catch { /* old server */ }
    if (canDumpHistory) await write(`-- ${versioned.size} system-versioned table(s): full row history included\nSET @@session.system_versioning_insert_history = 1;\n\n`);
    else {
      await write(`-- WARNING: ${versioned.size} system-versioned table(s) dumped WITHOUT history (server lacks system_versioning_insert_history)\n\n`);
      say('  WARNING: this server cannot dump row history; only current rows are in the backup.');
    }
  }
  report({ phase: 'start', total: tables.length });

  let totalRows = 0;
  let index = 0;
  for (const table of tables) {
    index++;
    const [[create]] = await conn.query(`SHOW CREATE TABLE \`${table}\``);
    const ddl = create['Create Table'];

    await write(`\n--\n-- ${table}\n--\nDROP TABLE IF EXISTS \`${table}\`;\n${ddl};\n\n`);

    if (skipData.has(table)) {
      const [[{ n: skipped }]] = await conn.query(`SELECT COUNT(*) AS n FROM \`${table}\``);
      await write(`-- row data intentionally omitted (${skipped} rows)\n`);
      say(`  ${table.padEnd(32)} STRUCTURE ONLY (${skipped} rows omitted)`);
      report({ phase: 'table', table, rows: skipped, index, total: tables.length, skipped: true });
      continue;
    }

    // History mode: every version of every row, with exact validity bounds. FROM_UNIXTIME()
    // keeps the timestamps independent of session time zone on both dump and restore.
    const withHistory = canDumpHistory && versioned.has(table);
    const [[{ n: count }]] = await conn.query(
      `SELECT COUNT(*) AS n FROM \`${table}\`${withHistory ? ' FOR SYSTEM_TIME ALL' : ''}`,
    );
    if (count === 0) {
      report({ phase: 'table', table, rows: 0, index, total: tables.length, skipped: false });
      continue;
    }
    totalRows += count;

    // Stream rather than loading the whole table into memory, and flush by
    // accumulated BYTE size rather than row count. Media tables store image
    // BLOBs, which become hex literals of twice the binary size — batching
    // those 500-at-a-time overflows V8's maximum string length.
    const MAX_BATCH_BYTES = 4 * 1024 * 1024;
    const MAX_BATCH_ROWS = 500;
    let buffer = [];
    let bufferBytes = 0;
    let insertHead = `INSERT INTO \`${table}\` VALUES`;
    let headSet = false;
    const flush = async () => {
      if (!buffer.length) return;
      await write(`${insertHead}\n${buffer.join(',\n')};\n`);
      buffer = [];
      bufferBytes = 0;
    };

    const stream = conn.connection.query(
      withHistory
        ? `SELECT *, UNIX_TIMESTAMP(row_start) AS __rs, UNIX_TIMESTAMP(row_end) AS __re FROM \`${table}\` FOR SYSTEM_TIME ALL`
        : `SELECT * FROM \`${table}\``,
    ).stream();
    for await (const row of stream) {
      let tuple;
      if (withHistory) {
        const { __rs, __re, ...cols } = row;
        // row_start/row_end are hidden columns, so history rows need an explicit column list.
        if (!headSet) {
          insertHead = `INSERT INTO \`${table}\` (${[...Object.keys(cols), 'row_start', 'row_end'].map((c) => `\`${c}\``).join(',')}) VALUES`;
          headSet = true;
        }
        tuple = `(${Object.values(cols).map(sqlValue).join(',')},FROM_UNIXTIME(${__rs}),FROM_UNIXTIME(${__re}))`;
      } else {
        tuple = `(${Object.values(row).map(sqlValue).join(',')})`;
      }
      // A single row can exceed the batch limit on its own (a large image);
      // write it out by itself rather than trying to group it.
      if (tuple.length >= MAX_BATCH_BYTES) {
        await flush();
        await write(`${insertHead}\n${tuple};\n`);
        continue;
      }
      buffer.push(tuple);
      bufferBytes += tuple.length + 2;
      if (buffer.length >= MAX_BATCH_ROWS || bufferBytes >= MAX_BATCH_BYTES) await flush();
    }
    await flush();
    say(`  ${table.padEnd(32)} ${count} rows`);
    report({ phase: 'table', table, rows: count, index, total: tables.length, skipped: false });
  }

  // Triggers (e.g. users -> user_change_log, migration 0051). SHOW CREATE TABLE does not include
  // them, and their migration is already recorded in schema_migrations, so without this a restored
  // database silently stops logging. DEFINER is stripped: on another server/user the restore would
  // otherwise need SUPER and fail; the restoring user becomes the definer instead.
  const [triggers] = await conn.query(
    'SELECT TRIGGER_NAME AS n FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = DATABASE() ORDER BY TRIGGER_NAME',
  );
  for (const { n } of triggers) {
    const [[t]] = await conn.query(`SHOW CREATE TRIGGER \`${n}\``);
    const ddl = t['SQL Original Statement'].replace(/\s+DEFINER\s*=\s*\S+@\S+/i, '');
    await write(`\n--\n-- trigger ${n}\n--\nDROP TRIGGER IF EXISTS \`${n}\`;\nDELIMITER ;;\n${ddl} ;;\nDELIMITER ;\n`);
  }
  if (triggers.length) say(`  ${'(triggers)'.padEnd(32)} ${triggers.length}`);

  await write(`\nSET FOREIGN_KEY_CHECKS = 1;\n`);
  await new Promise((res, rej) => {
    gzip.end();
    out.on('finish', res);
    out.on('error', rej);
  });
  await conn.end();

  const size = fs.statSync(outFile).size;
  say(`\nWrote ${path.basename(outFile)}  (${tables.length} tables, ${totalRows} rows, ${fmtBytes(size)})`);

  const removed = prune(dir);
  if (removed.length) say(`Pruned ${removed.length} backup(s) older than ${RETENTION_DAYS} days.`);

  return { file: outFile, tables: tables.length, rows: totalRows, size, pruned: removed.length, skipMedia };
}

module.exports = { backup, listBackups, backupDir };

if (require.main === module) {
  (async () => {
    if (process.argv.includes('--list')) {
      const rows = await listBackups();
      if (!rows.length) return console.log(`No backups in ${backupDir()}`);
      console.log(`Backups in ${backupDir()}:`);
      rows.forEach((r) => console.log(`  ${r.file.padEnd(40)} ${fmtBytes(r.size).padStart(9)}   ${r.mtime.toISOString()}`));
      return;
    }
    await backup({ skipMedia: process.argv.includes('--no-media') });
  })().catch((e) => {
    console.error('Backup failed:', e.message);
    process.exit(1);
  });
}
