// jobs/index.js
//
// Every scheduled background task in the API process, declared in one list
// (JOBS) and started from one place, so the boot sequence is readable and
// nothing schedules itself as a side effect of being require()d. The same list
// drives the admin Background Jobs panel (routes/jobs.js).
//
// Call startJobs() once, after the DB pool is up.
//
// A job's run(ctx) does its work and THROWS on failure (runJob logs it and
// records it in job_status); it may return a short note describing what it did
// ("3 fed, 1 starved", "skipped: done this cycle"), shown in the panel.

const cron = require('node-cron');
const pool = require('../db');
const { log } = require('../logger');
const { getSetting, getSettingStrict, setSetting, clearSettingCache } = require('../utils/settings');
const { broadcastNtfyAlert } = require('../utils/ntfy');
const { sendDiscordDM, sendDiscordMailNotifications } = require('../services/discord');
const { runHerdRegen, runSafetyRecovery } = require('../services/feedingCycleEnd');
const { runGhoulUpkeep } = require('../services/ghoulFeeding');
const { sendPushNotification } = require('../services/push');
const { flushQueuedMessages } = require('../services/commsQueue');
const { loadCommsState, statusPayload, clearExpiredOverride } = require('../services/commsState');
const { purgeOldIdempotencyKeys } = require('../utils/idempotency');
const { releasePendingAndNotify, advanceActiveCycle, broadcastMassDowntimeDiscordAnnouncement } = require('../services/downtimeSchedule');
const { checkAndAutoSendElysiumInvitations } = require('../services/elysiumDiscord');
const { closeStaleSessions } = require('../services/liveSession');
const { expireBloodHunts } = require('../services/bloodHunts');
const { runWillpowerReset } = require('../services/willpowerReset');

// Daily crons fire on Athens wall-clock time, not the host's (node-cron
// otherwise uses the server's local zone, which on a shared host may be UTC).
const TZ = 'Europe/Athens';
const athensNow = (opts) => new Date().toLocaleString('en-CA', { timeZone: TZ, hour12: false, ...opts });
const athensToday = () => athensNow({ year: 'numeric', month: '2-digit', day: '2-digit' }); // YYYY-MM-DD
const DAY_MIN = 24 * 60;

// Passenger can stop an idle app, and a stopped process misses its cron slot.
// So every daily job is either latched (runs at most once per period no matter
// how often it's triggered) or harmless to repeat, and is ALSO run at boot
// (`boot`): a missed slot is caught up on the next request that wakes the app.
// ponytail: catch-up only happens when something wakes the process; keep the app
// warm in Plesk (passenger_min_instances 1) if jobs must fire at exact times.
//
// Production runs several Passenger processes and EACH one calls startJobs(),
// so every job fires once per process. A MariaDB named lock makes a job run in
// one process at a time; the others skip that tick (and record nothing). The
// settings cache is cleared first because it is per process (30 s TTL): a latch
// written by the process that ran a moment ago must be read fresh.
async function exclusive(name, fn) {
  const lock = `erebus_job:${name}`;
  const conn = await pool.getConnection();
  try {
    const [[{ got }]] = await conn.query('SELECT GET_LOCK(?, 0) AS got', [lock]);
    if (got !== 1) return { ran: false };
    try {
      clearSettingCache();
      return { ran: true, value: await fn() };
    } finally {
      await conn.query('SELECT RELEASE_LOCK(?)', [lock]).catch(() => {});
    }
  } finally {
    conn.release();
  }
}

// job_status (migration 0074): one row per job, the latest outcome. Not
// system-versioned: some jobs tick every minute.
async function record(name, { ok, ms, note, error }) {
  await pool.query(
    `INSERT INTO job_status (job_name, last_run_at, last_duration_ms, last_note, last_ok_at, last_error, last_error_at, runs, failures)
     VALUES (?, NOW(), ?, ?, IF(?, NOW(), NULL), ?, IF(?, NULL, NOW()), 1, ?)
     ON DUPLICATE KEY UPDATE
       last_run_at = NOW(), last_duration_ms = VALUES(last_duration_ms), last_note = VALUES(last_note),
       last_ok_at = IF(?, NOW(), last_ok_at),
       last_error = IF(?, last_error, VALUES(last_error)),
       last_error_at = IF(?, last_error_at, NOW()),
       runs = runs + 1, failures = failures + VALUES(failures)`,
    [name, ms, note, ok, error, ok, ok ? 0 : 1, ok, ok, ok]
  );
}

// Run one job now: under the cross-process lock, timed, failures logged and
// recorded. Never throws. Returns { ran, ok, note, error } for the run-now button.
async function runJob(job, ctx = {}) {
  const started = Date.now();
  let outcome;
  try {
    const res = await exclusive(job.name, () => job.run(ctx));
    if (!res.ran) return { ran: false };
    outcome = { ok: true, note: res.value ? String(res.value).slice(0, 255) : null, error: null };
  } catch (e) {
    log.err(`Job ${job.name} failed`, { error: e.message });
    outcome = { ok: false, note: null, error: String(e.stack || e.message || e).slice(0, 2000) };
    if (job.alertOnFailure) {
      broadcastNtfyAlert(`${job.label} failed:\n${e.message}`, {
        title: `ðŸš¨ ${job.label} failed`, tags: ['rotating_light'], priority: 'high', requiresSubscription: 'errors',
      }).catch(() => {});
    }
  }
  await record(job.name, { ...outcome, ms: Date.now() - started }).catch((e) => log.err('Job status write failed', { job: job.name, error: e.message }));
  return { ran: true, ...outcome };
}

const backupEnabled = process.env.BACKUP_SCHEDULE_ENABLED !== 'false';
const backupSkipMedia = process.env.BACKUP_SCHEDULE_FULL !== 'true';
const backupFullEveryDays = Number(process.env.BACKUP_FULL_EVERY_DAYS ?? 7);

// name: lock + job_status key. cron: schedule (TZ applied). boot: run at startup
// (true = now, a number = after that many ms). maxGapMin: the longest it should
// ever go without running; the panel flags it as overdue past that.
const JOBS = [
  {
    // Once per deadline, at a civil hour (12:00-21:59 Athens): DM players who still
    // owe downtime actions when the deadline is 24-48h out. Checked hourly and at
    // boot; `downtime_deadline_ping_sent` (the deadline it was sent for) is the
    // latch, so a restart or a missed 12:00 neither skips nor repeats the DMs.
    name: 'deadline-pings', label: 'Downtime deadline DMs', cron: '0 * * * *', boot: true, maxGapMin: 3 * 60,
    async run() {
      const hour = Number(athensNow({ hour: '2-digit' }));
      if (hour < 12 || hour > 21) return 'outside 12:00-21:59';
      const deadlineStr = await getSetting('downtime_deadline', null);
      if (!deadlineStr) return 'no deadline set';
      if ((await getSettingStrict('downtime_deadline_ping_sent', '')) === deadlineStr) return 'already sent for this deadline';

      const hoursLeft = Math.ceil((new Date(deadlineStr).getTime() - Date.now()) / 3600000);
      if (hoursLeft <= 24 || hoursLeft > 48) return `deadline ${hoursLeft}h away`;
      // The bot runs in discordWorker.js; without a token there is nobody to DM.
      if (!process.env.DISCORD_BOT_TOKEN) return 'no Discord bot token';

      // Latch before sending: a crash mid-loop must not DM the same players twice.
      await setSetting('downtime_deadline_ping_sent', deadlineStr);
      const [lazyUsers] = await pool.query(`
        SELECT u.discord_id, c.name AS char_name
          FROM users u
          JOIN characters c ON c.user_id = u.id
         WHERE u.discord_id IS NOT NULL
           AND u.role = 'user'
           AND c.id NOT IN (
             SELECT character_id FROM downtimes
              WHERE status != 'rejected' AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
           )
      `);
      let sent = 0;
      for (const u of lazyUsers) {
        try {
          await sendDiscordDM(u.discord_id, `Hello ${u.char_name || 'there'}, this is an automated reminder. The server for actions (Downtimes) closes in 48 hours. Please submit your actions to avoid an AFK penalty.`);
          sent++;
        } catch (dmErr) {
          log.warn(`Could not send DM to Discord ID: ${u.discord_id}`, { err: dmErr.message });
        }
      }
      return `DMed ${sent} of ${lazyUsers.length} player(s)`;
    },
  },
  {
    // Every minute: fire a single broadcast the moment the Mass Release countdown
    // expires. `downtime_mass_release_notified` is the latch.
    name: 'mass-release', label: 'Downtime mass release', cron: '* * * * *', maxGapMin: 10,
    async run() {
      if ((await getSetting('downtime_mass_release_mode', 'false')) !== 'true') return 'mass release off';
      const dateStr = await getSetting('downtime_mass_release_date', null);
      if (!dateStr || new Date() < new Date(dateStr)) return 'countdown running';
      if ((await getSetting('downtime_mass_release_notified', 'false')) === 'true') return 'already released';

      await broadcastNtfyAlert('The countdown is over. Downtime Resolutions have just been released to all players!', {
        title: 'ðŸ¦‡ Downtimes Released', tags: ['loudspeaker', 'vampire'], priority: 'high',
      });
      await setSetting('downtime_mass_release_notified', 'true');
      const notified = await releasePendingAndNotify().catch((e) => { log.err('Mass release push failed', { error: e.message }); return 0; });
      await broadcastMassDowntimeDiscordAnnouncement().catch((e) => log.err('Mass release discord announcement failed', { error: e.message }));
      return `released, ${notified} player(s) notified`;
    },
  },
  {
    // When the next calendar cycle's opening date arrives it becomes the live cycle
    // (opening, deadline and mass release settings follow it). Forward only and
    // date-driven, so repeating it is a no-op. See services/downtimeSchedule.js.
    name: 'cycle-advance', label: 'Downtime cycle advance', cron: '2 0 * * *', boot: true, maxGapMin: DAY_MIN + 120,
    async run() {
      const cycle = await advanceActiveCycle();
      return cycle ? `advanced to ${cycle.title || cycle.id}` : 'no change';
    },
  },
  {
    // The admin-set send time lives in the DB (`discord_schedule_time`), so this
    // ticks every minute and fires on the first tick AT OR AFTER it (an exact
    // HH:MM match was skipped whenever drift or a sleeping process missed that
    // minute). `discord_mail_digest_last_date` keeps it to one send per day.
    name: 'mail-digest', label: 'Discord mail digest', cron: '* * * * *', maxGapMin: 10,
    async run() {
      if (!process.env.DISCORD_BOT_TOKEN) return 'no Discord bot token';
      const targetTime = await getSetting('discord_schedule_time', '12:00');
      const currentTime = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: TZ });
      const today = athensToday();
      if (currentTime < targetTime) return `waiting for ${targetTime}`;
      if ((await getSettingStrict('discord_mail_digest_last_date', '')) === today) return 'sent today';
      await setSetting('discord_mail_digest_last_date', today);
      await sendDiscordMailNotifications();
      return 'digest sent';
    },
  },
  {
    // 23:59: push the day's counters to ntfy, then reset them. Not caught up at
    // boot (the counters are for the day that's ending); the date latch stops a
    // second process sending a duplicate "0 / 0" right after the first.
    name: 'daily-summary', label: 'End-of-day summary', cron: '59 23 * * *', maxGapMin: DAY_MIN + 120,
    async run() {
      const today = athensToday();
      if ((await getSettingStrict('daily_summary_last_date', '')) === today) return 'sent today';
      await setSetting('daily_summary_last_date', today);
      const [[startsRow]] = await pool.query("SELECT setting_value FROM app_settings WHERE setting_key = 'daily_server_starts'");
      const [[loginsRow]] = await pool.query("SELECT setting_value FROM app_settings WHERE setting_key = 'daily_logins'");
      const starts = startsRow ? startsRow.setting_value : '0';
      const logins = loginsRow ? loginsRow.setting_value : '0';
      broadcastNtfyAlert(`Daily Summary:\n- Server starts: ${starts}\n- Logins: ${logins}`, { title: 'End of Day Summary', tags: 'bar_chart' });
      await pool.query("UPDATE app_settings SET setting_value = '0' WHERE setting_key IN ('daily_server_starts', 'daily_logins')");
      return `${starts} start(s), ${logins} login(s)`;
    },
  },
  {
    // Gzipped SQL dump to back/backups (scripts/backup-db.js), pruned past the
    // retention window. The newest dump on disk is the latch (shared by every
    // process; a pre-deploy backup counts too). Runs on schedule and 2 min after
    // boot (clear of the cold-start request), so a night the app slept through is
    // caught up. Media tables (premonition_media, news_media: ~370 MB of images)
    // are left out nightly but included at least every BACKUP_FULL_EVERY_DAYS
    // (default 7), since images uploaded since the last full dump exist nowhere
    // else. Full dumps are ~media-sized; set it to 0 if the disk quota can't take two.
    name: 'backup', label: 'Database backup', cron: process.env.BACKUP_SCHEDULE_CRON || '30 3 * * *',
    boot: 2 * 60 * 1000, maxGapMin: DAY_MIN + 180, enabled: backupEnabled, alertOnFailure: true,
    async run() {
      const { backup, listBackups } = require('../scripts/backup-db');
      const all = await listBackups();
      if (all[0] && Date.now() - new Date(all[0].mtime).getTime() < 20 * 3600000) return `fresh backup exists (${all[0].file})`;
      const lastFull = all.find((b) => !b.file.includes('-nomedia'));
      const fullDue = backupSkipMedia && backupFullEveryDays > 0 &&
        (!lastFull || Date.now() - new Date(lastFull.mtime).getTime() > backupFullEveryDays * DAY_MIN * 60000);
      const res = await backup({ quiet: true, skipMedia: backupSkipMedia && !fullDue });
      const note = `${(res.size / 1048576).toFixed(1)} MB, ${res.rows} rows${res.skipMedia ? ', media omitted' : ', full incl. media'}`;
      log.ok(`Database backup written (${note}).`);
      return res.pruned ? `${note}; pruned ${res.pruned}` : note;
    },
  },
  {
    // Daily: +1 domain Safety per 3 months without a failed hunt there, and
    // Herd regen once per completed cycle. Safety never drops on its own.
    name: 'feeding-cycle-end', label: 'Safety recovery + Herd regen', cron: '5 0 * * *', boot: true, maxGapMin: DAY_MIN + 120,
    async run() {
      const s = await runSafetyRecovery(pool);
      const h = await runHerdRegen(pool);
      const herd = h?.skipped ? `herd ${h.skipped}` : `cycle ${h.completedCycle}: ${h.herdRegen} herd(s) regrown`;
      return `${s.recovered} division(s) +1 Safety; ${herd}`;
    },
  },
  {
    // Once a cycle's ghoul_feeding_date (admin Calendar) has passed, feed or
    // starve every ghoul still unfed that cycle. Once per cycle; at boot too, so
    // a fresh deploy records its baseline before anyone can feed a ghoul.
    name: 'ghoul-upkeep', label: 'Ghoul upkeep', cron: '*/10 * * * *', boot: true, maxGapMin: 45,
    async run() {
      const r = await runGhoulUpkeep(pool, log);
      if (!r?.fed && !r?.starved) return r?.skipped ? `skipped: ${r.skipped}` : 'nothing due';
      await broadcastNtfyAlert(`Ghoul upkeep ran: ${r.fed} fed, ${r.starved} starved.\n${r.report.join('\n')}`, { title: 'Ghoul Upkeep', tags: ['drop_of_blood'] });
      return `cycle ${r.cycleIndex}: ${r.fed} fed, ${r.starved} starved`;
    },
  },
  {
    // Day after a Modern Day event: spent Willpower back to full. See services/willpowerReset.js.
    name: 'willpower-reset', label: 'Willpower reset', cron: '8 0 * * *', boot: true, maxGapMin: DAY_MIN + 120,
    async run() {
      const r = await runWillpowerReset();
      if (!r) return 'no event to reset after';
      await broadcastNtfyAlert(`Willpower reset to full after the ${r.day} event.\n${r.reset} character(s) had spent Willpower restored.`, { title: 'Willpower Reset', tags: ['sparkles'] });
      return `after ${r.day}: ${r.reset} character(s)`;
    },
  },
  {
    // The Send Later queue (SchreckNet + SurfaceWeb) goes out while comms are
    // open. Triggered by the per-process comms tick in startJobs(), not by cron:
    // the open/close broadcast must run in every process, the flush in only one.
    name: 'comms-flush', label: 'Queued message flush', cron: null, maxGapMin: 10,
    async run({ io }) {
      const r = await flushQueuedMessages(pool, { log, sendPushNotification, io });
      const n = (r?.flushedChat || 0) + (r?.flushedEmail || 0);
      return n ? `${r.flushedChat} chat, ${r.flushedEmail} email sent` : 'queue empty';
    },
  },
  {
    // Every chat send stores an idempotency row (utils/idempotency.js): drop the
    // ones past the retry window. Plus dead one-time secrets, kept a week for the audit trail.
    name: 'idempotency-purge', label: 'Housekeeping purge', cron: '20 0 * * *', boot: true, maxGapMin: DAY_MIN + 120,
    async run() {
      const keys = await purgeOldIdempotencyKeys();
      const [pr] = await pool.query('DELETE FROM password_resets WHERE expires_at < NOW() - INTERVAL 7 DAY');
      const [dl] = await pool.query('DELETE FROM debug_login_codes WHERE expires_at < NOW() - INTERVAL 7 DAY');
      return `${keys || 0} idempotency key(s), ${pr.affectedRows} reset token(s), ${dl.affectedRows} debug code(s)`;
    },
  },
  {
    // A live session the Storyteller never ended is closed after 24h.
    name: 'stale-sessions', label: 'Forgotten live sessions', cron: '*/5 * * * *', boot: true, maxGapMin: 30,
    async run({ io }) {
      const closed = await closeStaleSessions(io);
      return closed ? `closed ${closed}` : 'none open too long';
    },
  },
  {
    // Blood Hunts past their expiry end and the target's flag clears.
    name: 'blood-hunt-expiry', label: 'Blood Hunt expiry', cron: '*/10 * * * *', boot: true, maxGapMin: 45,
    async run() {
      const n = await expireBloodHunts();
      return n ? `expired ${n}` : 'none due';
    },
  },
  {
    // Any published Elysium invitation whose Monday before the event has arrived
    // is broadcast to Discord once.
    name: 'elysium-auto-send', label: 'Elysium invitation auto-send', cron: '*/15 * * * *', boot: true, maxGapMin: 60,
    async run() {
      const sent = await checkAndAutoSendElysiumInvitations(pool);
      return sent ? `sent ${sent}` : 'none due';
    },
  },
];

const findJob = (name) => JOBS.find((j) => j.name === name);

let started = false;
function startJobs(fastify) {
  if (started) return;
  started = true;
  const ctx = { io: fastify?.io };

  // Jobs DM players on Discord, push to their phones and alert ntfy. A local
  // dev server runs against a mirror of the production database (and may hold
  // the same Discord/VAPID keys), so it must not fire them on its own.
  // RUN_JOBS=true opts in; the admin panel's Run now works either way.
  const isProd = (process.env.NODE_ENV || '').toLowerCase() === 'production';
  if (!isProd && process.env.RUN_JOBS !== 'true') {
    log.info('Background jobs not scheduled (NODE_ENV is not production; set RUN_JOBS=true to run them here). Admin > Background Jobs > Run now still works.');
    return;
  }

  let bootChain = Promise.resolve(); // runJob never throws, so the chain never breaks
  for (const job of JOBS) {
    if (job.enabled === false) {
      log.info(`Job ${job.name} is disabled.`);
      continue;
    }
    if (job.cron) cron.schedule(job.cron, () => runJob(job, ctx), { timezone: TZ });
    // Boot catch-ups run ONE AT A TIME: each running job holds a pool connection
    // for its lock and needs another for its work, so nine at once could take the
    // whole pool (5) and leave logins queued behind them.
    if (job.boot === true) bootChain = bootChain.then(() => runJob(job, ctx));
    else if (typeof job.boot === 'number') setTimeout(() => runJob(job, ctx), job.boot).unref();
  }

  // Comms switch: the calendar opens and closes comms on its own, and an
  // emergency override expires at the calendar's next change. Every process
  // tells its OWN sockets when the live state flips (comms:status, instead of
  // their next 60 s poll); the queue flush then runs in one process only.
  let lastState = null;
  const commsFlush = findJob('comms-flush');
  cron.schedule('* * * * *', async () => {
    try {
      const info = await loadCommsState();
      if (await clearExpiredOverride(info)) log.info('Comms override expired: back on the calendar.');
      if (lastState !== null && lastState !== info.isCommsEnabled) {
        log.info(`Comms ${info.isCommsEnabled ? 'opened' : 'closed'} on schedule.`);
        ctx.io?.emit('comms:status', statusPayload(info));
      }
      lastState = info.isCommsEnabled;
      if (info.isCommsEnabled) await runJob(commsFlush, ctx);
    } catch (error) {
      log.err('Comms switch tick failed', { error: error.message });
    }
  });

  log.start('Background jobs scheduled.');
}

module.exports = { startJobs, JOBS, findJob, runJob };
