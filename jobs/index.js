// jobs/index.js
//
// Every scheduled background task in the API process, started from one place
// so the boot sequence is readable and nothing schedules itself as a side
// effect of being require()d.
//
// Call startJobs() once, after the DB pool is up.

const cron = require('node-cron');
const pool = require('../db');
const { log } = require('../logger');
const { getSetting, setSetting } = require('../utils/settings');
const { broadcastNtfyAlert } = require('../utils/ntfy');
const { discordClient, sendDiscordMailNotifications } = require('../services/discord');
const { runFeedingDecay } = require('../services/feedingDecay');

// ============================================================================
// AUTOMATED LOGISTICS - DOWNTIME DEADLINE PINGS
// ============================================================================
// Daily at 12:00 (server time): DM players who still owe downtime actions when
// the deadline is 24-48h out.
function scheduleDowntimeDeadlinePings() {
  return cron.schedule('0 12 * * *', async () => {
    try {
      // 1. Retrieve the downtime configuration to check the deadline
      const deadlineStr = await getSetting('downtime_deadline', null);
      if (!deadlineStr) return;

      const deadline = new Date(deadlineStr);
      const now = new Date();

      // Calculate the difference in hours
      const timeDiff = deadline.getTime() - now.getTime();
      const hoursLeft = Math.ceil(timeDiff / (1000 * 60 * 60));

      // If the deadline is roughly between 24 and 48 hours away
      if (hoursLeft > 24 && hoursLeft <= 48) {
        // The bot runs in discordWorker.js, not here — without a client
        // attached there is nobody to DM, so don't run the scan at all.
        // (Previously this queried for players and then threw a swallowed
        // ReferenceError on an undefined `client` for every one of them.)
        if (!discordClient?.isReady()) {
          log.info('Downtime deadline is in 48h, but no Discord client is attached here — skipping DMs.');
          return;
        }

        log.info('Downtime deadline is in 48h. Checking for missing actions.');

        // 2. Identify users with Discord IDs and linked characters who haven't submitted
        const [lazyUsers] = await pool.query(`
          SELECT u.discord_id, c.name AS char_name
          FROM users u
          JOIN characters c ON c.user_id = u.id
          WHERE u.discord_id IS NOT NULL
            AND u.role = 'user'
            AND c.id NOT IN (
              SELECT character_id
              FROM downtimes
              WHERE status != 'rejected' AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
            )
        `);

        // 3. Send a direct message to each identified player
        for (const u of lazyUsers) {
          if (!u.discord_id) continue;

          try {
            const discordUser = await discordClient.users.fetch(u.discord_id);
            if (discordUser) {
              const warningMessage = `Hello ${u.char_name || 'there'}, this is an automated reminder. The server for actions (Downtimes) closes in 48 hours. Please submit your actions to avoid an AFK penalty.`;

              await discordUser.send(warningMessage);
            }
          } catch (dmErr) {
            log.warn(`Could not send DM to Discord ID: ${u.discord_id}`, { err: dmErr.message });
          }
        }
      }
    } catch (error) {
      log.err('Cron Job Deadline Ping Error', { error: error.message });
    }
  });
}

// ============================================================================
// AUTOMATED LOGISTICS - MASS RELEASE PINGS
// ============================================================================
// Every minute: fire a single ntfy broadcast the moment the Mass Release
// countdown expires. `downtime_mass_release_notified` is the latch that keeps
// it from re-broadcasting every minute afterwards.
function scheduleMassReleasePings() {
  return cron.schedule('* * * * *', async () => {
    try {
      const isMassReleaseActive = await getSetting('downtime_mass_release_mode', 'false');
      if (isMassReleaseActive !== 'true') return;

      const massReleaseDateStr = await getSetting('downtime_mass_release_date', null);
      if (!massReleaseDateStr) return;

      const targetDate = new Date(massReleaseDateStr);
      const now = new Date();

      if (now >= targetDate) {
        // Check if we already notified
        const hasNotified = await getSetting('downtime_mass_release_notified', 'false');
        if (hasNotified !== 'true') {
          // We reached the date and haven't notified yet. Fire the ping!
          log.info('Mass Release timer expired! Broadcasting ntfy alert...');
          await broadcastNtfyAlert('The countdown is over. Downtime Resolutions have just been released to all players!', {
            title: '🦇 Downtimes Released',
            tags: ['loudspeaker', 'vampire'],
            priority: 'high'
          });

          // Mark as notified so we don't spam every minute
          await setSetting('downtime_mass_release_notified', 'true');
        }
      }
    } catch (error) {
      log.err('Cron Job Mass Release Ping Error', { error: error.message });
    }
  });
}

// ============================================================================
// DAILY DISCORD MAIL DIGEST
// ============================================================================
// The admin-configurable send time lives in the DB (`discord_schedule_time`),
// so this ticks once a minute and compares, rather than being a fixed cron
// expression. `lastDailyCheckDate` keeps it to one send per day.
let lastDailyCheckDate = '';
function scheduleDailyMailCheck() {
  return setInterval(async () => {
    if (!discordClient?.isReady()) return;

    try {
      // 1. Get Settings from DB
      const targetTime = await getSetting('discord_schedule_time', '12:00'); // Default 12:00

      const now = new Date();
      // Get current time string HH:MM (24h format)
      const currentTime = now.toLocaleTimeString('en-GB', {
        hour: '2-digit',
        minute: '2-digit',
        timeZone: 'Europe/Athens'
      });

      // Get current date string YYYY-MM-DD to ensure we run only once per day
      const currentDate = now.toISOString().split('T')[0];

      // 2. Check if it's time AND we haven't run today yet
      if (currentTime === targetTime && lastDailyCheckDate !== currentDate) {
        log.ok(`Triggering daily Discord mail check at ${currentTime}`);
        await sendDiscordMailNotifications();
        lastDailyCheckDate = currentDate;
      }
    } catch (e) {
      log.err('Daily Discord check error', { error: e.message });
    }
  }, 60000);
}

// ============================================================================
// END-OF-DAY SUMMARY
// ============================================================================
// 23:59 daily: push the day's counters to ntfy, then reset them.
function scheduleDailySummary() {
  return cron.schedule('59 23 * * *', async () => {
    try {
      const [[startsRow]] = await pool.query("SELECT setting_value FROM app_settings WHERE setting_key = 'daily_server_starts'");
      const [[loginsRow]] = await pool.query("SELECT setting_value FROM app_settings WHERE setting_key = 'daily_logins'");

      const starts = startsRow ? startsRow.setting_value : '0';
      const logins = loginsRow ? loginsRow.setting_value : '0';

      broadcastNtfyAlert(`Daily Summary:\n- Server starts: ${starts}\n- Logins: ${logins}`, {
        title: 'End of Day Summary',
        tags: 'bar_chart',
      });

      // Reset counters
      await pool.query("UPDATE app_settings SET setting_value = '0' WHERE setting_key IN ('daily_server_starts', 'daily_logins')");
    } catch (e) {
      log.err('Daily summary cron failed', { error: e.message });
    }
  });
}

// ============================================================================
// NIGHTLY DATABASE BACKUP
// ============================================================================
// Writes a gzipped SQL dump to back/backups (see scripts/backup-db.js) and
// prunes anything past the retention window.
//
// Defaults to --no-media: premonition_media and news_media hold full-size
// images as BLOBs and are ~370 MB of a ~383 MB database, so a nightly full dump
// would be 400 MB a night. Without them the dump is ~2.4 MB, and those images
// barely change. Set BACKUP_SCHEDULE_FULL=true for full nightly dumps, and take
// a manual `npm run backup` before anything risky either way.
function scheduleNightlyBackup() {
  if (process.env.BACKUP_SCHEDULE_ENABLED === 'false') {
    log.info('Nightly database backup is disabled (BACKUP_SCHEDULE_ENABLED=false).');
    return null;
  }
  const expr = process.env.BACKUP_SCHEDULE_CRON || '30 3 * * *';
  const skipMedia = process.env.BACKUP_SCHEDULE_FULL !== 'true';

  return cron.schedule(expr, async () => {
    try {
      const { backup } = require('../scripts/backup-db');
      const res = await backup({ quiet: true, skipMedia });
      const mb = (res.size / 1024 / 1024).toFixed(1);
      log.ok(`Database backup written (${mb} MB, ${res.rows} rows${skipMedia ? ', media omitted' : ''}).`);
      if (res.pruned) log.info(`Pruned ${res.pruned} expired backup(s).`);
    } catch (e) {
      log.err('Nightly database backup FAILED', { error: e.message });
      broadcastNtfyAlert(`Nightly database backup failed:\n${e.message}`, {
        title: '🚨 Backup failed',
        tags: ['rotating_light', 'floppy_disk'],
        priority: 'high',
        requiresSubscription: 'errors',
      }).catch(() => { });
    }
  });
}

// ============================================================================
// FEEDING CYCLE DECAY
// ============================================================================
// Daily, shortly after midnight: apply the Feeding system's cycle-end passive
// Masquerade decay for the most recently completed 3-week cycle (see
// services/feedingDecay.js for the actual rule and the deliberate
// no-back-fill behavior).
function scheduleFeedingCycleDecay() {
  return cron.schedule('5 0 * * *', async () => {
    try {
      const result = await runFeedingDecay(pool, log);
      if (result?.decayed) log.info(`Feeding decay: cycle ${result.completedCycle}, ${result.decayed} division(s) affected.`);
    } catch (error) {
      log.err('Feeding cycle decay cron failed', { error: error.message });
    }
  });
}

let started = false;
function startJobs() {
  if (started) return;
  started = true;
  scheduleDowntimeDeadlinePings();
  scheduleMassReleasePings();
  scheduleDailyMailCheck();
  scheduleDailySummary();
  scheduleNightlyBackup();
  scheduleFeedingCycleDecay();
  log.start('Background jobs scheduled.');
}

module.exports = { startJobs };
