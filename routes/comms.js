// routes/comms.js
//
// SchreckNet availability window: whether comms are open, and the schedule
// that opens them.
const { getSetting, setSetting, clearSettingCache } = require('../utils/settings');
const { flushQueuedMessages } = require('../services/commsQueue');
const { getAthensDate, getAthensHour, getAthensDayName, getAthensEuDate } = require('../utils/athensTime');

function resolveCommsSchedule(scheduleStr, masterEnabledStr, nowInput = new Date()) {
  const masterEnabled = masterEnabledStr === 'true';
  let isCommsEnabled = masterEnabled;
  let nextOpening = null;

  try {
    const schedule = typeof scheduleStr === 'string' ? JSON.parse(scheduleStr) : (scheduleStr || {});
    const now = nowInput instanceof Date && !isNaN(nowInput.getTime()) ? nowInput : new Date();

    const todayStr = getAthensDate(now);
    const yesterday = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const yesterdayStr = getAthensDate(yesterday);

    let activeState = schedule[todayStr];
    const currentHour = getAthensHour(now);

    // The carry-over must not steamroll an explicit override for today —
    // same principle as the killswitch fix below, just for the one branch it
    // didn't touch. 'event' was already excluded; an explicit Force OFF
    // (false) needs the same treatment, or a day an admin deliberately
    // closed still shows open all morning whenever yesterday opened at
    // 17:00, only correctly closing after today's own 17:00 rolls around.
    if (schedule[yesterdayStr] === '17:00' && currentHour < 17 && activeState !== 'event' && activeState !== false) {
      activeState = true;
    } else if (schedule[todayStr] === '17:00') {
      activeState = currentHour >= 17 ? true : false;
    }

    // An explicit schedule entry for today — or its 17:00/carry-over
    // resolution above — is authoritative regardless of the master
    // killswitch: that's exactly what the admin calendar's own legend
    // promises ("If blank, it follows the Master Killswitch above"). The
    // killswitch is only the fallback default for a day nobody scheduled at
    // all; it must not silently override a day an admin explicitly opened.
    if (activeState === false || activeState === 'event') {
      isCommsEnabled = false;
    } else if (activeState === true) {
      isCommsEnabled = true;
    } else {
      isCommsEnabled = masterEnabled;
    }

    if (!isCommsEnabled) {
      if (schedule[todayStr] === '17:00' && currentHour < 17) {
        const dayName = getAthensDayName(now);
        const euDate = getAthensEuDate(now);
        nextOpening = {
          day: dayName,
          time: '17:00',
          date: euDate,
          iso: `${todayStr}T17:00:00+03:00`,
          formatted: `${dayName} at 17:00 (${euDate})`
        };
      } else {
        for (let offset = 1; offset <= 30; offset++) {
          const futureDate = new Date(now.getTime() + offset * 24 * 60 * 60 * 1000);
          const futureDateStr = getAthensDate(futureDate);
          const state = schedule[futureDateStr];

          if (state === true) {
            const dayName = getAthensDayName(futureDate);
            const euDate = getAthensEuDate(futureDate);
            nextOpening = {
              day: dayName,
              time: '00:01',
              date: euDate,
              iso: `${futureDateStr}T00:01:00+03:00`,
              formatted: `${dayName} at 00:01 (${euDate})`
            };
            break;
          } else if (state === '17:00') {
            const dayName = getAthensDayName(futureDate);
            const euDate = getAthensEuDate(futureDate);
            nextOpening = {
              day: dayName,
              time: '17:00',
              date: euDate,
              iso: `${futureDateStr}T17:00:00+03:00`,
              formatted: `${dayName} at 17:00 (${euDate})`
            };
            break;
          }
        }
      }
    }
  } catch (err) { }

  return {
    isCommsEnabled,
    masterEnabled,
    nextOpening
  };
}

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, sendPushNotification, io } = opts;

  // Public: Check if comms are enabled and when they next open
  fastify.get('/api/comms/status', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const masterEnabled = await getSetting('comms_enabled', 'true');
      const scheduleStr = await getSetting('chat_schedule', '{}');

      const info = resolveCommsSchedule(scheduleStr, masterEnabled);

      reply.send({
        comms_enabled: info.isCommsEnabled,
        master_enabled: info.masterEnabled,
        next_opening: info.nextOpening
      });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch comms status' });
    }
  });

  // Admin: Toggle comms status
  fastify.post('/api/admin/comms/status', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { comms_enabled } = req.body;
      await setSetting('comms_enabled', String(comms_enabled));
      clearSettingCache('comms_enabled');
      log.adm(`Master comms switched to ${comms_enabled ? 'ONLINE' : 'OFFLINE'}`, { admin_id: req.user.id });

      const scheduleStr = await getSetting('chat_schedule', '{}');
      const info = resolveCommsSchedule(scheduleStr, String(comms_enabled));
      const payload = {
        comms_enabled: info.isCommsEnabled,
        master_enabled: info.masterEnabled,
        next_opening: info.nextOpening
      };
      if (io) io.emit('comms:status', payload);
      else if (fastify.io) fastify.io.emit('comms:status', payload);

      if (info.isCommsEnabled) {
        flushQueuedMessages(pool, { log, sendPushNotification, io: io || fastify.io })
          .catch((e) => log.err('Queued message flush failed', { error: e.message }));
      }

      reply.send({ ok: true, comms_enabled: info.isCommsEnabled, next_opening: info.nextOpening });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to update comms status' });
    }
  });

  // Admin: Get Comms Config (master switch and schedule)
  fastify.get('/api/admin/comms/config', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      clearSettingCache('chat_schedule');
      clearSettingCache('comms_enabled');
      const masterEnabled = await getSetting('comms_enabled', 'true');
      const scheduleStr = await getSetting('chat_schedule', '{}');
      let schedule = {};
      try { schedule = JSON.parse(scheduleStr); } catch (e) { }
      reply.send({ master_enabled: masterEnabled === 'true', schedule });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch comms config' });
    }
  });

  // Admin: Update Comms Schedule
  fastify.post('/api/admin/comms/schedule', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { schedule } = req.body;
      await setSetting('chat_schedule', JSON.stringify(schedule));
      clearSettingCache('chat_schedule');
      log.adm('Comms schedule updated', { admin_id: req.user.id });

      const masterEnabled = await getSetting('comms_enabled', 'true');
      const info = resolveCommsSchedule(JSON.stringify(schedule), masterEnabled);
      const payload = {
        comms_enabled: info.isCommsEnabled,
        master_enabled: info.masterEnabled,
        next_opening: info.nextOpening
      };
      if (io) io.emit('comms:status', payload);
      else if (fastify.io) fastify.io.emit('comms:status', payload);

      if (info.isCommsEnabled) {
        flushQueuedMessages(pool, { log, sendPushNotification, io: io || fastify.io })
          .catch((e) => log.err('Queued message flush failed', { error: e.message }));
      }

      reply.send({ ok: true, comms_enabled: info.isCommsEnabled, next_opening: info.nextOpening });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to update comms schedule' });
    }
  });
};

module.exports.resolveCommsSchedule = resolveCommsSchedule;
