// routes/comms.js
//
// SchreckNet availability window: whether comms are open, and the schedule
// that opens them.
const { getSetting, setSetting } = require('../utils/settings');

module.exports = async function (fastify, opts) {
  const { log, authRequired, requireAdmin } = opts;

  // Public: Check if comms are enabled
  fastify.get('/api/comms/status', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const masterEnabled = await getSetting('comms_enabled', 'true');
      let isCommsEnabled = masterEnabled === 'true';

      if (isCommsEnabled) {
        const scheduleStr = await getSetting('chat_schedule', '{}');
        try {
          const schedule = JSON.parse(scheduleStr);
          const today = new Date();
          const yesterday = new Date(today.getTime() - 24 * 60 * 60 * 1000);

          const toDateStr = (d) => {
            const y = d.getFullYear();
            const m = String(d.getMonth() + 1).padStart(2, '0');
            const dd = String(d.getDate()).padStart(2, '0');
            return `${y}-${m}-${dd}`;
          };

          const todayStr = toDateStr(today);
          const yesterdayStr = toDateStr(yesterday);

          let activeState = schedule[todayStr];
          const currentHour = today.getHours();

          if (schedule[yesterdayStr] === '17:00' && currentHour < 17) {
            activeState = true;
          } else if (schedule[todayStr] === '17:00') {
            activeState = currentHour >= 17 ? true : false;
          }

          if (activeState === false) {
            isCommsEnabled = false;
          } else if (activeState === true) {
            isCommsEnabled = true;
          }
        } catch (err) { }
      }

      reply.send({ comms_enabled: isCommsEnabled });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to fetch comms status' });
    }
  });

  // Admin: Toggle comms status
  fastify.post('/api/admin/comms/status', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { comms_enabled } = req.body;
      await setSetting('comms_enabled', String(comms_enabled));
      log.adm(`Master comms switched to ${comms_enabled ? 'ONLINE' : 'OFFLINE'}`, { admin_id: req.user.id });
      reply.send({ ok: true, comms_enabled });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to update comms status' });
    }
  });

  // Admin: Get Comms Config (master switch and schedule)
  fastify.get('/api/admin/comms/config', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
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
      log.adm('Comms schedule updated', { admin_id: req.user.id });
      reply.send({ ok: true });
    } catch (e) {
      reply.status(500).json({ error: 'Failed to update comms schedule' });
    }
  });
};
