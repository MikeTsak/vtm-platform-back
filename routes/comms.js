// routes/comms.js
//
// SchreckNet / Surface Web availability: whether comms are open, the calendar
// that opens and closes them, and the master switch. The switch follows the
// calendar on its own; flipping it is an emergency override that lasts until
// the calendar next changes (services/commsState.js).
const { getSetting, setSetting, clearSettingCache } = require('../utils/settings');
const { flushQueuedMessages } = require('../services/commsQueue');
const { loadCommsState, statusPayload, setCommsSwitch, reanchorOverride, resolveCommsState } = require('../services/commsState');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin, sendPushNotification, io } = opts;
  const socketIo = () => io || fastify.io;

  // Tell every client, and deliver the Send Later queue once comms are open.
  const broadcast = (info) => {
    socketIo()?.emit('comms:status', statusPayload(info));
    if (info.isCommsEnabled) {
      flushQueuedMessages(pool, { log, sendPushNotification, io: socketIo() })
        .catch((e) => log.err('Queued message flush failed', { error: e.message }));
    }
  };

  // Public: whether comms are open and when that next changes.
  fastify.get('/api/comms/status', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      reply.send(statusPayload(await loadCommsState()));
    } catch (e) {
      reply.status(500).send({ error: 'Failed to fetch comms status' });
    }
  });

  // Admin: flip the master switch. { comms_enabled: bool } overrides the
  // calendar until its next change (or returns to it, if that's what the
  // calendar says anyway); { follow_calendar: true } drops the override.
  fastify.post('/api/admin/comms/status', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { comms_enabled, follow_calendar } = req.body || {};
      if (!follow_calendar && typeof comms_enabled !== 'boolean') return reply.status(400).send({ error: 'comms_enabled must be true or false' });
      const info = await setCommsSwitch(follow_calendar ? null : comms_enabled, req.user.id);
      log.adm(info.override
        ? `Comms override: forced ${info.override.state ? 'ONLINE' : 'OFFLINE'} until ${info.override.until || 'cleared'}`
        : `Comms switch back on the calendar: ${info.isCommsEnabled ? 'ONLINE' : 'OFFLINE'}`, { admin_id: req.user.id });
      broadcast(info);
      reply.send({ ok: true, ...statusPayload(info) });
    } catch (e) {
      log.err('Failed to update comms status', { message: e.message });
      reply.status(500).send({ error: 'Failed to update comms status' });
    }
  });

  // Admin: the calendar plus the switch's live state.
  fastify.get('/api/admin/comms/config', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      clearSettingCache('chat_schedule');
      clearSettingCache('comms_override');
      const info = await loadCommsState();
      let schedule = {};
      try { schedule = JSON.parse(await getSetting('chat_schedule', '{}')); } catch (e) { }
      reply.send({ ...statusPayload(info), schedule });
    } catch (e) {
      reply.status(500).send({ error: 'Failed to fetch comms config' });
    }
  });

  // Admin: save the calendar. An override in force is re-anchored to it.
  fastify.post('/api/admin/comms/schedule', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { schedule } = req.body || {};
      if (!schedule || typeof schedule !== 'object' || Array.isArray(schedule)) return reply.status(400).send({ error: 'Invalid schedule' });
      await setSetting('chat_schedule', JSON.stringify(schedule));
      clearSettingCache('chat_schedule');
      await reanchorOverride();
      log.adm('Comms schedule updated', { admin_id: req.user.id });

      const info = await loadCommsState();
      broadcast(info);
      reply.send({ ok: true, ...statusPayload(info) });
    } catch (e) {
      reply.status(500).send({ error: 'Failed to update comms schedule' });
    }
  });
};

module.exports.resolveCommsState = resolveCommsState;
