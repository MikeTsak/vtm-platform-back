// routes/discordAdmin.js
//
// Discord bot configuration, connectivity tests, and manual DMs.
const { getSetting, setSetting, clearSettingCache } = require('../utils/settings');
const { discordClient, sendDiscordMailNotifications } = require('../services/discord');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  /* -------------------- ADMIN DISCORD SETTINGS -------------------- */

  // Get current Discord settings
  fastify.get('/api/admin/discord/config', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const channelId = await getSetting('discord_channel_id', '');
      const scheduleTime = await getSetting('discord_schedule_time', '12:00');

      // New feature toggles (default to true)
      const discord_enabled = await getSetting('discord_enabled', 'true') === 'true';
      const notify_mail = await getSetting('discord_notify_mail', 'true') === 'true';
      const notify_news = await getSetting('discord_notify_news', 'true') === 'true';
      const notify_prems = await getSetting('discord_notify_prems', 'true') === 'true';
      const ai_enabled = await getSetting('giannakis_ai_enabled', 'true') === 'true';

      clearSettingCache('discord_bot_last_heartbeat');
      clearSettingCache('discord_bot_name');
      const lastHeartbeat = await getSetting('discord_bot_last_heartbeat', '0');
      const isOnline = (Date.now() - Number(lastHeartbeat)) < 60000;
      const botName = await getSetting('discord_bot_name', 'N/A');

      reply.send({
        discord_channel_id: channelId,
        discord_schedule_time: scheduleTime,
        discord_enabled,
        notify_mail,
        notify_news,
        notify_prems,
        ai_enabled,
        bot_status: isOnline ? 'Online' : 'Offline',
        bot_name: botName
      });
    } catch (e) {
      log.err('Get discord config failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to fetch settings' });
    }
  });

  // Update Discord settings
  fastify.post('/api/admin/discord/config', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const {
        discord_channel_id, discord_schedule_time,
        discord_enabled, notify_mail, notify_news, notify_prems, ai_enabled
      } = req.body;

      if (discord_channel_id !== undefined) await setSetting('discord_channel_id', String(discord_channel_id).trim());

      if (discord_schedule_time !== undefined) {
        if (!/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(discord_schedule_time)) {
          return reply.status(400).json({ error: 'Invalid time format. Use HH:MM (24h).' });
        }
        await setSetting('discord_schedule_time', String(discord_schedule_time));
      }

      if (discord_enabled !== undefined) await setSetting('discord_enabled', String(discord_enabled));
      if (notify_mail !== undefined) await setSetting('discord_notify_mail', String(notify_mail));
      if (notify_news !== undefined) await setSetting('discord_notify_news', String(notify_news));
      if (notify_prems !== undefined) await setSetting('discord_notify_prems', String(notify_prems));
      if (ai_enabled !== undefined) await setSetting('giannakis_ai_enabled', String(ai_enabled));

      log.adm('Updated Discord settings', { admin_id: req.user.id });
      reply.send({ ok: true });
    } catch (e) {
      log.err('Update discord config failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to save settings' });
    }
  });

  // Trigger manual test notifications
  fastify.post('/api/admin/discord/test/:type', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { type } = req.params;
      const channelId = await getSetting('discord_channel_id', null);

      if (!discordClient?.isReady()) {
        return reply.status(503).json({ error: 'Discord bot is currently offline.' });
      }

      if (type === 'mail') {
        await sendDiscordMailNotifications(true); // Pass true to force the test
        return reply.send({ ok: true, message: 'Mail test triggered.' });
      }

      if (type === 'news') {
        if (!channelId) return reply.status(400).json({ error: 'No channel configured.' });
        const channel = await discordClient.channels.fetch(channelId);
        await channel.send("📰 **TEST BROADCAST** 📰\n\nThis is a test of the Erebus News Network emergency broadcast system.");
        return reply.send({ ok: true, message: 'News test broadcast sent.' });
      }

      if (type === 'premonition') {
        // Find the admin's discord ID to send them a test DM
        const [[adminRow]] = await pool.query('SELECT discord_id FROM users WHERE id=?', [req.user.id]);
        if (!adminRow?.discord_id) {
          return reply.status(400).json({ error: 'You must link your Discord ID in the Users tab to receive a test premonition.' });
        }
        const discordUser = await discordClient.users.fetch(adminRow.discord_id);
        await discordUser.send("🧠 **TEST VISION**\n\nThe shadows whisper to you: *The system is functioning perfectly.*");
        return reply.send({ ok: true, message: 'Test premonition sent to your DMs.' });
      }

      reply.status(400).json({ error: 'Unknown test type.' });
    } catch (e) {
      log.err('Manual Discord test failed', { message: e.message });
      reply.status(500).json({ error: 'Test failed: ' + e.message });
    }
  });

  // Hard Restart the Bot Connection
  fastify.post('/api/admin/discord/restart', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      if (discordClient && process.env.DISCORD_BOT_TOKEN) {
        log.adm('Admin requested Discord bot restart', { admin_id: req.user.id });
        discordClient.destroy();
        await discordClient.login(process.env.DISCORD_BOT_TOKEN);
        reply.send({ ok: true, message: "Bot connection restarted successfully." });
      } else {
        reply.status(400).json({ error: "Bot is not configured." });
      }
    } catch (e) {
      log.err('Bot restart failed', { error: e.message });
      reply.status(500).json({ error: 'Failed to restart bot.' });
    }
  });

  // Admin: Send Custom Direct Message to a specific user via Discord
  fastify.post('/api/admin/discord/dm', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const { user_id, message } = req.body;
      if (!user_id || !message) {
        return reply.status(400).json({ error: 'User and message are required.' });
      }

      if (!discordClient?.isReady()) {
        return reply.status(503).json({ error: 'Discord bot is currently offline.' });
      }

      // Lookup the user's Discord ID
      const [[user]] = await pool.query('SELECT discord_id, display_name FROM users WHERE id=?', [user_id]);
      if (!user || !user.discord_id) {
        return reply.status(400).json({ error: `${user?.display_name || 'User'} has not linked their Discord ID yet.` });
      }

      // Fetch the user on Discord and send the DM
      const discordUser = await discordClient.users.fetch(user.discord_id);
      await discordUser.send(`🦇 **Message from the Storytellers:**\n\n${message}`);

      log.adm('Admin sent custom Discord DM', { admin_id: req.user.id, target_user: user_id });
      reply.send({ ok: true, message: `DM successfully sent to ${user.display_name}.` });
    } catch (e) {
      log.err('Failed to send custom Discord DM', { error: e.message });
      reply.status(500).json({ error: 'Failed to send DM.' });
    }
  });
};
