// routes/discordAdmin.js
//
// Discord bot configuration, connectivity tests, and manual DMs.
const axios = require('axios');
const { getSetting, setSetting, clearSettingCache } = require('../utils/settings');
const {
  getDiscordClient,
  sendDiscordDM,
  sendDiscordChannelMessage,
  sendDiscordMailNotifications
} = require('../services/discord');

const KNOWN_EMOJI_KEYS = [
  'outlet_alpha', 'outlet_alter', 'outlet_ert', 'outlet_gossip',
  'outlet_kathimerini', 'outlet_mega', 'outlet_opentv', 'outlet_skai',
  'item_rumor'
];

async function autoDiscoverDiscordEmojis() {
  const token = process.env.DISCORD_BOT_TOKEN;
  if (!token) return {};

  try {
    const guildsRes = await axios.get('https://discord.com/api/v10/users/@me/guilds', {
      headers: { Authorization: `Bot ${token}` },
      timeout: 5000
    });

    const discovered = {};
    for (const guild of guildsRes.data || []) {
      try {
        const emojisRes = await axios.get(`https://discord.com/api/v10/guilds/${guild.id}/emojis`, {
          headers: { Authorization: `Bot ${token}` },
          timeout: 5000
        });

        for (const emoji of emojisRes.data || []) {
          if (KNOWN_EMOJI_KEYS.includes(emoji.name)) {
            discovered[emoji.name] = emoji.id;
          }
        }
      } catch (_) {}
    }
    return discovered;
  } catch (_) {
    return {};
  }
}

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
      const emojiIdsRaw = await getSetting('discord_emoji_ids', '{}');
      let emoji_ids = {};
      try {
        emoji_ids = JSON.parse(emojiIdsRaw || '{}');
      } catch (err) {
        emoji_ids = {};
      }

      // Auto-detect any missing emoji keys from connected Discord servers
      const hasMissing = KNOWN_EMOJI_KEYS.some(k => !emoji_ids[k]);
      if (hasMissing) {
        const discovered = await autoDiscoverDiscordEmojis();
        let changed = false;
        for (const [k, id] of Object.entries(discovered)) {
          if (!emoji_ids[k]) {
            emoji_ids[k] = id;
            changed = true;
          }
        }
        if (changed) {
          await setSetting('discord_emoji_ids', JSON.stringify(emoji_ids));
        }
      }

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
        discord_emoji_ids: emoji_ids,
        bot_status: isOnline ? 'Online' : 'Offline',
        bot_name: botName
      });
    } catch (e) {
      log.err('Get discord config failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to fetch settings' });
    }
  });

  // Auto-sync Discord custom emojis from all servers the bot is in
  fastify.post('/api/admin/discord/sync-emojis', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const discovered = await autoDiscoverDiscordEmojis();
      const emojiIdsRaw = await getSetting('discord_emoji_ids', '{}');
      let emoji_ids = {};
      try {
        emoji_ids = JSON.parse(emojiIdsRaw || '{}');
      } catch (_) {
        emoji_ids = {};
      }
      const merged = { ...emoji_ids, ...discovered };
      await setSetting('discord_emoji_ids', JSON.stringify(merged));
      log.ok('Synced discord custom emojis', { count: Object.keys(discovered).length });
      reply.send({ success: true, discord_emoji_ids: merged, count: Object.keys(discovered).length });
    } catch (e) {
      log.err('Sync discord emojis failed', { message: e.message });
      reply.status(500).json({ error: 'Failed to sync emojis from Discord' });
    }
  });

  // Update Discord settings
  fastify.post('/api/admin/discord/config', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const {
        discord_channel_id, discord_schedule_time,
        discord_enabled, notify_mail, notify_news, notify_prems, ai_enabled,
        discord_emoji_ids
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
      if (discord_emoji_ids !== undefined) {
        const payload = typeof discord_emoji_ids === 'object' && discord_emoji_ids !== null
          ? JSON.stringify(discord_emoji_ids)
          : String(discord_emoji_ids);
        await setSetting('discord_emoji_ids', payload);
      }

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

      if (!process.env.DISCORD_BOT_TOKEN) {
        return reply.status(503).json({ error: 'Discord bot token is not configured on the server.' });
      }

      if (type === 'mail') {
        await sendDiscordMailNotifications(true);
        return reply.send({ ok: true, message: 'Mail test triggered.' });
      }

      if (type === 'news') {
        if (!channelId) return reply.status(400).json({ error: 'No channel configured.' });
        await sendDiscordChannelMessage(channelId, "📰 **TEST BROADCAST** 📰\n\nThis is a test of the Erebus News Network emergency broadcast system.");
        return reply.send({ ok: true, message: 'News test broadcast sent.' });
      }

      if (type === 'premonition') {
        const [[adminRow]] = await pool.query('SELECT discord_id FROM users WHERE id=?', [req.user.id]);
        if (!adminRow?.discord_id) {
          return reply.status(400).json({ error: 'You must link your Discord ID in the Users tab to receive a test premonition.' });
        }
        await sendDiscordDM(adminRow.discord_id, "🧠 **TEST VISION**\n\nThe shadows whisper to you: *The system is functioning perfectly.*");
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
      const client = getDiscordClient();
      if (client && process.env.DISCORD_BOT_TOKEN) {
        log.adm('Admin requested Discord bot restart', { admin_id: req.user.id });
        client.destroy();
        await client.login(process.env.DISCORD_BOT_TOKEN);
        reply.send({ ok: true, message: "Bot connection restarted successfully." });
      } else if (process.env.DISCORD_BOT_TOKEN) {
        reply.send({ ok: true, message: "Bot token is active and operational via REST." });
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

      if (!process.env.DISCORD_BOT_TOKEN) {
        return reply.status(503).json({ error: 'Discord bot token is not configured on the server.' });
      }

      // Lookup the user's Discord ID
      const [[user]] = await pool.query('SELECT discord_id, display_name FROM users WHERE id=?', [user_id]);
      if (!user || !user.discord_id) {
        return reply.status(400).json({ error: `${user?.display_name || 'User'} has not linked their Discord ID yet.` });
      }

      // Send the DM via unified helper
      await sendDiscordDM(user.discord_id, `🦇 **Message from the Storytellers:**\n\n${message}`);

      log.adm('Admin sent custom Discord DM', { admin_id: req.user.id, target_user: user_id });
      reply.send({ ok: true, message: `DM successfully sent to ${user.display_name}.` });
    } catch (e) {
      log.err('Failed to send custom Discord DM', { error: e.message, response: e.response?.data });
      if (e.code === 50007 || e.response?.data?.code === 50007) {
        return reply.status(400).json({
          error: 'Cannot send DM: This player has direct messages disabled in their Discord privacy settings or does not share a mutual server with the bot.'
        });
      }
      reply.status(500).json({ error: e.response?.data?.message || e.message || 'Failed to send DM.' });
    }
  });
};
