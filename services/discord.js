// services/discord.js
//
// Everything that talks to Discord from the API process.
// Supports live Gateway bot client and automated REST API fallback for 100% reliable messaging.

const axios = require('axios');
const pool = require('../db');
const { log } = require('../logger');
const { getSetting } = require('../utils/settings');
const { broadcastNtfyAlert } = require('../utils/ntfy');

const LOG_CHANNEL_ID = '1469033259806625874';

function getDiscordClient() {
  try {
    const worker = require('../discordWorker');
    return worker.getClient ? worker.getClient() : null;
  } catch {
    return null;
  }
}

/**
 * Send a Direct Message to a Discord user.
 * Tries Gateway bot client first, then falls back to Discord REST API directly.
 */
async function sendDiscordDM(recipientDiscordId, messageText) {
  if (!recipientDiscordId) {
    throw new Error('Recipient Discord ID is required.');
  }
  if (!messageText) {
    throw new Error('Message content is required.');
  }

  const token = process.env.DISCORD_BOT_TOKEN;
  if (!token) {
    throw new Error('Discord bot token is not configured on the server.');
  }

  const payload = typeof messageText === 'string' ? { content: messageText } : messageText;

  const client = getDiscordClient();
  if (client?.isReady()) {
    try {
      const discordUser = await client.users.fetch(recipientDiscordId);
      if (discordUser) {
        return await discordUser.send(payload);
      }
    } catch (clientErr) {
      if (clientErr.code === 50007) {
        throw clientErr;
      }
      log.warn('Discord client DM failed, falling back to REST API', { error: clientErr.message });
    }
  }

  // Fallback: Discord REST API
  try {
    const channelRes = await axios.post(
      'https://discord.com/api/v10/users/@me/channels',
      { recipient_id: recipientDiscordId },
      {
        headers: {
          Authorization: `Bot ${token}`,
          'Content-Type': 'application/json'
        },
        timeout: 10000
      }
    );

    const dmChannelId = channelRes.data.id;

    const messageRes = await axios.post(
      `https://discord.com/api/v10/channels/${dmChannelId}/messages`,
      payload,
      {
        headers: {
          Authorization: `Bot ${token}`,
          'Content-Type': 'application/json'
        },
        timeout: 10000
      }
    );

    return messageRes.data;
  } catch (err) {
    if (err.response?.data?.code === 50007) {
      const e = new Error('Cannot send direct message: User has DMs disabled or does not share a mutual server with the bot.');
      e.code = 50007;
      throw e;
    }
    throw err;
  }
}

/**
 * Send a message to a Discord channel.
 * Tries Gateway bot client first, then falls back to Discord REST API directly.
 */
async function sendDiscordChannelMessage(channelId, content) {
  if (!channelId) {
    throw new Error('Channel ID is required.');
  }

  const token = process.env.DISCORD_BOT_TOKEN;
  if (!token) {
    throw new Error('Discord bot token is not configured on the server.');
  }

  const client = getDiscordClient();
  if (client?.isReady()) {
    try {
      const channel = await client.channels.fetch(channelId);
      if (channel) {
        return await channel.send(content);
      }
    } catch (clientErr) {
      log.warn('Discord client channel send failed, falling back to REST API', { error: clientErr.message });
    }
  }

  // Fallback: Discord REST API
  const messageRes = await axios.post(
    `https://discord.com/api/v10/channels/${channelId}/messages`,
    typeof content === 'string' ? { content } : content,
    {
      headers: {
        Authorization: `Bot ${token}`,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    }
  );

  return messageRes.data;
}

// Report errors to the defined Discord channel (and always to ntfy).
async function reportErrorToDiscord(source, error) {
  const errString = (error.stack || error.message || String(error)).slice(0, 1000);

  // Send to Ntfy
  await broadcastNtfyAlert(errString, {
    title: `🚨 Error: ${source}`,
    tags: ['rotating_light', 'error'],
    priority: 'high',
    requiresSubscription: 'errors',
  }).catch(() => { });

  if (process.env.NODE_ENV !== 'production') return;
  if (!process.env.DISCORD_BOT_TOKEN) return;

  try {
    await sendDiscordChannelMessage(LOG_CHANNEL_ID, `🚨 **Error Detected: ${source}**\n\`\`\`js\n${errString}\n\`\`\``);
  } catch (e) {
    console.error('Failed to report error to Discord:', e.message);
  }
}

// Helper: Send Discord Notifications (Consolidated Single Message)
async function sendDiscordMailNotifications(isTest = false) {
  if (!process.env.DISCORD_BOT_TOKEN) return;

  const isEnabled = await getSetting('discord_enabled', 'true') === 'true';
  const notifyMail = await getSetting('discord_notify_mail', 'true') === 'true';

  if (!isEnabled) return;
  if (!notifyMail && !isTest) return;

  try {
    const channelId = await getSetting('discord_channel_id', null);
    if (!channelId) {
      log.warn('Discord notification skipped: No channel ID configured in Admin Settings.');
      return;
    }

    // 2. Find users with unread Direct Messages
    const [recipients] = await pool.query(`
      SELECT DISTINCT u.discord_id
      FROM chat_messages m
      JOIN users u ON m.recipient_id = u.id
      WHERE m.read_at IS NULL
        AND u.discord_id IS NOT NULL
        AND u.discord_id != ''
    `);

    // 3. Check for recent NPC messages AND get the NPC names
    const [npcMessages] = await pool.query(`
      SELECT DISTINCT n.name
      FROM npc_messages m
      JOIN npcs n ON m.npc_id = n.id
      WHERE m.from_side = 'user'
      AND m.created_at > (NOW() - INTERVAL 5 DAY)
    `);

    const hasNpcMail = npcMessages.length > 0;
    const npcNames = npcMessages.map(npc => npc.name).join(', ');

    // 4. Get News
    let [newsRows] = await pool.query(`
      SELECT title, created_at
      FROM news_entries
      WHERE created_at > (NOW() - INTERVAL 3 DAY)
      ORDER BY created_at DESC
    `);

    let newsTitle = "🔥 **Fresh Off the Press**";

    if (newsRows.length === 0) {
      [newsRows] = await pool.query(`
        SELECT title, created_at
        FROM news_entries
        ORDER BY created_at DESC
        LIMIT 3
      `);
      newsTitle = "📜 **Previous Headlines**";
    }

    if (recipients.length === 0 && !hasNpcMail && newsRows.length === 0 && !isTest) return;

    const todayStr = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });

    let msg = `🦇 **Good Evening Kindred of Athens**, as of today **${todayStr}**, I would like to remind you of the following:\n\n`;

    if (recipients.length > 0) {
      const mentions = recipients.map(r => `<@${r.discord_id}>`).join(', ');
      msg += `📩 **Unread Mail:** ${mentions}, please check your inbox.\n`;
    }

    if (hasNpcMail || isTest) {
      msg += `🎭 **Storytellers** <@&1421503116871991490>, there are **NPC messages** to attend to`;
      if (hasNpcMail) {
        msg += ` for: **${npcNames}**.\n`;
      } else {
        msg += `.\n`;
      }
    }

    if (newsRows.length > 0) {
      msg += `\n━━━━━━━━━━━━━━━━━━━━\n📢  **EREBUS NEWS FLASH**\n${newsTitle}\n━━━━━━━━━━━━━━━━━━━━\n`;
      newsRows.forEach(n => {
        const d = new Date(n.created_at).toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit' });
        msg += `🔹 **${n.title}** : _${d}_\n`;
      });
    }

    await sendDiscordChannelMessage(channelId, msg);
    log.ok(`Discord notification sent. Players: ${recipients.length}, NPC Mail: ${hasNpcMail}, News: ${newsRows.length}`);
  } catch (e) {
    log.err('Discord mail notification process failed', { message: e.message });
  }
}

const exported = {
  getDiscordClient,
  sendDiscordDM,
  sendDiscordChannelMessage,
  LOG_CHANNEL_ID,
  reportErrorToDiscord,
  sendDiscordMailNotifications,
};

// Backwards-compatible getter for `discordClient`
Object.defineProperty(exported, 'discordClient', {
  get: () => getDiscordClient(),
  enumerable: true
});

module.exports = exported;
