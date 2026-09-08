// services/discord.js
//
// Everything that talks to Discord from the API process.
//
// The bot itself is decoupled — it runs in discordWorker.js as its own
// process. `discordClient` is a null stand-in so the code paths below can stay
// in place without throwing ReferenceErrors; every one of them checks
// `isReady()` first and no-ops when the bot is not attached here.

const pool = require('../db');
const { log } = require('../logger');
const { getSetting } = require('../utils/settings');
const { broadcastNtfyAlert } = require('../utils/ntfy');

const LOG_CHANNEL_ID = '1469033259806625874';

const discordClient = null;

// Report errors to the defined Discord channel (and always to ntfy).
async function reportErrorToDiscord(source, error) {
  // Truncate stack trace to avoid Discord 2000 char limit
  const errString = (error.stack || error.message || String(error)).slice(0, 1000);

  // Also send to Ntfy (independent of environment/Discord connection)
  await broadcastNtfyAlert(errString, {
    title: `🚨 Error: ${source}`,
    tags: ['rotating_light', 'error'],
    priority: 'high',
    requiresSubscription: 'errors',
  }).catch(() => { });

  // 1. Check if bot is connected
  if (!discordClient?.isReady()) return;

  // 2. CHECK: Only send error logs if we are in PRODUCTION
  // If we are in 'staging' or 'development', this function stops here.
  if (process.env.NODE_ENV !== 'production') return;

  try {
    const channel = await discordClient.channels.fetch(LOG_CHANNEL_ID);
    if (!channel) return;

    await channel.send(`🚨 **Error Detected: ${source}**\n\`\`\`js\n${errString}\n\`\`\``);
  } catch (e) {
    // Fail silently so we don't cause an infinite error loop
    console.error('Failed to report error to Discord:', e.message);
  }
}

// Helper: Send Discord Notifications (Consolidated Single Message)
async function sendDiscordMailNotifications(isTest = false) {
  if (!discordClient?.isReady()) return;

  const isEnabled = await getSetting('discord_enabled', 'true') === 'true';
  const notifyMail = await getSetting('discord_notify_mail', 'true') === 'true';

  if (!isEnabled) return;
  if (!notifyMail && !isTest) return; // Allow tests to bypass the mail toggle

  try {
    // 1. Get Channel ID from DB
    const channelId = await getSetting('discord_channel_id', null);
    if (!channelId) {
      log.warn('Discord notification skipped: No channel ID configured in Admin Settings.');
      return;
    }

    const channel = await discordClient.channels.fetch(channelId).catch(() => null);
    if (!channel) {
      log.warn('Discord notification skipped: Invalid Channel ID or Bot lacks permission.', { channelId });
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

    // 4. Get News (Logic: Recent 3 Days OR Last 3 Total)
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

    // Guard: If nothing to report, stop.
    if (recipients.length === 0 && !hasNpcMail && newsRows.length === 0 && !isTest) return;

    // --- CONSTRUCTING THE SINGLE MESSAGE ---
    const todayStr = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });

    // Start with Intro
    let msg = `🦇 **Good Evening Kindred of Athens**, as of today **${todayStr}**, I would like to remind you of the following:\n\n`;

    // Add Player Tags (One line)
    if (recipients.length > 0) {
      // Create a comma-separated list of mentions: <@123>, <@456>
      const mentions = recipients.map(r => `<@${r.discord_id}>`).join(', ');
      msg += `📩 **Unread Mail:** ${mentions}, please check your inbox.\n`;
    }

    // Add ST Tag with NPC Names
    if (hasNpcMail || isTest) {
      msg += `🎭 **Storytellers** <@&1421503116871991490>, there are **NPC messages** to attend to`;
      if (hasNpcMail) {
        msg += ` for: **${npcNames}**.\n`;
      } else {
        msg += `.\n`; // Fallback for manual test mode when no actual mail exists
      }
    }

    // Add News
    if (newsRows.length > 0) {
      msg += `\n━━━━━━━━━━━━━━━━━━━━\n📢  **EREBUS NEWS FLASH**\n${newsTitle}\n━━━━━━━━━━━━━━━━━━━━\n`;
      newsRows.forEach(n => {
        const d = new Date(n.created_at).toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit' });
        msg += `🔹 **${n.title}** — _${d}_\n`;
      });
    }

    // --- SENDING ---
    // We send 'msg' as one single block.
    await channel.send(msg);

    log.ok(`Discord notification sent. Players: ${recipients.length}, NPC Mail: ${hasNpcMail}, News: ${newsRows.length}`);

  } catch (e) {
    log.err('Discord mail notification process failed', { message: e.message });
  }
}

module.exports = {
  discordClient,
  LOG_CHANNEL_ID,
  reportErrorToDiscord,
  sendDiscordMailNotifications,
};
