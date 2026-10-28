// services/news.js
//
// Helpers shared by the news and rumour routes.

const discord = require('./discord');
const { getSetting } = require('../utils/settings');

const XML_ENTITIES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&apos;', '"': '&quot;' };

const xmlEscape = (str) => String(str).replace(/[&<>'"]/g, (c) => XML_ENTITIES[c]);

// Author identity columns for a news_entries row aliased `n`; pair with
// NEWS_AUTHOR_JOINS. A decree an admin issued as an NPC (n.npc_id) wears that
// NPC's name, titles and portrait; the posting account's name and role are
// nulled so it never reads as "Storyteller".
const NEWS_AUTHOR_COLUMNS = `
  IF(np.id IS NULL, u.display_name, NULL) as author_real_name,
  IF(np.id IS NULL, u.role, NULL) as author_role,
  COALESCE(np.name, c.name) as char_name,
  IF(np.id IS NULL, c.camarilla_titles, np.camarilla_titles) as char_titles,
  IF(np.id IS NULL, c.image_url, np.image_url) as char_image`;
const NEWS_AUTHOR_JOINS = `
  LEFT JOIN users u ON n.author_id = u.id
  LEFT JOIN characters c ON c.user_id = u.id
  LEFT JOIN npcs np ON np.id = n.npc_id`;

// News articles are signed by journalist_name only; who posted them stays in
// the DB. Decrees (announcements) keep their author: it's their byline.
const AUTHOR_FIELDS = ['author_id', 'published_by', 'author_real_name', 'author_role', 'char_name', 'char_titles', 'char_image'];
function redactNewsAuthor(row) {
  if (row.type === 'announcement') return row;
  const out = { ...row };
  for (const k of AUTHOR_FIELDS) delete out[k];
  return out;
}

// Renders the in-fiction byline for a news entry: character name plus their
// highest-ranking Camarilla title, falling back to the account's display name
// and finally to an anonymous Court attribution.
async function getAuthorSignature(entryId, pool) {
  try {
    const [[user]] = await pool.query(`
      SELECT ${NEWS_AUTHOR_COLUMNS}
      FROM news_entries n ${NEWS_AUTHOR_JOINS}
      WHERE n.id = ?
    `, [entryId]);

    if (!user) return 'Issued by Court Authority';

    let authorName = user.char_name || user.author_real_name || 'Court Authority';
    let authorRole = 'Court Member';

    if (user.author_role === 'admin' || (typeof user.author_real_name === 'string' && (user.author_real_name.startsWith('ST ') || user.author_real_name.toLowerCase() === 'admin'))) {
      authorRole = 'Storyteller';
    }

    const rawTitles = user.char_titles;
    let titles = [];
    if (Array.isArray(rawTitles)) {
      titles = rawTitles;
    } else if (typeof rawTitles === 'string' && rawTitles.trim()) {
      try {
        const parsed = JSON.parse(rawTitles);
        if (Array.isArray(parsed)) titles = parsed;
        else if (typeof parsed === 'string') titles = [parsed];
      } catch (e) {
        titles = rawTitles.split(',').map(s => s.trim()).filter(Boolean);
      }
    }

    titles = titles.filter(t => typeof t === 'string' && t.trim().length > 0);

    if (titles.length > 0) {
      const TITLES = ['Prince', 'Seneschal', 'Primogen', 'Sheriff', 'Scourge', 'Keeper', 'Harpy', 'Assistant Harpy', 'Hound', 'Shadow', 'Whip'];
      const sorted = [...titles].sort((a, b) => {
        let aIdx = TITLES.indexOf(a);
        let bIdx = TITLES.indexOf(b);
        if (aIdx === -1) aIdx = 99;
        if (bIdx === -1) bIdx = 99;
        return aIdx - bIdx;
      });
      authorRole = sorted.join(', ');
    }

    return `Issued by ${authorName}, ${authorRole}`;
  } catch (e) {
    return 'Issued by Court Authority';
  }
}

function isVideoUrl(url) {
  if (!url || typeof url !== 'string') return false;
  return /\.(mp4|webm|mov|m4v|ogg)(\?.*)?$/i.test(url) || url.includes('/video/');
}

async function resolveMediaUrl(rawUrl, appBase, pool) {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  const trimmed = rawUrl.trim();
  if (!trimmed) return null;

  const match = trimmed.match(/\/api\/news\/media\/(\d+)/);
  if (match && match[1] && pool) {
    try {
      const [mediaRows] = await pool.query('SELECT data_url FROM news_media WHERE id = ?', [match[1]]);
      if (mediaRows.length > 0 && mediaRows[0].data_url) {
        return mediaRows[0].data_url;
      }
    } catch (_) {}
  }

  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed;
  }

  const base = (appBase || process.env.APP_BASE_URL || 'https://portal.attlarp.gr').replace(/\/$/, '');
  return `${base}${trimmed.startsWith('/') ? '' : '/'}${trimmed}`;
}

/**
 * Broadcasts a news article or announcement to the configured Discord channel.
 *
 * @param {Object} entry - News entry { id, type, title, subtitle, theme, media_url }
 * @param {Object} options - { pool, log, discordPrefix, appBase }
 * @returns {Promise<{ ok: boolean, reason?: string }>}
 */
async function broadcastNewsEntry(entry, options = {}) {
  const { pool, log, discordPrefix, appBase: customAppBase } = options;
  const { id, type, title, subtitle, theme, media_url } = entry;

  const discordEnabled = (await getSetting('discord_enabled', 'true')) === 'true';
  const tokenPresent = Boolean(process.env.DISCORD_BOT_TOKEN);

  if (!discordEnabled || !tokenPresent) {
    const msg = 'Discord broadcasting is disabled or bot token is missing.';
    if (log) log.warn(msg);
    return { ok: false, reason: msg };
  }

  const channelId = await getSetting('discord_channel_id', null);
  if (!channelId) {
    const msg = 'Discord channel not configured.';
    if (log) log.warn(msg);
    return { ok: false, reason: msg };
  }

  const appBase = (customAppBase || process.env.APP_BASE_URL || 'https://portal.attlarp.gr').replace(/\/$/, '');
  const isAnnouncement = type === 'announcement';
  const articleLink = isAnnouncement
    ? `${appBase}/court/announcements/${id}`
    : `${appBase}/news/${id}`;

  const defaultPrefix = isAnnouncement
    ? '📜 **New Court Announcement!** 📜'
    : '🔥 **Hot news from the mortal world!** 🔥';

  const prefix = discordPrefix || defaultPrefix;
  let broadcast = `# ${prefix}\n\n**${title}**\n`;
  if (subtitle) broadcast += `*${subtitle}*\n`;

  if (!isAnnouncement) {
    const outletNames = {
      'ERT': 'ERT News', 'SKAI': 'SKAI.gr', 'ALPHA': 'Alpha News',
      'MEGA': 'Mega Gegonota', 'KATHIMERINI': 'Kathimerini',
      'GOSSIP': 'Gossip-tv', 'OPENTV': 'Open TV', 'ALTER': 'Alter Channel'
    };
    const outletEmojiKeys = {
      'ERT': 'outlet_ert', 'SKAI': 'outlet_skai', 'ALPHA': 'outlet_alpha',
      'MEGA': 'outlet_mega', 'KATHIMERINI': 'outlet_kathimerini',
      'GOSSIP': 'outlet_gossip', 'OPENTV': 'outlet_opentv', 'ALTER': 'outlet_alter'
    };
    const sourceName = outletNames[theme] || theme || 'Unknown';
    let emojiTag = '';
    try {
      const emojiIdsRaw = await getSetting('discord_emoji_ids', '{}');
      const emojiMap = JSON.parse(emojiIdsRaw || '{}');
      const emojiKey = outletEmojiKeys[theme];
      if (emojiKey && emojiMap[emojiKey]) {
        const val = String(emojiMap[emojiKey]).trim();
        if (val.startsWith('<') && val.endsWith('>')) emojiTag = val;
        else if (/^\d+$/.test(val)) emojiTag = `<:${emojiKey}:${val}>`;
      }
    } catch (_) {}

    broadcast += `\n**Source:** ${emojiTag ? `${emojiTag} ` : ''}${sourceName}`;
    broadcast += `\n**Read the full article:**\n${articleLink}`;
    broadcast += `\n\n> ℹ️ *Note: News articles feature real ads to help support and maintain the site, fitting naturally in universe with mortal media.*`;
  } else {
    const sig = await getAuthorSignature(id, pool);
    broadcast += `\n*${sig}*`;
    broadcast += `\n\n**Read the full announcement here:**\n${articleLink}`;
  }

  const payload = { content: broadcast };
  const resolvedImg = await resolveMediaUrl(media_url, appBase, pool);
  if (resolvedImg) {
    if (isVideoUrl(resolvedImg)) {
      payload.content += `\n\n🎥 **Attached Media:**\n${resolvedImg}`;
    } else {
      payload.embeds = [{ image: { url: resolvedImg } }];
    }
  }

  await (options.sendDiscordChannelMessage || discord.sendDiscordChannelMessage)(channelId, payload);
  if (log) log.ok('Discord news broadcast sent successfully', { entryId: id, channelId });
  return { ok: true };
}

module.exports = {
  xmlEscape,
  getAuthorSignature,
  isVideoUrl,
  resolveMediaUrl,
  redactNewsAuthor,
  broadcastNewsEntry,
  NEWS_AUTHOR_COLUMNS,
  NEWS_AUTHOR_JOINS
};
