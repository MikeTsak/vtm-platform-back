// services/elysiumDiscord.js
//
// Automated Discord delivery for the Keeper of Elysium's invitations.
// Broadcasts invitations to the configured Discord channel with @everyone:
// 1. Automatically on the Monday before an Elysium gathering.
// 2. Automatically upon publication if published on or after the Monday of the event.

const pool = require('../db');
const { log } = require('../logger');
const { getSetting } = require('../utils/settings');
const { sendDiscordChannelMessage } = require('./discord');

const athensDay = (d) => new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Athens' }).format(new Date(d));

const cleanTitle = (t) => String(t || '').replace(/modern\s*day\s*event/gi, 'Elysium').trim();

/**
 * Returns the YYYY-MM-DD (Athens time) of the Monday strictly preceding the event.
 * If the event is on a Saturday (typical for live sessions), returns the Monday of that same week (5 days prior).
 * If the event is on a Monday, returns the Monday 7 days prior.
 */
function getMondayBeforeEvent(eventDate) {
  if (!eventDate) return '';
  const d = new Date(eventDate);
  const athensStr = athensDay(d);
  const [y, m, day] = athensStr.split('-').map(Number);
  const localDate = new Date(Date.UTC(y, m - 1, day));
  const dayOfWeek = localDate.getUTCDay(); // 0: Sun, 1: Mon, ..., 6: Sat
  const daysToSubtract = dayOfWeek === 0 ? 6 : (dayOfWeek === 1 ? 7 : dayOfWeek - 1);
  localDate.setUTCDate(localDate.getUTCDate() - daysToSubtract);
  return localDate.toISOString().slice(0, 10);
}

/**
 * Formats date and time in Athens timezone.
 */
function formatAthensDateTime(eventDate, lang = 'en') {
  if (!eventDate) return '';
  const d = new Date(eventDate);
  const opts = { timeZone: 'Europe/Athens', weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' };
  const time = new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/Athens', hour: '2-digit', minute: '2-digit' }).format(d);
  if (lang === 'el') {
    const dayStr = new Intl.DateTimeFormat('el-GR', opts).format(d);
    return `${dayStr}, ώρα ${time}`;
  }
  const dayStr = new Intl.DateTimeFormat('en-GB', opts).format(d);
  return `${dayStr} at ${time}`;
}

/**
 * Strips personalized tokens like {name} and {clan} from generic Discord broadcast body text.
 */
function cleanGenericBody(bodyText) {
  return String(bodyText || '')
    .replace(/\{name\}/gi, 'Kindred')
    .replace(/\{clan\}/gi, 'the Blood')
    .trim();
}

/**
 * Broadcasts an Elysium invitation to Discord.
 */
async function sendElysiumInvitationToDiscord({ event, invitation, renderedCardBuffer, customPool }) {
  const db = customPool || pool;
  const isEnabled = (await getSetting('discord_enabled', 'true')) === 'true';
  if (!isEnabled) {
    log.info('Discord notifications disabled: skipping Elysium invitation broadcast.');
    return false;
  }

  const channelId = await getSetting('discord_channel_id', null);
  if (!channelId) {
    log.warn('Discord notification skipped: no channel ID configured for Elysium invitations.');
    return false;
  }

  const design = typeof invitation.design === 'string'
    ? (() => { try { return JSON.parse(invitation.design); } catch { return {}; } })()
    : (invitation.design || {});
  const lang = design.lang === 'el' ? 'el' : 'en';

  const title = cleanTitle(invitation.name || event.title || 'Elysium');
  const dateTimeFormatted = formatAthensDateTime(event.date, lang);

  let file = null;
  if (renderedCardBuffer) {
    file = {
      name: 'elysium-invitation.jpg',
      data: renderedCardBuffer,
      type: 'image/jpeg'
    };
  } else if (invitation.rendered_card_data) {
    const match = String(invitation.rendered_card_data).match(/^data:(image\/\w+);base64,(.+)$/);
    if (match) {
      file = {
        name: `elysium-invitation.${match[1].split('/')[1] === 'jpeg' ? 'jpg' : match[1].split('/')[1] || 'png'}`,
        data: Buffer.from(match[2], 'base64'),
        type: match[1]
      };
    }
  }

  const headline = lang === 'el'
    ? `@everyone\n🏛️ **Πρόσκληση στο Ηλύσιο: ${title}**\nΕκδόθηκε επίσημη πρόσκληση για το Ηλύσιο από τον Keeper.`
    : `@everyone\n🏛️ **Elysium Invitation: ${title}**\nAn invitation to Elysium has been issued by the Keeper of Elysium.`;

  const fields = [
    { name: lang === 'el' ? 'Ημερομηνία και Ώρα' : 'Date and Time', value: dateTimeFormatted, inline: true }
  ];
  if (invitation.location) {
    fields.push({ name: lang === 'el' ? 'Τοποθεσία' : 'Location', value: invitation.location, inline: true });
  }
  if (invitation.dress_code) {
    fields.push({ name: lang === 'el' ? 'Ενδυμασία' : 'Attire', value: invitation.dress_code, inline: true });
  }
  if (invitation.signature) {
    fields.push({ name: lang === 'el' ? 'Keeper' : 'Signature', value: invitation.signature, inline: true });
  }

  const payload = {
    content: headline,
    embeds: [{
      title: `🏛️ ${title}`,
      description: cleanGenericBody(invitation.body),
      color: 0x8a1826,
      fields,
      footer: { text: 'Athens by Night Court of Elysium' }
    }],
    allowed_mentions: { parse: ['everyone'] },
    allowedMentions: { parse: ['everyone'] }
  };

  if (file) {
    payload._customFile = file;
  }

  await sendDiscordChannelMessage(channelId, payload);

  await db.query(
    'UPDATE elysium_invitations SET discord_posted_at = NOW() WHERE event_id = ?',
    [event.id || invitation.event_id]
  );

  log.info('Elysium invitation Discord broadcast sent successfully', { event_id: event.id, title });
  return true;
}

/**
 * Checks for any published Elysium invitations whose Monday-before has arrived,
 * and broadcasts them if not yet posted.
 */
async function checkAndAutoSendElysiumInvitations(customPool) {
  const db = customPool || pool;
  try {
    const [rows] = await db.query(
      `SELECT e.id AS event_id, e.title, e.date,
              i.name, i.location, i.salutation, i.body, i.dress_code, i.signature, i.design,
              i.published_at, i.discord_posted_at, i.rendered_card_data
         FROM events e
         JOIN elysium_invitations i ON i.event_id = e.id
        WHERE e.is_elysium = 1
          AND e.date >= NOW()
          AND i.published_at IS NOT NULL
          AND i.discord_posted_at IS NULL
        ORDER BY e.date ASC`
    );

    if (!rows.length) return 0;

    const todayAthens = athensDay(new Date());
    let sentCount = 0;

    for (const row of rows) {
      const mondayBefore = getMondayBeforeEvent(row.date);
      if (todayAthens >= mondayBefore) {
        log.info('Auto sending Elysium invitation: Monday before event reached', {
          event_id: row.event_id,
          title: row.title,
          event_date: row.date,
          mondayBefore,
          todayAthens
        });

        const success = await sendElysiumInvitationToDiscord({
          event: { id: row.event_id, title: row.title, date: row.date },
          invitation: row,
          customPool: db
        });
        if (success) sentCount++;
      }
    }

    return sentCount;
  } catch (err) {
    log.err('Failed checking auto send Elysium invitations', { error: err.message });
    return 0;
  }
}

module.exports = {
  getMondayBeforeEvent,
  formatAthensDateTime,
  cleanGenericBody,
  sendElysiumInvitationToDiscord,
  checkAndAutoSendElysiumInvitations,
  athensDay,
  cleanTitle,
};
