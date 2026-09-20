// services/news.js
//
// Helpers shared by the news and rumour routes.

const XML_ENTITIES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&apos;', '"': '&quot;' };

const xmlEscape = (str) => String(str).replace(/[&<>'"]/g, (c) => XML_ENTITIES[c]);

// Renders the in-fiction byline for a news entry: character name plus their
// highest-ranking Camarilla title, falling back to the account's display name
// and finally to an anonymous Court attribution.
async function getAuthorSignature(authorId, pool) {
  try {
    const [[user]] = await pool.query(`
      SELECT u.display_name as author_real_name,
             c.name as char_name, c.camarilla_titles as char_titles
      FROM users u
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE u.id = ?
    `, [authorId]);

    if (!user) return '— Issued by Court Authority';

    let authorName = user.char_name || user.author_real_name || 'Court Authority';
    let authorRole = 'Court Member';
    if (user.char_titles) {
      try {
        const titles = JSON.parse(user.char_titles);
        const TITLES = ['Prince', 'Seneschal', 'Primogen', 'Sheriff', 'Scourge', 'Keeper', 'Harpy', 'Assistant Harpy', 'Hound', 'Shadow', 'Whip'];
        if (Array.isArray(titles) && titles.length > 0) {
          const sorted = [...titles].sort((a, b) => {
            let aIdx = TITLES.indexOf(a);
            let bIdx = TITLES.indexOf(b);
            if (aIdx === -1) aIdx = 99;
            if (bIdx === -1) bIdx = 99;
            return aIdx - bIdx;
          });
          authorRole = sorted[0];
        }
      } catch (e) { }
    }
    return `— Issued by ${authorName}, ${authorRole}`;
  } catch (e) {
    return '— Issued by Court Authority';
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

module.exports = { xmlEscape, getAuthorSignature, isVideoUrl, resolveMediaUrl };
