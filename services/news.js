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

module.exports = { xmlEscape, getAuthorSignature };
