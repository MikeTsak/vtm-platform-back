const fs = require('fs');
const mysql = require('mysql2/promise');
require('dotenv').config();

function slugify(text) {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)+/g, '');
}

(async () => {
  try {
    const content = fs.readFileSync('C:\\Users\\mixan\\.gemini\\antigravity-ide\\brain\\351d5cb5-c9e9-49de-bfa5-70b44852332d\\browser\\scratchpad_w6yv1ksl.md', 'utf-8');
    const dataCollectedIndex = content.indexOf('## Data Collected');
    const jsonStart = content.indexOf('[', dataCollectedIndex);
    const jsonEnd = content.lastIndexOf(']') + 1;
    const jsonString = content.substring(jsonStart, jsonEnd);
    
    const clans = JSON.parse(jsonString);
    console.log(`Found ${clans.length} clans to insert.`);

    const pool = mysql.createPool({
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'root',
      password: process.env.DB_PASSWORD || '',
      database: process.env.DB_NAME || 'vampire_platform'
    });

    for (const clan of clans) {
      const slug = slugify(clan.name);
      const articleContent = `<aside class="infobox">
  <div class="infobox-title">${clan.name}</div>
  <div class="infobox-image-wrap">
    <img src="${clan.logoUrl}" class="infobox-image" alt="${clan.name} Logo" />
  </div>
  <div class="infobox-section-title">Details</div>
  <div class="infobox-row">
    <div class="infobox-label">Nickname</div>
    <div class="infobox-value">${clan.nickname}</div>
  </div>
  <div class="infobox-row">
    <div class="infobox-label">Sect</div>
    <div class="infobox-value">${clan.sect}</div>
  </div>
</aside>

${clan.overview.split('\n\n').map(p => `<p>${p}</p>`).join('\n')}
`;

      const query = `
        INSERT INTO wiki_articles (slug, title, content, status, author_id)
        VALUES (?, ?, ?, 'published', 1)
        ON DUPLICATE KEY UPDATE
          title = VALUES(title),
          content = VALUES(content),
          updated_at = CURRENT_TIMESTAMP
      `;

      await pool.execute(query, [slug, clan.name, articleContent]);
      console.log(`Inserted/Updated clan: ${clan.name}`);
    }

    console.log('All clans imported successfully!');
    process.exit(0);
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
})();
