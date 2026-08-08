const mysql = require('mysql2/promise');
require('dotenv').config();

async function populateCharacters() {
  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'vtm',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

  try {
    const [characters] = await pool.query('SELECT * FROM characters');

    for (const char of characters) {
      if (!char.name) continue;

      const slug = char.name.replace(/\\s+/g, '-');
      
      const titleStr = Array.isArray(char.camarilla_titles) && char.camarilla_titles.length > 0 
        ? char.camarilla_titles.join(', ') 
        : 'Citizen';

      const imageUrl = char.user_id ? `/api/users/${char.user_id}/avatar` : `/api/npcs/${char.id}/avatar`;

      const content = `
<aside class="infobox">
  <div class="infobox-title">${char.name}</div>
  <img src="${imageUrl}" class="infobox-image" alt="${char.name}" />
  <div class="infobox-content">
    <table>
      <tbody>
        <tr><th>Clan</th><td><a href="/article/${char.clan}">${char.clan}</a></td></tr>
        <tr><th>Rank/Title</th><td>${titleStr}</td></tr>
        <tr><th>Status</th><td>${char.status}</td></tr>
      </tbody>
    </table>
  </div>
</aside>

## Overview
${char.name} is a kindred of Clan <a href="/article/${char.clan}">${char.clan}</a>. They hold the title of ${titleStr} within the domain.

## Background
[To Be Added]

## Known Associates
[To Be Added]
`;

      const conn = await pool.getConnection();
      await conn.beginTransaction();
      
      const [rows] = await conn.query('SELECT id FROM wiki_articles WHERE slug=?', [slug]);
      
      let articleId;
      if (rows.length > 0) {
        articleId = rows[0].id;
        await conn.query('UPDATE wiki_articles SET content=? WHERE id=?', [content, articleId]);
        console.log(`Article ${char.name} updated.`);
      } else {
        const [insertResult] = await conn.query(
          'INSERT INTO wiki_articles (title, slug, content, author_id, status) VALUES (?,?,?,?,?)',
          [char.name, slug, content, 1, 'published']
        );
        articleId = insertResult.insertId;
        console.log(`Created article for ${char.name}`);
      }

      await conn.query(
        'INSERT INTO wiki_article_versions (article_id, editor_id, content, edit_summary) VALUES (?,?,?,?)',
        [articleId, 1, content, 'Initial import from characters database']
      );

      // Add tags manually
      const tags = ['Character', char.clan];
      for (const tag of tags) {
        if (!tag) continue;
        const tslug = tag.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
        await conn.query('INSERT IGNORE INTO wiki_tags (name, slug) VALUES (?,?)', [tag.trim(), tslug]);
        const [tagRow] = await conn.query('SELECT id FROM wiki_tags WHERE slug=?', [tslug]);
        if (tagRow.length > 0) {
          await conn.query('INSERT IGNORE INTO wiki_article_tags (article_id, tag_id) VALUES (?,?)', [articleId, tagRow[0].id]);
        }
      }

      await conn.commit();
      conn.release();

      console.log(`Created article for ${char.name}`);
    }
  } catch (err) {
    console.error(`Failed to populate characters:`, err.message);
  }

  process.exit(0);
}

populateCharacters();
