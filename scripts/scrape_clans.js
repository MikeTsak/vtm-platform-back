const axios = require('axios');
const cheerio = require('cheerio');
const mysql = require('mysql2/promise');
require('dotenv').config();

const clansToScrape = [
  'Banu_Haqim', 'Brujah', 'Gangrel', 'Hecata', 'Lasombra', 
  'Malkavian', 'Ministry', 'Nosferatu', 'Ravnos', 'Salubri', 
  'Toreador', 'Tremere', 'Tzimisce', 'Ventrue'
];

async function scrapeClans() {
  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'vtm',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

  for (const clanSlug of clansToScrape) {
    try {
      console.log(`Scraping ${clanSlug}...`);
      const url = `https://vtm.paradoxwikis.com/${clanSlug}`;
      const { data } = await axios.get(url);
      const $ = cheerio.load(data);
      
      const title = $('#firstHeading').text().trim() || clanSlug.replace('_', ' ');
      
      let logoUrl = $('.infobox img').first().attr('src');
      if (logoUrl && logoUrl.startsWith('/')) {
        logoUrl = 'https://vtm.paradoxwikis.com' + logoUrl;
      }
      
      // Try to get nickname and sect from infobox
      let nickname = '[Unknown]';
      let faction = '[Unknown]';
      
      $('.infobox tr').each((i, el) => {
        const header = $(el).find('th').text().trim().toLowerCase();
        if (header.includes('nickname')) {
          nickname = $(el).find('td').text().trim();
        }
        if (header.includes('faction') || header.includes('sect')) {
          faction = $(el).find('td').text().trim();
        }
      });
      
      // Get the first couple of paragraphs for overview
      let overviewHtml = '';
      $('.mw-parser-output > p').each((i, el) => {
        if (i < 2) {
          // extract plain text or keep some links? Plain text is safer, then we add our own.
          overviewHtml += $(el).text().trim() + '\n\n';
        }
      });

      const content = `
<aside class="infobox">
  <div class="infobox-title">${title}</div>
  <img src="${logoUrl || 'https://via.placeholder.com/150'}" class="infobox-image" alt="${title} symbol" />
  <div class="infobox-content">
    <table>
      <tbody>
        <tr><th>Nickname</th><td>${nickname}</td></tr>
        <tr><th>Sect</th><td>${faction}</td></tr>
      </tbody>
    </table>
  </div>
</aside>

## Overview
${overviewHtml.trim() || 'Information not available.'}

## Further Information
Read more at the [Paradox Wiki](${url}).
`;

      const slug = title.replace(/\s+/g, '-');
      const conn = await pool.getConnection();
      await conn.beginTransaction();

      const [rows] = await conn.query('SELECT id FROM wiki_articles WHERE slug=?', [slug]);
      
      let articleId;
      if (rows.length > 0) {
        articleId = rows[0].id;
        await conn.query('UPDATE wiki_articles SET content=? WHERE id=?', [content, articleId]);
        console.log(`Article ${title} updated.`);
      } else {
        const [insertResult] = await conn.query(
          'INSERT INTO wiki_articles (title, slug, content, author_id, status) VALUES (?,?,?,?,?)',
          [title, slug, content, 1, 'published']
        );
        articleId = insertResult.insertId;
        console.log(`Created article for ${title}`);
      }

      await conn.query(
        'INSERT INTO wiki_article_versions (article_id, editor_id, content, edit_summary) VALUES (?,?,?,?)',
        [articleId, 1, content, 'Scraped from Paradox Wiki']
      );

      // Add tags manually
      const tags = ['Clan', 'Kindred'];
      for (const tag of tags) {
        const tslug = tag.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
        await conn.query('INSERT IGNORE INTO wiki_tags (name, slug) VALUES (?,?)', [tag.trim(), tslug]);
        const [tagRow] = await conn.query('SELECT id FROM wiki_tags WHERE slug=?', [tslug]);
        if (tagRow.length > 0) {
          await conn.query('INSERT IGNORE INTO wiki_article_tags (article_id, tag_id) VALUES (?,?)', [articleId, tagRow[0].id]);
        }
      }

      await conn.commit();
      conn.release();

    } catch (err) {
      console.error(`Failed to scrape ${clanSlug}:`, err.message);
    }
    
    // Slight delay to be polite to the wiki
    await new Promise(r => setTimeout(r, 500));
  }

  process.exit(0);
}

scrapeClans();
