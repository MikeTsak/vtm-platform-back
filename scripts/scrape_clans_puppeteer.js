const puppeteer = require('puppeteer');
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

  const browser = await puppeteer.launch({ headless: 'new' });
  const page = await browser.newPage();
  
  // Try to avoid simple bot detection
  await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36');

  for (const clanSlug of clansToScrape) {
    try {
      console.log(`Scraping ${clanSlug}...`);
      const url = `https://vtm.paradoxwikis.com/${clanSlug}`;
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
      
      // Extract data in browser context
      const data = await page.evaluate(() => {
        const title = document.querySelector('#firstHeading')?.innerText.trim() || '';
        
        let logoUrl = document.querySelector('.infobox img')?.getAttribute('src');
        if (logoUrl && logoUrl.startsWith('/')) {
          logoUrl = 'https://vtm.paradoxwikis.com' + logoUrl;
        }
        
        let nickname = '[Unknown]';
        let faction = '[Unknown]';
        
        const infoboxRows = document.querySelectorAll('.infobox tr');
        infoboxRows.forEach(row => {
          const header = row.querySelector('th')?.innerText.trim().toLowerCase() || '';
          if (header.includes('nickname')) {
            nickname = row.querySelector('td')?.innerText.trim() || '[Unknown]';
          }
          if (header.includes('faction') || header.includes('sect')) {
            faction = row.querySelector('td')?.innerText.trim() || '[Unknown]';
          }
        });
        
        let overviewHtml = '';
        const paragraphs = document.querySelectorAll('.mw-parser-output > p');
        let count = 0;
        paragraphs.forEach(p => {
          const text = p.innerText.trim();
          if (text.length > 20 && count < 3) {
            overviewHtml += text + '\\n\\n';
            count++;
          }
        });
        
        return { title, logoUrl, nickname, faction, overviewHtml };
      });
      
      console.log('Extracted:', data);
      
      const { title, logoUrl, nickname, faction, overviewHtml } = data;
      const finalTitle = title || clanSlug.replace('_', ' ');

      const content = `
<aside class="infobox">
  <div class="infobox-title">${finalTitle}</div>
  <img src="${logoUrl || 'https://via.placeholder.com/150'}" class="infobox-image" alt="${finalTitle} symbol" />
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

      const slug = finalTitle.replace(/\\s+/g, '-');
      const conn = await pool.getConnection();
      await conn.beginTransaction();

      const [rows] = await conn.query('SELECT id FROM wiki_articles WHERE slug=?', [slug]);
      
      let articleId;
      if (rows.length > 0) {
        articleId = rows[0].id;
        await conn.query('UPDATE wiki_articles SET content=? WHERE id=?', [content, articleId]);
        console.log(`Article ${finalTitle} updated.`);
      } else {
        const [insertResult] = await conn.query(
          'INSERT INTO wiki_articles (title, slug, content, author_id, status) VALUES (?,?,?,?,?)',
          [finalTitle, slug, content, 1, 'published']
        );
        articleId = insertResult.insertId;
        console.log(`Created article for ${finalTitle}`);
      }

      await conn.query(
        'INSERT INTO wiki_article_versions (article_id, editor_id, content, edit_summary) VALUES (?,?,?,?)',
        [articleId, 1, content, 'Scraped from Paradox Wiki via Puppeteer']
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
    
    // Slight delay to be polite
    await new Promise(r => setTimeout(r, 1000));
  }

  await browser.close();
  process.exit(0);
}

scrapeClans();
