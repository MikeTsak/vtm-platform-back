const mysql = require('mysql2/promise');
require('dotenv').config();

const clans = [
  {
    name: 'Brujah',
    summary: 'The Brujah are a clan of rebels, rabble-rousers, and philosophers.',
    image: 'https://vtm.paradoxwikis.com/images/thumb/8/8e/V5_Brujah_logo.png/120px-V5_Brujah_logo.png'
  },
  {
    name: 'Gangrel',
    summary: 'The Gangrel are wanderers, outcasts, and survivors connected to the beast within.',
    image: 'https://vtm.paradoxwikis.com/images/thumb/5/52/V5_Gangrel_logo.png/120px-V5_Gangrel_logo.png'
  },
  {
    name: 'Malkavian',
    summary: 'The Malkavians are seers and lunatics, cursed with madness but gifted with insight.',
    image: 'https://vtm.paradoxwikis.com/images/thumb/2/20/V5_Malkavian_logo.png/120px-V5_Malkavian_logo.png'
  },
  {
    name: 'Nosferatu',
    summary: 'Hideously deformed by the Embrace, the Nosferatu are the spies and information brokers of the kindred.',
    image: 'https://vtm.paradoxwikis.com/images/thumb/4/4f/V5_Nosferatu_logo.png/120px-V5_Nosferatu_logo.png'
  },
  {
    name: 'Toreador',
    summary: 'The Toreador are artists, socialites, and sensualists who cling to their mortal passions.',
    image: 'https://vtm.paradoxwikis.com/images/thumb/4/4b/V5_Toreador_logo.png/120px-V5_Toreador_logo.png'
  },
  {
    name: 'Tremere',
    summary: 'The Tremere are a clan of blood sorcerers and warlocks, bound by tight hierarchy.',
    image: 'https://vtm.paradoxwikis.com/images/thumb/a/a2/V5_Tremere_logo.png/120px-V5_Tremere_logo.png'
  },
  {
    name: 'Ventrue',
    summary: 'The Ventrue are the self-appointed aristocracy of the night, rulers and corporate leaders.',
    image: 'https://vtm.paradoxwikis.com/images/thumb/3/30/V5_Ventrue_logo.png/120px-V5_Ventrue_logo.png'
  }
];

async function populateClans() {
  const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'vtm',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
  });

  for (const clan of clans) {
    const slug = clan.name.replace(/\s+/g, '-');
    const content = `
<aside class="infobox">
  <div class="infobox-title">${clan.name}</div>
  <img src="${clan.image}" class="infobox-image" alt="${clan.name} symbol" />
  <div class="infobox-content">
    <table>
      <tbody>
        <tr><th>Nickname</th><td>[To Be Added]</td></tr>
        <tr><th>Sect</th><td>[To Be Added]</td></tr>
      </tbody>
    </table>
  </div>
</aside>

## Overview
${clan.summary}

## History
History of the ${clan.name} clan...

## Weakness
The bane of the ${clan.name}...
`;

    try {
      const conn = await pool.getConnection();
      
      const [rows] = await conn.query('SELECT id FROM wiki_articles WHERE slug=?', [slug]);
      if (rows.length > 0) {
        console.log(`Article ${clan.name} already exists. Skipping.`);
        conn.release();
        continue;
      }

      await conn.beginTransaction();

      const [insertResult] = await conn.query(
        'INSERT INTO wiki_articles (title, slug, content, author_id, status) VALUES (?,?,?,?,?)',
        [clan.name, slug, content, 1, 'published']
      );
      
      const articleId = insertResult.insertId;

      await conn.query(
        'INSERT INTO wiki_article_versions (article_id, editor_id, content, edit_summary) VALUES (?,?,?,?)',
        [articleId, 1, content, 'Initial import']
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

      console.log(`Created article for ${clan.name}`);
    } catch (err) {
      console.error(`Failed to create ${clan.name}:`, err.message);
    }
  }

  process.exit(0);
}

populateClans();
