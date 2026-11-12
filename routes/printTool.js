// routes/printTool.js
//
// Admin print tool (front: features/admin/PrintTool.jsx): rumours, news
// articles, court decrees and boons from a chosen period, printed on A4 or on
// the Epson TM-T20III thermal printer (one ticket per item, cut after each).
//
//   GET /api/admin/print/items   everything in the period, oldest first
//   GET /api/admin/print/dither  an image as pure black/white dots for the
//                                thermal printer (no grey: a dot is on or off)

const sharp = require('sharp');
const { NEWS_AUTHOR_COLUMNS, NEWS_AUTHOR_JOINS, resolveMediaUrl, isVideoUrl } = require('../services/news');
const { atkinson } = require('../utils/dither');

const KINDS = ['rumors', 'news', 'decrees', 'boons'];
const PER_KIND = 1000;
// TM-T20III: 72 mm printable at 203 dpi = 576 dots across.
const THERMAL_DOTS = 576;
const MAX_HEIGHT = 2000;
const MAX_BYTES = 15 * 1024 * 1024;
// The only place pictures are fetched from: the image host every upload goes
// to. Anything else is refused, so this can't be aimed at internal addresses.
const IMAGE_HOST = 'img.miketsak.gr';

const parseDate = (v) => {
  if (v == null || v === '') return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d;
};

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, requireAdmin } = opts;

  fastify.get('/api/admin/print/items', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    const kinds = String(req.query.kinds || '').split(',').filter((k) => KINDS.includes(k));
    const from = parseDate(req.query.from);
    const to = parseDate(req.query.to);
    if (!kinds.length) return reply.status(400).send({ error: 'Choose at least one kind of item.' });
    if (from === undefined || to === undefined) return reply.status(400).send({ error: 'Invalid date.' });

    // `col` between from and to, either end optional.
    const period = (col) => {
      const sql = [];
      const params = [];
      if (from) { sql.push(`${col} >= ?`); params.push(from); }
      if (to) { sql.push(`${col} <= ?`); params.push(to); }
      return { sql: sql.length ? sql.join(' AND ') : '1=1', params };
    };

    try {
      const items = [];

      if (kinds.includes('rumors')) {
        const p = period('created_at');
        // Anonymous: who posted a rumour is never sent.
        const [rows] = await pool.query(
          `SELECT id, title, body, media_url, created_at FROM rumors WHERE ${p.sql} ORDER BY created_at LIMIT ${PER_KIND}`,
          p.params
        );
        items.push(...rows.map((r) => ({ kind: 'rumor', ...r })));
      }

      const newsTypes = [kinds.includes('news') && 'news', kinds.includes('decrees') && 'announcement'].filter(Boolean);
      if (newsTypes.length) {
        const p = period('COALESCE(n.published_at, n.created_at)');
        const [rows] = await pool.query(
          `SELECT n.id, n.type, n.title, n.subtitle, n.body, n.theme, n.journalist_name, n.media_url,
                  COALESCE(n.published_at, n.created_at) AS created_at, ${NEWS_AUTHOR_COLUMNS}
             FROM news_entries n ${NEWS_AUTHOR_JOINS}
            WHERE n.is_private = 0 AND n.type IN (?) AND ${p.sql}
            ORDER BY created_at LIMIT ${PER_KIND * 2}`,
          [newsTypes, ...p.params]
        );
        for (const r of rows) {
          const base = {
            id: r.id, title: r.title, subtitle: r.subtitle, body: r.body, media_url: r.media_url, created_at: r.created_at,
          };
          // Articles are signed by their journalist only; a decree keeps its byline.
          if (r.type === 'news') items.push({ kind: 'news', ...base, theme: r.theme, journalist_name: r.journalist_name });
          else items.push({ kind: 'decree', ...base, author_name: r.char_name || null, author_titles: r.char_titles || null });
        }
      }

      if (kinds.includes('boons')) {
        const p = period('created_at');
        const [rows] = await pool.query(
          `SELECT id, from_name, to_name, LOWER(COALESCE(level, boon_level)) AS level, LOWER(status) AS status,
                  description, created_at
             FROM boons WHERE ${p.sql} ORDER BY created_at LIMIT ${PER_KIND}`,
          p.params
        );
        items.push(...rows.map((r) => ({ kind: 'boon', ...r })));
      }

      items.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
      reply.send({ items });
    } catch (e) {
      log.err('Print items failed', { message: e.message });
      reply.status(500).send({ error: 'Failed to load the items' });
    }
  });

  fastify.get('/api/admin/print/dither', { preHandler: [authRequired, requireAdmin] }, async (req, reply) => {
    try {
      const src = await resolveMediaUrl(String(req.query.src || ''), '', pool);
      let url;
      try { url = new URL(src); } catch { url = null; }
      if (!url || url.protocol !== 'https:' || url.hostname !== IMAGE_HOST || isVideoUrl(src)) {
        return reply.status(400).send({ error: 'Not a printable picture' });
      }

      const res = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(15000) });
      if (!res.ok) return reply.status(404).send({ error: 'Picture not found' });
      const input = Buffer.from(await res.arrayBuffer());
      if (input.length > MAX_BYTES) return reply.status(413).send({ error: 'Picture too large' });

      const { data, info } = await sharp(input, { limitInputPixels: 50e6 })
        .flatten({ background: '#ffffff' })
        .resize({ width: THERMAL_DOTS, height: MAX_HEIGHT, fit: 'inside' })
        .grayscale()
        .normalise()
        .raw()
        .toBuffer({ resolveWithObject: true });
      const dots = atkinson(data, info.width, info.height);
      const png = await sharp(Buffer.from(dots), { raw: { width: info.width, height: info.height, channels: 1 } })
        .png({ compressionLevel: 9 })
        .toBuffer();

      reply.header('Content-Type', 'image/png');
      reply.header('Cache-Control', 'private, max-age=86400');
      reply.send(png);
    } catch (e) {
      log.err('Print dither failed', { message: e.message });
      reply.status(422).send({ error: 'Could not convert that picture' });
    }
  });
};
