const { Meilisearch } = require('meilisearch');

module.exports = async function (fastify, opts) {
  const { pool, log, authRequired } = opts;

  // Initialize Meilisearch
  const meiliClient = new Meilisearch({
    host: process.env.MEILI_HOST || 'http://127.0.0.1:7700',
    apiKey: process.env.MEILI_MASTER_KEY || 'attlarp-secret-master-key-123'
  });
  const articleIndex = meiliClient.index('wiki_articles');

  /* -------------------- WIKI ARTICLES -------------------- */

  // Get all published articles (Dashboard / Feed)
  fastify.get('/api/wiki/articles', async (req, reply) => {
    try {
      const [rows] = await pool.query(
        `SELECT a.id, a.title, a.slug, a.created_at, u.display_name as author_name 
         FROM wiki_articles a 
         JOIN users u ON a.author_id = u.id 
         WHERE a.status = 'published' 
         ORDER BY a.created_at DESC LIMIT 50`
      );
      reply.send({ articles: rows });
    } catch (e) {
      log.err('Failed to fetch wiki articles', e);
      reply.status(500).send({ error: 'Database error' });
    }
  });

  // Get a specific article by slug
  fastify.get('/api/wiki/articles/:slug', async (req, reply) => {
    const { slug } = req.params;
    try {
      const [rows] = await pool.query('SELECT * FROM wiki_articles WHERE slug=?', [slug]);
      const article = rows[0];

      if (!article) return reply.status(404).send({ error: 'Article not found' });

      // Permission check for private articles
      if (article.status === 'private') {
         try {
           await authRequired(req, reply);
           if (req.user.role !== 'admin') {
              return reply.status(403).send({ error: 'Forbidden' });
           }
         } catch (err) {
           return reply.status(401).send({ error: 'Unauthorized' });
         }
      }

      reply.send({ article });
    } catch (e) {
      log.err('Failed to fetch wiki article', e);
      reply.status(500).send({ error: 'Database error' });
    }
  });

  // Create or update an article (Draft or Publish)
  fastify.post('/api/wiki/articles', { preHandler: [authRequired] }, async (req, reply) => {
    const { id, title, slug, content, status, category_id, edit_summary } = req.body;
    
    // Only admins can publish private articles
    if (status === 'private' && req.user.role !== 'admin') {
      return reply.status(403).send({ error: 'Only admins can create private articles' });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      let articleId = id;

      if (id) {
        // Update existing
        const [existing] = await conn.query('SELECT author_id FROM wiki_articles WHERE id=?', [id]);
        if (!existing.length) throw new Error('Article not found');
        
        await conn.query(
          'UPDATE wiki_articles SET title=?, slug=?, content=?, status=?, category_id=? WHERE id=?',
          [title, slug, content, status, category_id || null, id]
        );
      } else {
        // Create new
        const [result] = await conn.query(
          'INSERT INTO wiki_articles (title, slug, content, status, category_id, author_id) VALUES (?,?,?,?,?,?)',
          [title, slug, content, status, category_id || null, req.user.id]
        );
        articleId = result.insertId;
      }

      // Save version history
      if (status === 'published' || id) {
        await conn.query(
          'INSERT INTO wiki_article_versions (article_id, editor_id, content, edit_summary) VALUES (?,?,?,?)',
          [articleId, req.user.id, content, edit_summary || 'Update']
        );
      }

      await conn.commit();

      // Update Meilisearch
      if (status === 'published') {
        try {
          await articleIndex.addDocuments([{
            id: articleId,
            title: title,
            slug: slug,
            content: content
          }]);
        } catch (meiliErr) {
          log.err('Failed to sync to meilisearch', meiliErr);
        }
      } else {
        // If draft or private, ensure it's removed from search
        try {
          await articleIndex.deleteDocument(articleId);
        } catch (meiliErr) {
          log.err('Failed to delete from meilisearch', meiliErr);
        }
      }

      log.info('Wiki Article saved', { articleId, user_id: req.user.id, status });
      reply.send({ success: true, articleId });
    } catch (e) {
      await conn.rollback();
      log.err('Failed to save wiki article', e);
      reply.status(500).send({ error: e.message || 'Database error' });
    } finally {
      if (conn) conn.release();
    }
  });

  /* -------------------- WIKI NOTES (Private Journal) -------------------- */
  
  // Get private note for an article (or general journal if article_id is null)
  fastify.get('/api/wiki/notes/:articleId', { preHandler: [authRequired] }, async (req, reply) => {
    const { articleId } = req.params;
    try {
      const [rows] = await pool.query(
        'SELECT content FROM wiki_notes WHERE user_id=? AND article_id<=>?',
        [req.user.id, articleId === 'general' ? null : articleId]
      );
      reply.send({ note: rows[0] || { content: '' } });
    } catch (e) {
      log.err('Failed to fetch wiki note', e);
      reply.status(500).send({ error: 'Database error' });
    }
  });

  // Save private note
  fastify.post('/api/wiki/notes', { preHandler: [authRequired] }, async (req, reply) => {
    const { article_id, content } = req.body;
    try {
      await pool.query(
        `INSERT INTO wiki_notes (user_id, article_id, content) 
         VALUES (?, ?, ?) 
         ON DUPLICATE KEY UPDATE content=?, updated_at=CURRENT_TIMESTAMP`,
        [req.user.id, article_id || null, content, content]
      );
      reply.send({ success: true });
    } catch (e) {
      log.err('Failed to save wiki note', e);
      reply.status(500).send({ error: 'Database error' });
    }
  });

  /* -------------------- WIKI BOARDS -------------------- */
  
  fastify.get('/api/wiki/boards', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const query = req.user.role === 'admin' 
        ? 'SELECT * FROM wiki_boards'
        : 'SELECT b.* FROM wiki_boards b LEFT JOIN wiki_board_members m ON b.id = m.board_id WHERE b.visibility = "public" OR b.owner_id = ? OR (b.visibility = "shared" AND m.user_id = ?)';
      
      const params = req.user.role === 'admin' ? [] : [req.user.id, req.user.id];
      const [rows] = await pool.query(query, params);
      reply.send({ boards: rows });
    } catch (e) {
      log.err('Failed to fetch wiki boards', e);
      reply.status(500).send({ error: 'Database error' });
    }
  });

  /* -------------------- ELYSIUM BOARDS (Visual Corkboard) -------------------- */
  
  fastify.get('/api/wiki/elysium-boards', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const userId = req.user.id;
      // List all public boards, and any private/personal boards owned by the user or where they are a member
      const [rows] = await pool.query(`
        SELECT b.id, b.title, b.visibility, b.owner_id, b.created_at, b.updated_at 
        FROM wiki_elysium_boards b
        LEFT JOIN wiki_elysium_board_members m ON b.id = m.board_id AND m.user_id = ?
        WHERE b.visibility = 'public' OR b.owner_id = ? OR m.user_id IS NOT NULL
        GROUP BY b.id
        ORDER BY b.updated_at DESC
      `, [userId, userId]);
      reply.send({ boards: rows });
    } catch (e) {
      log.err('Failed to fetch elysium boards', e);
      reply.status(500).send({ error: 'Database error' });
    }
  });

  fastify.post('/api/wiki/elysium-boards', { preHandler: [authRequired] }, async (req, reply) => {
    const { title, data, visibility } = req.body;
    if (!title) return reply.status(400).send({ error: 'Title is required' });
    
    const boardVis = visibility || 'public';
    const ownerId = req.user.id;

    try {
      const [result] = await pool.query(
        'INSERT INTO wiki_elysium_boards (title, data, visibility, owner_id) VALUES (?, ?, ?, ?)',
        [title, JSON.stringify(data || { nodes: [], edges: [] }), boardVis, ownerId]
      );
      reply.send({ success: true, id: result.insertId });
    } catch (e) {
      log.err('Failed to create elysium board', e);
      reply.status(500).send({ error: 'Database error' });
    }
  });

  fastify.get('/api/wiki/elysium-boards/:id', { preHandler: [authRequired] }, async (req, reply) => {
    const { id } = req.params;
    const userId = req.user.id;
    try {
      const [rows] = await pool.query('SELECT * FROM wiki_elysium_boards WHERE id = ?', [id]);
      if (!rows.length) return reply.status(404).send({ error: 'Board not found' });
      
      const board = rows[0];
      
      const [memberRows] = await pool.query('SELECT user_id FROM wiki_elysium_board_members WHERE board_id = ? AND user_id = ?', [id, userId]);
      const isMember = memberRows.length > 0;

      // Enforce personal visibility
      if (board.visibility === 'personal' && board.owner_id !== userId && !isMember) {
        return reply.status(403).send({ error: 'Forbidden. This is a personal board.' });
      }

      reply.send({ board, isOwner: board.owner_id === userId });
    } catch (e) {
      log.err('Failed to fetch elysium board', e);
      reply.status(500).send({ error: 'Database error' });
    }
  });

  fastify.put('/api/wiki/elysium-boards/:id', { preHandler: [authRequired] }, async (req, reply) => {
    const { id } = req.params;
    const { title, data, visibility } = req.body;
    const userId = req.user.id;
    
    try {
      // Fetch board to check ownership for edits
      const [boardRows] = await pool.query('SELECT owner_id FROM wiki_elysium_boards WHERE id = ?', [id]);
      if (!boardRows.length) return reply.status(404).send({ error: 'Board not found' });
      
      const board = boardRows[0];
      
      const [memberRows] = await pool.query('SELECT user_id FROM wiki_elysium_board_members WHERE board_id = ? AND user_id = ?', [id, userId]);
      const isMember = memberRows.length > 0;

      // Owner or Member can edit the board
      if (board.owner_id !== null && board.owner_id !== userId && !isMember) {
         return reply.status(403).send({ error: 'Only the board owner or members can edit this board.' });
      }

      const [result] = await pool.query(
        'UPDATE wiki_elysium_boards SET title = ?, data = ?, visibility = COALESCE(?, visibility) WHERE id = ?',
        [title, JSON.stringify(data), visibility, id]
      );
      reply.send({ success: true });
    } catch (e) {
      log.err('Failed to update elysium board', e);
      reply.status(500).send({ error: 'Database error' });
    }
  });

  // GET Members
  fastify.get('/api/wiki/elysium-boards/:id/members', { preHandler: [authRequired] }, async (req, reply) => {
    const { id } = req.params;
    try {
      const [rows] = await pool.query(`
        SELECT u.id, u.display_name, u.email, m.added_at
        FROM wiki_elysium_board_members m
        JOIN users u ON m.user_id = u.id
        WHERE m.board_id = ?
      `, [id]);
      reply.send({ members: rows });
    } catch (e) {
      log.err('Failed to fetch board members', e);
      reply.status(500).send({ error: 'Database error' });
    }
  });

  // POST Add Member
  fastify.post('/api/wiki/elysium-boards/:id/members', { preHandler: [authRequired] }, async (req, reply) => {
    const { id } = req.params;
    const { userId } = req.body;
    const currentUserId = req.user.id;
    
    try {
      // Check ownership
      const [boardRows] = await pool.query('SELECT owner_id FROM wiki_elysium_boards WHERE id = ?', [id]);
      if (!boardRows.length || boardRows[0].owner_id !== currentUserId) {
        return reply.status(403).send({ error: 'Only owner can manage members' });
      }

      await pool.query('INSERT IGNORE INTO wiki_elysium_board_members (board_id, user_id) VALUES (?, ?)', [id, userId]);
      reply.send({ success: true });
    } catch (e) {
      log.err('Failed to add board member', e);
      reply.status(500).send({ error: 'Database error' });
    }
  });

  // DELETE Remove Member
  fastify.delete('/api/wiki/elysium-boards/:id/members/:userId', { preHandler: [authRequired] }, async (req, reply) => {
    const { id, userId } = req.params;
    const currentUserId = req.user.id;
    
    try {
      // Check ownership
      const [boardRows] = await pool.query('SELECT owner_id FROM wiki_elysium_boards WHERE id = ?', [id]);
      if (!boardRows.length || boardRows[0].owner_id !== currentUserId) {
        return reply.status(403).send({ error: 'Only owner can manage members' });
      }

      await pool.query('DELETE FROM wiki_elysium_board_members WHERE board_id = ? AND user_id = ?', [id, userId]);
      reply.send({ success: true });
    } catch (e) {
      log.err('Failed to remove board member', e);
      reply.status(500).send({ error: 'Database error' });
    }
  });

  /* -------------------- WIKIPEDIA IMPORT (wikijs) -------------------- */
  
  fastify.get('/api/wiki/external/wikipedia/search', { preHandler: [authRequired] }, async (req, reply) => {
    if (req.user.role !== 'admin') return reply.status(403).send({ error: 'Admin only' });
    
    const { q } = req.query;
    if (!q) return reply.send({ results: [] });
    
    try {
      const wiki = require('wikijs').default;
      const results = await wiki().search(q, 10);
      reply.send({ results: results.results });
    } catch (e) {
      log.err('Failed to search Wikipedia', e);
      reply.status(500).send({ error: 'Failed to search Wikipedia' });
    }
  });

  fastify.get('/api/wiki/external/wikipedia/fetch', { preHandler: [authRequired] }, async (req, reply) => {
    if (req.user.role !== 'admin') return reply.status(403).send({ error: 'Admin only' });

    const { title } = req.query;
    if (!title) return reply.status(400).send({ error: 'Missing title' });
    
    try {
      const wiki = require('wikijs').default;
      const page = await wiki().page(title);
      const content = await page.content();
      const summary = await page.summary();
      
      reply.send({ title, summary, content });
    } catch (e) {
      log.err('Failed to fetch Wikipedia page', e);
      reply.status(500).send({ error: 'Failed to fetch Wikipedia page' });
    }
  });

  /* -------------------- MEILISEARCH SYNC -------------------- */
  
  // Sync all published articles to Meilisearch
  fastify.post('/api/admin/meili/sync-wiki', { preHandler: [authRequired] }, async (req, reply) => {
    if (req.user.role !== 'admin') return reply.status(403).send({ error: 'Admin only' });
    
    try {
      const [rows] = await pool.query('SELECT id, title, slug, content FROM wiki_articles WHERE status = "published"');
      
      const documents = rows.map(r => ({
        id: r.id,
        title: r.title,
        slug: r.slug,
        content: r.content
      }));
      
      if (documents.length > 0) {
        await articleIndex.addDocuments(documents);
      }
      
      reply.send({ success: true, count: documents.length });
    } catch (e) {
      log.err('Failed to sync wiki to Meilisearch', e);
      reply.status(500).send({ error: 'Failed to sync to Meilisearch' });
    }
  });
};
