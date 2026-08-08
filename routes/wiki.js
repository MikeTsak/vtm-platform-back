module.exports = async function (fastify, opts) {
  const { pool, log, authRequired, imageClient } = opts;

  /* -------------------- WIKI ARTICLES -------------------- */

  // Get all published articles (Dashboard / Feed)
  fastify.get('/api/wiki/articles', async (req, reply) => {
    try {
      // Determine if caller is admin (token optional)
      let isAdmin = false;
      try { await authRequired(req, reply); isAdmin = req.user?.role === 'admin'; } catch (_) {}

      const statusFilter = isAdmin ? `a.status IN ('published','private')` : `a.status = 'published'`;
      const [rows] = await pool.query(
        `SELECT a.id, a.title, a.slug, a.status, a.created_at, u.display_name as author_name 
         FROM wiki_articles a 
         JOIN users u ON a.author_id = u.id 
         WHERE ${statusFilter} 
         ORDER BY a.created_at DESC LIMIT 50`
      );
      return reply.send({ articles: rows });
    } catch (e) {
      log.err('Failed to fetch wiki articles', e);
      return reply.status(500).send({ error: 'Database error' });
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

      const [tagRows] = await pool.query(
        `SELECT t.name FROM wiki_tags t 
         JOIN wiki_article_tags wat ON t.id = wat.tag_id 
         WHERE wat.article_id = ?`, [article.id]
      );
      article.tags = tagRows.map(t => t.name).join(', ');

      return reply.send({ article });
    } catch (e) {
      log.err('Failed to fetch wiki article', e);
      return reply.status(500).send({ error: 'Database error' });
    }
  });

  // Native MySQL Search
  fastify.get('/api/wiki/search', async (req, reply) => {
    const { q } = req.query;
    if (!q || q.length < 2) return reply.send({ results: [] });

    try {
      const searchTerm = `%${q}%`;
      const [rows] = await pool.query(
        `SELECT id, title, slug, SUBSTRING(content, 1, 150) as snippet
         FROM wiki_articles 
         WHERE status = 'published' AND (title LIKE ? OR content LIKE ?)
         LIMIT 10`,
        [searchTerm, searchTerm]
      );
      return reply.send({ results: rows });
    } catch (e) {
      log.err('Failed to search wiki', e);
      return reply.status(500).send({ error: 'Search failed' });
    }
  });

  // Graph Data (Lore Graph)
  fastify.get('/api/wiki/graph', async (req, reply) => {
    try {
      const [rows] = await pool.query(
        `SELECT id, title, slug, content 
         FROM wiki_articles 
         WHERE status = 'published'`
      );
      
      const nodes = rows.map(r => ({ id: r.slug, name: r.title }));
      const links = [];
      
      const slugSet = new Set(nodes.map(n => n.id));
      
      rows.forEach(r => {
        // Find [[Link]] patterns
        const regex = /(?:\\?\[){2}(.*?)(?:\\?\]){2}/g;
        let match;
        while ((match = regex.exec(r.content)) !== null) {
          const targetTitle = match[1].trim();
          const targetSlug = targetTitle.toLowerCase().replace(/[^\w ]+/g, '').replace(/ +/g, '-');
          if (slugSet.has(targetSlug)) {
            links.push({ source: r.slug, target: targetSlug });
          }
        }
      });
      
      return reply.send({ nodes, links });
    } catch (e) {
      log.err('Failed to generate wiki graph', e);
      return reply.status(500).send({ error: 'Graph generation failed' });
    }
  });

  // Sidebar Suggestions (Recently Added, Public, For You)
  fastify.get('/api/wiki/sidebar-suggestions', async (req, reply) => {
    try {
      // Recently added
      const [recentRows] = await pool.query(
        `SELECT id, title, slug FROM wiki_articles 
         WHERE status = 'published' 
         ORDER BY created_at DESC LIMIT 5`
      );

      // Random / General public (using ORDER BY RAND() is okay for small datasets)
      const [publicRows] = await pool.query(
        `SELECT id, title, slug FROM wiki_articles 
         WHERE status = 'published' 
         ORDER BY RAND() LIMIT 5`
      );

      // For You (Requires User Context)
      // Since we don't have full context on user preferences here, we'll just return a random set,
      // or if we had req.user, we could query based on their clan. For now, another random set or fallback.
      const [forYouRows] = await pool.query(
        `SELECT id, title, slug FROM wiki_articles 
         WHERE status = 'published' 
         ORDER BY RAND() LIMIT 5`
      );

      return reply.send({
        recent: recentRows,
        public: publicRows,
        forYou: forYouRows
      });
    } catch (e) {
      log.err('Failed to fetch sidebar suggestions', e);
      return reply.status(500).send({ error: 'Database error' });
    }
  });

  // Create or update an article (Draft or Publish)
  fastify.post('/api/wiki/articles', { preHandler: [authRequired] }, async (req, reply) => {
    const { id, title, slug, content, status, category_id, edit_summary, tags } = req.body;
    
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

      // Sync tags
      if (tags !== undefined) {
        await conn.query('DELETE FROM wiki_article_tags WHERE article_id=?', [articleId]);
        if (tags && tags.trim()) {
          const tagArray = tags.split(',').map(t => t.trim()).filter(Boolean);
          for (const tagName of tagArray) {
            const tagSlug = tagName.toLowerCase().replace(/\\s+/g, '-');
            await conn.query('INSERT IGNORE INTO wiki_tags (name, slug) VALUES (?, ?)', [tagName, tagSlug]);
            const [tRows] = await conn.query('SELECT id FROM wiki_tags WHERE slug=?', [tagSlug]);
            if (tRows.length) {
              await conn.query('INSERT IGNORE INTO wiki_article_tags (article_id, tag_id) VALUES (?, ?)', [articleId, tRows[0].id]);
            }
          }
        }
      }

      await conn.commit();

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

  /* -------------------- WIKI IMAGE UPLOAD & HISTORY -------------------- */

  fastify.post('/api/wiki/upload-image', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      if (!imageClient) return reply.status(500).send({ error: 'Image client not configured' });
      const data = await req.file();
      if (!data) return reply.status(400).send({ error: 'No file uploaded' });

      const buffer = await data.toBuffer();
      const result = await imageClient.uploadImage(buffer, data.filename);
      if (!result.success) return reply.status(500).send({ error: 'Failed to upload image' });
      
      return reply.send({ url: result.url });
    } catch (e) {
      log.err('Wiki image upload failed', e);
      return reply.status(500).send({ error: 'Internal server error' });
    }
  });

  fastify.get('/api/wiki/articles/:slug/history', async (req, reply) => {
    const { slug } = req.params;
    try {
      const [artRows] = await pool.query('SELECT id FROM wiki_articles WHERE slug=?', [slug]);
      if (!artRows.length) return reply.status(404).send({ error: 'Article not found' });
      
      const [rows] = await pool.query(
        `SELECT v.id, v.content, v.edit_summary, v.created_at, u.display_name as editor_name
         FROM wiki_article_versions v
         JOIN users u ON v.editor_id = u.id
         WHERE v.article_id = ?
         ORDER BY v.created_at DESC`,
        [artRows[0].id]
      );
      reply.send({ history: rows });
    } catch (e) {
      log.err('Failed to fetch wiki history', e);
      reply.status(500).send({ error: 'Database error' });
    }
  });

  fastify.post('/api/wiki/articles/:slug/rollback', { preHandler: [authRequired] }, async (req, reply) => {
    const { slug } = req.params;
    const { version_id } = req.body;
    
    if (req.user.role !== 'admin') return reply.status(403).send({ error: 'Only admins can rollback articles' });

    try {
      const [artRows] = await pool.query('SELECT id FROM wiki_articles WHERE slug=?', [slug]);
      if (!artRows.length) return reply.status(404).send({ error: 'Article not found' });
      const articleId = artRows[0].id;

      const [verRows] = await pool.query('SELECT content FROM wiki_article_versions WHERE id=? AND article_id=?', [version_id, articleId]);
      if (!verRows.length) return reply.status(404).send({ error: 'Version not found' });
      
      const newContent = verRows[0].content;
      
      const conn = await pool.getConnection();
      try {
        await conn.beginTransaction();
        await conn.query('UPDATE wiki_articles SET content=? WHERE id=?', [newContent, articleId]);
        await conn.query(
          'INSERT INTO wiki_article_versions (article_id, editor_id, content, edit_summary) VALUES (?,?,?,?)',
          [articleId, req.user.id, newContent, `Reverted to version ${version_id}`]
        );
        await conn.commit();
        reply.send({ success: true, content: newContent });
      } catch (e) {
        await conn.rollback();
        throw e;
      } finally {
        conn.release();
      }
    } catch (e) {
      log.err('Failed to rollback wiki article', e);
      reply.status(500).send({ error: 'Database error' });
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


  /* -------------------- TIMELINE -------------------- */

  fastify.get('/api/wiki/timeline', async (req, reply) => {
    try {
      const [rows] = await pool.query(
        `SELECT t.*, u.display_name as created_by_name
         FROM wiki_timeline_events t
         LEFT JOIN users u ON t.created_by = u.id
         ORDER BY t.sort_order ASC, t.created_at ASC`
      );
      return reply.send({ events: rows });
    } catch (e) {
      log.err('Failed to fetch timeline', e);
      return reply.status(500).send({ error: 'Database error' });
    }
  });

  fastify.post('/api/wiki/timeline', { preHandler: [authRequired] }, async (req, reply) => {
    if (req.user.role !== 'admin') return reply.status(403).send({ error: 'Admin only' });
    const { title, date_label, description, article_slug, category, sort_order } = req.body;
    if (!title || !date_label) return reply.status(400).send({ error: 'title and date_label are required' });
    try {
      const [result] = await pool.query(
        'INSERT INTO wiki_timeline_events (title, date_label, description, article_slug, category, sort_order, created_by) VALUES (?,?,?,?,?,?,?)',
        [title, date_label, description || '', article_slug || null, category || 'General', sort_order || 0, req.user.id]
      );
      return reply.send({ success: true, id: result.insertId });
    } catch (e) {
      log.err('Failed to create timeline event', e);
      return reply.status(500).send({ error: 'Database error' });
    }
  });

  fastify.put('/api/wiki/timeline/:id', { preHandler: [authRequired] }, async (req, reply) => {
    if (req.user.role !== 'admin') return reply.status(403).send({ error: 'Admin only' });
    const { id } = req.params;
    const { title, date_label, description, article_slug, category, sort_order } = req.body;
    try {
      await pool.query(
        'UPDATE wiki_timeline_events SET title=?, date_label=?, description=?, article_slug=?, category=?, sort_order=? WHERE id=?',
        [title, date_label, description || '', article_slug || null, category || 'General', sort_order || 0, id]
      );
      return reply.send({ success: true });
    } catch (e) {
      log.err('Failed to update timeline event', e);
      return reply.status(500).send({ error: 'Database error' });
    }
  });

  fastify.delete('/api/wiki/timeline/:id', { preHandler: [authRequired] }, async (req, reply) => {
    if (req.user.role !== 'admin') return reply.status(403).send({ error: 'Admin only' });
    try {
      await pool.query('DELETE FROM wiki_timeline_events WHERE id=?', [req.params.id]);
      return reply.send({ success: true });
    } catch (e) {
      log.err('Failed to delete timeline event', e);
      return reply.status(500).send({ error: 'Database error' });
    }
  });

  /* -------------------- PRIVATE JOURNAL -------------------- */

  fastify.get('/api/wiki/journal', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(
        'SELECT id, title, created_at, updated_at FROM wiki_journal_entries WHERE user_id=? ORDER BY updated_at DESC',
        [req.user.id]
      );
      return reply.send({ entries: rows });
    } catch (e) {
      log.err('Failed to fetch journal', e);
      return reply.status(500).send({ error: 'Database error' });
    }
  });

  fastify.get('/api/wiki/journal/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [rows] = await pool.query(
        'SELECT * FROM wiki_journal_entries WHERE id=? AND user_id=?',
        [req.params.id, req.user.id]
      );
      if (!rows.length) return reply.status(404).send({ error: 'Entry not found' });
      return reply.send({ entry: rows[0] });
    } catch (e) {
      log.err('Failed to fetch journal entry', e);
      return reply.status(500).send({ error: 'Database error' });
    }
  });

  fastify.post('/api/wiki/journal', { preHandler: [authRequired] }, async (req, reply) => {
    const { id, title, content } = req.body;
    try {
      if (id) {
        // Verify ownership before update
        const [rows] = await pool.query('SELECT user_id FROM wiki_journal_entries WHERE id=?', [id]);
        if (!rows.length || rows[0].user_id !== req.user.id) return reply.status(403).send({ error: 'Forbidden' });
        await pool.query('UPDATE wiki_journal_entries SET title=?, content=? WHERE id=?', [title, content, id]);
        return reply.send({ success: true, id });
      } else {
        const [result] = await pool.query(
          'INSERT INTO wiki_journal_entries (user_id, title, content) VALUES (?,?,?)',
          [req.user.id, title || 'Untitled Entry', content || '']
        );
        return reply.send({ success: true, id: result.insertId });
      }
    } catch (e) {
      log.err('Failed to save journal entry', e);
      return reply.status(500).send({ error: 'Database error' });
    }
  });

  fastify.delete('/api/wiki/journal/:id', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const [rows] = await pool.query('SELECT user_id FROM wiki_journal_entries WHERE id=?', [req.params.id]);
      if (!rows.length || rows[0].user_id !== req.user.id) return reply.status(403).send({ error: 'Forbidden' });
      await pool.query('DELETE FROM wiki_journal_entries WHERE id=?', [req.params.id]);
      return reply.send({ success: true });
    } catch (e) {
      log.err('Failed to delete journal entry', e);
      return reply.status(500).send({ error: 'Database error' });
    }
  });

  /* -------------------- ADMIN NOTES ON ARTICLES -------------------- */

  fastify.get('/api/wiki/articles/:slug/admin-notes', { preHandler: [authRequired] }, async (req, reply) => {
    if (req.user.role !== 'admin') return reply.status(403).send({ error: 'Admin only' });
    try {
      const [artRows] = await pool.query('SELECT id FROM wiki_articles WHERE slug=?', [req.params.slug]);
      if (!artRows.length) return reply.status(404).send({ error: 'Article not found' });
      const [rows] = await pool.query(
        `SELECT n.*, u.display_name as author_name
         FROM wiki_admin_notes n
         JOIN users u ON n.author_id = u.id
         WHERE n.article_id=?
         ORDER BY n.created_at DESC`,
        [artRows[0].id]
      );
      return reply.send({ notes: rows });
    } catch (e) {
      log.err('Failed to fetch admin notes', e);
      return reply.status(500).send({ error: 'Database error' });
    }
  });

  fastify.post('/api/wiki/articles/:slug/admin-notes', { preHandler: [authRequired] }, async (req, reply) => {
    if (req.user.role !== 'admin') return reply.status(403).send({ error: 'Admin only' });
    const { content } = req.body;
    if (!content?.trim()) return reply.status(400).send({ error: 'Content is required' });
    try {
      const [artRows] = await pool.query('SELECT id FROM wiki_articles WHERE slug=?', [req.params.slug]);
      if (!artRows.length) return reply.status(404).send({ error: 'Article not found' });
      const [result] = await pool.query(
        'INSERT INTO wiki_admin_notes (article_id, author_id, content) VALUES (?,?,?)',
        [artRows[0].id, req.user.id, content]
      );
      return reply.send({ success: true, id: result.insertId });
    } catch (e) {
      log.err('Failed to save admin note', e);
      return reply.status(500).send({ error: 'Database error' });
    }
  });

  fastify.delete('/api/wiki/admin-notes/:id', { preHandler: [authRequired] }, async (req, reply) => {
    if (req.user.role !== 'admin') return reply.status(403).send({ error: 'Admin only' });
    try {
      await pool.query('DELETE FROM wiki_admin_notes WHERE id=?', [req.params.id]);
      return reply.send({ success: true });
    } catch (e) {
      log.err('Failed to delete admin note', e);
      return reply.status(500).send({ error: 'Database error' });
    }
  });

};
