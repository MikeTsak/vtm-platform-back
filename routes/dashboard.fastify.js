module.exports = async function (fastify, opts) {
  const pool = require('../db');
  const { getSetting } = require('../utils/settings');
  const { authRequired } = require('../authMiddleware.fastify');
  const { log } = require('../logger');

  // Helper to get first and last day of current month
  const startOfMonth = () => {
    const d = new Date();
    return new Date(d.getFullYear(), d.getMonth(), 1);
  };
  const endOfMonth = () => {
    const d = new Date();
    return new Date(d.getFullYear(), d.getMonth() + 1, 0, 23, 59, 59, 999);
  };

  /**
   * Helper to aggregate dashboard data (Chronicle, Whispers, Log, Quota, Banner)
   */
  async function getDashboardData(userId, userRole, ch) {
    let quotaUsed = 0;
    const quotaLimit = 3;
    let recentDowntimes = [];
    let recentChats = [];
    let recentNews = [];

    // 1. Concurrently fetch settings, public news, and whispers
    const settingsPromise = Promise.all([
      getSetting('downtime_opening', null),
      getSetting('masquerade_threat_level', '1'),
      getSetting('banner_enabled', 'false'),
      getSetting('banner_message', ''),
      getSetting('banner_countdown', '')
    ]);

    // Public / chronicle news (never rumors, filtered for private unless admin)
    const newsPromise = pool.query(`
      SELECT n.id, n.title, n.subtitle, n.type, n.theme, n.journalist_name, n.media_url, n.created_at, n.is_private,
             u.display_name AS author_real_name,
             c.name AS char_name
      FROM news_entries n
      LEFT JOIN users u ON n.author_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE (n.is_private = 0 OR ? = 'admin') AND n.theme != 'RUMOR'
      ORDER BY n.created_at DESC
      LIMIT 5
    `, [userRole || 'user']);

    // Whispers: Direct messages (DMs), NPC conversations, and Chat Groups
    const whispersPromise = Promise.all([
      // Direct Player-to-Player DMs
      pool.query(`
        SELECT 
          CONCAT('dm_', CASE WHEN cm.sender_id = ? THEN cm.recipient_id ELSE cm.sender_id END) AS id,
          CASE WHEN cm.sender_id = ? THEN cm.recipient_id ELSE cm.sender_id END AS partner_id,
          cm.body AS lastMessage,
          cm.created_at AS timestamp,
          COALESCE(c.name, u.display_name) AS partnerName,
          0 AS isNPC,
          0 AS isGroup
        FROM chat_messages cm
        JOIN users u ON u.id = (CASE WHEN cm.sender_id = ? THEN cm.recipient_id ELSE cm.sender_id END)
        LEFT JOIN characters c ON c.user_id = u.id
        WHERE cm.id IN (
          SELECT MAX(id) FROM chat_messages WHERE sender_id = ? OR recipient_id = ?
          GROUP BY CASE WHEN sender_id = ? THEN recipient_id ELSE sender_id END
        )
        ORDER BY cm.created_at DESC LIMIT 5
      `, [userId, userId, userId, userId, userId, userId]).catch(err => {
        log.warn('Whispers: DM query error', { error: err.message });
        return [[]];
      }),

      // NPC Conversations
      pool.query(`
        SELECT 
          CONCAT('npc_', nm.npc_id) AS id,
          nm.npc_id AS partner_id,
          nm.body AS lastMessage,
          nm.created_at AS timestamp,
          n.name AS partnerName,
          1 AS isNPC,
          0 AS isGroup
        FROM npc_messages nm
        JOIN npcs n ON n.id = nm.npc_id
        WHERE nm.id IN (
          SELECT MAX(id) FROM npc_messages WHERE user_id = ? GROUP BY npc_id
        )
        ORDER BY nm.created_at DESC LIMIT 5
      `, [userId]).catch(err => {
        log.warn('Whispers: NPC query error', { error: err.message });
        return [[]];
      }),

      // Chat Groups
      pool.query(`
        SELECT 
          CONCAT('grp_', cg.id) AS id,
          cg.id AS partner_id,
          COALESCE(last_msg.body, '') AS lastMessage,
          COALESCE(last_msg.created_at, cg.created_at) AS timestamp,
          cg.name AS partnerName,
          0 AS isNPC,
          1 AS isGroup
        FROM chat_groups cg
        JOIN chat_group_members cgm ON cg.id = cgm.group_id AND cgm.user_id = ?
        LEFT JOIN chat_group_messages last_msg ON last_msg.id = (
          SELECT MAX(id) FROM chat_group_messages WHERE group_id = cg.id
        )
        ORDER BY timestamp DESC LIMIT 5
      `, [userId]).catch(err => {
        log.warn('Whispers: Group query error', { error: err.message });
        return [[]];
      })
    ]);

    // Await common queries
    const [
      [downtimeOpening, threatLevel, bannerEnabled, bannerMessage, bannerCountdown],
      [newsRows],
      [dmRows, npcRows, groupRows]
    ] = await Promise.all([settingsPromise, newsPromise, whispersPromise]);

    recentNews = newsRows || [];

    // Combine and sort whispers
    const combinedWhispers = [
      ...(dmRows[0] || []),
      ...(npcRows[0] || []),
      ...(groupRows[0] || [])
    ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 5);

    recentChats = combinedWhispers;

    // 2. Character-specific queries (quota & downtimes log)
    if (ch && ch.id) {
      const charId = ch.id;

      let from = startOfMonth();
      let to = endOfMonth();
      if (downtimeOpening) {
        const parsed = new Date(downtimeOpening);
        if (!isNaN(parsed.getTime())) {
          from = parsed;
          to = new Date(parsed.getTime() + 90 * 24 * 60 * 60 * 1000);
        }
      }

      const [quotaRows, downtimeRows] = await Promise.all([
        pool.query(
          'SELECT COUNT(*) AS c FROM downtimes WHERE character_id=? AND created_at >= ? AND created_at < ?',
          [charId, from, to]
        ),
        pool.query(
          'SELECT id, title, feeding_type, status, created_at, resolved_at FROM downtimes WHERE character_id=? ORDER BY created_at DESC LIMIT 5',
          [charId]
        )
      ]);

      quotaUsed = quotaRows[0][0]?.c || 0;
      recentDowntimes = downtimeRows[0] || [];
    }

    return {
      quota: { used: quotaUsed, limit: quotaLimit },
      downtimes: recentDowntimes,
      chats: recentChats,
      news: recentNews,
      config: { downtime_opening: downtimeOpening },
      banner: {
        banner_enabled: bannerEnabled === 'true',
        banner_message: bannerMessage,
        banner_countdown: bannerCountdown,
        masquerade_threat_level: parseInt(threatLevel, 10) || 1
      }
    };
  }

  // GET /api/home/dashboard - Aggregated dashboard data (Existing backward-compatible endpoint)
  fastify.get('/dashboard', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const userId = req.user.id;
      const userRole = req.user.role;
      const [[ch]] = await pool.query('SELECT id, clan FROM characters WHERE user_id=?', [userId]);

      const dashboardData = await getDashboardData(userId, userRole, ch);

      const payload = JSON.stringify({
        success: true,
        data: dashboardData
      });

      return reply
        .header('Content-Type', 'application/json; charset=utf-8')
        .header('Cache-Control', 'no-store, no-cache, must-revalidate, private')
        .header('Content-Length', Buffer.byteLength(payload))
        .send(payload);
    } catch (error) {
      log.err('Dashboard fetch error', { error: error.message });
      reply.status(500).json({ success: false, error: 'Failed to fetch dashboard data' });
    }
  });

  // GET /api/home/bootstrap - Unified bootstrap endpoint for the Home page
  // Consolidates /auth/me, /characters/me, and /home/dashboard into a SINGLE HTTP request
  fastify.get('/bootstrap', { preHandler: [authRequired] }, async (req, reply) => {
    try {
      const userId = req.user.id;

      // Parallel DB queries for User, Character, and Dashboard
      const [userRows, charRows] = await Promise.all([
        pool.query(
          'SELECT id, email, display_name, role, theme, ui_sounds_enabled FROM users WHERE id = ?',
          [userId]
        ),
        pool.query('SELECT * FROM characters WHERE user_id = ?', [userId])
      ]);

      const rawUser = userRows[0][0] || null;
      const user = rawUser
        ? {
            ...req.user,
            ...rawUser,
            ui_sounds_enabled: rawUser.ui_sounds_enabled !== 0
          }
        : req.user;

      let character = charRows[0][0] || null;
      if (character && character.sheet && typeof character.sheet === 'string') {
        try {
          character.sheet = JSON.parse(character.sheet);
        } catch { }
      }

      // Aggregate dashboard data
      const dashboard = await getDashboardData(userId, user?.role, character);

      const payload = JSON.stringify({
        success: true,
        user,
        character,
        dashboard
      });

      return reply
        .header('Content-Type', 'application/json; charset=utf-8')
        .header('Cache-Control', 'no-store, no-cache, must-revalidate, private')
        .header('Content-Length', Buffer.byteLength(payload))
        .send(payload);
    } catch (error) {
      log.err('Home bootstrap fetch error', { error: error.message, stack: error.stack });
      reply.status(500).json({ success: false, error: 'Failed to bootstrap home data' });
    }
  });
};

