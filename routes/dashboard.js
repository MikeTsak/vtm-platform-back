const express = require('express');
const router = express.Router();
const pool = require('../db');
const { getSetting } = require('../utils/settings');
const { authRequired } = require('../authMiddleware');
const { log } = require('../logger');

// Helper to get first and last day of current month (from server.js)
const startOfMonth = () => {
  const d = new Date();
  return new Date(d.getFullYear(), d.getMonth(), 1);
};
const endOfMonth = () => {
  const d = new Date();
  return new Date(d.getFullYear(), d.getMonth() + 1, 0, 23, 59, 59, 999);
};

// GET /api/home/dashboard - Aggregated dashboard data
router.get('/dashboard', authRequired, async (req, res) => {
  try {
    const userId = req.user.id;

    // 1. Fetch character
    const [[ch]] = await pool.query('SELECT id, clan FROM characters WHERE user_id=?', [userId]);

    let quotaUsed = 0;
    const quotaLimit = 3;
    let recentDowntimes = [];
    let recentChats = [];
    let recentNews = [];
    let downtimeOpening = null;
    let threatLevel = 1;
    let bannerEnabled = false;
    let bannerMessage = '';
    let bannerCountdown = '';

    // Fetch config and banner settings
    [downtimeOpening, threatLevel, bannerEnabled, bannerMessage, bannerCountdown] = await Promise.all([
      getSetting('downtime_opening', null),
      getSetting('masquerade_threat_level', '1'),
      getSetting('banner_enabled', 'false'),
      getSetting('banner_message', ''),
      getSetting('banner_countdown', '')
    ]);

    // If character exists, fetch character-specific data in parallel
    if (ch) {
      const charId = ch.id;

      // Quota logic
      let from = startOfMonth();
      let to = endOfMonth();
      if (downtimeOpening) {
        const parsed = new Date(downtimeOpening);
        if (!isNaN(parsed.getTime())) {
          from = parsed;
          to = new Date(parsed.getTime() + 90 * 24 * 60 * 60 * 1000);
        }
      }

      // Parallelize DB queries for downtimes, chats, and news
      const [quotaRows, downtimeRows, chatRows, newsRows] = await Promise.all([
        pool.query('SELECT COUNT(*) AS c FROM downtimes WHERE character_id=? AND created_at >= ? AND created_at < ?', [charId, from, to]),
        pool.query('SELECT * FROM downtimes WHERE character_id=? ORDER BY created_at DESC LIMIT 5', [charId]),
        // Get recent chats (simplified version of my-recent, adjust if need exact matching)
        pool.query(`
          SELECT cg.id, cg.name, cg.created_at, cg.created_by,
                 MAX(cm.created_at) as last_activity
          FROM chat_groups cg
          JOIN chat_group_members cgm ON cg.id = cgm.group_id
          LEFT JOIN chat_group_messages cm ON cg.id = cm.group_id
          WHERE cgm.user_id = ?
          GROUP BY cg.id
          ORDER BY last_activity DESC
          LIMIT 10
        `, [userId]),
        pool.query('SELECT * FROM news_entries ORDER BY created_at DESC LIMIT 5')
      ]);

      quotaUsed = quotaRows[0][0].c;
      recentDowntimes = downtimeRows[0];
      recentChats = chatRows[0];
      recentNews = newsRows[0];
      
      log.info(`📊 [dashboard] Aggregated data for user ${userId}: ${recentDowntimes.length} downtimes, ${recentChats.length} chats, ${recentNews.length} news items`);
    }

    res.json({
      success: true,
      data: {
        quota: { used: quotaUsed, limit: quotaLimit },
        downtimes: recentDowntimes,
        chats: recentChats,
        news: recentNews,
        config: { downtime_opening: downtimeOpening },
        banner: {
          banner_enabled: bannerEnabled === 'true',
          banner_message: bannerMessage,
          banner_countdown: bannerCountdown,
          masquerade_threat_level: parseInt(threatLevel, 10)
        }
      }
    });

  } catch (error) {
    log.err('Dashboard fetch error', { error: error.message });
    res.status(500).json({ success: false, error: 'Failed to fetch dashboard data' });
  }
});

module.exports = router;
