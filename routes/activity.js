const pool = require('../db');
const { log } = require('../logger');
const { authRequired, requireAdmin } = require('../authMiddleware.fastify');

async function activityRoutes(fastify, options) {
  fastify.get('/stats', { preHandler: [authRequired, requireAdmin] }, async (request, reply) => {
    try {
      const { userId } = request.query;
      let query = `
        SELECT DATE(session_start) as date, SUM(duration_seconds) as total_seconds
        FROM user_sessions
      `;
      const params = [];
      
      if (userId) {
        query += ` WHERE user_id = ?`;
        params.push(userId);
      }
      
      query += ` GROUP BY DATE(session_start) ORDER BY date ASC`;
      
      const [rows] = await pool.query(query, params);
      
      // Convert to format required by react-activity-calendar:
      // { date: 'YYYY-MM-DD', count: N }
      const data = rows.map(r => {
        // MySQL DATE() returns a Date object in mysql2 by default, or a string.
        // Let's ensure it's a YYYY-MM-DD string.
        const dateObj = new Date(r.date);
        const yyyy = dateObj.getFullYear();
        const mm = String(dateObj.getMonth() + 1).padStart(2, '0');
        const dd = String(dateObj.getDate()).padStart(2, '0');
        
        return {
          date: `${yyyy}-${mm}-${dd}`,
          count: Math.floor(r.total_seconds / 60) // convert to minutes for easier reading
        };
      });
      
      reply.send(data);
    } catch (error) {
      log.err('Error in GET /api/activity/stats:', { error: error.message });
      reply.status(500).send({ error: 'Internal Server Error' });
    }
  });
  fastify.post('/heartbeat', { preHandler: [authRequired] }, async (request, reply) => {
    try {
      const userId = request.user.id;
      // We consider a session active if the last ping was within the last 5 minutes.
      // 5 minutes = 300 seconds. Let's use 5 minutes for buffer since interval is 60 seconds.

      const [rows] = await pool.query(
        'SELECT * FROM user_sessions WHERE user_id = ? ORDER BY last_active DESC LIMIT 1',
        [userId]
      );

      const now = new Date();
      let activeSession = null;

      if (rows.length > 0) {
        const lastSession = rows[0];
        const lastActiveTime = new Date(lastSession.last_active).getTime();
        const diffMs = now.getTime() - lastActiveTime;

        if (diffMs <= 5 * 60 * 1000) {
          activeSession = lastSession;
        }
      }

      if (activeSession) {
        // Update the existing session
        const newDuration = activeSession.duration_seconds + Math.floor((now.getTime() - new Date(activeSession.last_active).getTime()) / 1000);
        
        await pool.query(
          'UPDATE user_sessions SET last_active = ?, duration_seconds = ? WHERE id = ?',
          [now, newDuration, activeSession.id]
        );
      } else {
        // Create a new session
        await pool.query(
          'INSERT INTO user_sessions (user_id, session_start, last_active, duration_seconds) VALUES (?, ?, ?, ?)',
          [userId, now, now, 0]
        );
      }

      reply.send({ success: true });
    } catch (error) {
      log.err('Error in heartbeat:', { error: error.message });
      reply.status(500).send({ error: 'Internal Server Error' });
    }
  });
}

module.exports = activityRoutes;
