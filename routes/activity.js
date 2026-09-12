const pool = require('../db');
const { log } = require('../logger');
const { authRequired } = require('../authMiddleware.fastify');

async function activityRoutes(fastify, options) {
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
