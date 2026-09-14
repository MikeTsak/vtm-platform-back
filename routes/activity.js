const pool = require('../db');
const { log } = require('../logger');
const { authRequired, requireAdmin } = require('../authMiddleware.fastify');

async function activityRoutes(fastify, options) {
  fastify.get('/stats', { preHandler: [authRequired, requireAdmin] }, async (request, reply) => {
    try {
      const { userId } = request.query;
      let query = `
        SELECT 
          DATE(session_start) as date, 
          SUM(duration_seconds) as total_seconds,
          COUNT(DISTINCT user_id) as active_users,
          COUNT(id) as session_count
        FROM user_sessions
      `;
      const params = [];
      
      if (userId && userId !== 'global' && userId !== 'none') {
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
        const minutes = Math.floor(r.total_seconds / 60);

        let level = 0;
        if (minutes > 0 && minutes < 15) level = 1;
        else if (minutes >= 15 && minutes < 45) level = 2;
        else if (minutes >= 45 && minutes < 90) level = 3;
        else if (minutes >= 90 && minutes < 180) level = 4;
        else if (minutes >= 180) level = 5;
        
        return {
          date: `${yyyy}-${mm}-${dd}`,
          count: minutes, // convert to minutes for easier reading
          level,
          activeUsers: Number(r.active_users) || 1,
          sessionCount: Number(r.session_count) || 1
        };
      });
      
      reply.send(data);
    } catch (error) {
      log.err('Error in GET /api/activity/stats:', { error: error.message });
      reply.status(500).send({ error: 'Internal Server Error' });
    }
  });

  fastify.get('/day-stats', { preHandler: [authRequired, requireAdmin] }, async (request, reply) => {
    try {
      const { date, userId } = request.query;
      if (!date) {
        return reply.status(400).send({ error: 'Date query parameter is required' });
      }

      let query = `
        SELECT 
          us.id,
          us.user_id,
          u.display_name,
          u.email,
          us.session_start,
          us.last_active,
          us.duration_seconds
        FROM user_sessions us
        LEFT JOIN users u ON u.id = us.user_id
        WHERE DATE(us.session_start) = ?
      `;
      const params = [date];

      if (userId && userId !== 'global' && userId !== 'none') {
        query += ` AND us.user_id = ?`;
        params.push(userId);
      }

      query += ` ORDER BY us.session_start ASC`;

      const [rows] = await pool.query(query, params);

      // 24-hour slots: 0 to 23
      const hourly = Array.from({ length: 24 }, (_, hour) => ({
        hour,
        label: `${String(hour).padStart(2, '0')}:00`,
        minutes: 0,
        activeUsers: [],
        sessionCount: 0,
        level: 0,
      }));

      const userMap = new Map();

      for (const row of rows) {
        const start = new Date(row.session_start);
        const end = new Date(row.last_active);
        const startHour = isNaN(start.getTime()) ? 0 : start.getHours();
        const endHour = isNaN(end.getTime()) ? startHour : end.getHours();

        const totalMin = Math.max(1, Math.round((row.duration_seconds || 0) / 60));
        const hourSpan = Math.max(1, endHour - startHour + 1);
        const slotMin = Math.min(60, Math.max(1, Math.round(totalMin / hourSpan)));

        for (let h = startHour; h <= Math.min(23, endHour); h++) {
          hourly[h].minutes += slotMin;
          hourly[h].sessionCount += 1;
          if (!hourly[h].activeUsers.some(u => u.id === row.user_id)) {
            hourly[h].activeUsers.push({
              id: row.user_id,
              name: row.display_name || `User #${row.user_id}`,
            });
          }
        }

        if (!userMap.has(row.user_id)) {
          userMap.set(row.user_id, {
            id: row.user_id,
            name: row.display_name || `User #${row.user_id}`,
            totalMinutes: 0,
            hours: Array(24).fill(0),
          });
        }
        const uData = userMap.get(row.user_id);
        uData.totalMinutes += totalMin;
        for (let h = startHour; h <= Math.min(23, endHour); h++) {
          uData.hours[h] = Math.min(60, uData.hours[h] + slotMin);
        }
      }

      // Calculate hourly level tiers (0 to 5)
      for (const h of hourly) {
        if (h.minutes <= 0) h.level = 0;
        else if (h.minutes < 10) h.level = 1;
        else if (h.minutes < 25) h.level = 2;
        else if (h.minutes < 45) h.level = 3;
        else if (h.minutes < 75) h.level = 4;
        else h.level = 5;
      }

      reply.send({
        date,
        totalSessions: rows.length,
        totalMinutes: rows.reduce((acc, r) => acc + Math.round((r.duration_seconds || 0) / 60), 0),
        activeUserCount: userMap.size,
        hourly,
        users: Array.from(userMap.values()).sort((a, b) => b.totalMinutes - a.totalMinutes),
      });
    } catch (error) {
      log.err('Error in GET /api/activity/day-stats:', { error: error.message });
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
