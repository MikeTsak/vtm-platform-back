const pool = require('../db');
const { log } = require('../logger');
const { authRequired, requireAdmin } = require('../authMiddleware.fastify');
const { getAthensHour, getAthensDate } = require('../utils/athensTime');

async function activityRoutes(fastify, options) {
  fastify.get('/stats', { preHandler: [authRequired, requireAdmin] }, async (request, reply) => {
    try {
      const { userId } = request.query;
      let query = `
        SELECT 
          id,
          user_id,
          session_start,
          duration_seconds
        FROM user_sessions
      `;
      const params = [];
      
      if (userId && userId !== 'global' && userId !== 'none') {
        query += ` WHERE user_id = ?`;
        params.push(userId);
      }
      
      query += ` ORDER BY session_start ASC`;
      
      const [rows] = await pool.query(query, params);
      
      // Group sessions strictly by Athens Greece calendar date
      const dayMap = new Map();
      for (const r of rows) {
        const dateStr = getAthensDate(r.session_start);
        if (!dateStr) continue;
        if (!dayMap.has(dateStr)) {
          dayMap.set(dateStr, {
            date: dateStr,
            totalSeconds: 0,
            activeUsers: new Set(),
            sessionCount: 0,
          });
        }
        const entry = dayMap.get(dateStr);
        entry.totalSeconds += (r.duration_seconds || 0);
        entry.activeUsers.add(r.user_id);
        entry.sessionCount += 1;
      }

      const data = Array.from(dayMap.values()).map(entry => {
        const minutes = Math.floor(entry.totalSeconds / 60);
        let level = 0;
        if (minutes > 0 && minutes < 15) level = 1;
        else if (minutes >= 15 && minutes < 45) level = 2;
        else if (minutes >= 45 && minutes < 90) level = 3;
        else if (minutes >= 90 && minutes < 180) level = 4;
        else if (minutes >= 180) level = 5;

        return {
          date: entry.date,
          count: minutes,
          level,
          activeUsers: entry.activeUsers.size,
          sessionCount: entry.sessionCount,
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

      // Fetch window of +/- 1 day to ensure timezone boundary coverage
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
        WHERE us.session_start >= DATE_SUB(?, INTERVAL 1 DAY)
          AND us.session_start <= DATE_ADD(?, INTERVAL 1 DAY)
      `;
      const params = [date, date];

      if (userId && userId !== 'global' && userId !== 'none') {
        query += ` AND us.user_id = ?`;
        params.push(userId);
      }

      query += ` ORDER BY us.session_start ASC`;

      const [allRows] = await pool.query(query, params);

      // Filter rows whose session_start belongs to the requested Athens calendar date
      const rows = allRows.filter(r => getAthensDate(r.session_start) === date);

      // 24-hour slots: 00:00 to 23:00 Athens Time
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
        const startHour = getAthensHour(start);
        const endHour = Math.max(startHour, getAthensHour(end));

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
