// services/bloodHunts.js
//
// Blood Hunt side effects shared by the Court Actions routes and the job runner:
// keeping characters/npcs.is_bloodhunted in step with the blood_hunts ledger,
// expiring hunts whose expiry has passed, and the court-wide pushes.

const pool = require('../db');
const { log } = require('../logger');
const { sendPushNotification } = require('./push');
const { parseTitles } = require('./courtOffices');
const { broadcastDiscordAnnouncement } = require('./discord');

// The flag mirrors the ledger: set while any active hunt names the target.
async function setBloodhuntFlag(targetType, targetId) {
  const table = targetType === 'player' ? 'characters' : 'npcs';
  const [[row]] = await pool.query(
    "SELECT COUNT(*) AS n FROM blood_hunts WHERE target_type=? AND target_id=? AND status='active'",
    [targetType, targetId]
  );
  await pool.query(`UPDATE ${table} SET is_bloodhunted=? WHERE id=?`, [row.n > 0 ? 1 : 0, targetId]);
}

async function expireBloodHunts() {
  const [due] = await pool.query(
    "SELECT id, target_type, target_id, target_name, status FROM blood_hunts WHERE status IN ('proposed','active') AND expires_at IS NOT NULL AND expires_at <= NOW()"
  );
  for (const h of due) {
    await pool.query("UPDATE blood_hunts SET status='expired', closed_at=NOW() WHERE id=?", [h.id]);
    if (h.status === 'active') {
      await setBloodhuntFlag(h.target_type, h.target_id);
      broadcastDiscordAnnouncement(`🕊️ **BLOOD HUNT EXPIRED**\nThe Blood Hunt for **${h.target_name}** has expired and is no longer in effect.`);
    }
    log.info('Blood Hunt expired', { id: h.id, target: h.target_name });
  }
  return due.length;
}

// Fire-and-forget: a failed push must never fail the court action.
function pushEveryone(title, body, url) {
  pool.query('SELECT id FROM users')
    .then(([users]) => Promise.all(users.map(u => sendPushNotification(u.id, title, body, { url }, 'system'))))
    .catch(e => log.err('Court push failed', { message: e.message }));
}

function pushOfficeHolders(offices, title, body, url) {
  pool.query(
    "SELECT DISTINCT c.user_id, c.camarilla_titles FROM characters c JOIN users u ON u.id = c.user_id WHERE u.role IN ('courtuser','admin') AND COALESCE(c.is_ex,0)=0 AND COALESCE(c.is_deceased,0)=0"
  )
    .then(([rows]) => {
      const ids = [...new Set(rows.filter(r => parseTitles(r.camarilla_titles).some(t => offices.includes(t))).map(r => r.user_id))];
      return Promise.all(ids.map(id => sendPushNotification(id, title, body, { url }, 'system')));
    })
    .catch(e => log.err('Court office push failed', { message: e.message }));
}

module.exports = { setBloodhuntFlag, expireBloodHunts, pushEveryone, pushOfficeHolders };
