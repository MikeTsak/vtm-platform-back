// services/commsQueue.js
//
// Flushes admin-queued NPC messages (SchreckNet chat + SurfaceWeb email)
// the moment comms come back online. Called instantly from the admin
// comms status/schedule routes, and once a minute as a safety net for
// schedule-based openings (see jobs/index.js).

async function flushQueuedMessages(pool, { log, sendPushNotification, io }) {
  let flushedChat = 0;
  let flushedEmail = 0;

  // --- SchreckNet (NPC chat) ---
  const [queuedChat] = await pool.query(
    `SELECT id, npc_id, user_id, body, attachment_id
     FROM npc_messages WHERE status = 'queued' ORDER BY id ASC`
  );
  for (const m of queuedChat) {
    // Claim atomically: the instant (comms-toggle) trigger and the once-a-
    // minute cron safety net can race each other, so only whichever call
    // actually flips status='queued' -> 'sent' gets to push/emit for it.
    const [claim] = await pool.query(`UPDATE npc_messages SET status='sent' WHERE id=? AND status='queued'`, [m.id]);
    if (!claim.affectedRows) continue;
    flushedChat++;

    try {
      const [[npcInfo]] = await pool.query('SELECT name FROM npcs WHERE id=?', [m.npc_id]);
      const npcName = npcInfo?.name || 'NPC';
      const notifBody = m.attachment_id ? '📷 Image Attachment' : m.body;
      await sendPushNotification(m.user_id, npcName, notifBody, { url: '/schrecknet', icon: `/api/npcs/${m.npc_id}/avatar` }, 'chat').catch(() => {});
    } catch (pushErr) {
      log.err('Queued NPC chat push failed', { error: pushErr.message });
    }

    if (io) {
      io.to(`user_${m.user_id}`).emit('chat:refresh', { type: 'npc', partnerId: Number(m.npc_id) });
      io.to('admin_chat').emit('chat:refresh', { type: 'npc', partnerId: Number(m.npc_id), userId: Number(m.user_id) });
    }
  }

  // --- SurfaceWeb (NPC email) ---
  const [queuedEmail] = await pool.query(
    `SELECT id, thread_id FROM email_messages
     WHERE status = 'queued' AND sender_type = 'identity' ORDER BY id ASC`
  );
  for (const m of queuedEmail) {
    const [claim] = await pool.query(`UPDATE email_messages SET status='sent' WHERE id=? AND status='queued'`, [m.id]);
    if (!claim.affectedRows) continue;
    await pool.query(`UPDATE email_threads SET updated_at=NOW() WHERE id=?`, [m.thread_id]);
    flushedEmail++;

    try {
      const [[thread]] = await pool.query('SELECT user_id, identity_id, subject FROM email_threads WHERE id=?', [m.thread_id]);
      const [[identity]] = await pool.query('SELECT display_name FROM email_identities WHERE id=?', [thread.identity_id]);
      const pushTitle = `📧 Reply from ${identity?.display_name || 'NPC'}`;
      const pushBody = `Re: ${thread.subject}`;
      await sendPushNotification(thread.user_id, pushTitle, pushBody, { url: '/surfaceweb', icon: `/api/identities/${thread.identity_id}/avatar` }, 'chat').catch(() => {});
    } catch (pushErr) {
      log.err('Queued email push failed', { error: pushErr.message });
    }
  }

  if (flushedChat || flushedEmail) {
    log.info(`Flushed queued NPC messages: ${flushedChat} chat, ${flushedEmail} email.`);
  }

  return { flushedChat, flushedEmail };
}

module.exports = { flushQueuedMessages };
