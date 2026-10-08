// Row history (MariaDB system versioning) for the editable game tables, a
// change log for users, three composite indexes, and MyISAM -> InnoDB.
// Same change as migrations/sql/0051_history_and_indexes.sql (the by-hand
// version); this file is what normally applies it, on boot after a deploy.
//
// Lossless: no row is changed, moved or deleted. Versioning adds hidden
// ROW_START/ROW_END columns that SELECT * does not return, so no app query
// changes. Every UPDATE/DELETE then keeps the previous row version:
//   SELECT * FROM characters FOR SYSTEM_TIME AS OF '2026-09-01' WHERE id = 7;
//
// Verified on a restored copy of the dev database (11.4.9; prod is 11.4.13):
//   - history survives FK cascade deletes (a deleted character and its
//     downtimes stay queryable FOR SYSTEM_TIME ALL)
//   - scripts/backup-db.js dumps and restores the full history exactly. It
//     had to learn TABLE_TYPE 'SYSTEM VERSIONED' first: filtering on
//     'BASE TABLE' alone silently skipped every versioned table.
//   - reads unchanged; an UPDATE costs ~15-20% more (it also writes the old
//     row); storage grows by one old-row copy per UPDATE.
//
// NOT versioned, on purpose:
//   - users: push_settings held up to 75 MB per row (see routes/push.js), and
//     each version would copy it. user_change_log + triggers cover the
//     identity fields instead.
//   - append-only logs (chat*, dice_rolls, xp_log, ...) are history already;
//     high-churn tables (user_sessions, live_session*, idempotency_keys) and
//     media/wiki tables would only grow.
// Gotchas for future code: TRUNCATE is refused on a versioned table (use
// DELETE), and MariaDB writes a history row even for an UPDATE that changes
// nothing.
//
// Every step is existence-checked, so re-running is a no-op and a partial run
// resumes where it stopped. ALTERs wait at most LOCK_WAIT_S for a busy table;
// on timeout the migration throws, is NOT recorded, and boot (or
// `npm run migrations`) retries it later.

const LOCK_WAIT_S = 30;

const VERSIONED = [
  'characters', 'coteries', 'coterie_members', 'retainers', 'npcs',
  'domain_claims', 'domain_claim_requests', 'domain_guests', 'domain_residents',
  'domain_manager_grants', 'domain_overlay_grants', 'domain_problems', 'domain_codex_entries',
  'boons', 'inventory_items', 'discipline_access', 'discipline_requests', 'downtimes',
  'news_entries', 'rumors', 'events', 'premonitions', 'elysium_invitations',
  'blood_hunts', 'court_wanted', 'user_news_permissions', 'app_settings', 'portal_settings',
  'hunts', 'hunt_steps', 'hunt_groups', 'feedings',
];

const INDEXES = [
  // admin per-character view: WHERE character_id = ? ORDER BY created_at DESC LIMIT 500 (was a filesort)
  ['xp_log', 'idx_xp_char_created', 'character_id, created_at'],
  ['dice_rolls', 'idx_dice_char_created', 'character_id, created_at'],
  // activity heatmap: WHERE session_start BETWEEN ... (was a full scan of a table that only grows)
  ['user_sessions', 'idx_us_session_start', 'session_start'],
];

const ANALYZE = [
  'users', 'characters', 'chat_messages', 'chat_group_messages', 'npc_messages', 'downtimes',
  'dice_rolls', 'xp_log', 'user_sessions', 'domain_claims', 'coteries',
];

// Privilege refusals on CREATE TRIGGER (shared hosting can deny TRIGGER).
const ACCESS_DENIED = new Set(['ER_TABLEACCESS_DENIED_ERROR', 'ER_SPECIFIC_ACCESS_DENIED_ERROR', 'ER_DBACCESS_DENIED_ERROR']);

async function tableInfo(conn, table) {
  const [rows] = await conn.query(
    `SELECT TABLE_TYPE AS type, ENGINE AS engine FROM information_schema.TABLES
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? LIMIT 1`,
    [table],
  );
  return rows[0] || null;
}

async function indexExists(conn, table, name) {
  const [rows] = await conn.query(
    `SELECT 1 FROM information_schema.STATISTICS
     WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ? LIMIT 1`,
    [table, name],
  );
  return rows.length > 0;
}

// System versioning needs MariaDB >= 10.3.4 (and does not exist in MySQL).
function supportsVersioning(version) {
  if (!/mariadb/i.test(version)) return false;
  const [maj, min, patch] = version.split(/[.-]/).map(Number);
  return maj > 10 || (maj === 10 && (min > 3 || (min === 3 && patch >= 4)));
}

module.exports = {
  name: '0051_history_and_indexes',
  async up(pool) {
    const { log } = require('../../logger');
    // One dedicated connection so the lock-wait cap applies to every ALTER.
    const conn = await pool.getConnection();
    try {
      await conn.query(`SET SESSION lock_wait_timeout = ${LOCK_WAIT_S}`);
      const [[{ v: version }]] = await conn.query('SELECT VERSION() AS v');

      // 1. MyISAM -> InnoDB (crash-safe, transactional). Lossless engine change.
      const [myisam] = await conn.query(
        `SELECT TABLE_NAME AS n FROM information_schema.TABLES
         WHERE TABLE_SCHEMA = DATABASE() AND ENGINE = 'MyISAM' AND TABLE_TYPE = 'BASE TABLE'`,
      );
      for (const { n } of myisam) await conn.query(`ALTER TABLE \`${n}\` ENGINE = InnoDB`);

      // 2. Composite indexes.
      for (const [table, name, cols] of INDEXES) {
        if (!(await tableInfo(conn, table)) || (await indexExists(conn, table, name))) continue;
        await conn.query(`CREATE INDEX \`${name}\` ON \`${table}\` (${cols})`);
      }

      // 3. users change log. No FOREIGN KEY on purpose: the log must outlive the user it describes.
      await conn.query(`
        CREATE TABLE IF NOT EXISTS user_change_log (
          id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
          user_id INT UNSIGNED NOT NULL,
          action ENUM('update','delete') NOT NULL,
          changed_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
          old_email VARCHAR(190) NULL, new_email VARCHAR(190) NULL,
          old_display_name VARCHAR(100) NULL, new_display_name VARCHAR(100) NULL,
          old_role VARCHAR(20) NULL, new_role VARCHAR(20) NULL,
          old_discord_id VARCHAR(50) NULL, new_discord_id VARCHAR(50) NULL,
          PRIMARY KEY (id),
          KEY idx_ucl_user (user_id, changed_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
      // Only identity fields are logged; theme/push/ntfy/avatar/password/token_version changes are not.
      try {
        await conn.query(`
          CREATE OR REPLACE TRIGGER trg_users_change_log AFTER UPDATE ON users FOR EACH ROW
          INSERT INTO user_change_log (user_id, action, old_email, new_email, old_display_name, new_display_name, old_role, new_role, old_discord_id, new_discord_id)
          SELECT OLD.id, 'update', OLD.email, NEW.email, OLD.display_name, NEW.display_name, OLD.role, NEW.role, OLD.discord_id, NEW.discord_id
          FROM DUAL
          WHERE NOT (OLD.email <=> NEW.email AND OLD.display_name <=> NEW.display_name AND OLD.role <=> NEW.role AND OLD.discord_id <=> NEW.discord_id)`);
        await conn.query(`
          CREATE OR REPLACE TRIGGER trg_users_delete_log AFTER DELETE ON users FOR EACH ROW
          INSERT INTO user_change_log (user_id, action, old_email, old_display_name, old_role, old_discord_id)
          VALUES (OLD.id, 'delete', OLD.email, OLD.display_name, OLD.role, OLD.discord_id)`);
      } catch (e) {
        if (!ACCESS_DENIED.has(e.code)) throw e;
        // Non-fatal: nothing depends on the log. Everything else still applies.
        log.warn('0051: CREATE TRIGGER refused by the host; user_change_log will stay empty', { code: e.code });
      }

      // 4. System versioning.
      if (supportsVersioning(version)) {
        for (const table of VERSIONED) {
          const info = await tableInfo(conn, table);
          if (!info || info.type !== 'BASE TABLE') continue; // missing, or already versioned
          await conn.query(`ALTER TABLE \`${table}\` ADD SYSTEM VERSIONING`);
        }
      } else {
        log.warn('0051: server does not support system versioning; history step skipped', { version });
      }

      // 5. Fresh optimizer statistics. Harmless; never fatal.
      for (const table of ANALYZE) {
        if (await tableInfo(conn, table)) await conn.query(`ANALYZE TABLE \`${table}\``).catch(() => {});
      }
    } finally {
      conn.release();
    }
  },
};
