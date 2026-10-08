-- =====================================================================
-- 0051_history_and_indexes — manual/production equivalent (FALLBACK ONLY)
-- =====================================================================
--
-- You normally do NOT need this file. migrations/list/0051_history_and_indexes.js applies the
-- same change automatically on the first boot after npm run deploy, and records itself in
-- schema_migrations. Use this only if you want to apply it by hand in phpMyAdmin. Running both
-- is harmless: every statement here is idempotent.
-- =====================================================================
--
-- What it does (all lossless — no row is changed, moved or deleted):
--   1. Converts the empty MyISAM wiki_* tables to InnoDB (crash-safe, FK-capable).
--   2. Adds 3 composite indexes backing real queries (xp_log, dice_rolls, user_sessions).
--   3. Adds user_change_log + triggers: who had which email / display name / role /
--      discord id, and when it changed. (users is NOT versioned natively: its
--      push_settings column is ~80 MB, which would be copied into history.)
--   4. Turns on MariaDB SYSTEM VERSIONING for 32 editable tables, so every
--      UPDATE/DELETE keeps the previous row version automatically ("what did this
--      character / domain / downtime look like last month?").
--   5. ANALYZE TABLE so the optimizer has fresh statistics.
--
-- The app needs NO code change: versioning adds hidden ROW_START / ROW_END columns,
-- SELECT * does not return them, INSERT/UPDATE statements are unaffected.
--
-- SCHEMA NAME: this file targets the database named vtm explicitly (objects are written as vtm.table with
--   backticks) and never relies on the "current database". phpMyAdmin silently switches the current database
--   to information_schema whenever a query mentions it, which makes DATABASE() lie. If your database has a
--   different name, find-and-replace vtm with it everywhere in this file.
--
-- BEFORE YOU RUN
--   * Take a backup:  npm run deploy:backup:full   (in back/)
--   * Run STEP 0 alone first and read it. Need MariaDB >= 10.3.4 for system versioning
--     and >= 10.1.4 for CREATE OR REPLACE TRIGGER. Below 10.3.4 skip STEP 4.
--   * Run in a quiet moment. ALTER TABLE waits for running queries on that table; every
--     table is tiny so each ALTER takes milliseconds.
--   * Every statement is idempotent: a table already versioned / converted / indexed is
--     skipped, and a missing table is skipped. Safe to re-run.
--   * Nothing here is expected to fail except CREATE TRIGGER on hosts that deny the
--     TRIGGER privilege (non-fatal, see STEP 3).
--
-- ALSO REQUIRED if you adopt this: deploy the updated back/scripts/backup-db.js.
--   Versioned tables report TABLE_TYPE = 'SYSTEM VERSIONED'. The OLD backup script only
--   dumped 'BASE TABLE', so it would silently SKIP every table in STEP 4.
-- =====================================================================

-- ---------------------------------------------------------------------
-- STEP 0 — preflight (read-only). Run on its own first.
-- ---------------------------------------------------------------------
SELECT VERSION() AS mariadb_version, @@innodb_buffer_pool_size / 1048576 AS buffer_pool_mb;
SELECT TABLE_NAME, ENGINE FROM information_schema.TABLES
 WHERE TABLE_SCHEMA = 'vtm' AND ENGINE <> 'InnoDB' AND TABLE_TYPE = 'BASE TABLE';
-- sanity: must be about 90 tables, and must include characters / users / downtimes. If it says 0, the schema name is wrong.
SELECT COUNT(*) AS tables_in_schema, SUM(TABLE_NAME IN ('characters','users','downtimes')) AS key_tables_found
 FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm';
-- tables from STEP 4 that do not exist on this server (they will just be skipped):
SELECT t.n AS missing_table FROM (SELECT 'characters' AS n UNION ALL SELECT 'coteries' AS n UNION ALL SELECT 'coterie_members' AS n UNION ALL SELECT 'retainers' AS n UNION ALL SELECT 'npcs' AS n UNION ALL SELECT 'domain_claims' AS n UNION ALL SELECT 'domain_claim_requests' AS n UNION ALL SELECT 'domain_guests' AS n UNION ALL SELECT 'domain_residents' AS n UNION ALL SELECT 'domain_manager_grants' AS n UNION ALL SELECT 'domain_overlay_grants' AS n UNION ALL SELECT 'domain_problems' AS n UNION ALL SELECT 'domain_codex_entries' AS n UNION ALL SELECT 'boons' AS n UNION ALL SELECT 'inventory_items' AS n UNION ALL SELECT 'discipline_access' AS n UNION ALL SELECT 'discipline_requests' AS n UNION ALL SELECT 'downtimes' AS n UNION ALL SELECT 'news_entries' AS n UNION ALL SELECT 'rumors' AS n UNION ALL SELECT 'events' AS n UNION ALL SELECT 'premonitions' AS n UNION ALL SELECT 'elysium_invitations' AS n UNION ALL SELECT 'blood_hunts' AS n UNION ALL SELECT 'court_wanted' AS n UNION ALL SELECT 'user_news_permissions' AS n UNION ALL SELECT 'app_settings' AS n UNION ALL SELECT 'portal_settings' AS n UNION ALL SELECT 'hunts' AS n UNION ALL SELECT 'hunt_steps' AS n UNION ALL SELECT 'hunt_groups' AS n UNION ALL SELECT 'feedings' AS n) t
 LEFT JOIN information_schema.TABLES i ON i.TABLE_SCHEMA = 'vtm' AND i.TABLE_NAME = t.n
 WHERE i.TABLE_NAME IS NULL;

-- ---------------------------------------------------------------------
-- STEP 1 — MyISAM -> InnoDB (lossless engine change)
-- ---------------------------------------------------------------------
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'wiki_tags' AND ENGINE = 'MyISAM') = 1, 'ALTER TABLE `vtm`.`wiki_tags` ENGINE = InnoDB', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'wiki_article_tags' AND ENGINE = 'MyISAM') = 1, 'ALTER TABLE `vtm`.`wiki_article_tags` ENGINE = InnoDB', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'wiki_journal_entries' AND ENGINE = 'MyISAM') = 1, 'ALTER TABLE `vtm`.`wiki_journal_entries` ENGINE = InnoDB', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'wiki_timeline_events' AND ENGINE = 'MyISAM') = 1, 'ALTER TABLE `vtm`.`wiki_timeline_events` ENGINE = InnoDB', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'wiki_admin_notes' AND ENGINE = 'MyISAM') = 1, 'ALTER TABLE `vtm`.`wiki_admin_notes` ENGINE = InnoDB', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;

-- ---------------------------------------------------------------------
-- STEP 2 — composite indexes (additive; IF NOT EXISTS makes them idempotent)
-- ---------------------------------------------------------------------
-- admin per-character view: WHERE character_id = ? ORDER BY created_at DESC LIMIT 500
CREATE INDEX IF NOT EXISTS idx_xp_char_created ON `vtm`.`xp_log` (character_id, created_at);
CREATE INDEX IF NOT EXISTS idx_dice_char_created ON `vtm`.`dice_rolls` (character_id, created_at);
-- activity heatmap: WHERE session_start BETWEEN ... (was a full scan; table grows forever)
CREATE INDEX IF NOT EXISTS idx_us_session_start ON `vtm`.`user_sessions` (session_start);

-- ---------------------------------------------------------------------
-- STEP 3 — user_change_log + triggers (history for users without copying 80 MB blobs)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `vtm`.`user_change_log` (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- Deliberately no FOREIGN KEY: the log must outlive the user it describes.
-- If CREATE TRIGGER is refused (host denies the TRIGGER privilege) skip these two; nothing else depends on them.
CREATE OR REPLACE TRIGGER `vtm`.trg_users_change_log AFTER UPDATE ON `vtm`.`users` FOR EACH ROW INSERT INTO `vtm`.`user_change_log` (user_id, action, old_email, new_email, old_display_name, new_display_name, old_role, new_role, old_discord_id, new_discord_id) SELECT OLD.id, 'update', OLD.email, NEW.email, OLD.display_name, NEW.display_name, OLD.role, NEW.role, OLD.discord_id, NEW.discord_id FROM DUAL WHERE NOT (OLD.email <=> NEW.email AND OLD.display_name <=> NEW.display_name AND OLD.role <=> NEW.role AND OLD.discord_id <=> NEW.discord_id);
CREATE OR REPLACE TRIGGER `vtm`.trg_users_delete_log AFTER DELETE ON `vtm`.`users` FOR EACH ROW INSERT INTO `vtm`.`user_change_log` (user_id, action, old_email, old_display_name, old_role, old_discord_id) VALUES (OLD.id, 'delete', OLD.email, OLD.display_name, OLD.role, OLD.discord_id);

-- ---------------------------------------------------------------------
-- STEP 4 — system versioning (32 tables). Needs MariaDB >= 10.3.4
-- ---------------------------------------------------------------------
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'characters' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`characters` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'coteries' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`coteries` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'coterie_members' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`coterie_members` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'retainers' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`retainers` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'npcs' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`npcs` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'domain_claims' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`domain_claims` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'domain_claim_requests' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`domain_claim_requests` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'domain_guests' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`domain_guests` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'domain_residents' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`domain_residents` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'domain_manager_grants' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`domain_manager_grants` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'domain_overlay_grants' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`domain_overlay_grants` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'domain_problems' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`domain_problems` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'domain_codex_entries' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`domain_codex_entries` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'boons' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`boons` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'inventory_items' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`inventory_items` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'discipline_access' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`discipline_access` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'discipline_requests' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`discipline_requests` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'downtimes' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`downtimes` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'news_entries' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`news_entries` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'rumors' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`rumors` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'events' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`events` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'premonitions' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`premonitions` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'elysium_invitations' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`elysium_invitations` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'blood_hunts' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`blood_hunts` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'court_wanted' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`court_wanted` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'user_news_permissions' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`user_news_permissions` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'app_settings' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`app_settings` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'portal_settings' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`portal_settings` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'hunts' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`hunts` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'hunt_steps' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`hunt_steps` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'hunt_groups' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`hunt_groups` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;
SET @s = IF((SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_NAME = 'feedings' AND TABLE_TYPE = 'BASE TABLE') = 1, 'ALTER TABLE `vtm`.`feedings` ADD SYSTEM VERSIONING', 'DO 0'); PREPARE p FROM @s; EXECUTE p; DEALLOCATE PREPARE p;

-- ---------------------------------------------------------------------
-- STEP 5 — refresh optimizer statistics (harmless)
-- ---------------------------------------------------------------------
ANALYZE TABLE `vtm`.`users`, `vtm`.`characters`, `vtm`.`chat_messages`, `vtm`.`chat_group_messages`, `vtm`.`npc_messages`, `vtm`.`downtimes`, `vtm`.`dice_rolls`, `vtm`.`xp_log`, `vtm`.`user_sessions`, `vtm`.`domain_claims`, `vtm`.`coteries`;

-- ---------------------------------------------------------------------
-- STEP 6 — verify (read-only)
-- ---------------------------------------------------------------------
SELECT COUNT(*) AS versioned_tables FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND TABLE_TYPE = 'SYSTEM VERSIONED';  -- expect 32 (fewer = some tables absent, see STEP 0)
SELECT TABLE_NAME, ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA = 'vtm' AND ENGINE = 'MyISAM';  -- expect no rows
SELECT TRIGGER_NAME FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = 'vtm' AND TRIGGER_NAME LIKE 'trg_users_%';  -- expect 2 rows
SELECT TABLE_NAME, INDEX_NAME FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = 'vtm' AND INDEX_NAME IN ('idx_xp_char_created','idx_dice_char_created','idx_us_session_start');  -- expect 3 rows

-- ---------------------------------------------------------------------
-- OPTIONAL — shrink corrupted users.push_settings (MODIFIES DATA, so commented out; read the notes)
-- ---------------------------------------------------------------------
-- Cause (fixed in routes/push.js): saving push settings spread a JSON *string* into an object, so the
-- value became {"0":"{","1":"\"",...,"chat":true,"system":true} and re-embedded itself on every save.
-- On the dev copy this made 3 users' rows 5 MB / 5 MB / 75 MB — 81 of the ~100 MB database — and the
-- 75 MB row alone exceeds a 64 MB max_allowed_packet, so backups of it cannot be restored.
-- The numeric keys are pure garbage; only 'chat' and 'system' carry information.
--
-- The code only ever reads/writes the two categories 'chat' and 'system' (sendPushNotification callers),
-- so nothing real is lost by keeping just those. (Listing every key with JSON_TABLE is NOT practical on a
-- 75 MB row — it times out — so don't try.)
--
-- A) read-only: who is affected, and what are their two real values?
-- SELECT id, ROUND(LENGTH(push_settings) / 1048576, 2) AS mb, JSON_EXTRACT(push_settings, '$.chat') AS chat, JSON_EXTRACT(push_settings, '$.system') AS system_flag
--   FROM `vtm`.`users` WHERE LENGTH(push_settings) > 10000;   -- slow on the 75 MB row (tens of seconds); that is normal
-- B) shrink them. Back up first.
-- UPDATE `vtm`.`users` SET push_settings = JSON_OBJECT('chat', JSON_EXTRACT(push_settings, '$.chat'), 'system', JSON_EXTRACT(push_settings, '$.system'))
--   WHERE LENGTH(push_settings) > 10000;
-- C) reclaim the freed space on disk (brief table lock; 38 rows, so fast):
-- OPTIMIZE TABLE `vtm`.`users`;

-- ---------------------------------------------------------------------
-- HOW TO USE THE HISTORY (examples — commented out)
-- ---------------------------------------------------------------------
-- SELECT * FROM `vtm`.`characters` FOR SYSTEM_TIME AS OF '2026-09-01 00:00:00' WHERE id = 7;                      -- the sheet as of a date
-- SELECT id, xp, ROW_START, ROW_END FROM `vtm`.`characters` FOR SYSTEM_TIME ALL WHERE id = 7 ORDER BY ROW_START;     -- every version of it
-- SELECT * FROM `vtm`.`downtimes` FOR SYSTEM_TIME ALL WHERE ROW_END < '2038-01-01';                                  -- only superseded / deleted rows
-- SELECT * FROM `vtm`.`user_change_log` WHERE user_id = 12 ORDER BY changed_at;

-- ---------------------------------------------------------------------
-- OPTIONAL — retention (history grows forever; these tables are tiny, so this is just a lever)
-- ---------------------------------------------------------------------
-- Needs the DELETE HISTORY privilege. Removes ONLY superseded versions, never current rows.
-- DELETE HISTORY FROM `vtm`.`downtimes` BEFORE SYSTEM_TIME '2025-01-01 00:00:00';
-- DELETE FROM `vtm`.`user_change_log` WHERE changed_at < '2025-01-01';

-- ---------------------------------------------------------------------
-- OPTIONAL — server settings (need SUPER / host support; skip on shared hosting)
-- ---------------------------------------------------------------------
-- SET GLOBAL slow_query_log = 1;  SET GLOBAL long_query_time = 1;   -- find slow queries with real data
-- innodb_buffer_pool_size: ~60-70% of RAM on a dedicated DB box (my.cnf, restart). Keep innodb_flush_log_at_trx_commit = 1 (durability).

-- ---------------------------------------------------------------------
-- ROLLBACK (commented). NOTE: DROP SYSTEM VERSIONING DELETES the stored history.
-- ---------------------------------------------------------------------
-- ALTER TABLE `vtm`.`characters` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`coteries` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`coterie_members` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`retainers` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`npcs` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`domain_claims` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`domain_claim_requests` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`domain_guests` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`domain_residents` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`domain_manager_grants` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`domain_overlay_grants` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`domain_problems` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`domain_codex_entries` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`boons` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`inventory_items` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`discipline_access` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`discipline_requests` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`downtimes` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`news_entries` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`rumors` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`events` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`premonitions` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`elysium_invitations` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`blood_hunts` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`court_wanted` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`user_news_permissions` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`app_settings` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`portal_settings` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`hunts` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`hunt_steps` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`hunt_groups` DROP SYSTEM VERSIONING;
-- ALTER TABLE `vtm`.`feedings` DROP SYSTEM VERSIONING;
-- DROP TRIGGER IF EXISTS `vtm`.trg_users_change_log;  DROP TRIGGER IF EXISTS `vtm`.trg_users_delete_log;  DROP TABLE IF EXISTS `vtm`.`user_change_log`;
-- DROP INDEX IF EXISTS idx_xp_char_created ON `vtm`.`xp_log`;  DROP INDEX IF EXISTS idx_dice_char_created ON `vtm`.`dice_rolls`;  DROP INDEX IF EXISTS idx_us_session_start ON `vtm`.`user_sessions`;
