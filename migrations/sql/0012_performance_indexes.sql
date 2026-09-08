-- =====================================================================
-- 0012_performance_indexes — manual/production equivalent
-- =====================================================================
--
-- You normally do NOT need this file. migrations/list/0012_performance_indexes.js
-- runs automatically via initDatabase() the first time the deployed server
-- boots, and records itself in schema_migrations. Deploying the code and
-- restarting the API is the supported path.
--
-- This file exists for running the same change by hand in phpMyAdmin, e.g. if
-- you want to apply it during a maintenance window before deploying.
--
-- Requires MariaDB 10.1+ for "IF [NOT] EXISTS" on index DDL (dev is 11.4.9 —
-- confirm production with:  SELECT VERSION(); ).
--
-- Every statement is idempotent: running this twice does nothing the second
-- time. Take a backup first anyway.
--
-- IMPORTANT: index NAMES may differ between staging and production. Run STEP 0
-- first and read the output before running STEP 2.
-- =====================================================================


-- ---------------------------------------------------------------------
-- STEP 0 — inspect (read-only). Run this on its own first.
-- ---------------------------------------------------------------------
SELECT
    TABLE_NAME,
    INDEX_NAME,
    GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS columns_in_order
FROM information_schema.STATISTICS
WHERE TABLE_SCHEMA = DATABASE()
  AND TABLE_NAME IN ('chat_messages','npc_messages','chat_group_messages',
                     'downtimes','characters','push_subscriptions')
GROUP BY TABLE_NAME, INDEX_NAME
ORDER BY TABLE_NAME, INDEX_NAME;


-- ---------------------------------------------------------------------
-- STEP 1 — add the composite indexes.
-- Safe and additive. These are what remove "Using filesort" from the
-- npc-thread, group-message and downtime queries.
-- ---------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_npc_user_created
    ON npc_messages (npc_id, user_id, created_at);

CREATE INDEX IF NOT EXISTS idx_group_created
    ON chat_group_messages (group_id, created_at);

CREATE INDEX IF NOT EXISTS idx_char_created
    ON downtimes (character_id, created_at);


-- ---------------------------------------------------------------------
-- STEP 2 — remove exact duplicate indexes.
--
-- These pairs index an identical column list under two names, and BOTH are
-- maintained on every INSERT/UPDATE. The name kept is noted in each comment.
--
-- Run STEP 1 before STEP 2. Each of these columns also carries a FOREIGN KEY,
-- and InnoDB refuses to drop the last index that can serve one.
--
-- If a statement fails with errno 1553 ("Cannot drop index ... needed in a
-- foreign key constraint"), that index is the only one backing the FK on your
-- production schema — SKIP that one line and carry on. Nothing is left broken.
--
-- If a name below doesn't exist in your STEP 0 output, IF EXISTS makes it a
-- no-op — but check STEP 0 for a differently-named duplicate instead.
-- ---------------------------------------------------------------------
-- keeps idx_sender_id
DROP INDEX IF EXISTS sender_id_idx ON chat_messages;

-- keeps idx_recipient_id
DROP INDEX IF EXISTS recipient_id_idx ON chat_messages;

-- keeps idx_dt_char
DROP INDEX IF EXISTS idx_character ON downtimes;

-- keeps user_id
DROP INDEX IF EXISTS idx_user_id ON characters;

-- keeps user_id
DROP INDEX IF EXISTS idx_user_id ON push_subscriptions;


-- ---------------------------------------------------------------------
-- STEP 3 — columns from 0010_downtime_read.
--
-- That migration was never recorded (it exported the wrong shape, so the
-- runner skipped it silently). The columns almost certainly already exist
-- because the legacy run-migrations.js added them; these are no-ops if so.
-- ---------------------------------------------------------------------
ALTER TABLE downtimes ADD COLUMN IF NOT EXISTS is_read BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE users     ADD COLUMN IF NOT EXISTS ntfy_subscribe_downtimes BOOLEAN NOT NULL DEFAULT 0;


-- ---------------------------------------------------------------------
-- STEP 4 — bookkeeping.
--
-- Marks both migrations as applied so the app doesn't try to run them again.
-- Harmless to skip: the JS versions are existence-checked, so if the app runs
-- them later they simply do nothing and record themselves then.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema_migrations (
    id         int(11) NOT NULL AUTO_INCREMENT,
    name       varchar(255) NOT NULL,
    applied_at timestamp NOT NULL DEFAULT current_timestamp(),
    PRIMARY KEY (id),
    UNIQUE KEY name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO schema_migrations (name) VALUES
    ('0010_downtime_read'),
    ('0012_performance_indexes');


-- ---------------------------------------------------------------------
-- STEP 5 — verify.
--
-- Expect: the three idx_*_created indexes present, and no duplicate pairs
-- left. "Using filesort" should be gone from the three EXPLAINs below.
-- (It will REMAIN on the chat DM query — that one is a bidirectional OR and
-- no index can pre-sort it. Expected; see the .js migration's header.)
-- ---------------------------------------------------------------------
SELECT TABLE_NAME, INDEX_NAME, GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS cols
FROM information_schema.STATISTICS
WHERE TABLE_SCHEMA = DATABASE()
  AND INDEX_NAME IN ('idx_npc_user_created','idx_group_created','idx_char_created')
GROUP BY TABLE_NAME, INDEX_NAME;

-- Replace the ? values with real ids from your data before running these.
-- EXPLAIN SELECT * FROM npc_messages        WHERE npc_id = ? AND user_id = ? ORDER BY created_at ASC;
-- EXPLAIN SELECT * FROM chat_group_messages WHERE group_id = ?                ORDER BY created_at ASC;
-- EXPLAIN SELECT * FROM downtimes           WHERE character_id = ?            ORDER BY created_at DESC LIMIT 5;


-- ---------------------------------------------------------------------
-- APPENDIX — find duplicates by shape, not by name.
--
-- If STEP 0 shows production using different index names than dev, run this.
-- It finds every pair of indexes on the SAME table covering the SAME columns
-- in the SAME order, and writes out the DROP statement for the one to remove
-- (it always keeps one of each pair, so a foreign key is never left without
-- an index). Read the output, then run the statements it produces.
--
-- Read-only. It generates SQL; it does not execute anything.
-- ---------------------------------------------------------------------
SELECT
    CONCAT('DROP INDEX `', a.INDEX_NAME, '` ON `', a.TABLE_NAME, '`') AS statement_to_run,
    b.INDEX_NAME AS keeps_this_one,
    a.cols       AS identical_columns
FROM (
    SELECT TABLE_NAME, INDEX_NAME, GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS cols
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND INDEX_NAME <> 'PRIMARY'
    GROUP BY TABLE_NAME, INDEX_NAME
) a
JOIN (
    SELECT TABLE_NAME, INDEX_NAME, GROUP_CONCAT(COLUMN_NAME ORDER BY SEQ_IN_INDEX) AS cols
    FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE() AND INDEX_NAME <> 'PRIMARY'
    GROUP BY TABLE_NAME, INDEX_NAME
) b
  ON  a.TABLE_NAME = b.TABLE_NAME
  AND a.cols       = b.cols
  AND a.INDEX_NAME > b.INDEX_NAME
ORDER BY a.TABLE_NAME, a.INDEX_NAME;
