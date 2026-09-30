-- =====================================================================
-- 0035_chat_emoji_size — manual/production equivalent
-- =====================================================================
--
-- Hand-run version of migrations/list/0035_chat_emoji_size.js, for
-- phpMyAdmin. Optional: the server also applies it on boot. If a statement
-- fails with "Duplicate column name", that table already has it: continue.

-- 1. Size (1-3) of a hold-to-grow conversation emoji; NULL for normal messages.
ALTER TABLE chat_messages ADD COLUMN `emoji_size` TINYINT UNSIGNED DEFAULT NULL;
ALTER TABLE chat_group_messages ADD COLUMN `emoji_size` TINYINT UNSIGNED DEFAULT NULL;
ALTER TABLE npc_messages ADD COLUMN `emoji_size` TINYINT UNSIGNED DEFAULT NULL;

-- 2. Mark the migration as applied so the server doesn't run it again.
INSERT IGNORE INTO schema_migrations (name) VALUES ('0035_chat_emoji_size');
