-- =====================================================================
-- 0036_chat_system_message_type — manual/production equivalent
-- =====================================================================

ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS `type` ENUM('text','system') NOT NULL DEFAULT 'text' AFTER `body`;
ALTER TABLE npc_messages ADD COLUMN IF NOT EXISTS `type` ENUM('text','system') NOT NULL DEFAULT 'text' AFTER `body`;

INSERT IGNORE INTO schema_migrations (name) VALUES ('0036_chat_system_message_type');
