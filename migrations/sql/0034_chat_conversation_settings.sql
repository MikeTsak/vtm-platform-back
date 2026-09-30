-- =====================================================================
-- 0034_chat_conversation_settings — manual/production equivalent
-- =====================================================================
--
-- Hand-run version of migrations/list/0034_chat_conversation_settings.js,
-- for phpMyAdmin. Optional: the server also applies it on boot. Safe to
-- re-run (IF NOT EXISTS + INSERT IGNORE).

-- 1. Shared per-conversation settings (theme, conversation emoji).
CREATE TABLE IF NOT EXISTS chat_conversation_settings (
  conv_key VARCHAR(64) NOT NULL,
  theme VARCHAR(32) DEFAULT NULL,
  emoji VARCHAR(32) DEFAULT NULL,
  updated_by INT UNSIGNED DEFAULT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (conv_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 2. Mark the migration as applied so the server doesn't run it again.
INSERT IGNORE INTO schema_migrations (name) VALUES ('0034_chat_conversation_settings');
