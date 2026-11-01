-- Migration 0072: bot liveness off the versioned app_settings table. Runs
-- automatically on boot via migrations/list/0072_runtime_status.js; this is
-- the same change by hand (schema-qualified for phpMyAdmin).
CREATE TABLE IF NOT EXISTS `vtm`.`runtime_status` (
  `status_key`   VARCHAR(64)  NOT NULL PRIMARY KEY,
  `status_value` VARCHAR(255) NULL,
  `updated_at`   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

DELETE FROM `vtm`.`app_settings`
 WHERE setting_key IN ('discord_bot_last_heartbeat', 'discord_bot_name', 'discord_bot_active_instance');

-- History purge (keeps every real setting's history). DELETE HISTORY is not
-- transactional: run all of it in ONE session, and only drop the copy once the
-- INSERT has succeeded.
SET SESSION system_versioning_insert_history = 1;
CREATE TABLE `vtm`.`_0072_app_settings_history` AS
  SELECT setting_key, setting_value, updated_at, ROW_START AS rs, ROW_END AS re
    FROM `vtm`.`app_settings` FOR SYSTEM_TIME ALL
   WHERE ROW_END < NOW(6)
     AND setting_key NOT IN ('discord_bot_last_heartbeat', 'discord_bot_name', 'discord_bot_active_instance');
DELETE HISTORY FROM `vtm`.`app_settings`;
INSERT INTO `vtm`.`app_settings` (setting_key, setting_value, updated_at, ROW_START, ROW_END)
  SELECT setting_key, setting_value, updated_at, rs, re FROM `vtm`.`_0072_app_settings_history`;
DROP TABLE `vtm`.`_0072_app_settings_history`;
