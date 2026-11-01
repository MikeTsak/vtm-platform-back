-- Migration 0073: index housekeeping. Runs automatically on boot via
-- migrations/list/0073_index_cleanup.js (which checks state first); this is the
-- same change by hand, schema-qualified for phpMyAdmin.
SET SESSION system_versioning_alter_history = KEEP;

ALTER TABLE `vtm`.`downtimes` DROP INDEX `idx_dt_char`;
ALTER TABLE `vtm`.`dice_rolls` DROP INDEX `character_id`;
ALTER TABLE `vtm`.`chat_group_messages` DROP INDEX `fk_cgms_group`;
ALTER TABLE `vtm`.`chat_messages`
  DROP INDEX `idx_sender_id`,
  DROP INDEX `idx_recipient_id`,
  DROP INDEX `conversation_idx`,
  ADD INDEX `conversation_idx` (`sender_id`, `recipient_id`, `created_at`);

-- Only if this returns no rows (one current character per account):
--   SELECT user_id, COUNT(*) n FROM `vtm`.`characters` WHERE user_id IS NOT NULL GROUP BY user_id HAVING n > 1;
ALTER TABLE `vtm`.`characters` ADD UNIQUE INDEX `uniq_char_user` (`user_id`);
ALTER TABLE `vtm`.`characters` DROP INDEX `user_id`;
