-- Migration 0042: coterie retainers. Runs automatically on boot via
-- migrations/list/0042_coterie_retainers.js; this is the same change by hand.
ALTER TABLE retainers MODIFY character_id INT(10) UNSIGNED NULL;
ALTER TABLE retainers
  ADD COLUMN coterie_id INT(11) NULL DEFAULT NULL AFTER character_id,
  ADD COLUMN domitor_character_id INT(10) UNSIGNED NULL DEFAULT NULL AFTER coterie_id,
  ADD KEY idx_retainers_coterie (coterie_id),
  ADD CONSTRAINT fk_retainers_coterie FOREIGN KEY (coterie_id) REFERENCES coteries (id) ON DELETE CASCADE,
  ADD CONSTRAINT fk_retainers_domitor FOREIGN KEY (domitor_character_id) REFERENCES characters (id) ON DELETE SET NULL,
  ADD CONSTRAINT chk_retainers_one_owner CHECK ((character_id IS NULL) <> (coterie_id IS NULL));
