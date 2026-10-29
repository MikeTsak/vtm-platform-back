-- Migration 0067: ghoul upkeep. Runs automatically on boot via
-- migrations/list/0067_ghoul_feedings.js; this is the same change by hand.
SET SESSION system_versioning_alter_history = KEEP;

CREATE TABLE IF NOT EXISTS ghoul_feedings (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  retainer_id INT(11) NOT NULL,
  cycle_index INT NOT NULL,
  status ENUM('fed','starved') NOT NULL,
  method VARCHAR(20) NOT NULL,
  fed_by_character_id INT(10) UNSIGNED DEFAULT NULL,
  rouse_dice VARCHAR(20) DEFAULT NULL,
  hunger_before TINYINT DEFAULT NULL,
  hunger_after TINYINT DEFAULT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_ghoul_cycle (retainer_id, cycle_index),
  KEY idx_ghoul_feedings_cycle (cycle_index),
  CONSTRAINT fk_ghoul_feedings_retainer FOREIGN KEY (retainer_id) REFERENCES retainers (id) ON DELETE CASCADE,
  CONSTRAINT fk_ghoul_feedings_feeder FOREIGN KEY (fed_by_character_id) REFERENCES characters (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

ALTER TABLE retainers ADD COLUMN let_starve TINYINT(1) NOT NULL DEFAULT 0;
