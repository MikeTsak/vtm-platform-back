-- Migration 0068: Storyteller-recorded feedings. Runs automatically on boot via
-- migrations/list/0068_feeding_outcome_manual.js; this is the same change by hand.
SET SESSION system_versioning_alter_history = KEEP;
ALTER TABLE feedings
  MODIFY COLUMN outcome ENUM('bestial_failure','failure','success','critical','messy_critical','herd','manual') DEFAULT NULL;
