-- Migration 0069: safe feeding paid with a downtime action. Runs automatically on boot via
-- migrations/list/0069_feeding_outcome_downtime.js; this is the same change by hand.
SET SESSION system_versioning_alter_history = KEEP;
ALTER TABLE feedings
  MODIFY COLUMN outcome ENUM('bestial_failure','failure','success','critical','messy_critical','herd','manual','downtime') DEFAULT NULL;
