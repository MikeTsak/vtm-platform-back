-- Migration 0070: domain Safety before a hunt. Runs automatically on boot via
-- migrations/list/0070_feeding_safety_before.js; this is the same change by hand.
SET SESSION system_versioning_alter_history = KEEP;
ALTER TABLE feedings ADD COLUMN safety_before TINYINT NULL DEFAULT NULL AFTER safety_delta;
