-- Migration 0074: background job health. Runs automatically on boot via
-- migrations/list/0074_job_status.js; this is the same change by hand.
CREATE TABLE IF NOT EXISTS `vtm`.`job_status` (
  `job_name`         VARCHAR(64)  NOT NULL PRIMARY KEY,
  `last_run_at`      DATETIME     NULL,
  `last_duration_ms` INT UNSIGNED NULL,
  `last_note`        VARCHAR(255) NULL,
  `last_ok_at`       DATETIME     NULL,
  `last_error`       TEXT         NULL,
  `last_error_at`    DATETIME     NULL,
  `runs`             INT UNSIGNED NOT NULL DEFAULT 0,
  `failures`         INT UNSIGNED NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
