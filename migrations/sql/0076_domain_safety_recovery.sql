-- 0076_domain_safety_recovery: domain Safety no longer decays on its own; +1 per 3 months without a failed hunt.
-- migrations/list/0076_domain_safety_recovery.js does this on boot; this is the same change by hand.

SET SESSION system_versioning_alter_history = KEEP;
ALTER TABLE domain_claims ADD COLUMN safety_recovered_at DATETIME NULL DEFAULT CURRENT_TIMESTAMP;

START TRANSACTION;

-- Recovery clock for existing divisions starts when the Feeding system went live.
UPDATE domain_claims SET safety_recovered_at = COALESCE((SELECT MIN(created_at) FROM feedings), NOW());

-- Give back every Safety point an automatic cycle-end decay run took (visible history starts 2026-10-09).
UPDATE domain_claims d JOIN (
  SELECT n.division, COUNT(*) AS points
    FROM app_settings FOR SYSTEM_TIME ALL s
    JOIN domain_claims FOR SYSTEM_TIME ALL n ON n.row_start BETWEEN s.row_start - INTERVAL 10 SECOND AND s.row_start
    JOIN domain_claims FOR SYSTEM_TIME ALL o ON o.division = n.division AND o.row_end = n.row_start
   WHERE s.setting_key = 'feeding_last_decay_cycle_index' AND o.safety_rating = n.safety_rating + 1
   GROUP BY n.division
) x ON x.division = d.division
SET d.safety_rating = LEAST(10, d.safety_rating + x.points)
WHERE d.safety_rating IS NOT NULL;

-- Take back the Herd point the duplicate run of 2026-11-02 gave (characters 15, 25, 28 on prod).
UPDATE characters c JOIN (
  SELECT DISTINCT cn.id
    FROM app_settings FOR SYSTEM_TIME ALL s
    JOIN app_settings FOR SYSTEM_TIME ALL sp ON sp.setting_key = s.setting_key AND sp.row_end = s.row_start AND sp.setting_value = s.setting_value
    JOIN characters FOR SYSTEM_TIME ALL cn ON cn.row_start BETWEEN s.row_start AND s.row_start + INTERVAL 60 SECOND
    JOIN characters FOR SYSTEM_TIME ALL co ON co.id = cn.id AND co.row_end = cn.row_start
   WHERE s.setting_key = 'feeding_last_decay_cycle_index'
     AND CAST(JSON_VALUE(cn.sheet, '$.herd_current') AS SIGNED) = CAST(JSON_VALUE(co.sheet, '$.herd_current') AS SIGNED) + 1
) x ON x.id = c.id
SET c.sheet = JSON_SET(c.sheet, '$.herd_current', CAST(JSON_VALUE(c.sheet, '$.herd_current') AS SIGNED) - 1)
WHERE CAST(JSON_VALUE(c.sheet, '$.herd_current') AS SIGNED) > 0;

INSERT IGNORE INTO schema_migrations (name) VALUES ('0076_domain_safety_recovery');
COMMIT;
