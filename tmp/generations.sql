-- Generations, sires and Blood Potency for every PC and NPC. DATA ONLY, no schema change.
-- NOT a migration: do not move into back/migrations (those auto-apply on boot).
-- Safe to re-run. Each row matches on id AND name prefix, so a drifted id is skipped, not corrupted.
-- Take a backup first. characters and npcs are system-versioned, so old values also stay in history.

START TRANSACTION;

-- 1) NPC generations (8 rows)
UPDATE npcs t JOIN (
  SELECT 3 id, 'Handro' p, 8 g UNION ALL
  SELECT 12, 'Ζαχαρίας', 8 UNION ALL
  SELECT 10, 'Κος Κουμ', 9 UNION ALL
  SELECT 11, 'Πρίγκιπας', 10 UNION ALL
  SELECT 9,  'Γιαννάκης', 12 UNION ALL
  SELECT 8,  'Βάκχος', 10 UNION ALL
  SELECT 6,  'Θύμιος', 10 UNION ALL
  SELECT 7,  'Μυριάνα', 10
) v ON v.id = t.id AND t.name LIKE CONCAT(v.p, '%')
SET t.sheet = JSON_SET(t.sheet, '$.generation', v.g)
WHERE JSON_VALID(t.sheet);

-- 2) Player generations (38 rows)
UPDATE characters t JOIN (
  SELECT 31 id, 'Aeolus' p, 11 g UNION ALL
  SELECT 15, 'Alexandros', 9 UNION ALL
  SELECT 18, 'Andreas', 10 UNION ALL
  SELECT 54, 'Edward', 10 UNION ALL
  SELECT 21, 'Elena', 10 UNION ALL
  SELECT 11, 'Esmene', 10 UNION ALL
  SELECT 55, 'Evelyn', 10 UNION ALL
  SELECT 52, 'Ikaros', 7 UNION ALL
  SELECT 35, 'Iliana', 9 UNION ALL
  SELECT 24, 'Iokasti', 10 UNION ALL
  SELECT 27, 'Ioulia', 10 UNION ALL
  SELECT 28, 'Isidora', 9 UNION ALL
  SELECT 29, 'Issabela', 9 UNION ALL
  SELECT 32, 'Kimon', 10 UNION ALL
  SELECT 53, 'Leo', 10 UNION ALL
  SELECT 36, 'Livearyn', 10 UNION ALL
  SELECT 44, 'Markos', 10 UNION ALL
  SELECT 42, 'Matteo', 10 UNION ALL
  SELECT 47, 'Natt', 9 UNION ALL
  SELECT 50, 'Nevenka', 10 UNION ALL
  SELECT 25, 'Roxane', 9 UNION ALL
  SELECT 37, 'Victoras', 11 UNION ALL
  SELECT 48, 'Victoria', 9 UNION ALL
  SELECT 41, 'Αλέξιος', 10 UNION ALL
  SELECT 43, 'Ανδρομάχη', 10 UNION ALL
  SELECT 51, 'Αριάδνη', 10 UNION ALL
  SELECT 38, 'Αστέριος', 11 UNION ALL
  SELECT 45, 'ΔΕΥΚΑΛΙΩΝ', 10 UNION ALL
  SELECT 26, 'Δημοσθένης', 9 UNION ALL
  SELECT 3,  'Ιάσονας', 10 UNION ALL
  SELECT 49, 'Ιόλη', 10 UNION ALL
  SELECT 14, 'Καλυψώ', 10 UNION ALL
  SELECT 40, 'Οδυσσέας', 10 UNION ALL
  SELECT 30, 'Παυλίνα', 9 UNION ALL
  SELECT 19, 'Πέτρος', 10 UNION ALL
  SELECT 39, 'Σαμουήλ', 11 UNION ALL
  SELECT 46, 'Σελήνη', 11 UNION ALL
  SELECT 34, 'Τηλέμαχος', 10
) v ON v.id = t.id AND t.name LIKE CONCAT(v.p, '%')
SET t.sheet = JSON_SET(t.sheet, '$.generation', v.g)
WHERE JSON_VALID(t.sheet);

-- 3) Blood Potency to the generation minimum: Ikaros (7th, min 3), Natt and Victoria Vaidou (9th, min 2)
UPDATE characters
SET sheet = JSON_SET(sheet, '$.blood_potency', CASE id WHEN 52 THEN 3 ELSE 2 END)
WHERE id IN (52, 47, 48) AND JSON_VALID(sheet);

-- 4) Sires that are NPCs: the NPC's real name, read from npcs so it can never drift (3 Handro, 10 Koumoundouros, 11 Prince, 12 Zacharias)
UPDATE characters c JOIN npcs n ON n.id = CASE c.id
    WHEN 15 THEN 3 WHEN 29 THEN 3     -- Alexandros, Issabela -> Handro Giovanni
    WHEN 11 THEN 10                   -- Esmene -> Κος Κουμουνδούρος
    WHEN 38 THEN 11                   -- Αστέριος -> Πρίγκιπας Μιλτιάδης Τζανέτος
    WHEN 47 THEN 12                   -- Natt -> Ζαχαρίας Χαλκοκαντήλης
  END
SET c.sheet = JSON_SET(c.sheet, '$.sire', TRIM(n.name))
WHERE c.id IN (15, 29, 11, 38, 47) AND JSON_VALID(c.sheet);

-- 5) Sires that are other player characters: their real character name (optional: drop this block to leave the typed text)
UPDATE characters c JOIN characters s ON s.id = CASE c.id
    WHEN 27 THEN 48                   -- Ioulia -> Victoria Vaidou
    WHEN 46 THEN 27                   -- Σελήνη -> Ioulia Koniordou
    WHEN 37 THEN 3                    -- Victoras -> Ιάσονας Παπαπέτρου
    WHEN 39 THEN 24                   -- Σαμουήλ -> Iokasti Petrakou
  END
SET c.sheet = JSON_SET(c.sheet, '$.sire', TRIM(s.name))
WHERE c.id IN (27, 46, 37, 39) AND JSON_VALID(c.sheet);

-- 6) Ikaros's sire (not in the system, stays free text)
UPDATE characters
SET sheet = JSON_SET(sheet, '$.sire', 'Ιωάννης ο Αρχαίος')
WHERE id = 52 AND JSON_VALID(sheet);

COMMIT;

-- CHECK: expect 0 rows (every character has a generation) ...
SELECT 'PC' k, id, name FROM characters WHERE JSON_VALID(sheet) AND JSON_VALUE(sheet, '$.generation') IS NULL
UNION ALL
SELECT 'NPC', id, name FROM npcs WHERE JSON_VALID(sheet) AND JSON_VALUE(sheet, '$.generation') IS NULL;

-- ... and expect 0 rows (Blood Potency below the generation minimum: gen 7 -> 3, gen 8-9 -> 2)
SELECT 'PC' k, id, name, JSON_VALUE(sheet, '$.generation') gen, JSON_VALUE(sheet, '$.blood_potency') bp FROM characters
WHERE JSON_VALID(sheet) AND CAST(JSON_VALUE(sheet, '$.blood_potency') AS UNSIGNED) < CASE
  WHEN CAST(JSON_VALUE(sheet, '$.generation') AS UNSIGNED) <= 5 THEN 4
  WHEN CAST(JSON_VALUE(sheet, '$.generation') AS UNSIGNED) <= 7 THEN 3
  WHEN CAST(JSON_VALUE(sheet, '$.generation') AS UNSIGNED) <= 9 THEN 2 ELSE 0 END;
