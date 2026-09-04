// Brings the coterie tables up to what the V5 rules actually need.
//
// 1. `merits_json` — coterie Merits (Bolt Holes, On Tap, the Domain Merits,
//    the clan coterie Merits) had nowhere to live, so the whole Players Guide
//    Merit layer was missing from the app.
// 2. `concept` — a one-line "what is this coterie for", shown on the sheet.
// 3. `rules_override` — ST flag that relaxes pool/rating enforcement for a
//    single coterie without weakening validation for everyone else.
// 4. `coterie_members.character_id` — a coterie is made of characters, not
//    accounts. The old code inferred the character by joining on user_id,
//    which silently picks an arbitrary row for any user with more than one.
// 5. `coterie_xp_log` — the XP bank was a bare integer any member could
//    increment without limit and with no record. Every award, spend and
//    adjustment is now an auditable row.
//
// utf8mb3 on the existing tables is deliberate: the columns added here match
// the charset already in use on those tables so no implicit conversion or
// table rebuild is forced on the live data.
module.exports = {
  name: '0008_coterie_v5_rules',
  async up(pool) {
    const [cols] = await pool.query(`
      SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'coteries'
    `);
    const has = (c) => cols.some((r) => r.COLUMN_NAME === c);

    const additions = [];
    if (!has('merits_json')) {
      additions.push(
        "ADD COLUMN `merits_json` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`merits_json`))"
      );
    }
    if (!has('concept')) {
      additions.push("ADD COLUMN `concept` varchar(500) DEFAULT NULL");
    }
    if (!has('rules_override')) {
      additions.push("ADD COLUMN `rules_override` tinyint(1) NOT NULL DEFAULT 0");
    }
    if (additions.length) {
      await pool.query(`ALTER TABLE \`coteries\` ${additions.join(', ')}`);
    }

    const [memberCols] = await pool.query(`
      SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'coterie_members'
    `);
    if (!memberCols.some((r) => r.COLUMN_NAME === 'character_id')) {
      await pool.query(`
        ALTER TABLE \`coterie_members\`
          ADD COLUMN \`character_id\` int(11) DEFAULT NULL,
          ADD KEY \`idx_coterie_member_character\` (\`character_id\`)
      `);
      // Backfill from the existing one-character-per-user assumption. MIN(id)
      // makes the pick deterministic where a user somehow has several.
      await pool.query(`
        UPDATE \`coterie_members\` m
        JOIN (
          SELECT user_id, MIN(id) AS character_id
          FROM \`characters\`
          GROUP BY user_id
        ) c ON c.user_id = m.user_id
        SET m.character_id = c.character_id
        WHERE m.character_id IS NULL
      `);
    }

    await pool.query(`
      CREATE TABLE IF NOT EXISTS \`coterie_xp_log\` (
        \`id\` int(11) NOT NULL AUTO_INCREMENT,
        \`coterie_id\` int(11) NOT NULL,
        \`user_id\` int(11) DEFAULT NULL,
        \`kind\` varchar(16) NOT NULL,
        \`bank_delta\` int(11) NOT NULL DEFAULT 0,
        \`personal_delta\` int(11) NOT NULL DEFAULT 0,
        \`character_id\` int(11) DEFAULT NULL,
        \`target_type\` varchar(24) DEFAULT NULL,
        \`target_key\` varchar(64) DEFAULT NULL,
        \`target_name\` varchar(160) DEFAULT NULL,
        \`from_dots\` tinyint(4) DEFAULT NULL,
        \`to_dots\` tinyint(4) DEFAULT NULL,
        \`note\` varchar(500) DEFAULT NULL,
        \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
        PRIMARY KEY (\`id\`),
        KEY \`idx_cxl_coterie\` (\`coterie_id\`,\`created_at\`),
        CONSTRAINT \`fk_coterie_xp_log_coteries\` FOREIGN KEY (\`coterie_id\`)
          REFERENCES \`coteries\` (\`id\`) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);
  },
};
