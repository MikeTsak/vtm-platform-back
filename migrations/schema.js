const pool = require('../db');
const { log } = require('../logger');

async function initDatabase() {
  try {
    log.info('Disabling foreign key checks...');
    await pool.query('SET FOREIGN_KEY_CHECKS=0;');

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`admin_audit_logs\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`admin_id\` int(11) NOT NULL,
  \`action\` varchar(100) NOT NULL,
  \`details\` text DEFAULT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`app_settings\` (
  \`setting_key\` varchar(100) NOT NULL,
  \`setting_value\` text DEFAULT NULL,
  \`updated_at\` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (\`setting_key\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`boons\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`from_name\` varchar(255) NOT NULL COMMENT 'The Kindred/NPC who owes the boon (Debtor)',
  \`to_name\` varchar(255) NOT NULL COMMENT 'The Kindred/NPC who holds the boon (Creditor)',
  \`boon_level\` enum('Trivial','Minor','Major','Life') NOT NULL,
  \`status\` enum('Owed','Paid','Excused','Defaulted') DEFAULT 'Owed',
  \`date_incurred\` date NOT NULL,
  \`details\` text DEFAULT NULL COMMENT 'Description of the boon/favor',
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`level\` enum('trivial','minor','major','life') NOT NULL,
  \`description\` text DEFAULT NULL,
  \`updated_at\` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (\`id\`),
  KEY \`idx_from\` (\`from_name\`),
  KEY \`idx_to\` (\`to_name\`)
) ENGINE=InnoDB AUTO_INCREMENT=59 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`character_inventory\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`character_id\` int(10) unsigned NOT NULL,
  \`name\` varchar(190) NOT NULL,
  \`description\` text DEFAULT NULL,
  \`image\` longtext DEFAULT NULL,
  \`researched\` tinyint(1) NOT NULL DEFAULT 0,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`updated_at\` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (\`id\`),
  KEY \`idx_char_inv\` (\`character_id\`),
  CONSTRAINT \`fk_char_inv_char\` FOREIGN KEY (\`character_id\`) REFERENCES \`characters\` (\`id\`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`characters\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`user_id\` int(10) unsigned NOT NULL,
  \`name\` varchar(100) NOT NULL,
  \`clan\` varchar(60) NOT NULL,
  \`sheet\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`sheet\`)),
  \`xp\` int(11) NOT NULL DEFAULT 50,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`camarilla_titles\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`camarilla_titles\`)),
  \`status\` int(11) DEFAULT 1,
  \`image_url\` varchar(2048) DEFAULT NULL,
  \`is_ex\` tinyint(1) DEFAULT 0,
  \`is_deceased\` tinyint(1) DEFAULT 0,
  \`is_hidden\` tinyint(1) DEFAULT 0,
  \`is_left\` tinyint(1) DEFAULT 0,
  \`is_called\` tinyint(1) DEFAULT 0,
  \`is_missing\` tinyint(1) DEFAULT 0,
  \`is_exiled\` tinyint(1) DEFAULT 0,
  \`is_bloodhunted\` tinyint(1) DEFAULT 0,
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`user_id\` (\`user_id\`),
  KEY \`idx_user_id\` (\`user_id\`),
  CONSTRAINT \`fk_char_user\` FOREIGN KEY (\`user_id\`) REFERENCES \`users\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=41 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`chat_group_members\` (
  \`group_id\` int(10) unsigned NOT NULL,
  \`user_id\` int(11) NOT NULL,
  \`joined_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`last_read_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`group_id\`,\`user_id\`),
  CONSTRAINT \`fk_cgm_group\` FOREIGN KEY (\`group_id\`) REFERENCES \`chat_groups\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`chat_group_messages\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`group_id\` int(10) unsigned NOT NULL,
  \`sender_id\` int(11) NOT NULL,
  \`body\` text NOT NULL,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`attachment_id\` int(10) unsigned DEFAULT NULL,
  \`edited\` tinyint(1) DEFAULT 0,
  PRIMARY KEY (\`id\`),
  KEY \`fk_cgms_group\` (\`group_id\`),
  CONSTRAINT \`fk_cgms_group\` FOREIGN KEY (\`group_id\`) REFERENCES \`chat_groups\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1606 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`chat_groups\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`name\` varchar(100) NOT NULL,
  \`created_by\` int(11) NOT NULL,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`avatar\` longblob DEFAULT NULL,
  \`avatar_url\` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (\`id\`)
) ENGINE=InnoDB AUTO_INCREMENT=26 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`chat_media\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`uploader_id\` int(11) NOT NULL,
  \`filename\` varchar(255) DEFAULT NULL,
  \`mime\` varchar(100) NOT NULL,
  \`size\` int(10) unsigned NOT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  \`data\` longblob DEFAULT NULL,
  \`data_url\` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (\`id\`)
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`chat_messages\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`sender_id\` int(10) unsigned NOT NULL,
  \`recipient_id\` int(10) unsigned NOT NULL,
  \`body\` text NOT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  \`read_at\` timestamp NULL DEFAULT NULL,
  \`delivered_at\` timestamp NULL DEFAULT NULL,
  \`attachment_id\` int(10) unsigned DEFAULT NULL,
  \`edited\` tinyint(1) DEFAULT 0,
  PRIMARY KEY (\`id\`),
  KEY \`sender_id_idx\` (\`sender_id\`),
  KEY \`recipient_id_idx\` (\`recipient_id\`),
  KEY \`conversation_idx\` (\`sender_id\`,\`recipient_id\`),
  KEY \`idx_sender_id\` (\`sender_id\`),
  KEY \`idx_recipient_id\` (\`recipient_id\`),
  KEY \`idx_recipient_read_at\` (\`recipient_id\`,\`read_at\`),
  CONSTRAINT \`chat_messages_recipient_fk\` FOREIGN KEY (\`recipient_id\`) REFERENCES \`users\` (\`id\`) ON DELETE CASCADE,
  CONSTRAINT \`chat_messages_sender_fk\` FOREIGN KEY (\`sender_id\`) REFERENCES \`users\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=7593 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`coterie_members\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`coterie_id\` int(11) NOT NULL,
  \`user_id\` int(11) NOT NULL,
  \`display_name\` varchar(160) DEFAULT NULL,
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`uniq_coterie_member\` (\`coterie_id\`,\`user_id\`),
  KEY \`idx_coterie\` (\`coterie_id\`),
  KEY \`idx_user\` (\`user_id\`),
  CONSTRAINT \`fk_coterie_members_coteries\` FOREIGN KEY (\`coterie_id\`) REFERENCES \`coteries\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=34 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`coteries\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`name\` varchar(160) NOT NULL,
  \`type\` varchar(120) DEFAULT NULL,
  \`domain_id\` int(11) DEFAULT NULL,
  \`chasse\` tinyint(3) unsigned DEFAULT 0,
  \`lien\` tinyint(3) unsigned DEFAULT 0,
  \`portillon\` tinyint(3) unsigned DEFAULT 0,
  \`required_json\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`required_json\`)),
  \`backgrounds_json\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`backgrounds_json\`)),
  \`extras_json\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`extras_json\`)),
  \`points_per_member\` tinyint(3) unsigned DEFAULT 1,
  \`coterie_xp\` int(11) DEFAULT 0,
  \`created_by\` int(11) NOT NULL,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`updated_at\` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  \`flaws_json\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`flaws_json\`)),
  \`bonus_points\` int(11) DEFAULT 0,
  PRIMARY KEY (\`id\`),
  KEY \`idx_domain\` (\`domain_id\`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`dice_rolls\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`user_id\` int(11) NOT NULL,
  \`character_id\` int(11) DEFAULT NULL,
  \`pool\` int(11) NOT NULL,
  \`hunger\` int(11) NOT NULL,
  \`sides\` int(11) NOT NULL DEFAULT 10,
  \`results_json\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL CHECK (json_valid(\`results_json\`)),
  \`successes\` int(11) NOT NULL,
  \`crit_pairs\` int(11) NOT NULL,
  \`messy_crit\` tinyint(1) NOT NULL DEFAULT 0,
  \`bestial_failure\` tinyint(1) NOT NULL DEFAULT 0,
  \`note\` varchar(255) DEFAULT NULL,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`is_hidden\` tinyint(1) DEFAULT 0,
  PRIMARY KEY (\`id\`),
  KEY \`user_id\` (\`user_id\`),
  KEY \`character_id\` (\`character_id\`),
  KEY \`created_at\` (\`created_at\`)
) ENGINE=InnoDB AUTO_INCREMENT=976 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`domain_claims\` (
  \`division\` int(11) NOT NULL,
  \`owner_character_id\` int(10) unsigned DEFAULT NULL,
  \`owner_npc_id\` int(11) DEFAULT NULL,
  \`owner_name\` varchar(100) NOT NULL,
  \`color\` char(7) NOT NULL,
  \`claimed_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`is_abaton\` tinyint(1) DEFAULT 0,
  \`safety_rating\` int(11) DEFAULT 10,
  PRIMARY KEY (\`division\`),
  KEY \`idx_owner_character_id\` (\`owner_character_id\`),
  KEY \`fk_claim_npc\` (\`owner_npc_id\`),
  CONSTRAINT \`fk_claim_char\` FOREIGN KEY (\`owner_character_id\`) REFERENCES \`characters\` (\`id\`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT \`fk_claim_npc\` FOREIGN KEY (\`owner_npc_id\`) REFERENCES \`npcs\` (\`id\`) ON DELETE SET NULL ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`domain_members\` (
  \`domain_id\` int(10) unsigned NOT NULL,
  \`character_id\` int(10) unsigned NOT NULL,
  PRIMARY KEY (\`domain_id\`,\`character_id\`),
  KEY \`fk_dom_c\` (\`character_id\`),
  CONSTRAINT \`fk_dom_c\` FOREIGN KEY (\`character_id\`) REFERENCES \`characters\` (\`id\`) ON DELETE CASCADE,
  CONSTRAINT \`fk_dom_d\` FOREIGN KEY (\`domain_id\`) REFERENCES \`domains\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`domain_problems\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`domain_id\` int(11) NOT NULL,
  \`problem_text\` varchar(255) NOT NULL,
  \`is_custom\` tinyint(1) DEFAULT 0,
  \`resolved\` tinyint(1) DEFAULT 0,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`domains\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`name\` varchar(120) NOT NULL,
  \`description\` text DEFAULT NULL,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`safety_rating\` int(11) DEFAULT 10,
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`name\` (\`name\`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`downtimes\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`character_id\` int(10) unsigned NOT NULL,
  \`title\` varchar(140) NOT NULL,
  \`feeding_type\` varchar(80) DEFAULT NULL,
  \`body\` text NOT NULL,
  \`status\` enum('submitted','approved','rejected','resolved','Needs a Scene','Resolved in scene') NOT NULL DEFAULT 'submitted',
  \`gm_notes\` text DEFAULT NULL,
  \`gm_resolution\` text DEFAULT NULL,
  \`resolved_at\` datetime DEFAULT NULL,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`updated_at\` timestamp NULL DEFAULT NULL ON UPDATE current_timestamp(),
  PRIMARY KEY (\`id\`),
  KEY \`idx_dt_char\` (\`character_id\`),
  KEY \`idx_dt_created\` (\`created_at\`),
  KEY \`idx_character\` (\`character_id\`),
  CONSTRAINT \`fk_dt_char\` FOREIGN KEY (\`character_id\`) REFERENCES \`characters\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=296 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`email_identities\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`email_address\` varchar(150) NOT NULL,
  \`display_name\` varchar(150) DEFAULT NULL,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`avatar\` longblob DEFAULT NULL,
  \`avatar_url\` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`email_address\` (\`email_address\`)
) ENGINE=InnoDB AUTO_INCREMENT=16 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`email_messages\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`thread_id\` int(10) unsigned NOT NULL,
  \`sender_type\` enum('user','identity') NOT NULL,
  \`body\` text DEFAULT NULL,
  \`is_read\` tinyint(4) DEFAULT 0,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  KEY \`thread_id\` (\`thread_id\`),
  CONSTRAINT \`email_messages_ibfk_1\` FOREIGN KEY (\`thread_id\`) REFERENCES \`email_threads\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=84 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`email_threads\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`user_id\` int(11) NOT NULL,
  \`identity_id\` int(10) unsigned NOT NULL,
  \`subject\` varchar(255) DEFAULT NULL,
  \`updated_at\` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  KEY \`identity_id\` (\`identity_id\`),
  CONSTRAINT \`email_threads_ibfk_1\` FOREIGN KEY (\`identity_id\`) REFERENCES \`email_identities\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`events\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`title\` varchar(255) NOT NULL,
  \`date\` datetime NOT NULL,
  \`description\` text DEFAULT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  KEY \`idx_date\` (\`date\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`hunt_group_members\` (
  \`group_id\` int(10) unsigned NOT NULL,
  \`user_id\` int(11) NOT NULL,
  \`joined_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`group_id\`,\`user_id\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`hunt_groups\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`hunt_id\` int(11) NOT NULL,
  \`name\` varchar(255) NOT NULL,
  \`invite_code\` varchar(10) NOT NULL,
  \`created_by\` int(11) NOT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`invite_code\` (\`invite_code\`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`hunt_progress\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`user_id\` int(11) NOT NULL,
  \`hunt_id\` int(10) unsigned NOT NULL,
  \`current_step_id\` int(10) unsigned DEFAULT NULL,
  \`completed\` tinyint(1) DEFAULT 0,
  \`updated_at\` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`uniq_user_hunt\` (\`user_id\`,\`hunt_id\`)
) ENGINE=MyISAM AUTO_INCREMENT=142 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`hunt_steps\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`hunt_id\` int(10) unsigned NOT NULL,
  \`step_order\` int(11) NOT NULL,
  \`task_type\` enum('gps','photo','qr','text','draw','audio') NOT NULL,
  \`prompt\` text NOT NULL,
  \`target_data\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`target_data\`)),
  \`manual_review\` tinyint(1) DEFAULT 0,
  PRIMARY KEY (\`id\`),
  KEY \`hunt_steps_ibfk_1\` (\`hunt_id\`)
) ENGINE=MyISAM AUTO_INCREMENT=19 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`hunt_submissions\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`user_id\` int(11) NOT NULL,
  \`step_id\` int(10) unsigned NOT NULL,
  \`media_id\` int(10) unsigned DEFAULT NULL,
  \`text_answer\` text DEFAULT NULL,
  \`is_verified\` tinyint(1) DEFAULT 0,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  \`status\` varchar(50) DEFAULT 'pending',
  PRIMARY KEY (\`id\`)
) ENGINE=MyISAM AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`hunts\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`title\` varchar(255) NOT NULL,
  \`description\` text DEFAULT NULL,
  \`is_active\` tinyint(1) DEFAULT 0,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`)
) ENGINE=MyISAM AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`idempotency_keys\` (
  \`idempotency_key\` varchar(255) NOT NULL,
  \`user_id\` int(11) DEFAULT NULL,
  \`request_path\` varchar(255) NOT NULL,
  \`request_method\` varchar(10) NOT NULL,
  \`response_code\` int(11) DEFAULT NULL,
  \`response_body\` longtext DEFAULT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`idempotency_key\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`inventory\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`character_id\` int(10) unsigned NOT NULL,
  \`name\` varchar(190) NOT NULL,
  \`description\` text DEFAULT NULL,
  \`image\` longtext DEFAULT NULL,
  \`researched\` tinyint(1) NOT NULL DEFAULT 0,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`updated_at\` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (\`id\`),
  KEY \`idx_inv_char\` (\`character_id\`),
  CONSTRAINT \`fk_inv_char\` FOREIGN KEY (\`character_id\`) REFERENCES \`characters\` (\`id\`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`inventory_items\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`character_id\` int(11) NOT NULL,
  \`name\` varchar(255) NOT NULL,
  \`item_type\` enum('Relic','Artifact','Blood Magic','Weapon','Armor','Mundane') DEFAULT 'Mundane',
  \`description\` text DEFAULT NULL,
  \`mechanic_notes\` text DEFAULT NULL,
  \`quantity\` int(11) DEFAULT 1,
  \`is_equipped\` tinyint(1) DEFAULT 0,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  \`image\` longtext DEFAULT NULL,
  \`researched\` tinyint(1) DEFAULT 0,
  PRIMARY KEY (\`id\`),
  KEY \`idx_char\` (\`character_id\`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`live_session_broadcasts\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`session_id\` int(10) unsigned NOT NULL,
  \`message\` text NOT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  \`target_character_id\` int(11) DEFAULT NULL,
  PRIMARY KEY (\`id\`),
  KEY \`session_id\` (\`session_id\`),
  CONSTRAINT \`live_session_broadcasts_ibfk_1\` FOREIGN KEY (\`session_id\`) REFERENCES \`live_sessions\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`live_session_participants\` (
  \`session_id\` int(10) unsigned NOT NULL,
  \`user_id\` int(11) NOT NULL,
  \`character_id\` int(11) NOT NULL,
  \`joined_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`session_id\`,\`user_id\`),
  CONSTRAINT \`live_session_participants_ibfk_1\` FOREIGN KEY (\`session_id\`) REFERENCES \`live_sessions\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`live_session_rolls\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`session_id\` int(10) unsigned NOT NULL,
  \`character_id\` int(11) DEFAULT NULL,
  \`roll_type\` varchar(50) DEFAULT NULL,
  \`pool\` int(11) DEFAULT NULL,
  \`hunger\` int(11) DEFAULT NULL,
  \`results\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`results\`)),
  \`successes\` int(11) DEFAULT NULL,
  \`note\` text DEFAULT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  \`is_hidden\` tinyint(1) DEFAULT 0,
  \`character_name\` varchar(255) DEFAULT NULL,
  PRIMARY KEY (\`id\`),
  KEY \`session_id\` (\`session_id\`),
  CONSTRAINT \`live_session_rolls_ibfk_1\` FOREIGN KEY (\`session_id\`) REFERENCES \`live_sessions\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=57 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`live_sessions\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`session_code\` varchar(10) DEFAULT NULL,
  \`name\` varchar(255) NOT NULL,
  \`admin_id\` int(11) NOT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  \`status\` enum('active','ended') DEFAULT 'active',
  \`ended_at\` timestamp NULL DEFAULT NULL,
  \`duration_seconds\` int(11) DEFAULT NULL,
  \`metadata\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`metadata\`)),
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`session_code\` (\`session_code\`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`news_entries\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`author_id\` int(11) NOT NULL,
  \`type\` enum('news','announcement') NOT NULL,
  \`title\` varchar(255) NOT NULL,
  \`subtitle\` varchar(255) DEFAULT NULL,
  \`body\` text NOT NULL,
  \`theme\` varchar(100) DEFAULT NULL,
  \`journalist_name\` varchar(100) DEFAULT NULL,
  \`media_url\` varchar(2048) DEFAULT NULL,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`)
) ENGINE=InnoDB AUTO_INCREMENT=71 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`news_media\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`filename\` varchar(255) DEFAULT NULL,
  \`mime\` varchar(100) NOT NULL,
  \`size\` int(10) unsigned NOT NULL,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`data\` longblob DEFAULT NULL,
  \`data_url\` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (\`id\`)
) ENGINE=InnoDB AUTO_INCREMENT=34 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`npc_email_messages\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`thread_id\` int(11) NOT NULL,
  \`from_side\` enum('user','npc') NOT NULL,
  \`body\` text NOT NULL,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`read_by_user_at\` timestamp NULL DEFAULT NULL,
  \`read_by_admin_at\` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (\`id\`),
  KEY \`idx_thread_created\` (\`thread_id\`,\`created_at\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`npc_email_threads\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`npc_email_id\` int(11) NOT NULL,
  \`user_id\` int(11) NOT NULL,
  \`subject\` varchar(255) NOT NULL DEFAULT '(no subject)',
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`last_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`uq_thread\` (\`npc_email_id\`,\`user_id\`,\`subject\`),
  KEY \`idx_user_last\` (\`user_id\`,\`last_at\`),
  KEY \`idx_npc_last\` (\`npc_email_id\`,\`last_at\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`npc_emails\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`npc_id\` int(11) NOT NULL,
  \`email\` varchar(255) NOT NULL,
  \`label\` varchar(255) DEFAULT NULL,
  \`enabled\` tinyint(1) NOT NULL DEFAULT 1,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`uq_npc_email\` (\`email\`),
  KEY \`idx_npc_id\` (\`npc_id\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`npc_messages\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`npc_id\` int(11) NOT NULL,
  \`user_id\` int(11) NOT NULL,
  \`from_side\` enum('npc','user') NOT NULL,
  \`body\` mediumtext NOT NULL,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`delivered_at\` timestamp NULL DEFAULT NULL,
  \`attachment_id\` int(10) unsigned DEFAULT NULL,
  \`read_at\` timestamp NULL DEFAULT NULL,
  \`edited\` tinyint(1) DEFAULT 0,
  PRIMARY KEY (\`id\`),
  KEY \`idx_npc_id\` (\`npc_id\`),
  KEY \`idx_user_id\` (\`user_id\`),
  KEY \`idx_user_read_at\` (\`user_id\`,\`read_at\`)
) ENGINE=InnoDB AUTO_INCREMENT=1507 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`npcs\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`name\` varchar(120) NOT NULL,
  \`clan\` varchar(64) NOT NULL,
  \`sheet\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`sheet\`)),
  \`xp\` int(11) NOT NULL DEFAULT 10000,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`updated_at\` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  \`camarilla_titles\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`camarilla_titles\`)),
  \`status\` int(11) DEFAULT 1,
  \`image_url\` varchar(2048) DEFAULT NULL,
  \`is_ex\` tinyint(1) DEFAULT 0,
  \`is_deceased\` tinyint(1) DEFAULT 0,
  \`is_hidden\` tinyint(1) DEFAULT 0,
  \`is_left\` tinyint(1) DEFAULT 0,
  \`is_called\` tinyint(1) DEFAULT 0,
  \`is_missing\` tinyint(1) DEFAULT 0,
  \`is_exiled\` tinyint(1) DEFAULT 0,
  \`is_bloodhunted\` tinyint(1) DEFAULT 0,
  \`is_disabled\` tinyint(1) DEFAULT 0,
  \`avatar\` longblob DEFAULT NULL,
  \`avatar_url\` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (\`id\`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`password_resets\` (
  \`id\` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  \`user_id\` bigint(20) unsigned NOT NULL,
  \`token_id\` char(36) NOT NULL,
  \`secret_hash\` varchar(100) NOT NULL,
  \`expires_at\` datetime NOT NULL,
  \`used_at\` datetime DEFAULT NULL,
  \`created_at\` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`token_id\` (\`token_id\`),
  KEY \`user_id\` (\`user_id\`),
  KEY \`expires_at\` (\`expires_at\`)
) ENGINE=InnoDB AUTO_INCREMENT=24 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`portal_settings\` (
  \`key\` varchar(64) NOT NULL,
  \`value\` varchar(255) NOT NULL,
  PRIMARY KEY (\`key\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`premonition_media\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`filename\` varchar(255) DEFAULT NULL,
  \`mime\` varchar(100) NOT NULL,
  \`size\` int(11) NOT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  \`data\` longblob DEFAULT NULL,
  \`data_url\` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (\`id\`)
) ENGINE=InnoDB AUTO_INCREMENT=39 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`premonition_recipients\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`premonition_id\` int(10) unsigned NOT NULL,
  \`user_id\` int(11) NOT NULL,
  \`viewed_at\` timestamp NULL DEFAULT NULL,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`unique_premonition_user\` (\`premonition_id\`,\`user_id\`),
  CONSTRAINT \`fk_premonition_id\` FOREIGN KEY (\`premonition_id\`) REFERENCES \`premonitions\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=52 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`premonition_targets\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`premonition_id\` int(10) unsigned NOT NULL,
  \`user_id\` int(10) unsigned DEFAULT NULL,
  \`all_malkavians\` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (\`id\`),
  KEY \`premonition_targets_pid_idx\` (\`premonition_id\`),
  KEY \`premonition_targets_uid_idx\` (\`user_id\`),
  CONSTRAINT \`premonition_targets_p_fk\` FOREIGN KEY (\`premonition_id\`) REFERENCES \`premonitions\` (\`id\`) ON DELETE CASCADE,
  CONSTRAINT \`premonition_targets_u_fk\` FOREIGN KEY (\`user_id\`) REFERENCES \`users\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`premonitions\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`sender_id\` int(11) NOT NULL,
  \`content_type\` enum('text','image','video') NOT NULL,
  \`content_text\` text DEFAULT NULL,
  \`content_url\` varchar(2048) DEFAULT NULL,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  KEY \`sender_id_idx\` (\`sender_id\`)
) ENGINE=InnoDB AUTO_INCREMENT=35 DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`push_subscriptions\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`user_id\` int(10) unsigned NOT NULL,
  \`subscription_json\` text NOT NULL,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  KEY \`user_id\` (\`user_id\`),
  KEY \`idx_user_id\` (\`user_id\`),
  CONSTRAINT \`push_subscriptions_ibfk_1\` FOREIGN KEY (\`user_id\`) REFERENCES \`users\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3 COLLATE=utf8mb3_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`retainers\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`character_id\` int(10) unsigned NOT NULL,
  \`name\` varchar(255) NOT NULL,
  \`tier\` int(11) DEFAULT 1,
  \`sheet\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`sheet\`)),
  \`xp\` int(11) DEFAULT 0,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  \`avatar\` longblob DEFAULT NULL,
  \`avatar_url\` varchar(2048) DEFAULT NULL,
  \`is_favorite\` tinyint(1) DEFAULT 0,
  PRIMARY KEY (\`id\`),
  KEY \`character_id\` (\`character_id\`),
  CONSTRAINT \`retainers_ibfk_1\` FOREIGN KEY (\`character_id\`) REFERENCES \`characters\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=15 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`rumors\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`author_id\` int(11) NOT NULL,
  \`title\` varchar(255) NOT NULL,
  \`body\` text NOT NULL,
  \`media_url\` varchar(2048) DEFAULT NULL,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`)
) ENGINE=InnoDB AUTO_INCREMENT=69 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`user_news_permissions\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`user_id\` int(11) NOT NULL,
  \`theme\` varchar(255) NOT NULL,
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`uniq_user_theme\` (\`user_id\`,\`theme\`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`user_push_subscriptions\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`user_id\` int(10) unsigned NOT NULL,
  \`endpoint\` varchar(512) NOT NULL,
  \`p256dh\` varchar(255) NOT NULL,
  \`auth\` varchar(255) NOT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`endpoint\` (\`endpoint\`),
  KEY \`user_id\` (\`user_id\`),
  CONSTRAINT \`user_push_subscriptions_ibfk_1\` FOREIGN KEY (\`user_id\`) REFERENCES \`users\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`users\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`email\` varchar(190) NOT NULL,
  \`display_name\` varchar(100) NOT NULL,
  \`password_hash\` varchar(255) NOT NULL,
  \`role\` enum('user','courtuser','admin') NOT NULL DEFAULT 'user',
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  \`discord_id\` varchar(50) DEFAULT NULL,
  \`theme\` varchar(50) DEFAULT 'camarilla',
  \`push_settings\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`push_settings\`)),
  \`ntfy_topic\` varchar(255) DEFAULT NULL,
  \`ntfy_subscribed_npcs\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`ntfy_subscribed_npcs\`)),
  \`ui_sounds_enabled\` tinyint(1) DEFAULT 1,
  \`avatar\` longblob DEFAULT NULL,
  \`avatar_url\` varchar(2048) DEFAULT NULL,
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`email\` (\`email\`),
  KEY \`idx_discord_id\` (\`discord_id\`)
) ENGINE=InnoDB AUTO_INCREMENT=30 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`wiki_admin_notes\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`article_id\` int(11) NOT NULL,
  \`author_id\` int(11) NOT NULL,
  \`content\` longtext DEFAULT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  \`updated_at\` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (\`id\`),
  KEY \`article_id\` (\`article_id\`),
  KEY \`author_id\` (\`author_id\`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`wiki_article_tags\` (
  \`article_id\` int(11) NOT NULL,
  \`tag_id\` int(11) NOT NULL,
  PRIMARY KEY (\`article_id\`,\`tag_id\`),
  KEY \`tag_id\` (\`tag_id\`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`wiki_article_versions\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`article_id\` int(11) NOT NULL,
  \`editor_id\` int(11) NOT NULL,
  \`content\` longtext NOT NULL,
  \`edit_summary\` varchar(500) DEFAULT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  KEY \`article_id\` (\`article_id\`),
  CONSTRAINT \`wiki_article_versions_ibfk_1\` FOREIGN KEY (\`article_id\`) REFERENCES \`wiki_articles\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=90 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`wiki_articles\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`category_id\` int(11) DEFAULT NULL,
  \`author_id\` int(11) NOT NULL,
  \`title\` varchar(255) NOT NULL,
  \`slug\` varchar(255) NOT NULL,
  \`content\` longtext NOT NULL,
  \`status\` enum('draft','published','private') DEFAULT 'draft',
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  \`updated_at\` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`slug\` (\`slug\`),
  KEY \`category_id\` (\`category_id\`),
  KEY \`idx_status\` (\`status\`),
  CONSTRAINT \`wiki_articles_ibfk_1\` FOREIGN KEY (\`category_id\`) REFERENCES \`wiki_categories\` (\`id\`) ON DELETE SET NULL
) ENGINE=InnoDB AUTO_INCREMENT=67 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`wiki_board_items\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`board_id\` int(11) NOT NULL,
  \`user_id\` int(11) NOT NULL,
  \`content\` text NOT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  KEY \`board_id\` (\`board_id\`),
  CONSTRAINT \`wiki_board_items_ibfk_1\` FOREIGN KEY (\`board_id\`) REFERENCES \`wiki_boards\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`wiki_board_members\` (
  \`board_id\` int(11) NOT NULL,
  \`user_id\` int(11) NOT NULL,
  \`role\` enum('viewer','editor') DEFAULT 'viewer',
  PRIMARY KEY (\`board_id\`,\`user_id\`),
  CONSTRAINT \`wiki_board_members_ibfk_1\` FOREIGN KEY (\`board_id\`) REFERENCES \`wiki_boards\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`wiki_boards\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`owner_id\` int(11) NOT NULL,
  \`name\` varchar(255) NOT NULL,
  \`description\` text DEFAULT NULL,
  \`visibility\` enum('private','shared','public','admin_only') DEFAULT 'private',
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`wiki_categories\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`parent_id\` int(11) DEFAULT NULL,
  \`name\` varchar(255) NOT NULL,
  \`slug\` varchar(255) NOT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`slug\` (\`slug\`),
  KEY \`parent_id\` (\`parent_id\`),
  CONSTRAINT \`wiki_categories_ibfk_1\` FOREIGN KEY (\`parent_id\`) REFERENCES \`wiki_categories\` (\`id\`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`wiki_elysium_board_members\` (
  \`board_id\` int(11) NOT NULL,
  \`user_id\` int(11) NOT NULL,
  \`added_at\` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (\`board_id\`,\`user_id\`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`wiki_elysium_boards\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`title\` varchar(255) NOT NULL,
  \`data\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`data\`)),
  \`created_at\` datetime DEFAULT current_timestamp(),
  \`updated_at\` datetime DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  \`visibility\` varchar(50) DEFAULT 'public',
  \`owner_id\` int(11) DEFAULT NULL,
  PRIMARY KEY (\`id\`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`wiki_journal_entries\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`user_id\` int(11) NOT NULL,
  \`title\` varchar(255) NOT NULL DEFAULT 'Untitled Entry',
  \`content\` longtext DEFAULT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  \`updated_at\` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (\`id\`),
  KEY \`user_id\` (\`user_id\`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`wiki_notes\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`article_id\` int(11) DEFAULT NULL,
  \`user_id\` int(11) NOT NULL,
  \`content\` text NOT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  \`updated_at\` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`unique_user_article_note\` (\`user_id\`,\`article_id\`),
  KEY \`article_id\` (\`article_id\`),
  CONSTRAINT \`wiki_notes_ibfk_1\` FOREIGN KEY (\`article_id\`) REFERENCES \`wiki_articles\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`wiki_tags\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`name\` varchar(255) NOT NULL,
  \`slug\` varchar(255) NOT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  UNIQUE KEY \`slug\` (\`slug\`) USING HASH
) ENGINE=MyISAM AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`wiki_timeline_events\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`title\` varchar(255) NOT NULL,
  \`date_label\` varchar(200) NOT NULL,
  \`description\` text DEFAULT NULL,
  \`article_slug\` varchar(255) DEFAULT NULL,
  \`category\` varchar(100) DEFAULT 'General',
  \`sort_order\` int(11) DEFAULT 0,
  \`created_by\` int(11) DEFAULT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  KEY \`created_by\` (\`created_by\`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`xp_log\` (
  \`id\` int(10) unsigned NOT NULL AUTO_INCREMENT,
  \`character_id\` int(10) unsigned NOT NULL,
  \`action\` varchar(80) NOT NULL,
  \`target\` varchar(120) DEFAULT NULL,
  \`from_level\` int(11) DEFAULT NULL,
  \`to_level\` int(11) DEFAULT NULL,
  \`cost\` int(11) NOT NULL,
  \`payload\` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(\`payload\`)),
  \`created_at\` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`),
  KEY \`fk_xp_char\` (\`character_id\`),
  CONSTRAINT \`fk_xp_char\` FOREIGN KEY (\`character_id\`) REFERENCES \`characters\` (\`id\`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=761 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci
    `);

    await pool.query(`
CREATE TABLE IF NOT EXISTS \`xp_logs\` (
  \`id\` int(11) NOT NULL AUTO_INCREMENT,
  \`character_id\` int(11) DEFAULT NULL,
  \`user_id\` int(11) DEFAULT NULL,
  \`amount\` int(11) DEFAULT NULL,
  \`action_type\` varchar(50) DEFAULT NULL,
  \`reason\` text DEFAULT NULL,
  \`created_at\` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (\`id\`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    log.info('Re-enabling foreign key checks...');
    await pool.query('SET FOREIGN_KEY_CHECKS=1;');
    log.ok('All tables synced with live schema.');
  } catch (e) {
    log.err('Failed to init database', { message: e.message });
  }
}

module.exports = { initDatabase };
