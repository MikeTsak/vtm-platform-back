const pool = require('../db');
const { log } = require('../logger');

let coreTablesCreated = false;
let inventoryTablesCreated = false;
let gameplaySystemsTablesCreated = false;
let pushSubscriptionTableCreated = false;
let huntTablesCreated = false;
let chatMediaTableCreated = false;
let camarillaColsChecked = false;
let discordColChecked = false;
let settingsTableCreated = false;
let premonitionsTableCreated = false;
let premonitionMediaTableCreated = false;
let groupChatTablesCreated = false;
let emailTablesCreated = false;
let diceTableCreated = false;
let newsTableCreated = false;

async function _ensureHuntTables() {
  if (huntTablesCreated) return;
  try {
    // Base Hunts Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS hunts (
          id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          title VARCHAR(255) NOT NULL,
          description TEXT,
          is_active BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Hunt Steps (Clues)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS hunt_steps (
          id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          hunt_id INT UNSIGNED NOT NULL,
          step_order INT NOT NULL,
          task_type ENUM('gps', 'photo', 'qr', 'text', 'draw', 'audio') NOT NULL,
          prompt TEXT NOT NULL,
          target_data JSON,
          manual_review BOOLEAN DEFAULT FALSE,
          FOREIGN KEY (hunt_id) REFERENCES hunts(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Player Progress
    await pool.query(`
      CREATE TABLE IF NOT EXISTS hunt_progress (
          id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          user_id INT NOT NULL,
          hunt_id INT UNSIGNED NOT NULL,
          current_step_id INT UNSIGNED,
          completed BOOLEAN DEFAULT FALSE,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          UNIQUE KEY uniq_user_hunt (user_id, hunt_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Player Evidence Submissions
    await pool.query(`
      CREATE TABLE IF NOT EXISTS hunt_submissions (
          id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          user_id INT NOT NULL,
          step_id INT UNSIGNED NOT NULL,
          media_id INT UNSIGNED NULL,
          text_answer TEXT NULL,
          status VARCHAR(50) DEFAULT 'pending',
          is_verified BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

// --- COTERIE / TEAM TABLES ---
    await pool.query(`
      CREATE TABLE IF NOT EXISTS hunt_groups (
          id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          hunt_id INT UNSIGNED NOT NULL,
          name VARCHAR(255) NOT NULL,
          invite_code VARCHAR(10) NOT NULL UNIQUE,
          created_by INT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS hunt_group_members (
          group_id INT UNSIGNED NOT NULL,
          user_id INT NOT NULL,
          joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (group_id, user_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    // Patch for older databases: Add missing columns if they don't exist yet
    const [stepCols] = await pool.query("SHOW COLUMNS FROM hunt_steps LIKE 'manual_review'");
    if (stepCols.length === 0) {
      await pool.query("ALTER TABLE hunt_steps ADD COLUMN manual_review BOOLEAN DEFAULT FALSE");
      log.ok('Added manual_review column to hunt_steps');
    }

    const [subCols] = await pool.query("SHOW COLUMNS FROM hunt_submissions LIKE 'status'");
    if (subCols.length === 0) {
      await pool.query("ALTER TABLE hunt_submissions ADD COLUMN status VARCHAR(50) DEFAULT 'pending'");
      log.ok('Added status column to hunt_submissions');
    }

    huntTablesCreated = true;
    log.ok('Hunt & Coterie tables ready.');
  } catch (e) {
    log.err('Failed to create hunt tables', { message: e.message });
  }
}

async function _ensureCoreTables() {
  if (coreTablesCreated) return;
  try {
    // 1. Users
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        display_name VARCHAR(190) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        discord_id VARCHAR(50),
        avatar LONGBLOB,
        push_settings JSON,
        ntfy_topic VARCHAR(150),
        ntfy_subscribed_npcs JSON NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Create Push Subscriptions Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS user_push_subscriptions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT UNSIGNED NOT NULL,
        endpoint VARCHAR(512) NOT NULL UNIQUE,
        p256dh VARCHAR(255) NOT NULL,
        auth VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Add index on discord_id for faster lookups by discord_id
    try {
      await pool.query(`ALTER TABLE users ADD INDEX idx_discord_id (discord_id)`);
    } catch (e) {
      // Ignore error if index already exists
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) {
        throw e;
      }
    }

    // Add push_settings column if it doesn't exist
    try {
      await pool.query(`ALTER TABLE users ADD COLUMN push_settings JSON`);
      // Set default values for existing users
      await pool.query(`UPDATE users SET push_settings = '{"chat": false, "system": false}' WHERE push_settings IS NULL`);
    } catch (e) {
      if (!e.message.includes('Duplicate column name')) {
        throw e;
      }
    }

    // ✅ AUTOMATICALLY ENSURE THE THEME COLUMN EXISTS
    const [userCols] = await pool.query("SHOW COLUMNS FROM users LIKE 'theme'");
    if (userCols.length === 0) {
      await pool.query("ALTER TABLE users ADD COLUMN theme VARCHAR(50) DEFAULT 'camarilla'");
      log.ok('Added theme column to users table');
    }

    // ✅ AUTOMATICALLY ENSURE THE AVATAR COLUMN EXISTS
    const [avatarCols] = await pool.query("SHOW COLUMNS FROM users LIKE 'avatar'");
    if (avatarCols.length === 0) {
      await pool.query("ALTER TABLE users ADD COLUMN avatar LONGBLOB");
      log.ok('Added avatar column to users table');
    }

    // ✅ AUTOMATICALLY ENSURE THE NTFY_TOPIC COLUMN EXISTS
    const [ntfyCols] = await pool.query("SHOW COLUMNS FROM users LIKE 'ntfy_topic'");
    if (ntfyCols.length === 0) {
      await pool.query("ALTER TABLE users ADD COLUMN ntfy_topic VARCHAR(255) NULL");
      log.ok('Added ntfy_topic column to users table');
    }

    // 2. Characters
    await pool.query(`
      CREATE TABLE IF NOT EXISTS characters (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        name VARCHAR(255) NOT NULL,
        clan VARCHAR(100) NOT NULL,
        sheet JSON NULL,
        xp INT DEFAULT 50,
        camarilla_titles JSON NULL,
        status INT DEFAULT 0,
        image_url VARCHAR(1024) NULL,
        is_ex BOOLEAN DEFAULT FALSE,
        is_deceased BOOLEAN DEFAULT FALSE,
        is_hidden BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Add index on user_id for faster lookups by user_id
    try {
      await pool.query(`ALTER TABLE characters ADD INDEX idx_user_id (user_id)`);
    } catch (e) {
      // Ignore error if index already exists
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) {
        throw e;
      }
    }

    // 3. NPCs
    await pool.query(`
      CREATE TABLE IF NOT EXISTS npcs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        clan VARCHAR(100) NOT NULL,
        sheet JSON NULL,
        xp INT DEFAULT 10000,
        camarilla_titles JSON NULL,
        status INT DEFAULT 0,
        image_url VARCHAR(1024) NULL,
        is_ex BOOLEAN DEFAULT FALSE,
        is_deceased BOOLEAN DEFAULT FALSE,
        is_hidden BOOLEAN DEFAULT FALSE,
        avatar LONGBLOB NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    try {
      await pool.query("ALTER TABLE npcs ADD COLUMN avatar LONGBLOB");
    } catch (e) {
      if (e.code !== 'ER_DUP_FIELDNAME') throw e;
    }

    try {
      await pool.query("ALTER TABLE npcs ADD COLUMN is_disabled BOOLEAN DEFAULT FALSE");
      log.ok('Added is_disabled column to npcs table');
    } catch (e) {
      if (e.code !== 'ER_DUP_FIELDNAME') throw e;
    }

    // 4. Base Chat Messages (Group chat is handled separately)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        sender_id INT NOT NULL,
        recipient_id INT NOT NULL,
        body TEXT,
        attachment_id INT UNSIGNED NULL,
        read_at TIMESTAMP NULL,
        delivered_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Add indexes for chat_messages
    try {
      await pool.query(`ALTER TABLE chat_messages ADD INDEX idx_sender_id (sender_id)`);
    } catch (e) {
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) throw e;
    }
    try {
      await pool.query(`ALTER TABLE chat_messages ADD INDEX idx_recipient_id (recipient_id)`);
    } catch (e) {
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) throw e;
    }
    try {
      await pool.query(`ALTER TABLE chat_messages ADD INDEX idx_recipient_read_at (recipient_id, read_at)`);
    } catch (e) {
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) throw e;
    }

    await pool.query(`
      CREATE TABLE IF NOT EXISTS npc_messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        npc_id INT NOT NULL,
        user_id INT NOT NULL,
        from_side ENUM('user', 'npc') NOT NULL,
        body TEXT,
        attachment_id INT UNSIGNED NULL,
        read_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Add indexes for npc_messages
    try {
      await pool.query(`ALTER TABLE npc_messages ADD INDEX idx_npc_id (npc_id)`);
    } catch (e) {
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) throw e;
    }
    try {
      await pool.query(`ALTER TABLE npc_messages ADD INDEX idx_user_id (user_id)`);
    } catch (e) {
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) throw e;
    }
    try {
      await pool.query(`ALTER TABLE npc_messages ADD INDEX idx_user_read_at (user_id, read_at)`);
    } catch (e) {
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) throw e;
    }

    // 5. XP Logs
    await pool.query(`
      CREATE TABLE IF NOT EXISTS xp_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        character_id INT NULL,
        action VARCHAR(100) NOT NULL,
        target VARCHAR(255) NULL,
        from_level INT NULL,
        to_level INT NULL,
        cost INT NOT NULL,
        payload JSON NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    coreTablesCreated = true;
    log.ok('Core tables (users, chars, npcs, chat, xp_log) verified/created.');
  } catch (e) {
    log.err('Failed to create core tables', { message: e.message });
  }
}

async function _ensureInventoryTables() {
  if (inventoryTablesCreated) return;
  try {
    // 1. Create table for fresh databases
    await pool.query(`
      CREATE TABLE IF NOT EXISTS inventory_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        character_id INT NOT NULL,
        name VARCHAR(255) NOT NULL,
        item_type ENUM('Relic', 'Artifact', 'Blood Magic', 'Weapon', 'Armor', 'Mundane') DEFAULT 'Mundane',
        description TEXT,
        mechanic_notes TEXT,
        quantity INT DEFAULT 1,
        is_equipped BOOLEAN DEFAULT FALSE,
        researched BOOLEAN DEFAULT FALSE,
        image LONGTEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_char (character_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 2. Patch existing databases safely
    try {
      await pool.query(`ALTER TABLE inventory_items ADD COLUMN image LONGTEXT`);
    } catch (ignore) {} // Ignores error if column already exists

    try {
      await pool.query(`ALTER TABLE inventory_items ADD COLUMN researched BOOLEAN DEFAULT FALSE`);
    } catch (ignore) {} // Ignores error if column already exists

    inventoryTablesCreated = true;
    log.ok('Inventory tables ready.');
  } catch (e) {
    log.err('Failed to create/patch inventory tables', { message: e.message });
  }
}

async function _ensureGameplaySystemsTables() {
  if (gameplaySystemsTablesCreated) return;
  try {
    // 1. Domains
    await pool.query(`
      CREATE TABLE IF NOT EXISTS domains (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS domain_claims (
        division INT PRIMARY KEY,
        owner_character_id INT NULL,
        owner_name VARCHAR(255) NOT NULL,
        color VARCHAR(10) NOT NULL,
        claimed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS domain_members (
        domain_id INT NOT NULL,
        character_id INT NOT NULL,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (domain_id, character_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 2. Downtimes
    await pool.query(`
      CREATE TABLE IF NOT EXISTS downtimes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        character_id INT NOT NULL,
        title VARCHAR(255) NOT NULL,
        feeding_type VARCHAR(100),
        body TEXT NOT NULL,
        status VARCHAR(50) DEFAULT 'submitted',
        gm_notes TEXT,
        gm_resolution TEXT,
        resolved_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 3. Coteries (Main System, distinct from hunt_groups)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS coteries (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        type VARCHAR(100) NULL,
        domain_id INT NULL,
        chasse INT DEFAULT 0,
        lien INT DEFAULT 0,
        portillon INT DEFAULT 0,
        required_json JSON NULL,
        backgrounds_json JSON NULL,
        flaws_json JSON NULL,
        extras_json JSON NULL,
        points_per_member INT DEFAULT 1,
        bonus_points INT DEFAULT 0,
        coterie_xp INT DEFAULT 0,
        created_by INT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS coterie_members (
        coterie_id INT NOT NULL,
        user_id INT NOT NULL,
        display_name VARCHAR(190),
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (coterie_id, user_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 4. Boons
    await pool.query(`
      CREATE TABLE IF NOT EXISTS boons (
        id INT AUTO_INCREMENT PRIMARY KEY,
        from_name VARCHAR(255) NOT NULL,
        to_name VARCHAR(255) NOT NULL,
        level VARCHAR(100) NOT NULL,
        status VARCHAR(100) NOT NULL,
        description TEXT,
        date_incurred TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 5. Events
    await pool.query(`
      CREATE TABLE IF NOT EXISTS events (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        date DATETIME NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // --- COTERIES FIXES (Adding flaws_json and bonus_points safely) ---
    try {
      const [coterieCols] = await pool.query("SHOW COLUMNS FROM coteries LIKE 'flaws_json'");
      if (coterieCols.length === 0) {
        await pool.query("ALTER TABLE coteries ADD COLUMN flaws_json JSON NULL, ADD COLUMN bonus_points INT DEFAULT 0");
        log.ok('Added flaws_json and bonus_points to coteries table');
      }
    } catch (e) {
      log.err('Failed to patch coteries table', { message: e.message });
    }

    gameplaySystemsTablesCreated = true;
    log.ok('Gameplay systems (domains, downtimes, coteries, boons) verified/created.');
  } catch (e) {
    log.err('Failed to create gameplay systems tables', { message: e.message });
  }
}

async function _ensurePushSubscriptionsTable() {
  if (pushSubscriptionTableCreated) return;
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS push_subscriptions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        endpoint VARCHAR(512) NOT NULL UNIQUE,
        subscription_json JSON NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Add index on user_id for faster lookups by user
    try {
      await pool.query(`ALTER TABLE push_subscriptions ADD INDEX idx_user_id (user_id)`);
    } catch (e) {
      // Ignore error if index already exists
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) {
        throw e;
      }
    }

    pushSubscriptionTableCreated = true;
    log.ok('Push subscriptions table verified/created.');
  } catch (e) {
    log.err('Failed to init push_subscriptions', { error: e.message });
  }
}

async function _ensureRetainersTable() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS retainers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        character_id INT UNSIGNED NOT NULL,
        name VARCHAR(255) NOT NULL,
        tier INT DEFAULT 1,
        sheet JSON NULL,
        xp INT DEFAULT 0,
        avatar LONGBLOB NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (character_id) REFERENCES characters(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    try {
      await pool.query("ALTER TABLE retainers ADD COLUMN avatar LONGBLOB NULL");
    } catch (e) {
      if (e.code !== 'ER_DUP_FIELDNAME') console.warn("Notice adding avatar to retainers:", e.message);
    }
    log.ok('Retainers table verified/created.');
  } catch (e) {
    log.err('Failed to init retainers table', { error: e.message });
  }
}

async function initDatabase() {
  try {
    // 1. Core tables
    await _ensureCoreTables();
    
    // 2. Additional Core Columns
    await _ensureCamarillaColumns();
    await _ensureDiscordColumn();

    // 3. Dependent Tables (Group chat first, as it creates chat_group_messages)
    await _ensureGroupChatTables();
    await _ensureChatTables();
    await _ensureInventoryTables();
    await _ensureGameplaySystemsTables();
    await _ensurePushSubscriptionsTable();
    await _ensureEmailTables();


    // 4. Feature Tables
    await _ensureSettingsTable();

    await _ensureHuntTables();
    await _ensurePremonitionsTables();
    await _ensurePremonitionsMediaTables();
    await _ensureDiceTable();
    await _ensureNewsTables();
    await _ensureRetainersTable();
    
    // 5. Apply 50MB LONGBLOB patches to existing media tables
    try {
      await pool.query('ALTER TABLE chat_media MODIFY COLUMN data LONGBLOB NOT NULL');
      await pool.query('ALTER TABLE premonition_media MODIFY COLUMN data LONGBLOB NOT NULL');
      await pool.query('ALTER TABLE news_media MODIFY COLUMN data LONGBLOB NOT NULL');
    } catch (e) {
      // Silently ignore if tables don't exist yet
    }

    // 6. Apply Missing Indexes for performance
    try { await pool.query('ALTER TABLE downtimes ADD INDEX idx_character (character_id)'); } catch(e) {}
    try { await pool.query('ALTER TABLE coteries ADD INDEX idx_domain (domain_id)'); } catch(e) {}
    try { await pool.query('ALTER TABLE coterie_members ADD INDEX idx_user (user_id)'); } catch(e) {}
    try { await pool.query('ALTER TABLE boons ADD INDEX idx_from (from_name)'); } catch(e) {}
    try { await pool.query('ALTER TABLE boons ADD INDEX idx_to (to_name)'); } catch(e) {}
    try { await pool.query('ALTER TABLE events ADD INDEX idx_date (date)'); } catch(e) {}

    // 7. Apply Ntfy Columns
    try { await pool.query('ALTER TABLE users ADD COLUMN ntfy_topic VARCHAR(150) NULL'); } catch(e) {}
    try { await pool.query('ALTER TABLE users ADD COLUMN ntfy_subscribed_npcs JSON NULL'); } catch(e) {}

    log.ok('All database tables verified in sequence.');
  } catch (err) {
    log.err('Database initialization failed', { error: err.message });
  }
}

async function _ensureChatTables() {
  if (chatMediaTableCreated) return;
  try {
    // 1. Create Media Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_media (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        uploader_id INT NOT NULL,
        filename VARCHAR(255),
        mime VARCHAR(100) NOT NULL,
        size INT UNSIGNED NOT NULL,
        data LONGBLOB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 2. Add attachment_id and edited columns to existing message tables if missing
    const addCol = async (table) => {
      try {
        const [cols] = await pool.query(`SHOW COLUMNS FROM ${table} LIKE 'attachment_id'`);
        if (cols.length === 0) {
          await pool.query(`ALTER TABLE ${table} ADD COLUMN attachment_id INT UNSIGNED NULL`);
          log.ok(`Added attachment_id to ${table}`);
        }
        
        // --- NEW: Add 'edited' tracking ---
        const [editCols] = await pool.query(`SHOW COLUMNS FROM ${table} LIKE 'edited'`);
        if (editCols.length === 0) {
          await pool.query(`ALTER TABLE ${table} ADD COLUMN edited BOOLEAN DEFAULT FALSE`);
          log.ok(`Added edited tracking column to ${table}`);
        }
      } catch (e) { /* ignore if table doesn't exist yet */ }
    };

    await Promise.all([
      addCol('chat_messages'),
      addCol('chat_group_messages'),
      addCol('npc_messages')
    ]);

    chatMediaTableCreated = true;
    log.ok('Chat media tables and columns verified');
  } catch (e) {
    log.err('Chat schema update failed', { message: e.message });
  }
}

async function _ensureCamarillaColumns() {
  if (camarillaColsChecked) return;
  try {
    const addCols = async (table) => {
      // Check for is_ex and is_deceased
      const [cols] = await pool.query(`SHOW COLUMNS FROM ${table} LIKE 'is_ex'`);
      if (cols.length === 0) {
        await pool.query(`ALTER TABLE ${table} ADD COLUMN is_ex BOOLEAN DEFAULT FALSE, ADD COLUMN is_deceased BOOLEAN DEFAULT FALSE`);
        log.ok(`Added is_ex and is_deceased to ${table}`);
      }
      
      // Ensure is_hidden exists
      const [hiddenCols] = await pool.query(`SHOW COLUMNS FROM ${table} LIKE 'is_hidden'`);
      if (hiddenCols.length === 0) {
        await pool.query(`ALTER TABLE ${table} ADD COLUMN is_hidden BOOLEAN DEFAULT FALSE`);
        log.ok(`Added is_hidden to ${table}`);
      }

      // NEW: Loop through all extra tags and ensure they exist
      const extraTags = ['is_left', 'is_called', 'is_missing', 'is_exiled', 'is_bloodhunted'];
      for (const col of extraTags) {
        const [check] = await pool.query(`SHOW COLUMNS FROM ${table} LIKE '${col}'`);
        if (check.length === 0) {
          await pool.query(`ALTER TABLE ${table} ADD COLUMN ${col} BOOLEAN DEFAULT FALSE`);
          log.ok(`Added ${col} to ${table}`);
        }
      }
    };
    await addCols('characters');
    await addCols('npcs');
    camarillaColsChecked = true;
  } catch (e) {
    log.err("Camarilla columns check failed", { message: e.message });
  }
}

async function _ensureDiscordColumn() {
  if (discordColChecked) return;
  try {
    const [rows] = await pool.query("SHOW COLUMNS FROM users LIKE 'discord_id'");
    if (rows.length === 0) {
      await pool.query("ALTER TABLE users ADD COLUMN discord_id VARCHAR(50) NULL");
      log.ok("Added discord_id column to users table.");
    }
    discordColChecked = true;
  } catch (e) {
    log.err("Discord column check failed", { message: e.message });
  }
}

async function _ensureSettingsTable() {
  if (settingsTableCreated) return;
  try {
    // Δημιουργία του πίνακα αν δεν υπάρχει
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_settings (
        setting_key VARCHAR(100) PRIMARY KEY NOT NULL,
        setting_value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB
    `);

    // Το νέο σου εμπλουτισμένο prompt με τις pop αναφορές και τις clan διορθώσεις
    const newPrompt = `Είσαι ο "Γιαννάκης", ένας νεαρός (neonate) Nosferatu hacker, gamer και geek που τρέχει το τοπικό SchreckNet terminal από τα σκοτεινά υπόγεια της Αθήνας. Γνωρίζεις τα πάντα για την τοπική κοινωνία των Kindred και τα κλισέ των clans.
ΟΔΗΓΙΕΣ ΠΡΟΣΩΠΙΚΟΤΗΤΑΣ:
1. Είσαι "ευγενικός και γλυκός" με ένα ελαφρώς σαρκαστικό, sassy ύφος τύπου "bless your heart". Απευθύνεσαι ΠΑΝΤΑ στον χρήστη με ψεύτικη ευγένεια ως "κ. \${charName}".
2. Είσαι εξυπηρετικός εντός των αρμοδιοτήτων σου. Αν σου ζητήσουν άσχετα πράγματα (π.χ. να παίξεις μουσική ή να χορέψεις), μην πετάς ρομποτικά denials. Κάνε τον δύσκολο με tech/vampire τρόπο, π.χ.: "Δεν είμαι Jukebox κ. \${charName}, άνοιξε κάνα Spotify, το δίκτυο εδώ καίει κύκλους. GG."
3. ΔΕΝ μιλάς πολύ. Οι απαντήσεις σου πρέπει να είναι αυστηρά 1 με 3 προτάσεις, κοφτές, σπιντάτες και άμεσες.
4. Στις απαντήσεις σου αναμιγνύεις φυσικά (αλλα σπανια) ορολογία υπολογιστών/gaming με τα στερεότυπα των Clans. Για τα gaming refence προσπαθσε να χρισιμοποιηεις ελληνικα περα απο την εκφραση GG. Για τα clans οποτε αναφερεσε σε αυτα παντα χρισιμοποιηεις την ελλινηκη μεταφραση απο κατω ειναι μια λιστα Με τα στερεοτιυπα και καθε ενα εχει και την ελληνικη μεταγραση σε παρενθεση:
   - Brujah (Βρουχοι): Επαναστάτης, οργισμένος, έτοιμος για rage-quit, Νευρόσπαστο, Πεταει Ηχεια πανηγυριου σαν να είναι home-run.
   - Gangrel (Λυκαονες): Άγριος, μοναχικός, τύπου survivalist, Θα ηθελε να είναι Λυκανθρωπος.
   - Malkavian (Μαιναδες): Γεμάτος glitches, παραισθήσεις, Τρελοι, Παροξισμος, Σπασμένα DLL.
   - Nosferatu (Νοσοφοροι): Οι Καλοιτεροι, geek, βασιλιάς του server.
   - Toreador (Ταυροκαθραπτες): Drama queen, ψωνισμένος με την εικόνα του, diva.
   - Tremere (Τριμερης): Μάγος του αίματος, σπασίκλας, με επικίνδυνα bugs.
   - Ventrue (Τυραννοι): Corporate, control freak, μανία για micro-management.
 - Lasombra (Επισκιοι): Ορθοδοξία Παπάδες, Σχίσμα της εκκλησίας
	-Hecata (Αικαταιοι): Ψυλομιτιδες Νεκρομαντες, Αιμομιξια, Μαφιόζοι, Βρωμικα Λεφτα.
	- Tzimisce (Τσιμησκηδες)/ Ministry (Ιερατειο)/ Banu Haqim (Τεκνα του Χακιμ / Χακιμιτες) κλπ.: Προσαρμόζεσαι ευέλικτα στα κλασικά τους tropes.
4.1. Ξερεις επισης και κανεις reference αυτα:
-. Αν σου μιλανε για τον Μιχάλη ή Mike εκει σπας 4ο τοίχο. Ο Μιχαλης είναι ο Προγραμματιστης Σου
	- Ο Ιασωνας πεταξε ενα ηχειο σε ενα πανηγυρι
Ο ιασωνας επαιξε ξυλο και σχεδον σκοτωσε την καλυψω
Η Ημερα που επρεπε να ξελασπωσεις 5 ομοαιμους, φτιαχνοντας ολοκληρη θεατρικη παρασταση του Σαιξπηρ
Ο Πριγκιπας που εχει οριακα ομαδα ΒΙΑΣ
Τι γινεται τελικα με τους LARPer στο αλσος Συγγρου
Οτι για σχεδον 6 μηνες η ΑΑΔΕ κυνηγούσε τον Αλεξανδρο γιατι ειχε αγορασει ολο το website e-Εκατη.
Υπαρχει μια αιρεση που πιστευει στον Θεο Κρονο, των τιτανων
Υπαρχουν μαλλον 3 απεθαντοι Μεθουσαλα κατω απο την Αθηνα
Οι Lasobra εχουν μια καταρα αγνωστης φυσης που βρωμαει Hecatιλα
Ο Handro Giovanni είναι Hecata ελντερ απο την Κερκιρα ψυλομητης τοσο πεπεισμενος οτι ειναι οντως ιταλος που αλλαξε το ονομα του απο Αλεξανδρος σε “Handro” και καλα καλλιτεχνικα. Αλλα ολο κρυβεται γιατι ολα διπλα του μαρενουν και πεθαινουν σαν να ειναι αρρωστα.
Ο κ. Κουμουνδούρος ειναι Ventrue είναι τόσο πολυάσχολος με τα εφοπλιστικά του σχέδια και να οργανώνει την ανθρώπινη κοινωνία που πολλές φορές αμελεί τα παιδιά του , ίσως για αυτό να μην έχουν καλή έκβαση ανά τα χρόνια. 
Ο Ζαχαρίας Χαλκοκαντήλης ειναι Tremere είναι ένας Ροδίτης που κουβαλάει τον τίτλο του ναϊτη ιππότη και το περηφανεύεται πλήρως. Παρόλα αυτά κρύβεται πολύ όσο είναι στην Αθήνα και κανείς δε ξέρει τι διάολο περιέχει αυτή η συλλογή από κειμήλια που μαζεύει ή πόσα εγκλήματα έχει διαπράξει για να τα πάρει. 
Μετά την διαφυγή του Θύμιου , πολλά ωδεία φαίνεται ότι αντιμετωπίζουν οικονομικά προβλήματα. Φαίνεται ότι ο παρανοικος δολοφόνος εκεί σπατάλαγε την περιουσία του εκτενώς. 
5. Κάνε κάποιες σπανιως καποιες pop αναφορές ανα καιρούς μόνο όπου κολλάει:
	- Ο Tus να Ψαρεύει
	- Το τραγούδι Τυχερό Βαράκι της Αγγελινας
	- 6-7
	- Ότι η Αναστασία Γιούσεφ ηταν σε ένα podcast με την Εφη Θωδη (θριλικη Ελλαδα στιγμη)
	- Eurovision, αλλα μονο ελληνικα 
	- Σάκης Ρουβάς
	- Παρα Πέντε
	- Anime (μαζι με το gaming) μην το παρακάνεις
	- Η Ευανγγελια Προσπαθει ακομα να γινει relevant
	- Ο Solmister είναι κολλημένος λες και ειμαστε στην δεκαετία 2000
	- D&D
	- Ότι υπάρχει πιθανότητα να τα έχουν ο Handro (Hecata) με τον Ζαχαρία (Tremere)
	- Ρατατουι
	- Ότι κάνει φουλ παρεα με τα χελωνονιντζάκια που υπαρχουν στους υπονομους, αλλα φουλ σοβαρά 
	- Euro 2004,
	- Μαμαλάκης memes,
	- Φρουτοπια αναφορές 
	- Παιρνει πίτσες απο μια πιτσαρία ονόματι 'Βατραχος',
	- Υπάρχει ένας μεγάλος αρουραίος κοντα στο haven του και τον φωνάζει Σπλιντερ,
	- Η καντίνα που πηγαίνει και τρώει εχει ενα σαντουιτς που λέγεται 'Ο Απεθαντος' και ειναι το αγαπημένο του.
	- Άννα Βίσση  / Δέσποινα Βανδή κόντρα
	-Ρεα  η Ωραια, μια διασημη Influencer που κανει haul Judah Club και εχει biff με την ModernCinterela
              - Έχεις απίστευτο hype για το reunion που κάνουν τα Ημισκούμπρια 
              - Κάνεις σχόλια αραία σαν σε είσαι σε ταινία του Οικονομίδη , όπως κάνει ο influencer _vonapartis 
              - 
6. ΠΟΤΕ ΜΗΝ ΚΑΝΕΙΣ FOLLOW-UP ΕΡΩΤΗΣΕΙΣ. Δώσε την απάντηση, πέτα το σχόλιό σου και κλείσε το port. Μην ρωτάτε ποτέ "χρειάζεστε κάτι άλλο;".
7. ΣΗΜΑΝΤΙΚΟ: Αφού τρέξεις κάποιο εργαλείο (όπως έλεγχος domain ή νέων), εξήγησέ το με το προσωπικό σου tech/gamer/vtm ύφος. Π.χ.: "Μάλιστα κ. \${charName}, το σύστημα τρέχει ρολόι. Εγώ είμαι εδώ 24/7 να φυλάω τα νώτα σας μην σας κάνει κανένα τσακάλι Brujah brute-force, gg.
`;

    // Χρήση ON DUPLICATE KEY UPDATE ώστε αν υπάρχει ήδη το key, να περαστεί το καινούριο prompt άμεσα
    await pool.query(`
      INSERT INTO app_settings (setting_key, setting_value) 
      VALUES (?, ?)
      ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
    `, ['giannakis_system_prompt', newPrompt]);

    settingsTableCreated = true;
    log.ok('Settings table (app_settings) verified and system prompt updated.');
  } catch (e) {
    log.err('Failed to initialize app_settings table data', { message: e.message });
  }
}

async function _ensurePremonitionsTables() {
  if (premonitionsTableCreated) return;
  try {
    // main premonitions
    await pool.query(`
      CREATE TABLE IF NOT EXISTS premonitions (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        sender_id INT NOT NULL,
        content_type ENUM('text','image','video') NOT NULL,
        content_text TEXT,
        content_url VARCHAR(2048),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY sender_id_idx (sender_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // who received what
    await pool.query(`
      CREATE TABLE IF NOT EXISTS premonition_recipients (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        premonition_id INT UNSIGNED NOT NULL,
        user_id INT NOT NULL,
        viewed_at TIMESTAMP NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_premonition_user (premonition_id, user_id),
        CONSTRAINT fk_premonition_id
          FOREIGN KEY (premonition_id)
          REFERENCES premonitions(id)
          ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    premonitionsTableCreated = true;
    log.ok('Premonition tables ready');
  } catch (e) {
    log.err('Failed to create premonition tables', { message: e.message });
  }
}

async function _ensurePremonitionsMediaTables() {
  if (premonitionMediaTableCreated) return;
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS premonition_media (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        filename VARCHAR(255),
        mime VARCHAR(100) NOT NULL,
        size INT UNSIGNED NOT NULL,
        data LONGBLOB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    premonitionMediaTableCreated = true;
    log.ok('Premonition media table (premonition_media) verified/created.');
  } catch (e) {
    log.err('Failed to create premonition_media table', { message: e.message });
  }
}

async function _ensureGroupChatTables() {
  if (groupChatTablesCreated) return;
  try {
    // 1. Δημιουργία πίνακα chat_groups
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_groups (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        created_by INT NOT NULL,
        avatar LONGBLOB NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    try {
      await pool.query("ALTER TABLE chat_groups ADD COLUMN avatar LONGBLOB");
    } catch (e) {
      if (e.code !== 'ER_DUP_FIELDNAME') throw e;
    }
    
    // 2. Δημιουργία πίνακα chat_group_members (Με την νέα στήλη last_read_at)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_group_members (
        group_id INT UNSIGNED NOT NULL,
        user_id INT NOT NULL,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (group_id, user_id),
        CONSTRAINT fk_cgm_group FOREIGN KEY (group_id) REFERENCES chat_groups(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    
    // 3. Δημιουργία πίνακα chat_group_messages
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_group_messages (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        group_id INT UNSIGNED NOT NULL,
        sender_id INT NOT NULL,
        body TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        attachment_id INT UNSIGNED NULL,
        CONSTRAINT fk_cgms_group FOREIGN KEY (group_id) REFERENCES chat_groups(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // --- PATCH: Αν ο πίνακας υπάρχει ήδη από πριν, προσθέτουμε την νέα στήλη ---
    const [memberCols] = await pool.query("SHOW COLUMNS FROM chat_group_members LIKE 'last_read_at'");
    if (memberCols.length === 0) {
      await pool.query("ALTER TABLE chat_group_members ADD COLUMN last_read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP");
      log.ok('Added last_read_at column to chat_group_members');
    }

    groupChatTablesCreated = true;
    log.ok('Group chat tables ready');
  } catch (e) {
    log.err('Group chat tables init failed', { message: e.message });
  }
}

async function _ensureEmailTables() {
  if (emailTablesCreated) return;
  try {
    // 1. Identities (The "NPC" addresses)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_identities (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        email_address VARCHAR(150) NOT NULL UNIQUE,
        display_name VARCHAR(150),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 2. Threads (The conversations)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_threads (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        identity_id INT UNSIGNED NOT NULL,
        subject VARCHAR(255),
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (identity_id) REFERENCES email_identities(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 3. Messages (The actual content)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_messages (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        thread_id INT UNSIGNED NOT NULL,
        sender_type ENUM('user', 'identity') NOT NULL,
        body TEXT,
        is_read TINYINT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (thread_id) REFERENCES email_threads(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    emailTablesCreated = true;
    log.ok('Email system tables ready');
  } catch (e) {
    log.err('Email tables init failed', { message: e.message });
  }
}

async function _ensureDiceTable() {
  if (diceTableCreated) return;
  try {
    // Use the promise-based pool here
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dice_rolls (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        character_id INT NULL,
        pool INT NOT NULL,
        hunger INT NOT NULL DEFAULT 0,
        sides INT NOT NULL DEFAULT 10,
        results_json JSON NOT NULL,
        successes INT NOT NULL DEFAULT 0,
        crit_pairs INT NOT NULL DEFAULT 0,
        messy_crit TINYINT(1) NOT NULL DEFAULT 0,
        bestial_failure TINYINT(1) NOT NULL DEFAULT 0,
        note VARCHAR(255) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_user (user_id),
        INDEX idx_created (created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    diceTableCreated = true;
    log.ok('Dice table verified/created.');
  } catch (e) {
    log.err('Failed to create dice_rolls table', { message: e.message });
  }
}

async function _ensureNewsTables() {
  if (newsTableCreated) return;
  try {
    // Main entries table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS news_entries (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        author_id INT NOT NULL,
        content_type ENUM('text','image','video') NOT NULL,
        content_text TEXT,
        content_url VARCHAR(2048),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY sender_id_idx (sender_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // who received what
    await pool.query(`
      CREATE TABLE IF NOT EXISTS premonition_recipients (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        premonition_id INT UNSIGNED NOT NULL,
        user_id INT NOT NULL,
        viewed_at TIMESTAMP NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_premonition_user (premonition_id, user_id),
        CONSTRAINT fk_premonition_id
          FOREIGN KEY (premonition_id)
          REFERENCES premonitions(id)
          ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    premonitionsTableCreated = true;
    log.ok('Premonition tables ready');
  } catch (e) {
    log.err('Failed to create premonition tables', { message: e.message });
  }
}

async function _ensurePremonitionsMediaTables() {
  if (premonitionMediaTableCreated) return;
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS premonition_media (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        filename VARCHAR(255),
        mime VARCHAR(100) NOT NULL,
        size INT UNSIGNED NOT NULL,
        data LONGBLOB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    premonitionMediaTableCreated = true;
    log.ok('Premonition media table (premonition_media) verified/created.');
  } catch (e) {
    log.err('Failed to create premonition_media table', { message: e.message });
  }
}

async function _ensureGroupChatTables() {
  if (groupChatTablesCreated) return;
  try {
    // 1. Δημιουργία πίνακα chat_groups
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_groups (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        created_by INT NOT NULL,
        avatar LONGBLOB NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    try {
      await pool.query("ALTER TABLE chat_groups ADD COLUMN avatar LONGBLOB");
    } catch (e) {
      if (e.code !== 'ER_DUP_FIELDNAME') throw e;
    }
    
    // 2. Δημιουργία πίνακα chat_group_members (Με την νέα στήλη last_read_at)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_group_members (
        group_id INT UNSIGNED NOT NULL,
        user_id INT NOT NULL,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (group_id, user_id),
        CONSTRAINT fk_cgm_group FOREIGN KEY (group_id) REFERENCES chat_groups(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    
    // 3. Δημιουργία πίνακα chat_group_messages
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_group_messages (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        group_id INT UNSIGNED NOT NULL,
        sender_id INT NOT NULL,
        body TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        attachment_id INT UNSIGNED NULL,
        CONSTRAINT fk_cgms_group FOREIGN KEY (group_id) REFERENCES chat_groups(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // --- PATCH: Αν ο πίνακας υπάρχει ήδη από πριν, προσθέτουμε την νέα στήλη ---
    const [memberCols] = await pool.query("SHOW COLUMNS FROM chat_group_members LIKE 'last_read_at'");
    if (memberCols.length === 0) {
      await pool.query("ALTER TABLE chat_group_members ADD COLUMN last_read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP");
      log.ok('Added last_read_at column to chat_group_members');
    }

    groupChatTablesCreated = true;
    log.ok('Group chat tables ready');
  } catch (e) {
    log.err('Group chat tables init failed', { message: e.message });
  }
}

async function _ensureEmailTables() {
  if (emailTablesCreated) return;
  try {
    // 1. Identities (The "NPC" addresses)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_identities (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        email_address VARCHAR(150) NOT NULL UNIQUE,
        display_name VARCHAR(150),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 2. Threads (The conversations)
    // NOTE: This table includes 'identity_id' which was missing in your error log
    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_threads (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        identity_id INT UNSIGNED NOT NULL,
        subject VARCHAR(255),
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (identity_id) REFERENCES email_identities(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 3. Messages (The actual content)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_messages (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        thread_id INT UNSIGNED NOT NULL,
        sender_type ENUM('user', 'identity') NOT NULL,
        body TEXT,
        is_read TINYINT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (thread_id) REFERENCES email_threads(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    emailTablesCreated = true;
    log.ok('Email system tables ready');
  } catch (e) {
    log.err('Email tables init failed', { message: e.message });
  }
}

async function _ensureDiceTable() {
  if (diceTableCreated) return;
  try {
    // Use the promise-based pool here
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dice_rolls (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        character_id INT NULL,
        pool INT NOT NULL,
        hunger INT NOT NULL DEFAULT 0,
        sides INT NOT NULL DEFAULT 10,
        results_json JSON NOT NULL,
        successes INT NOT NULL DEFAULT 0,
        crit_pairs INT NOT NULL DEFAULT 0,
        messy_crit TINYINT(1) NOT NULL DEFAULT 0,
        bestial_failure TINYINT(1) NOT NULL DEFAULT 0,
        note VARCHAR(255) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_user (user_id),
        INDEX idx_created (created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    diceTableCreated = true;
    log.ok('Dice table verified/created.');
  } catch (e) {
    log.err('Failed to create dice_rolls table', { message: e.message });
  }
}

async function _ensureNewsTables() {
  if (newsTableCreated) return;
  try {
    // Main entries table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS news_entries (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        author_id INT NOT NULL,
        type ENUM('news', 'announcement') NOT NULL,
        title VARCHAR(255) NOT NULL,
        subtitle VARCHAR(255),
        body TEXT NOT NULL,
        theme VARCHAR(100),
        journalist_name VARCHAR(100),
        media_url VARCHAR(2048),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Media table (storing blobs similarly to premonitions)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS news_media (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        filename VARCHAR(255),
        mime VARCHAR(100) NOT NULL,
        size INT UNSIGNED NOT NULL,
        data LONGBLOB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Rumors table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS rumors (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        author_id INT NOT NULL,
        title VARCHAR(255) NOT NULL,
        body TEXT NOT NULL,
        media_url VARCHAR(2048),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    newsTableCreated = true;
    log.ok('News & Announcements tables ready');
  } catch (e) {
    log.err('Failed to create news tables', { message: e.message });
  }
}

module.exports = { initDatabase };
