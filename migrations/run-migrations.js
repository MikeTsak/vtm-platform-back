const pool = require('../db');
const { log } = require('../logger');

async function runMigrations() {
  log.start('Starting database migrations...');
  
  try {
    // 1. Password Resets
    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_resets (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        token_id VARCHAR(255) NOT NULL,
        secret_hash VARCHAR(255) NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_token (token_id),
        CONSTRAINT fk_reset_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    log.ok('Password resets table verified/created.');

    // 2. Live Sessions
    await pool.query(`
      CREATE TABLE IF NOT EXISTS live_sessions (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        admin_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Schema Patch: Add Session Code, Status, and Timers
    const [lsCols] = await pool.query("SHOW COLUMNS FROM live_sessions LIKE 'session_code'");
    if (lsCols.length === 0) {
      await pool.query(`
        ALTER TABLE live_sessions 
        ADD COLUMN session_code VARCHAR(10) UNIQUE AFTER id,
        ADD COLUMN status ENUM('active', 'ended') DEFAULT 'active',
        ADD COLUMN ended_at TIMESTAMP NULL,
        ADD COLUMN duration_seconds INT NULL
      `);
      log.ok('Added 8-character code, status, and duration tracking to live_sessions');
    }

    await pool.query(`
      CREATE TABLE IF NOT EXISTS live_session_participants (
        session_id INT UNSIGNED NOT NULL,
        user_id INT NOT NULL,
        character_id INT NOT NULL,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (session_id, user_id),
        FOREIGN KEY (session_id) REFERENCES live_sessions(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS live_session_rolls (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        session_id INT UNSIGNED NOT NULL,
        character_id INT NULL,
        character_name VARCHAR(255) NULL,
        roll_type VARCHAR(50),
        pool INT,
        hunger INT,
        results JSON,
        successes INT,
        note TEXT,
        is_hidden BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (session_id) REFERENCES live_sessions(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS live_session_broadcasts (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        session_id INT UNSIGNED NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (session_id) REFERENCES live_sessions(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    log.ok('Live Session tables verified/patched.');

    // 3. User Push Settings
    try {
      await pool.query(`ALTER TABLE users ADD COLUMN push_settings JSON`);
      await pool.query(`UPDATE users SET push_settings = '{"chat": false, "system": false}' WHERE push_settings IS NULL`);
      log.info("Added push_settings column");
    } catch (e) {
      if (!e.message.includes('Duplicate column name')) log.err("Error adding column:", { message: e.message });
    }

    // 4. Domain Safety Rating
    try {
      await pool.query(`ALTER TABLE domains ADD COLUMN safety_rating INT DEFAULT 10`);
      log.info("Added safety_rating to domains");
    } catch (e) {
      if (!e.message.includes('Duplicate column')) log.err("Error adding safety_rating:", { message: e.message });
    }

    // 5. Domain Problems
    await pool.query(`
      CREATE TABLE IF NOT EXISTS domain_problems (
        id INT AUTO_INCREMENT PRIMARY KEY,
        domain_id INT NOT NULL,
        problem_text VARCHAR(255) NOT NULL,
        is_custom BOOLEAN DEFAULT FALSE,
        resolved BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 6. Admin Audit Logs
    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin_audit_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id INT NOT NULL,
        action VARCHAR(100) NOT NULL,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 7. App Settings
    try {
      await pool.query(`INSERT INTO app_settings (setting_key, setting_value) VALUES ('masquerade_threat_level', '1') ON DUPLICATE KEY UPDATE setting_key=setting_key`);
    } catch(e) {}

    // 8. Push Subscriptions
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
    log.info("Push subscriptions table verified.");

    log.ok('All migrations completed successfully.');
  } catch (err) {
    log.err('Migration failed:', { error: err.message });
    process.exit(1);
  } finally {
    process.exit(0);
  }
}

runMigrations();
