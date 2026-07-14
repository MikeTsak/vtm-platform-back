const pool = require('../db');
const { log } = require('../logger');

const settingsCache = new Map();

/**
 * Get a value from the app_settings table with in-memory caching
 * @param {string} key - The setting_key
 * @param {any} [defaultValue=null] - Value to return if key not found
 */
async function getSetting(key, defaultValue = null) {
  if (settingsCache.has(key)) {
    // log.info(`⚡ [cache hit] ${key}`); // Uncomment for extreme debugging
    return settingsCache.get(key);
  }

  try {
    const [[row]] = await pool.query(
      'SELECT setting_value FROM app_settings WHERE setting_key = ?',
      [key]
    );
    const value = row ? row.setting_value : defaultValue;
    if (row) {
      log.info(`💾 [cache miss] Fetched ${key} from DB and caching it.`);
      settingsCache.set(key, value); // Only cache if it exists in DB
    }
    return value;
  } catch (e) {
    log.err('getSetting failed', { key, message: e.message });
    return defaultValue;
  }
}

/**
 * Set a value in the app_settings table and update cache
 * @param {string} key - The setting_key
 * @param {string|null} value - The value to set
 */
async function setSetting(key, value) {
  try {
    await pool.query(
      `INSERT INTO app_settings (setting_key, setting_value)
       VALUES (?, ?)
       ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)`,
      [key, value]
    );
    settingsCache.set(key, value);
    return true;
  } catch (e) {
    log.err('setSetting failed', { key, message: e.message });
    return false;
  }
}

/**
 * Clear a specific key or all keys from the cache
 */
function clearSettingCache(key = null) {
  if (key) {
    settingsCache.delete(key);
  } else {
    settingsCache.clear();
  }
}

module.exports = {
  getSetting,
  setSetting,
  clearSettingCache
};
