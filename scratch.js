require('dotenv').config();
const pool = require('./db');

async function main() {
  try {
    const [users] = await pool.query('SELECT id, email, role, discord_id, push_settings FROM users WHERE id = 6 OR email = "an.margaronis@gmail.com"');
    console.log('User:', users[0]);
    if (users.length > 0) {
      const [char] = await pool.query('SELECT id, name, clan FROM characters WHERE user_id = ?', [users[0].id]);
      console.log('Character:', char[0]);
    }
  } catch (e) {
    console.error(e);
  }
  process.exit(0);
}
main();
