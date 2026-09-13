module.exports = {
  name: '0018_feeding_outcome_herd',
  async up(pool) {
    await pool.query(`
      ALTER TABLE feedings
      MODIFY COLUMN outcome ENUM('bestial_failure','failure','success','critical','messy_critical','herd') DEFAULT NULL
    `);
  },
};
