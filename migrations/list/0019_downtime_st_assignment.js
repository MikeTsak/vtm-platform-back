// back/migrations/list/0019_downtime_st_assignment.js
// Expands downtime status from ENUM to VARCHAR(60) to support Storyteller-assigned
// approval statuses (such as 'Approved: Kikos' and 'Approved: Mike') seamlessly.

module.exports = {
  name: '0019_downtime_st_assignment',
  async up(pool) {
    await pool.query(`
      ALTER TABLE \`downtimes\`
      MODIFY COLUMN \`status\` VARCHAR(60) NOT NULL DEFAULT 'submitted'
    `);
  },
};
