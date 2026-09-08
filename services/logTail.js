// services/logTail.js
//
// Reads the last N lines of a log file without loading the whole thing into
// memory — the log files on the production box get large.

const fs = require('fs');
const readline = require('readline');

async function tailFile(filePath, maxLines = 200) {
  // fallback if file missing
  if (!fs.existsSync(filePath)) return [];

  return new Promise((resolve, reject) => {
    const input = fs.createReadStream(filePath, { encoding: 'utf8' });
    const rl = readline.createInterface({ input, crlfDelay: Infinity });
    const buf = [];
    rl.on('line', (line) => {
      buf.push(line);
      if (buf.length > maxLines) buf.shift();
    });
    rl.on('close', () => resolve(buf));
    rl.on('error', (err) => reject(err));
  });
}

module.exports = { tailFile };
