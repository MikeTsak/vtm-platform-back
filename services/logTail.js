// services/logTail.js
//
// Reads the last N lines of a log file. Only the end of the file is read: the
// admin Logs page asks often, and streaming the whole file was slow under the
// host's 6 MB/s IO cap.

const fs = require('fs');

const MAX_LINE_BYTES = 4096; // a line with a stack trace; shorter lines just mean more of them fit

async function tailFile(filePath, maxLines = 200) {
  let fh;
  try {
    fh = await fs.promises.open(filePath, 'r');
  } catch (e) {
    if (e.code === 'ENOENT') return [];
    throw e;
  }
  try {
    const { size } = await fh.stat();
    const length = Math.min(size, maxLines * MAX_LINE_BYTES);
    const { buffer, bytesRead } = await fh.read(Buffer.alloc(length), 0, length, size - length);
    const lines = buffer.toString('utf8', 0, bytesRead).split(/\r?\n/);
    if (length < size) lines.shift(); // started mid-line
    if (lines[lines.length - 1] === '') lines.pop();
    return lines.slice(-maxLines);
  } finally {
    await fh.close();
  }
}

module.exports = { tailFile };
