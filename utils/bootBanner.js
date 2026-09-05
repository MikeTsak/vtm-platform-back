// utils/bootBanner.js
//
// Startup used to print an ASCII-art banner plus one console.log per plugin
// as it finished registering ("Finished loading plugin 7", "...8", etc.) —
// a wall of scrolling lines with no summary at the end. This replaces both
// with: a single progress line that updates in place while plugins load,
// then one clean summary once the server is actually listening.
const colors = require('colors/safe');

const isTTY = !!process.stdout.isTTY;
const barWidth = 24;

let total = 0;
let loaded = 0;

function renderProgress(name) {
  const filled = Math.round((loaded / total) * barWidth);
  const bar = '█'.repeat(filled) + '░'.repeat(barWidth - filled);
  const line = `  booting [${bar}] ${loaded}/${total} ${name}`;
  if (isTTY) {
    // \r + clear-to-end-of-line overwrites the previous line instead of
    // scrolling — the "loading bar" effect. Non-TTY sinks (a Plesk log
    // file, `| tee`, etc.) can't usefully render \r overwrites, so those
    // fall back to one line per step instead.
    process.stdout.write(`\r\x1b[K${colors.gray(line)}`);
  } else {
    process.stdout.write(line + '\n');
  }
}

// Call once, before registering any plugins, with the full ordered list of
// plugin names you're about to register — needed up front so the progress
// bar knows the total instead of guessing.
function startBootProgress(pluginNames) {
  total = pluginNames.length;
  loaded = 0;
}

// Call from each plugin's fastify.after(() => pluginLoaded('name')).
function pluginLoaded(name) {
  loaded++;
  renderProgress(name);
  if (loaded === total && isTTY) process.stdout.write('\n');
}

// Call once, after fastify.listen() succeeds, with everything worth knowing
// about this boot. Replaces the old ASCII-art banner.
function printReadyBanner({ address, env, nodeVersion, bootMs }) {
  const rows = [
    ['Node', nodeVersion],
    ['Address', address],
    ['Env', env],
    ['Plugins', `${loaded}/${total} loaded`],
    ['Boot time', `${bootMs}ms`],
  ];
  const labelWidth = Math.max(...rows.map(([k]) => k.length));
  const rule = '─'.repeat(44);

  console.log(colors.red(rule));
  console.log(`🦇  Erebus Portal API — ${colors.green('ready')}`);
  console.log(colors.red(rule));
  for (const [k, v] of rows) {
    console.log(`  ${colors.gray(k.padEnd(labelWidth))}   ${v}`);
  }
  console.log(colors.red(rule));
}

module.exports = { startBootProgress, pluginLoaded, printReadyBanner };
