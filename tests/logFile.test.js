// logger.js file sink + services/logTail.js. Production used to log to stdout
// only, so LOG_FILE (the admin Logs page) stayed empty from 2026-07-21 on.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { tailFile } = require('../services/logTail');

const back = path.join(__dirname, '..');
const logIn = (file, script) => execFileSync(process.execPath, ['-e', `const { log } = require('./logger'); ${script}`], {
  cwd: back, env: { ...process.env, NODE_ENV: 'production', LOG_FILE: file, LOG_LEVEL: 'info' }, stdio: 'ignore',
});

describe('log file', () => {
  let dir;
  beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), 'logfile-')); });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('production writes JSON lines the admin Logs page reads', async () => {
    const file = path.join(dir, 'app.log');
    logIn(file, "log.err('Boom', { status: 500, level: 'spoof' }); log.info('plain', 'a string ctx');");
    const [err, info] = (await tailFile(file, 10)).map((l) => JSON.parse(l));
    expect(err).toMatchObject({ level: 'error', cat: 'err', msg: 'Boom', status: 500 });
    expect(err.pid).toEqual(expect.any(Number));
    expect(info).toMatchObject({ level: 'info', msg: 'plain', detail: 'a string ctx' });
  });

  it('a full file is rotated to .1 on boot', () => {
    const file = path.join(dir, 'app.log');
    fs.writeFileSync(file, '');
    fs.truncateSync(file, 21 * 1024 * 1024); // sparse, instant
    logIn(file, "log.info('after rotation');");
    expect(fs.statSync(`${file}.1`).size).toBe(21 * 1024 * 1024);
    expect(fs.readFileSync(file, 'utf8')).toContain('after rotation');
  });

  it('tailFile reads only the end and never returns a cut-off first line', async () => {
    const file = path.join(dir, 'big.log');
    fs.writeFileSync(file, Array.from({ length: 5000 }, (_, i) => `line ${i} ${'x'.repeat(3000)}`).join('\n') + '\n');
    const last = await tailFile(file, 3);
    expect(last.map((l) => l.split(' ')[1])).toEqual(['4997', '4998', '4999']);
    const many = await tailFile(file, 1000);
    expect(many.every((l) => /^line \d+ x+$/.test(l))).toBe(true);
    expect(many[many.length - 1].startsWith('line 4999 ')).toBe(true);
    expect(await tailFile(path.join(dir, 'missing.log'))).toEqual([]);
  });
});
