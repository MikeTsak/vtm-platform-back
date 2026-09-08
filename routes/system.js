// routes/system.js
//
// Liveness/health probes and the human-readable "/" status page.
// No game state here — safe to hit from uptime monitors.
const os = require('os');
const fs = require('fs');
const path = require('path');
const { getSetting } = require('../utils/settings');
const { formatDate } = require('../services/format');
const { DEFAULT_CORS_ORIGINS } = require('../config/cors');

// This module lives in routes/, but the files it reads (views/, package.json)
// sit at the application root.
const APP_ROOT = path.join(__dirname, '..');

module.exports = async function (fastify, opts) {
  const { pool } = opts;

  // --- Simple status/health ---

  // Optional: capture server start time
  const startedAt = new Date();


  // JSON health probe (good for uptime checks / Kubernetes / monitors)
  fastify.get('/api/health', async (req, reply) => {
    try {
      // Quick DB ping (remove if you don't want DB coupled to health)
      const [rows] = await pool.query('SELECT 1 AS ok');
      const dbOk = rows?.[0]?.ok === 1;

      reply.header('Cache-Control', 'no-store');
      return reply.send({
        ok: true,
        db: dbOk,
        env: process.env.NODE_ENV || 'stable',
        uptime_sec: Math.floor(process.uptime()),
        started_at: startedAt.toISOString(),
        now: new Date().toISOString(),
      });
    } catch (e) {
      return reply.status(500).json({
        ok: false,
        db: false,
        error: e.message,
        now: new Date().toISOString(),
      });
    }
  });

  fastify.get('/api/debug/db-check', async (req, reply) => {
    try {
      const [hunts] = await pool.query('SELECT id, title, is_active, created_at FROM hunts ORDER BY created_at DESC LIMIT 10');
      const [steps] = await pool.query('SELECT id, hunt_id, step_order, task_type, prompt FROM hunt_steps ORDER BY id DESC LIMIT 10');
      reply.send({
        ok: true,
        env: process.env.NODE_ENV || 'unknown',
        db_name: process.env.DB_NAME || process.env.MYSQL_DATABASE || null,
        hunts,
        steps
      });
    } catch (e) {
      reply.status(500).json({ ok: false, error: e.message });
    }
  });

  // Friendly HTML at "/" (quick glance in the browser)
  fastify.get('/', async (req, reply) => {
    const errors = [];

    // 1. Check DB
    let dbStatus = 'UNKNOWN';
    let dbLatencyMs = 0;
    try {
      const startDb = Date.now();
      const [rows] = await pool.query('SELECT 1 AS ok');
      dbLatencyMs = Date.now() - startDb;
      dbStatus = rows?.[0]?.ok === 1 ? 'OK' : 'DOWN';
    } catch (e) {
      dbStatus = 'DOWN';
      errors.push(`Database: ${e.message}`);
    }

    // 2. Check Discord Bot
    let discordStatus = 'DISABLED';
    let discordClass = 'muted';
    if (process.env.DISCORD_BOT_TOKEN) {
      const isDiscordEnabled = await getSetting('discord_enabled', 'true') === 'true';

      if (!isDiscordEnabled) {
        discordStatus = 'OFFLINE (Toggled Off via Master Switch)';
        discordClass = 'muted';
      } else {
        if (!global.cachedDiscordTag) {
          try {
            const discordRes = await fetch('https://discord.com/api/v10/users/@me', {
              headers: { Authorization: `Bot ${process.env.DISCORD_BOT_TOKEN}` }
            });
            if (discordRes.ok) {
              const data = await discordRes.json();
              global.cachedDiscordTag = data.discriminator && data.discriminator !== '0'
                ? `${data.username}#${data.discriminator}`
                : `@${data.username}`;
            } else {
              global.cachedDiscordTag = 'Unknown Bot';
            }
          } catch (e) {
            global.cachedDiscordTag = 'Unknown Bot';
          }
        }
        discordStatus = `ONLINE (${global.cachedDiscordTag || 'Unknown Bot'}) [Decoupled]`;
        discordClass = 'ok';
      }
    }

    // 3. Check Email Service (Configuration check)
    let emailStatus = 'MISSING CONFIG';
    let emailClass = 'bad';
    if (
      process.env.EMAILJS_SERVICE_ID &&
      process.env.EMAILJS_TEMPLATE_ID &&
      process.env.EMAILJS_PUBLIC_KEY
    ) {
      emailStatus = 'CONFIGURED';
      emailClass = 'ok';
    } else {
      errors.push('Email: Missing EmailJS environment variables (SERVICE_ID, TEMPLATE_ID, or PUBLIC_KEY).');
    }

    // Collect enhanced system information
    const enhancedInfo = {};
    try {
      // OS Info
      enhancedInfo.os = {
        platform: os.platform(),
        release: os.release(),
        arch: os.arch(),
        hostname: os.hostname(),
        totalmem: os.totalmem(),
        freemem: os.freemem(),
        loadavg: os.loadavg(),
        user: os.userInfo().username
      };

      // CPU Info
      const cpus = os.cpus();
      if (cpus.length > 0) {
        enhancedInfo.cpu = {
          count: cpus.length,
          model: cpus[0].model,
          speed: `${cpus[0].speed} MHz`
        };
      }

      // Process Info
      enhancedInfo.process = {
        pid: process.pid,
        cwd: process.cwd(),
        memoryUsage: process.memoryUsage(),
        versions: process.versions,
        uptime: process.uptime()
      };

      // Try to get package version
      try {
        const packageJson = require('../package.json');
        enhancedInfo.app = {
          version: packageJson.version,
          name: packageJson.name
        };
      } catch (e) {
        enhancedInfo.app = {
          version: 'unknown',
          name: 'back'
        };
      }

      // Git Hash
      try {
        const gitHead = fs.readFileSync(path.join(process.cwd(), '.git', 'HEAD'), 'utf8').trim();
        let gitHash = 'unknown';
        if (gitHead.startsWith('ref: ')) {
          const refPath = gitHead.replace('ref: ', '');
          gitHash = fs.readFileSync(path.join(process.cwd(), '.git', refPath), 'utf8').trim().substring(0, 7);
        } else {
          gitHash = gitHead.substring(0, 7);
        }
        enhancedInfo.app.gitHash = gitHash;
      } catch (e) {
        enhancedInfo.app.gitHash = 'unknown';
      }

      // Socket.io Info
      if (fastify.io) {
        enhancedInfo.sockets = {
          connected: fastify.io.engine.clientsCount
        };
      }
    } catch (e) {
      // If we can't collect enhanced info, continue with basic info
      console.warn('Could not collect enhanced system info:', e.message);
    }

    // Determine overall system health
    const systemStatus = (dbStatus === 'OK' && discordClass !== 'bad' && emailClass !== 'bad') ? 'Ok' : 'Bad';
    const systemClass = systemStatus === 'Ok' ? 'ok' : 'bad';

    let html = '';
    try {
      html = await fs.promises.readFile(path.join(APP_ROOT, 'views', 'status.html'), 'utf8');
    } catch (err) {
      html = '<h1>Status Page Error</h1><p>' + err.message + '</p>';
    }

    // uptime calculation
    const total = Math.floor(process.uptime());
    const days = Math.floor(total / 86400);
    const hours = Math.floor((total % 86400) / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    const seconds = total % 60;
    const parts = [];
    if (days) parts.push(`${days}d`);
    if (hours) parts.push(`${hours}h`);
    if (minutes) parts.push(`${minutes}m`);
    parts.push(`${seconds}s`);
    const uptimeStr = parts.join(" ");

    // system memory
    const osTotalMem = Math.floor(((enhancedInfo.os || {}).totalmem || 0) / 1024 / 1024);
    const osFreeMem = Math.floor(((enhancedInfo.os || {}).freemem || 0) / 1024 / 1024);
    const osUsedPct = Math.round(100 - (((enhancedInfo.os || {}).freemem || 0) / ((enhancedInfo.os || {}).totalmem || 1)) * 100) / 100;
    const osMemoryStr = `${osTotalMem} MB Total • ${osFreeMem} MB Free • ${osUsedPct}% Used`;

    // process memory
    const heapUsed = Math.floor((enhancedInfo.process?.memoryUsage?.heapUsed || 0) / 1024 / 1024);
    const heapTotal = Math.floor((enhancedInfo.process?.memoryUsage?.heapTotal || 0) / 1024 / 1024);
    const procRss = Math.floor((enhancedInfo.process?.memoryUsage?.rss || 0) / 1024 / 1024);
    const procMemoryStr = `${heapUsed} MB Heap Used / ${heapTotal} MB Heap Total • ${procRss} MB RSS`;

    // CPU
    const cpuModel = (enhancedInfo.cpu || {}).model || 'N/A';
    const cpuInfoStr = `${((enhancedInfo.cpu || {}).count || 'N/A')}× ${cpuModel.substring(0, 30)}${cpuModel.length > 30 ? '...' : ''}`;

    // Load Avg
    const loadavg = (enhancedInfo.os || {}).loadavg;
    const loadAvgStr = Array.isArray(loadavg) ? `${(loadavg[0] || 0).toFixed(2)}, ${(loadavg[1] || 0).toFixed(2)}, ${(loadavg[2] || 0).toFixed(2)}` : 'N/A';

    const errorsHtml = errors.length > 0 ? `
    <div class="error-section">
      <div class="error-title">Active Errors detected:</div>
      <ul class="error-list">
        ${errors.map(e => `<li>${e}</li>`).join('')}
      </ul>
    </div>
  ` : '';

    // local IP
    let localIp = '127.0.0.1';
    try {
      const interfaces = os.networkInterfaces();
      for (const name of Object.keys(interfaces)) {
        for (const net of interfaces[name]) {
          if (net.family === 'IPv4' && !net.internal) {
            localIp = net.address;
            break;
          }
        }
      }
    } catch (e) { }

    // Environment checks
    const jwtStatus = process.env.JWT_SECRET ? 'CONFIGURED' : 'MISSING';
    const jwtClass = process.env.JWT_SECRET ? 'ok' : 'bad';

    const ntfyStatus = process.env.NTFY_TOPIC ? `CONFIGURED (${process.env.NTFY_TOPIC})` : 'NOT SET';
    const ntfyClass = process.env.NTFY_TOPIC ? 'ok' : 'bad';

    const corsStatus = process.env.CORS_ORIGIN || `${DEFAULT_CORS_ORIGINS.join(', ')} (default)`;

    const apiDocsLink = enhancedInfo.app && enhancedInfo.app.version ? `<div class="k">API Docs</div><div class="v"><a href="/api-docs">/api-docs</a></div>` : '';

    const dbStatusStr = dbStatus === 'OK' ? `OK (${dbLatencyMs}ms)` : dbStatus;
    const socketUsersStr = (enhancedInfo.sockets?.connected !== undefined) ? `${enhancedInfo.sockets.connected} Connected Users` : 'N/A';
    const gitHashStr = enhancedInfo.app?.gitHash || 'unknown';

    // JSON Content Negotiation
    const acceptHeader = req.headers.accept || '';
    if (acceptHeader.includes('application/json')) {
      return reply.send({
        status: systemStatus,
        app: enhancedInfo.app,
        startedAt,
        uptime: total,
        errors,
        services: {
          database: { status: dbStatus, latencyMs: dbLatencyMs },
          discord: { status: discordStatus.split(' ')[0], details: discordStatus },
          email: { status: emailStatus },
          jwt: { status: jwtStatus },
          ntfy: { status: ntfyStatus.split(' ')[0], details: ntfyStatus },
        },
        sockets: enhancedInfo.sockets,
        os: enhancedInfo.os,
        cpu: enhancedInfo.cpu,
        process: enhancedInfo.process,
        requester: {
          ip: req.ip
        }
      });
    }

    html = html
      .replace('{{STYLE_NONCE}}', reply.cspNonce?.style || '')
      .replace('{{SYSTEM_CLASS}}', systemClass)
      .replace('{{SYSTEM_STATUS}}', systemStatus)
      .replaceAll('{{APP_NAME}}', 'Erebus API')
      .replace('{{APP_VERSION}}', (enhancedInfo.app || {}).version || '0.0.0')
      .replace('{{NODE_ENV}}', process.env.NODE_ENV || 'stable')
      .replace('{{STARTED_AT}}', formatDate(startedAt))
      .replace('{{NOW}}', formatDate(new Date()))
      .replace('{{UPTIME}}', uptimeStr)
      .replace('{{NODE_VERSION}}', process.version)
      .replace('{{V8_VERSION}}', process.versions?.v8 || 'N/A')
      .replace('{{API_DOCS_LINK}}', apiDocsLink)
      .replace('{{OS_PLATFORM}}', `${enhancedInfo.os?.platform || 'N/A'} ${enhancedInfo.os?.release || ''} (${enhancedInfo.os?.arch || ''})`)
      .replace('{{HOSTNAME}}', enhancedInfo.os?.hostname || 'N/A')
      .replace('{{LOCAL_IP}}', localIp)
      .replace('{{OS_USER}}', enhancedInfo.os?.user || 'N/A')
      .replace('{{PROCESS_PID}}', enhancedInfo.process?.pid || 'N/A')
      .replace('{{PROCESS_CWD}}', enhancedInfo.process?.cwd || 'N/A')
      .replace('{{CPU_INFO}}', cpuInfoStr)
      .replace('{{OS_MEMORY}}', osMemoryStr)
      .replace('{{PROC_MEMORY}}', procMemoryStr)
      .replace('{{LOAD_AVG}}', loadAvgStr)
      .replace('{{DB_CLASS}}', dbStatus === 'OK' ? 'ok' : 'bad')
      .replace('{{DB_STATUS}}', dbStatusStr)
      .replace('{{DISCORD_CLASS}}', discordClass)
      .replace('{{DISCORD_STATUS}}', discordStatus)
      .replace('{{EMAIL_CLASS}}', emailClass)
      .replace('{{EMAIL_STATUS}}', emailStatus)
      .replace('{{JWT_CLASS}}', jwtClass)
      .replace('{{JWT_STATUS}}', jwtStatus)
      .replace('{{NTFY_CLASS}}', ntfyClass)
      .replace('{{NTFY_STATUS}}', ntfyStatus)
      .replace('{{CORS_STATUS}}', corsStatus)
      .replaceAll('{{GIT_HASH}}', gitHashStr)
      .replace('{{SOCKET_USERS}}', socketUsersStr)
      .replace('{{REQ_IP}}', req.ip)
      .replace('{{ERRORS}}', errorsHtml);

    reply.header('Cache-Control', 'no-store').header('Content-Type', 'text/html; charset=utf-8').send(html);
  });
};
