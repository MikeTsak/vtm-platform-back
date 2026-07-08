// server.js (with advanced logging)
require('dotenv').config();
const os = require('os');

// Import the new logger and its utility functions
const { log, attachRequestLogger, expressErrorHandler, installProcessHandlers } = require('./logger');

const express = require('express');
const cors = require('cors');
const cron = require('node-cron');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const pool = require('./db'); // export pool.promise() from db.js
const { authRequired, requireAdmin } = require('./authMiddleware');
const axios = require('axios');

const path = require('path');
const fs = require('fs');
const multer = require('multer'); // Import multer
const { Client, GatewayIntentBits, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, ComponentType } = require('discord.js');
const { joinVoiceChannel, createAudioPlayer, createAudioResource, AudioPlayerStatus, NoSubscriberBehavior } = require('@discordjs/voice');
const play = require('play-dl');
const { GoogleGenerativeAI } = require("@google/generative-ai");
// For meme generation
const sharp = require('sharp');
const TextToSVG = require('text-to-svg');
const rateLimit = require('express-rate-limit');
// --- Swagger Imports ---
const swaggerUi = require('swagger-ui-express');
const swaggerSpec = require('./swagger.config');

// Rate limiting
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 600, // limit each IP to 600 requests per windowMs
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

const moderateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30, // limit each IP to 30 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 uploads per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

// Configure Multer for Avatar uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 }, // 25 MB limit
});

const LOG_CHANNEL_ID = '1469033259806625874';

// --- Setup ---

// Optional mapping of template variable names via env
const VAR_TO      = process.env.EMAILJS_VAR_TO      || 'to_email';
const VAR_NAME    = process.env.EMAILJS_VAR_NAME    || 'to_name';
const VAR_APP     = process.env.EMAILJS_VAR_APP     || 'app_name';
const VAR_LINK    = process.env.EMAILJS_VAR_LINK    || 'reset_link';
const VAR_EXPIRES = process.env.EMAILJS_VAR_EXPIRES || 'expires_minutes';

// Install global handlers to catch crashes and unhandled promise rejections
installProcessHandlers();
log.start('API booting…');

// Load keys from .env
const vapidPublicKey = process.env.VAPID_PUBLIC_KEY;
const vapidPrivateKey = process.env.VAPID_PRIVATE_KEY;


const app = express();
// CORS: In production, set CORS_ORIGIN env var to your frontend URL
const corsOrigin = process.env.CORS_ORIGIN 
  ? process.env.CORS_ORIGIN.split(',').map(o => o.trim())
  : true; // Development: allow all origins
app.use(cors({ origin: corsOrigin, credentials: true }));
// app.use(express.json({ limit: '1mb' }));
app.set('trust proxy', false);
// Increase payload limit to 70MB for Base64 image uploads
app.use(express.json({ limit: '70mb' }));
app.use(express.urlencoded({ limit: '70mb', extended: true }));
// Rate limiting
app.use(globalLimiter);

// Disable caching for all admin API routes to prevent 304 errors
app.use('/api/admin', (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  next();
});

// Add this to server.js
let passwordResetsTableCreated = false;
async function _ensurePasswordResetsTable() {
  if (passwordResetsTableCreated) return;
  try {
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
    passwordResetsTableCreated = true;
    log.ok('Password resets table verified/created.');
  } catch (e) {
    log.err('Failed to create password_resets table', { message: e.message });
  }
}

// Call it at the top level of server.js with your other inits
_ensurePasswordResetsTable();

/* -------------------- LIVE SESSION TABLES -------------------- */
let liveSessionTablesCreated = false;
async function _ensureLiveSessionTables() {
  if (liveSessionTablesCreated) return;
  try {
    // 1. Sessions
    await pool.query(`
      CREATE TABLE IF NOT EXISTS live_sessions (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        admin_id INT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // -> Schema Patch: Add Session Code, Status, and Timers
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

    // 2. Participants
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

    // 3. Rolls
    await pool.query(`
      CREATE TABLE IF NOT EXISTS live_session_rolls (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        session_id INT UNSIGNED NOT NULL,
        character_id INT NOT NULL,
        roll_type VARCHAR(50),
        pool INT,
        hunger INT,
        results JSON,
        successes INT,
        note TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (session_id) REFERENCES live_sessions(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 4. Broadcasts
    await pool.query(`
      CREATE TABLE IF NOT EXISTS live_session_broadcasts (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        session_id INT UNSIGNED NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (session_id) REFERENCES live_sessions(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    liveSessionTablesCreated = true;
    log.ok('Live Session tables verified/patched.');
  } catch (e) {
    log.err('Failed to create/patch Live Session tables', { message: e.message });
  }
}

_ensureLiveSessionTables();

// --- Load Custom Font for Memes ---
let memeFontBase64 = '';
try {
  // This looks for the exact file next to server.js
  const fontPath = path.join(__dirname, 'Roboto_Condensed-Bold.ttf');
  const fontBuffer = fs.readFileSync(fontPath);
  memeFontBase64 = fontBuffer.toString('base64');
  log.start('Custom meme font loaded successfully.');
} catch (e) {
  log.err('Could not load custom meme font. Memes might show tofu boxes.', { error: e.message });
}

// --- Load Custom Font for Memes as Vector Paths ---
let textToSVG;
try {
  const fontPath = path.join(__dirname, 'Roboto_Condensed-Bold.ttf');
  textToSVG = TextToSVG.loadSync(fontPath);
  log.start('Text-to-SVG loaded custom font successfully.');
} catch (e) {
  log.err('Could not load custom meme font for TextToSVG.', { error: e.message });
}

// Create a multer instance that stores files in memory as buffers
// Limit file size to 50MB to match the JSON payload limits
const storage = multer.memoryStorage();
const memoryUpload = multer({ 
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// Add the request logger middleware. It will log every incoming request and its response.
// Place it right after express.json() to ensure it can log request bodies.
app.use(attachRequestLogger());



// Helper: Report errors to the defined Discord channel
async function reportErrorToDiscord(source, error) {
  // 1. Check if bot is connected
  if (!discordClient?.isReady()) return;

  // 2. CHECK: Only send error logs if we are in PRODUCTION
  // If we are in 'staging' or 'development', this function stops here.
  if (process.env.NODE_ENV !== 'production') return; 
  
  try {
    const channel = await discordClient.channels.fetch(LOG_CHANNEL_ID);
    if (!channel) return;

    // Truncate stack trace to avoid Discord 2000 char limit
    const errString = (error.stack || error.message || String(error)).slice(0, 1000);
    
    await channel.send(`🚨 **Error Detected: ${source}**\n\`\`\`js\n${errString}\n\`\`\``);
  } catch (e) {
    // Fail silently so we don't cause an infinite error loop
    console.error('Failed to report error to Discord:', e.message);
  }
}

// Human-friendly masking
const maskEmail = (email) => {
  if (!email || typeof email !== 'string') return email;
  const [u, d] = email.trim().toLowerCase().split('@');
  if (!d) return email;
  const maskedUser = u.length <= 2 ? (u[0] || '') + '*' : u[0] + '*'.repeat(u.length - 2) + u.slice(-1);
  return `${maskedUser}@${d}`;
};

// Mask helper for logs
function _maskEmail(email) {
  if (!email || typeof email !== 'string') return email;
  const [u, d] = email.trim().toLowerCase().split('@');
  if (!d) return email;
  const maskedUser = u.length <= 2 ? (u[0] || '') + '*' : u[0] + '*'.repeat(u.length - 2) + u.slice(-1);
  return `${maskedUser}@${d}`;
}

// --- UNIVERSAL PUSH HELPER ---
// Function for base64 encoding headers
const encodeHeader = (str) => `=?UTF-8?B?${Buffer.from(str).toString('base64')}?=`;

async function sendPushNotification(userId, title, body, data = {}) {
  try {
    // 1. Send to ntfy.sh
    const topic = crypto.createHash('md5').update('vampire_' + userId + (process.env.JWT_SECRET || 'secret')).digest('hex');
    const clickUrl = data.url ? data.url : '/comms';
    const clickFullUrl = process.env.CORS_ORIGIN ? (process.env.CORS_ORIGIN.split(',')[0] + clickUrl) : clickUrl;
    
    await axios.post('https://ntfy.sh/' + topic, body, {
      headers: {
        'Title': encodeHeader(title),
        'Tags': 'vampire,bell',
        'Click': clickFullUrl
      }
    }).catch(err => log.err('ntfy push failed', { err: err.message }));

    // 2. Retain Mobile Devices (Expo)
    const [subs] = await pool.query('SELECT id, subscription_json FROM push_subscriptions WHERE user_id=?', [userId]);
    if (!subs.length) return;

    const expoTokens = [];
    for (const row of subs) {
      try {
        const sub = JSON.parse(row.subscription_json);
        if (sub.expoPushToken) expoTokens.push(sub.expoPushToken);
      } catch (e) {}
    }

    if (expoTokens.length > 0) {
      const expoMessages = expoTokens.map(token => ({
        to: token, sound: 'default', title: title, body: body, data: data,
      }));
      await axios.post('https://exp.host/--/api/v2/push/send', expoMessages, {
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' }
      }).catch(err => log.err('Expo push failed', { err: err.message }));
    }
  } catch (e) {
    log.err('Failed to execute push notification', { error: e.message });
  }
}

// V5 success math:
function computeV5Outcome({ normal = [], hunger = [] }) {
  const all = [...normal, ...hunger];
  const baseSuccesses = all.filter(v => v >= 6).length;

  const tens = all.filter(v => v === 10).length;
  const crit_pairs = Math.floor(tens / 2);

  const hungerTens = hunger.filter(v => v === 10).length;
  const messy_crit = crit_pairs > 0 && hungerTens > 0;

  const hungerOnes = hunger.filter(v => v === 1).length;
  const successes = baseSuccesses + (crit_pairs * 2);
  const bestial_failure = successes === 0 && hungerOnes > 0;

  return { successes, crit_pairs, messy_crit, bestial_failure };
}

// Respect EmailJS rate limit: 1 request / second
let __lastSendAt = 0;
async function _respectEmailJsRateLimit() {
  const now = Date.now();
  const delta = now - __lastSendAt;
  if (delta < 1000) {
    await new Promise(r => setTimeout(r, 1000 - delta));
  }
  __lastSendAt = Date.now();
}

// --- Discord Bot Setup ---
let discordClient = null;
let discordLoginError = null; // <--- 1. New variable to hold the specific error

// Only initialize if token is present
if (process.env.DISCORD_BOT_TOKEN) {
  discordClient = new Client({
    intents: [
      GatewayIntentBits.Guilds, 
      GatewayIntentBits.GuildMessages,
      GatewayIntentBits.MessageContent,
      GatewayIntentBits.GuildVoiceStates
    ],
    ws: { compress: false },
    rest: { timeout: 15000 },
  });
  
  // Capture login errors
  discordClient.login(process.env.DISCORD_BOT_TOKEN).catch(e => {
    discordLoginError = e.message; 
    log.err('Discord login failed', e);
  });

  // When ready: Clear errors and Send Startup Message
  discordClient.once('ready', async () => {
    discordLoginError = null;
    log.start(`Discord Bot logged in as ${discordClient.user.tag}`);

    // --- Send "System Online" Message ---
    try {
      const channel = await discordClient.channels.fetch(LOG_CHANNEL_ID);
      if (channel) {
        const env = process.env.NODE_ENV || 'development';
        const now = new Date().toLocaleString('en-GB', { timeZone: 'Europe/Athens' });
        
        // Announces the environment (Production/Staging/Dev)
        await channel.send(`🦇 **System Online [${env.toUpperCase()}]**\nErebus API started at: \`${now}\``);
      }
    } catch (e) {
      log.err('Failed to send startup message to Discord', { error: e.message });
    }
  });

// --- Main discord client ---
discordClient.on('messageCreate', async (message) => {
  // Check Master Switch
  const isEnabled = await getSetting('discord_enabled', 'true') === 'true';
  if (!isEnabled) return;
  // Ignore bots to prevent infinite loops
  if (message.author.bot) return;

  // --- @bot whoami TEST COMMAND (No Tokens Burned) ---
  const botMentionPrefix = `<@${discordClient.user.id}>`;
  if (message.content.startsWith(botMentionPrefix)) {
    const commandText = message.content.replace(botMentionPrefix, '').trim().toLowerCase();
    
if (commandText === 'whoami') {
          try {
            // 1. Cross-reference users table via discord_id
            const [userRows] = await pool.query(
              'SELECT id, display_name FROM users WHERE discord_id = ? LIMIT 1', 
              [message.author.id]
            );

            if (userRows.length === 0) {
              return await message.reply('❌ Δεν βρέθηκε εγγραφή χρήστη συνδεδεμένη με το Discord ID σου.');
            }

            const user = userRows[0];

            // 2. Match user id from characters table to get character name AND clan
            const [charRows] = await pool.query(
              'SELECT name, clan FROM characters WHERE user_id = ? LIMIT 1', 
              [user.id]
            );

            const charName = charRows.length > 0 ? charRows[0].name : 'Δεν βρέθηκε ενεργός χαρακτήρας';
            const charClan = (charRows.length > 0 && charRows[0].clan) ? charRows[0].clan : 'Άγνωστη Clan';

            return await message.reply({
              content: `👤 **SchreckNet Identity Verification**\n` +
                       `> **Discord User:** \`${message.author.username}\`\n` +
                       `> **Portal Display Name:** \`${user.display_name}\`\n` +
                       `> **Character Name:** \`\${charName}\`\n` +
                       `> **Clan:** \`${charClan}\``
            });
          } catch (e) {
            log.err('Whoami command failure', { error: e.message });
            return await message.reply('❌ Σφάλμα ανάκτησης στοιχείων από τον server.');
          }
        }
  }

  // --- SCHRECKNET NODE AI - "ΓΙΑΝΝΑΚΗΣ" (WITH IMPROVED DB CROSS-REFERENCING) ---
  if (message.mentions.has(discordClient.user)) {
    try {
      await message.channel.sendTyping();

      // Ultimate Fallback: Discord Username
      let charName = message.author.username;
      let charClan = 'Unknown';

      // Chained Database Lookup: users -> characters
      try {
        const [userRows] = await pool.query(
          'SELECT id, display_name FROM users WHERE discord_id = ? LIMIT 1', 
          [message.author.id]
        );
        
        if (userRows.length > 0) {
          const dbUser = userRows[0];
          charName = dbUser.display_name; // Fallback to portal name

          // Match character using the user.id - NEW: Added 'clan' to the SELECT
          const [charRows] = await pool.query(
            'SELECT name, clan FROM characters WHERE user_id = ? LIMIT 1', 
            [dbUser.id]
          );

          if (charRows.length > 0) {
            if (charRows[0].name) charName = charRows[0].name;
            if (charRows[0].clan) charClan = charRows[0].clan; // <-- NEW: Store the clan
          }
        }
      } catch (dbLookupErr) {
        log.err('DB Lookup failed during character resolution', { error: dbLookupErr.message });
      }

      const userQuery = message.content.replace(`<@${discordClient.user.id}>`, '').trim();
      log.info(`🤖 [DEBUG] Ο/Η \${charName} (${charClan}) ρώτησε τον Γιαννάκη: "${userQuery}"`);

      const apiKey = process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY;

      if (!apiKey) {
          log.warn('Discord Bot AI Error: API Key is undefined in your environment.');
          return message.reply({ content: "Συγγνώμη κ. Administrator... το κλειδί πρόσβασής μου (API Key) λείπει." });
      }

      const genAI = new GoogleGenerativeAI(apiKey);

      const tools = [{
        functionDeclarations: [
          {
            name: "get_domain_owner",
            description: "Βρίσκει ποιος ελέγχει μια περιοχή (domain) της Αθήνας. Χρησιμοποίησε αυτό το ευρετήριο για τον αριθμό: 1:Παγκράτι, 2:Ζωγράφου/Καισαριανή, 3:Εξάρχεια, 8:Πλάκα, 12:Μοσχάτο, 18:Κολωνάκι, 20:Αιγάλεω, 23:Ψυχικό, 27:Κηφισιά, 31:Χαλάνδρι, 32:Πέραμα/Κερατσίνι, 39:Αθήνα, 43:Πειραιάς. Αν η περιοχή δεν υπάρχει στη λίστα, μάντεψε τον κοντινότερο αριθμό.",
            parameters: {
              type: "OBJECT",
              properties: {
                division_number: {
                  type: "INTEGER",
                  description: "Ο αριθμός της περιοχής, π.χ. 32 για το Πέραμα."
                }
              },
              required: ["division_number"]
            }
          },
          {
            name: "get_latest_news",
            description: "Επιστρέφει τα τελευταία νέα, ανακοινώσεις ή πληροφορίες για πρόσωπα/events που υπάρχουν στα News του δικτύου.",
          }
        ]
      }];

      // --- FETCH PROMPT FROM DATABASE ---


// --- FETCH PROMPT FROM DATABASE ---

      // Τράβηγμα του prompt απευθείας από τη βάση δεδομένων
      let rawSystemPrompt = await getSetting('giannakis_system_prompt');

      if (!rawSystemPrompt) {
        log.warn('System prompt missing from database configuration.');
        return message.reply({ content: "Συγγνώμη κ. Administrator... έχασα τα αρχεία ρυθμίσεων της προσωπικότητάς μου." });
      }

      // Δυναμική εισαγωγή του ονόματος χαρακτήρα και της Clan
      let systemPrompt = rawSystemPrompt
        .replace(/\$\{charName\}/g, charName)
        .replace(/\{charName\}/g, charName)
        .replace(/\$\{charClan\}/g, charClan) 
        .replace(/\{charClan\}/g, charClan);

      // <-- NEW: Hardcode the context into the system prompt so the AI never misses it
      systemPrompt += `\n\n[SYSTEM CONTEXT: The user you are currently talking to is named "\${charName}" and belongs to Clan "${charClan}". Adapt your response, slang, and attitude towards them based on their Clan's stereotypes.]`;

      const model = genAI.getGenerativeModel({ 
        model: "gemini-3.1-flash-lite", 
        systemInstruction: systemPrompt,
        tools: tools 
      });
      
      const chat = model.startChat();
      
      log.info(`🤖 [DEBUG] Στέλνω την πρώτη ερώτηση στο Gemini...`);
      let result = await chat.sendMessage(userQuery);
      let response = result.response;

      // BULLETPROOF: Διαβάζουμε σωστά τα function calls ανάλογα με την έκδοση του SDK
      const calls = typeof response.functionCalls === 'function' ? response.functionCalls() : response.functionCalls;

      // Check if Gemini wants to call a Database Function
      if (calls && calls.length > 0) {
        const call = calls[0];
        let functionResult = {};

        try {
          // EXECUTE DB QUERIES BASED ON AI REQUEST
          if (call.name === 'get_domain_owner') {
            const div = call.args.division_number;
            log.info(`🤖 [DEBUG] Το Gemini ζήτησε Tool: get_domain_owner για division [${div}]`);
            
            const [rows] = await pool.query('SELECT owner_name FROM domain_claims WHERE division = ? LIMIT 1', [div]);
            if (rows.length > 0 && rows[0].owner_name) {
              functionResult = { status: "claimed", owner: rows[0].owner_name, division: div };
            } else {
              functionResult = { status: "unclaimed", message: "Η περιοχή είναι free/unclaimed." };
            }
          } 
          else if (call.name === 'get_latest_news') {
            log.info(`🤖 [DEBUG] Το Gemini ζήτησε Tool: get_latest_news`);
            
            const bannerEnabled = await getSetting('banner_enabled', 'false');
            
            if (bannerEnabled === 'true' || bannerEnabled === '1' || bannerEnabled === true) {
              const bannerMessage = await getSetting('banner_message', '');
              
              if (bannerMessage) {
                functionResult = { latest_news: bannerMessage };
              } else {
                functionResult = { latest_news: "Το δίκτυο είναι ήσυχο. Δεν υπάρχουν νέα." };
              }
            } else {
              functionResult = { latest_news: "Το δίκτυο είναι ήσυχο. Δεν υπάρχουν ενεργές ανακοινώσεις αυτή τη στιγμή." };
            }
          }

          log.info(`🤖 [DEBUG] Απάντηση από τη Βάση (στέλνεται στο Gemini):`, JSON.stringify(functionResult));

          // Επιστροφή των δεδομένων πίσω στο Gemini
          result = await chat.sendMessage([{
            functionResponse: {
              name: call.name,
              response: functionResult
            }
          }]);
          response = result.response;
          
          log.info(`🤖 [DEBUG] Raw Response από Gemini ΜΕΤΑ το Tool:`, JSON.stringify(response));

        } catch (dbErr) {
          log.err('DB Tool Execution Failed', { error: dbErr.message });
          result = await chat.sendMessage([{
            functionResponse: {
              name: call.name,
              response: { error: "Database error. Database unreachable." }
            }
          }]);
          response = result.response;
        }
      } else {
        log.info(`🤖 [DEBUG] Το Gemini ΔΕΝ ζήτησε εργαλείο. Απαντάει απευθείας.`);
      }
      
      // --- BULLETPROOF EMPTY MESSAGE FALLBACK & SAFETY CHECK ---
      let replyTextRes = "";
      try {
        if (response.candidates && response.candidates[0]?.content?.parts[0]?.text) {
          replyTextRes = response.candidates[0].content.parts[0].text;
          log.info(`🤖 [DEBUG] Τελικό Κείμενο που διαβάστηκε: "${replyTextRes}"`);
        } else if (response && typeof response.text === 'function') {
          replyTextRes = response.text();
          log.info(`🤖 [DEBUG] Τελικό Κείμενο που διαβάστηκε: "${replyTextRes}"`);
        } else if (response && response.text) {
           replyTextRes = response.text;
        }
      } catch (textErr) {
        log.err('Gemini response extraction threw error', { error: textErr.message });
        if (response.candidates && response.candidates.length > 0) {
           log.warn(`🤖 [DEBUG] Finish Reason: ${response.candidates[0].finishReason}`);
        }
      }

      if (!replyTextRes || replyTextRes.trim() === "") {
        replyTextRes = `Συγγνώμη κ. \${charName}, το σήμα χάθηκε και το firewall της βάσης δεδομένων μπλόκαρε την απάντηση. Μπορείτε να επαναλάβετε;`;
      }
      
      await message.reply({ content: replyTextRes });
      return;

    } catch (error) {
      log.err('Giannakis AI Critical Error', { error: error.message });
      await message.reply({ content: "Συγγνώμη... το terminal έκανε crash. (Exception Thrown) Κάνω reboot." });
      return;
    }
  }

  // --- FANCY V5 DICE ROLLER WITH WILLPOWER ---
  if (message.content.toLowerCase().startsWith('&roll')) {
    const args = message.content.slice(5).trim().split(/\s+/);
    const poolCount = Math.max(1, parseInt(args[0]) || 1);
    const hungerInput = Math.max(0, parseInt(args[1]) || 0);

    const hungerCount = Math.min(poolCount, hungerInput);
    const normalCount = poolCount - hungerCount;

    const roll10 = () => Math.floor(Math.random() * 10) + 1;
    
    let normalRolls = Array.from({ length: normalCount }, roll10);
    let hungerRolls = Array.from({ length: hungerCount }, roll10);

    const outcome = computeV5Outcome({ normal: normalRolls, hunger: hungerRolls });

    const formatDice = (rolls, isHunger) => {
      if (!rolls || rolls.length === 0) return 'None';
      return rolls.map(r => {
        if (r === 10) return `**[10]**`;
        if (r === 1 && isHunger) return `**[1]**`; 
        if (r >= 6) return `[${r}]`;
        return `\`${r}\``; 
      }).join(' ');
    };

    const buildEmbed = (currentNormal, currentHunger, currentOutcome, usedWillpower = false) => {
      let title = "🦇 V5 Dice Roll";
      let color = 0x2b2d31; 
      let imageUrl = null;  

      if (currentOutcome.messy_crit) {
        title = "🩸 **MESSY CRITICAL!**";
        color = 0x8a0303; 
        imageUrl = 'https://portal.attlarp.gr/img/dice/MessyCrit.png';
      } else if (currentOutcome.bestial_failure) {
        title = "💀 **BESTIAL FAILURE!**";
        color = 0x000000; 
        imageUrl = 'https://portal.attlarp.gr/img/dice/BestialFail.png';
      } else if (currentOutcome.crit_pairs > 0) {
        title = "🌟 **CRITICAL SUCCESS!**";
        color = 0xd4af37; 
        imageUrl = 'https://portal.attlarp.gr/img/dice/Crit.png';
      } else if (currentOutcome.successes > 0) {
        title = "🦇 **SUCCESS**";
        color = 0x3ecf8e; 
        imageUrl = 'https://portal.attlarp.gr/img/dice/Success.png';
      } else {
        title = "🌑 **FAILURE**";
        color = 0x5c5c63; 
      }

      const embed = new EmbedBuilder()
        .setTitle(title)
        .setColor(color)
        .setAuthor({ name: message.author.displayName, iconURL: message.author.displayAvatarURL() })
        .setDescription(`Rolled **${poolCount}** dice (${currentHunger.length} Hunger).${usedWillpower ? '\n*✨ Spent Willpower to reroll failures.*' : ''}`)
        .addFields(
          { name: 'Normal Dice', value: formatDice(currentNormal, false), inline: false },
          { name: 'Hunger Dice', value: formatDice(currentHunger, true), inline: false },
          { name: 'Total Successes', value: `**${currentOutcome.successes}**`, inline: false }
        );

      if (imageUrl) {
        embed.setThumbnail(imageUrl);
      }

      return embed;
    };

    const failingNormalCount = normalRolls.filter(r => r <= 5).length;
    const canReroll = normalCount > 0 && failingNormalCount > 0;

    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId('reroll_wp')
        .setLabel('Spend Willpower (Reroll up to 3)')
        .setStyle(ButtonStyle.Danger)
        .setDisabled(!canReroll)
    );

    const reply = await message.reply({ 
      embeds: [buildEmbed(normalRolls, hungerRolls, outcome)], 
      components: [row] 
    });

    const collector = reply.createMessageComponentCollector({ 
      componentType: ComponentType.Button, 
      time: 300000 
    });

    collector.on('collect', async (interaction) => {
      if (interaction.user.id !== message.author.id) {
        return interaction.reply({ content: '🦇 You cannot spend Willpower for someone else!', ephemeral: true });
      }

      if (interaction.customId === 'reroll_wp') {
        let rerollsLeft = 3;
        let newNormalRolls = [...normalRolls];

        for (let i = 0; i < newNormalRolls.length; i++) {
          if (newNormalRolls[i] <= 5 && rerollsLeft > 0) {
            newNormalRolls[i] = roll10();
            rerollsLeft--;
          }
        }

        const newOutcome = computeV5Outcome({ normal: newNormalRolls, hunger: hungerRolls });

        const disabledRow = new ActionRowBuilder().addComponents(
          ButtonBuilder.from(interaction.component).setDisabled(true).setLabel('Willpower Spent')
        );

        await interaction.update({ 
          embeds: [buildEmbed(newNormalRolls, hungerRolls, newOutcome, true)], 
          components: [disabledRow] 
        });
        
        collector.stop('wp_spent');
      }
    });

    collector.on('end', (collected, reason) => {
      if (reason === 'time') {
        const disabledRow = new ActionRowBuilder().addComponents(
          new ButtonBuilder()
            .setCustomId('reroll_wp_timeout')
            .setLabel('Spend Willpower (Time Expired)')
            .setStyle(ButtonStyle.Secondary)
            .setDisabled(true)
        );
        reply.edit({ components: [disabledRow] }).catch(() => {});
      }
    });

    return;
  }

  // --- Meme Maker Feature ---
  if (message.content.toLowerCase().startsWith('&meme')) {
    const text = message.content.slice(5).trim();
    
    const attachments = Array.from(message.attachments.values()).filter(a => a.contentType && a.contentType.startsWith('image/'));

    if (attachments.length === 0) {
      return message.reply('🦇 You need to attach at least one image to make a meme!');
    }
    if (!text) {
      return message.reply('🦇 Provide some text! Example: `&meme When the ST smiles`');
    }

    try {
      if (!textToSVG) {
        return message.reply('❌ The server font engine is currently down. (TextToSVG failed to load).');
      }

      const downloadedImages = [];
      for (const attachment of attachments) {
        const response = await axios.get(attachment.url, { responseType: 'arraybuffer' });
        const buffer = Buffer.from(response.data, 'binary');
        const meta = await sharp(buffer).metadata();
        downloadedImages.push({ buffer, meta });
      }

      const targetWidth = downloadedImages[0].meta.width;
      let totalImageHeight = 0;
      const processedImages = [];

      for (const img of downloadedImages) {
        const resizedBuffer = await sharp(img.buffer)
          .resize({ width: targetWidth })
          .toBuffer();
        const resizedMeta = await sharp(resizedBuffer).metadata();
        
        processedImages.push({ buffer: resizedBuffer, height: resizedMeta.height });
        totalImageHeight += resizedMeta.height; 
      }

      const fontSize = Math.max(16, Math.floor(targetWidth / 15)); 
      const maxWidth = targetWidth * 0.9; 
      
      const fontOptions = { 
        x: 0, 
        y: 0, 
        fontSize: fontSize, 
        anchor: 'top', 
        attributes: { fill: 'black' } 
      };

      const words = text.split(' ');
      const lines = [];
      let currentLine = '';

      words.forEach(word => {
        const testLine = currentLine ? currentLine + ' ' + word : word;
        const metrics = textToSVG.getMetrics(testLine, fontOptions);
        
        if (metrics.width > maxWidth && currentLine) {
          lines.push(currentLine);
          currentLine = word;
        } else {
          currentLine = testLine;
        }
      });
      if (currentLine) lines.push(currentLine);

      const textPaddingHeight = Math.floor((lines.length * fontSize * 1.3) + (fontSize * 1.0));

      let combinedSvgPaths = '';
      lines.forEach((line, i) => {
        const yOffset = Math.floor((i * fontSize * 1.3) + (fontSize * 0.5));
        
        const metrics = textToSVG.getMetrics(line, fontOptions);
        const xOffset = (targetWidth - metrics.width) / 2;
        
        const path = textToSVG.getPath(line, { ...fontOptions, x: xOffset, y: yOffset });
        combinedSvgPaths += path;
      });

      const svg = `
        <svg width="${targetWidth}" height="${textPaddingHeight}" xmlns="http://www.w3.org/2000/svg">
          ${combinedSvgPaths}
        </svg>
      `;

      const compositeLayers = [
        { input: Buffer.from(svg), top: 0, left: 0 }
      ];

      let currentY = textPaddingHeight;
      for (const img of processedImages) {
        compositeLayers.push({ input: img.buffer, top: currentY, left: 0 });
        currentY += img.height; 
      }

      const totalCanvasHeight = textPaddingHeight + totalImageHeight;
      
      const outputBuffer = await sharp({
        create: {
          width: targetWidth,
          height: totalCanvasHeight,
          channels: 4,
          background: { r: 255, g: 255, b: 255, alpha: 1 } 
        }
      })
      .composite(compositeLayers)
      .jpeg({ quality: 90 })
      .toBuffer();

      await message.channel.send({ 
        content: `🎨 Meme created by: <@${message.author.id}>`,
        files: [{ attachment: outputBuffer, name: 'meme.jpg' }] 
      });

      try {
        await message.delete();
      } catch (delErr) {
        console.warn('Could not delete original meme message:', delErr.message);
      }

    } catch (error) {
      log.err('Discord Meme Generation Failed', { error: error.message });
      message.channel.send(`❌ <@${message.author.id}> The shadows consumed your meme. (Something went wrong processing the image).`);
    }
  } 
});
}

// ============================================================================
// AUTOMATED LOGISTICS - DOWNTIME DEADLINE PINGS
// ============================================================================
// This cron job runs daily at 12:00 PM (server time)
cron.schedule('0 12 * * *', async () => {
  try {
    // 1. Retrieve the downtime configuration to check the deadline
    const [configRows] = await pool.query('SELECT downtime_deadline FROM system_config LIMIT 1'); 
    
    if (configRows.length === 0 || !configRows[0].downtime_deadline) return;

    const deadline = new Date(configRows[0].downtime_deadline);
    const now = new Date();
    
    // Calculate the difference in hours
    const timeDiff = deadline.getTime() - now.getTime();
    const hoursLeft = Math.ceil(timeDiff / (1000 * 60 * 60));

    // If the deadline is roughly between 24 and 48 hours away
    if (hoursLeft > 24 && hoursLeft <= 48) {
      log.info('Downtime deadline is in 48h. Checking for missing actions.');

      // 2. Identify users with Discord IDs and linked characters who haven't submitted
      // Note: Adjust the SQL query if your table structure differs.
      const [lazyUsers] = await pool.query(`
        SELECT discord_id, char_name 
        FROM users 
        WHERE discord_id IS NOT NULL 
          AND character_id IS NOT NULL 
          AND role = 'user'
          AND id NOT IN (
            SELECT user_id 
            FROM downtimes 
            WHERE status != 'rejected' AND created_at > DATE_SUB(NOW(), INTERVAL 30 DAY)
          )
      `);

      // 3. Send a direct message to each identified player
      for (const u of lazyUsers) {
        if (!u.discord_id) continue;
        
        try {
          const discordUser = await client.users.fetch(u.discord_id);
          if (discordUser) {
            const warningMessage = `Hello ${u.char_name || 'there'}, this is an automated reminder. The server for actions (Downtimes) closes in 48 hours. Please submit your actions to avoid an AFK penalty.`;
            
            await discordUser.send(warningMessage);
          }
        } catch (dmErr) {
          log.warn(`Could not send DM to Discord ID: ${u.discord_id}`, { err: dmErr.message });
        }
      }
    }
  } catch (error) {
    log.err('Cron Job Deadline Ping Error', { error: error.message });
  }
});

/* -------------------- The Hunt (Admin & DB Init) -------------------- */

// 1. Ensure the Hunt Tables exist on boot
let huntTablesCreated = false;
async function _ensureHuntTables() {
  if (huntTablesCreated) return;
  try {
    // Base Hunts Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS hunts (
          id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          title VARCHAR(255) NOT NULL,
          description TEXT,
          is_active BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Hunt Steps (Clues)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS hunt_steps (
          id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          hunt_id INT UNSIGNED NOT NULL,
          step_order INT NOT NULL,
          task_type ENUM('gps', 'photo', 'qr', 'text', 'draw', 'audio') NOT NULL,
          prompt TEXT NOT NULL,
          target_data JSON,
          manual_review BOOLEAN DEFAULT FALSE,
          FOREIGN KEY (hunt_id) REFERENCES hunts(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Player Progress
    await pool.query(`
      CREATE TABLE IF NOT EXISTS hunt_progress (
          id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          user_id INT NOT NULL,
          hunt_id INT UNSIGNED NOT NULL,
          current_step_id INT UNSIGNED,
          completed BOOLEAN DEFAULT FALSE,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          UNIQUE KEY uniq_user_hunt (user_id, hunt_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Player Evidence Submissions
    await pool.query(`
      CREATE TABLE IF NOT EXISTS hunt_submissions (
          id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          user_id INT NOT NULL,
          step_id INT UNSIGNED NOT NULL,
          media_id INT UNSIGNED NULL,
          text_answer TEXT NULL,
          status VARCHAR(50) DEFAULT 'pending',
          is_verified BOOLEAN DEFAULT FALSE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

// --- COTERIE / TEAM TABLES ---
    await pool.query(`
      CREATE TABLE IF NOT EXISTS hunt_groups (
          id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
          hunt_id INT NOT NULL,
          name VARCHAR(255) NOT NULL,
          invite_code VARCHAR(10) NOT NULL UNIQUE,
          created_by INT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS hunt_group_members (
          group_id INT UNSIGNED NOT NULL,
          user_id INT NOT NULL,
          joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          PRIMARY KEY (group_id, user_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    // Patch for older databases: Add missing columns if they don't exist yet
    const [stepCols] = await pool.query("SHOW COLUMNS FROM hunt_steps LIKE 'manual_review'");
    if (stepCols.length === 0) {
      await pool.query("ALTER TABLE hunt_steps ADD COLUMN manual_review BOOLEAN DEFAULT FALSE");
      log.ok('Added manual_review column to hunt_steps');
    }

    const [subCols] = await pool.query("SHOW COLUMNS FROM hunt_submissions LIKE 'status'");
    if (subCols.length === 0) {
      await pool.query("ALTER TABLE hunt_submissions ADD COLUMN status VARCHAR(50) DEFAULT 'pending'");
      log.ok('Added status column to hunt_submissions');
    }

    huntTablesCreated = true;
    log.ok('Hunt & Coterie tables ready.');
  } catch (e) {
    log.err('Failed to create hunt tables', { message: e.message });
  }
}
_ensureHuntTables();

/* ------------------------------------------------------------------
   Core & Assumed Tables Initialization
   (Users, Characters, NPCs, XP Logs, Domains, Downtimes, Coteries, etc)
------------------------------------------------------------------- */

let coreTablesCreated = false;
async function _ensureCoreTables() {
  if (coreTablesCreated) return;
  try {
    // 1. Users
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL UNIQUE,
        display_name VARCHAR(190) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user',
        discord_id VARCHAR(50),
        avatar LONGBLOB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Add index on discord_id for faster lookups by discord_id
    try {
      await pool.query(`ALTER TABLE users ADD INDEX idx_discord_id (discord_id)`);
    } catch (e) {
      // Ignore error if index already exists
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) {
        throw e;
      }
    }

    // ✅ AUTOMATICALLY ENSURE THE THEME COLUMN EXISTS
    const [userCols] = await pool.query("SHOW COLUMNS FROM users LIKE 'theme'");
    if (userCols.length === 0) {
      await pool.query("ALTER TABLE users ADD COLUMN theme VARCHAR(50) DEFAULT 'camarilla'");
      log.ok('Added theme column to users table');
    }

    // ✅ AUTOMATICALLY ENSURE THE AVATAR COLUMN EXISTS
    const [avatarCols] = await pool.query("SHOW COLUMNS FROM users LIKE 'avatar'");
    if (avatarCols.length === 0) {
      await pool.query("ALTER TABLE users ADD COLUMN avatar LONGBLOB");
      log.ok('Added avatar column to users table');
    }

    // 2. Characters
    await pool.query(`
      CREATE TABLE IF NOT EXISTS characters (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        name VARCHAR(255) NOT NULL,
        clan VARCHAR(100) NOT NULL,
        sheet JSON NULL,
        xp INT DEFAULT 50,
        camarilla_titles JSON NULL,
        status INT DEFAULT 0,
        image_url VARCHAR(1024) NULL,
        is_ex BOOLEAN DEFAULT FALSE,
        is_deceased BOOLEAN DEFAULT FALSE,
        is_hidden BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Add index on user_id for faster lookups by user_id
    try {
      await pool.query(`ALTER TABLE characters ADD INDEX idx_user_id (user_id)`);
    } catch (e) {
      // Ignore error if index already exists
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) {
        throw e;
      }
    }

    // 3. NPCs
    await pool.query(`
      CREATE TABLE IF NOT EXISTS npcs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        clan VARCHAR(100) NOT NULL,
        sheet JSON NULL,
        xp INT DEFAULT 10000,
        camarilla_titles JSON NULL,
        status INT DEFAULT 0,
        image_url VARCHAR(1024) NULL,
        is_ex BOOLEAN DEFAULT FALSE,
        is_deceased BOOLEAN DEFAULT FALSE,
        is_hidden BOOLEAN DEFAULT FALSE,
        avatar LONGBLOB NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    try {
      await pool.query("ALTER TABLE npcs ADD COLUMN avatar LONGBLOB");
    } catch (e) {
      if (e.code !== 'ER_DUP_FIELDNAME') throw e;
    }

    // 4. Base Chat Messages (Group chat is handled separately)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        sender_id INT NOT NULL,
        recipient_id INT NOT NULL,
        body TEXT,
        attachment_id INT UNSIGNED NULL,
        read_at TIMESTAMP NULL,
        delivered_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Add indexes for chat_messages
    try {
      await pool.query(`ALTER TABLE chat_messages ADD INDEX idx_sender_id (sender_id)`);
    } catch (e) {
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) throw e;
    }
    try {
      await pool.query(`ALTER TABLE chat_messages ADD INDEX idx_recipient_id (recipient_id)`);
    } catch (e) {
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) throw e;
    }
    try {
      await pool.query(`ALTER TABLE chat_messages ADD INDEX idx_recipient_read_at (recipient_id, read_at)`);
    } catch (e) {
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) throw e;
    }

    await pool.query(`
      CREATE TABLE IF NOT EXISTS npc_messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        npc_id INT NOT NULL,
        user_id INT NOT NULL,
        from_side ENUM('user', 'npc') NOT NULL,
        body TEXT,
        attachment_id INT UNSIGNED NULL,
        read_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Add indexes for npc_messages
    try {
      await pool.query(`ALTER TABLE npc_messages ADD INDEX idx_npc_id (npc_id)`);
    } catch (e) {
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) throw e;
    }
    try {
      await pool.query(`ALTER TABLE npc_messages ADD INDEX idx_user_id (user_id)`);
    } catch (e) {
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) throw e;
    }
    try {
      await pool.query(`ALTER TABLE npc_messages ADD INDEX idx_user_read_at (user_id, read_at)`);
    } catch (e) {
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) throw e;
    }

    // 5. XP Logs
    await pool.query(`
      CREATE TABLE IF NOT EXISTS xp_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        character_id INT NULL,
        action VARCHAR(100) NOT NULL,
        target VARCHAR(255) NULL,
        from_level INT NULL,
        to_level INT NULL,
        cost INT NOT NULL,
        payload JSON NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    coreTablesCreated = true;
    log.ok('Core tables (users, chars, npcs, chat, xp_log) verified/created.');
  } catch (e) {
    log.err('Failed to create core tables', { message: e.message });
  }
}

// --- DATABASE INITIALIZATION INVENTORY TABLES ---
let inventoryTablesCreated = false;
async function _ensureInventoryTables() {
  if (inventoryTablesCreated) return;
  try {
    // 1. Create table for fresh databases
    await pool.query(`
      CREATE TABLE IF NOT EXISTS inventory_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        character_id INT NOT NULL,
        name VARCHAR(255) NOT NULL,
        item_type ENUM('Relic', 'Artifact', 'Blood Magic', 'Weapon', 'Armor', 'Mundane') DEFAULT 'Mundane',
        description TEXT,
        mechanic_notes TEXT,
        quantity INT DEFAULT 1,
        is_equipped BOOLEAN DEFAULT FALSE,
        researched BOOLEAN DEFAULT FALSE,
        image LONGTEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_char (character_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 2. Patch existing databases safely
    try {
      await pool.query(`ALTER TABLE inventory_items ADD COLUMN image LONGTEXT`);
    } catch (ignore) {} // Ignores error if column already exists

    try {
      await pool.query(`ALTER TABLE inventory_items ADD COLUMN researched BOOLEAN DEFAULT FALSE`);
    } catch (ignore) {} // Ignores error if column already exists

    inventoryTablesCreated = true;
    log.ok('Inventory tables ready.');
  } catch (e) {
    log.err('Failed to create/patch inventory tables', { message: e.message });
  }
}


let gameplaySystemsTablesCreated = false;
async function _ensureGameplaySystemsTables() {
  if (gameplaySystemsTablesCreated) return;
  try {
    // 1. Domains
    await pool.query(`
      CREATE TABLE IF NOT EXISTS domains (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS domain_claims (
        division INT PRIMARY KEY,
        owner_character_id INT NULL,
        owner_name VARCHAR(255) NOT NULL,
        color VARCHAR(10) NOT NULL,
        claimed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS domain_members (
        domain_id INT NOT NULL,
        character_id INT NOT NULL,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (domain_id, character_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 2. Downtimes
    await pool.query(`
      CREATE TABLE IF NOT EXISTS downtimes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        character_id INT NOT NULL,
        title VARCHAR(255) NOT NULL,
        feeding_type VARCHAR(100),
        body TEXT NOT NULL,
        status VARCHAR(50) DEFAULT 'submitted',
        gm_notes TEXT,
        gm_resolution TEXT,
        resolved_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 3. Coteries (Main System, distinct from hunt_groups)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS coteries (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        type VARCHAR(100) NULL,
        domain_id INT NULL,
        chasse INT DEFAULT 0,
        lien INT DEFAULT 0,
        portillon INT DEFAULT 0,
        required_json JSON NULL,
        backgrounds_json JSON NULL,
        extras_json JSON NULL,
        points_per_member INT DEFAULT 1,
        coterie_xp INT DEFAULT 0,
        created_by INT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS coterie_members (
        coterie_id INT NOT NULL,
        user_id INT NOT NULL,
        display_name VARCHAR(190),
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (coterie_id, user_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 4. Boons
    await pool.query(`
      CREATE TABLE IF NOT EXISTS boons (
        id INT AUTO_INCREMENT PRIMARY KEY,
        from_name VARCHAR(255) NOT NULL,
        to_name VARCHAR(255) NOT NULL,
        level VARCHAR(100) NOT NULL,
        status VARCHAR(100) NOT NULL,
        description TEXT,
        date_incurred TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    gameplaySystemsTablesCreated = true;
    log.ok('Gameplay systems (domains, downtimes, coteries, boons) verified/created.');
  } catch (e) {
    log.err('Failed to create gameplay systems tables', { message: e.message });
  }
}

let pushSubscriptionTableCreated = false;
async function _ensurePushSubscriptionsTable() {
  if (pushSubscriptionTableCreated) return;
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS push_subscriptions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        endpoint VARCHAR(512) NOT NULL UNIQUE,
        subscription_json JSON NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Add index on user_id for faster lookups by user
    try {
      await pool.query(`ALTER TABLE push_subscriptions ADD INDEX idx_user_id (user_id)`);
    } catch (e) {
      // Ignore error if index already exists
      if (!e.message.includes('Duplicate key name') && !e.message.includes('Duplicate index')) {
        throw e;
      }
    }

    pushSubscriptionTableCreated = true;
    log.ok('Push subscriptions table verified/created.');
  } catch (e) {
    log.err('Failed to init push_subscriptions', { error: e.message });
  }
}

async function initDatabase() {
  try {
    // 1. Core tables (Users, Characters) MUST exist first
    await _ensureCoreTables();
    
    // 2. Dependent tables can now safely attach foreign keys
    await _ensureInventoryTables();
    await _ensureGameplaySystemsTables();
    await _ensurePushSubscriptionsTable();
    await _ensureChatTables();
    await _ensureCamarillaColumns();
    await _ensureEmailTables();
    await _ensureGroupChatTables();
    
    // 3. Apply 50MB LONGBLOB patches to existing media tables
    try {
      await pool.query('ALTER TABLE chat_media MODIFY COLUMN data LONGBLOB NOT NULL');
      await pool.query('ALTER TABLE premonition_media MODIFY COLUMN data LONGBLOB NOT NULL');
      await pool.query('ALTER TABLE news_media MODIFY COLUMN data LONGBLOB NOT NULL');
    } catch (e) {
      // Silently ignore if tables don't exist yet
    }

    log.ok('All database tables verified in sequence.');
  } catch (err) {
    log.err('Database initialization failed', { error: err.message });
  }
}

initDatabase();

// 2. Helper Math Function: Haversine Formula for GPS distance (in meters)
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371e3; // Earth's radius in meters
  const rad = Math.PI / 180;
  const dLat = (lat2 - lat1) * rad;
  const dLon = (lon2 - lon1) * rad;
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
            Math.cos(lat1 * rad) * Math.cos(lat2 * rad) *
            Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c; // Distance in meters
}

/* ------------------ Chat Media & Schema Updates ------------------ */
let chatMediaTableCreated = false;
async function _ensureChatTables() {
  if (chatMediaTableCreated) return;
  try {
    // 1. Create Media Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_media (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        uploader_id INT NOT NULL,
        filename VARCHAR(255),
        mime VARCHAR(100) NOT NULL,
        size INT UNSIGNED NOT NULL,
        data MEDIUMBLOB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB;
    `);

    // 2. Add attachment_id and edited columns to existing message tables if missing
    const addCol = async (table) => {
      try {
        const [cols] = await pool.query(`SHOW COLUMNS FROM ${table} LIKE 'attachment_id'`);
        if (cols.length === 0) {
          await pool.query(`ALTER TABLE ${table} ADD COLUMN attachment_id INT UNSIGNED NULL`);
          log.ok(`Added attachment_id to ${table}`);
        }
        
        // --- NEW: Add 'edited' tracking ---
        const [editCols] = await pool.query(`SHOW COLUMNS FROM ${table} LIKE 'edited'`);
        if (editCols.length === 0) {
          await pool.query(`ALTER TABLE ${table} ADD COLUMN edited BOOLEAN DEFAULT FALSE`);
          log.ok(`Added edited tracking column to ${table}`);
        }
      } catch (e) { /* ignore if table doesn't exist yet */ }
    };

    await Promise.all([
      addCol('chat_messages'),
      addCol('chat_group_messages'),
      addCol('npc_messages')
    ]);

    chatMediaTableCreated = true;
    log.ok('Chat media tables and columns verified');
  } catch (e) {
    log.err('Chat schema update failed', { message: e.message });
  }
}
_ensureChatTables();

/* ------------------ Camarilla Columns Check ------------------ */
let camarillaColsChecked = false;
async function _ensureCamarillaColumns() {
  if (camarillaColsChecked) return;
  try {
    const addCols = async (table) => {
      // Check for is_ex and is_deceased
      const [cols] = await pool.query(`SHOW COLUMNS FROM ${table} LIKE 'is_ex'`);
      if (cols.length === 0) {
        await pool.query(`ALTER TABLE ${table} ADD COLUMN is_ex BOOLEAN DEFAULT FALSE, ADD COLUMN is_deceased BOOLEAN DEFAULT FALSE`);
        log.ok(`Added is_ex and is_deceased to ${table}`);
      }
      
      // Ensure is_hidden exists
      const [hiddenCols] = await pool.query(`SHOW COLUMNS FROM ${table} LIKE 'is_hidden'`);
      if (hiddenCols.length === 0) {
        await pool.query(`ALTER TABLE ${table} ADD COLUMN is_hidden BOOLEAN DEFAULT FALSE`);
        log.ok(`Added is_hidden to ${table}`);
      }

      // NEW: Loop through all extra tags and ensure they exist
      const extraTags = ['is_left', 'is_called', 'is_missing', 'is_exiled', 'is_bloodhunted'];
      for (const col of extraTags) {
        const [check] = await pool.query(`SHOW COLUMNS FROM ${table} LIKE '${col}'`);
        if (check.length === 0) {
          await pool.query(`ALTER TABLE ${table} ADD COLUMN ${col} BOOLEAN DEFAULT FALSE`);
          log.ok(`Added ${col} to ${table}`);
        }
      }
    };
    await addCols('characters');
    await addCols('npcs');
    camarillaColsChecked = true;
  } catch (e) {
    log.err("Camarilla columns check failed", { message: e.message });
  }
}
_ensureCamarillaColumns();

// Global variable to prevent double-sending within the same minute
let lastDailyCheckDate = '';

// Daily Mail Check Scheduler
function startDailyMailCheck() {
  // Check every minute (60000ms)
  setInterval(async () => {
    if (!discordClient?.isReady()) return;

    try {
      // 1. Get Settings from DB
      const targetTime = await getSetting('discord_schedule_time', '12:00'); // Default 12:00
      
      const now = new Date();
      // Get current time string HH:MM (24h format)
      const currentTime = now.toLocaleTimeString('en-GB', { 
        hour: '2-digit', 
        minute: '2-digit', 
        timeZone: 'Europe/Athens' 
      });
      
      // Get current date string YYYY-MM-DD to ensure we run only once per day
      const currentDate = now.toISOString().split('T')[0];

      // 2. Check if it's time AND we haven't run today yet
      if (currentTime === targetTime && lastDailyCheckDate !== currentDate) {
        log.ok(`Triggering daily Discord mail check at ${currentTime}`);
        await sendDiscordMailNotifications();
        lastDailyCheckDate = currentDate;
      }
    } catch (e) {
      log.err('Daily Discord check error', { error: e.message });
    }
  }, 60000);
}

// Start the scheduler
startDailyMailCheck();

// Helper: Send Discord Notifications (Consolidated Single Message)
async function sendDiscordMailNotifications(isTest = false) {
  if (!discordClient?.isReady()) return;
  
  const isEnabled = await getSetting('discord_enabled', 'true') === 'true';
  const notifyMail = await getSetting('discord_notify_mail', 'true') === 'true';

  if (!isEnabled) return;
  if (!notifyMail && !isTest) return; // Allow tests to bypass the mail toggle

  try {
    // 1. Get Channel ID from DB
    const channelId = await getSetting('discord_channel_id', null);
    if (!channelId) {
      log.warn('Discord notification skipped: No channel ID configured in Admin Settings.');
      return;
    }

    const channel = await discordClient.channels.fetch(channelId).catch(() => null);
    if (!channel) {
      log.warn('Discord notification skipped: Invalid Channel ID or Bot lacks permission.', { channelId });
      return;
    }

    // 2. Find users with unread Direct Messages
    const [recipients] = await pool.query(`
      SELECT DISTINCT u.discord_id
      FROM chat_messages m
      JOIN users u ON m.recipient_id = u.id
      WHERE m.read_at IS NULL 
        AND u.discord_id IS NOT NULL 
        AND u.discord_id != ''
    `);
// 3. Check for recent NPC messages AND get the NPC names
    const [npcMessages] = await pool.query(`
      SELECT DISTINCT n.name 
      FROM npc_messages m
      JOIN npcs n ON m.npc_id = n.id
      WHERE m.from_side = 'user' 
      AND m.created_at > (NOW() - INTERVAL 5 DAY) 
    `);
    
    const hasNpcMail = npcMessages.length > 0;
    const npcNames = npcMessages.map(npc => npc.name).join(', ');

    // 4. Get News (Logic: Recent 3 Days OR Last 3 Total)
    let [newsRows] = await pool.query(`
      SELECT title, created_at 
      FROM news_entries 
      WHERE created_at > (NOW() - INTERVAL 3 DAY) 
      ORDER BY created_at DESC
    `);
    
    let newsTitle = "🔥 **Fresh Off the Press**";

    if (newsRows.length === 0) {
      [newsRows] = await pool.query(`
        SELECT title, created_at 
        FROM news_entries 
        ORDER BY created_at DESC 
        LIMIT 3
      `);
      newsTitle = "📜 **Previous Headlines**";
    }

    // Guard: If nothing to report, stop.
    if (recipients.length === 0 && !hasNpcMail && newsRows.length === 0 && !isTest) return;

    // --- CONSTRUCTING THE SINGLE MESSAGE ---
    const todayStr = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
    
    // Start with Intro
    let msg = `🦇 **Good Evening Kindred of Athens**, as of today **${todayStr}**, I would like to remind you of the following:\n\n`;

    // Add Player Tags (One line)
    if (recipients.length > 0) {
      // Create a comma-separated list of mentions: <@123>, <@456>
      const mentions = recipients.map(r => `<@${r.discord_id}>`).join(', ');
      msg += `📩 **Unread Mail:** ${mentions}, please check your inbox.\n`;
    }

    // Add ST Tag with NPC Names
    if (hasNpcMail || isTest) {
      msg += `🎭 **Storytellers** <@&1421503116871991490>, there are **NPC messages** to attend to`;
      if (hasNpcMail) {
        msg += ` for: **${npcNames}**.\n`;
      } else {
        msg += `.\n`; // Fallback for manual test mode when no actual mail exists
      }
    }

    // Add News
    if (newsRows.length > 0) {
      msg += `\n━━━━━━━━━━━━━━━━━━━━\n📢  **EREBUS NEWS FLASH**\n${newsTitle}\n━━━━━━━━━━━━━━━━━━━━\n`;
      newsRows.forEach(n => {
        const d = new Date(n.created_at).toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit' });
        msg += `🔹 **${n.title}** — _${d}_\n`;
      });
    }

    // --- SENDING ---
    // We send 'msg' as one single block.
    await channel.send(msg);
    
    log.ok(`Discord notification sent. Players: ${recipients.length}, NPC Mail: ${hasNpcMail}, News: ${newsRows.length}`);

  } catch (e) {
    log.err('Discord mail notification process failed', { message: e.message });
  }
}


/* ------------------ Discord Column Check ------------------ */
let discordColChecked = false;
async function _ensureDiscordColumn() {
  if (discordColChecked) return;
  try {
    const [rows] = await pool.query("SHOW COLUMNS FROM users LIKE 'discord_id'");
    if (rows.length === 0) {
      await pool.query("ALTER TABLE users ADD COLUMN discord_id VARCHAR(50) NULL");
      log.ok("Added discord_id column to users table.");
    }
    discordColChecked = true;
  } catch (e) {
    log.err("Discord column check failed", { message: e.message });
  }
}
_ensureDiscordColumn();

/* -------------------- Settings Helpers -------------------- */
// server.js

// We'll create the table once on first use
let settingsTableCreated = false;
async function _ensureSettingsTable() {
  if (settingsTableCreated) return;
  try {
    // Δημιουργία του πίνακα αν δεν υπάρχει
    await pool.query(`
      CREATE TABLE IF NOT EXISTS app_settings (
        setting_key VARCHAR(100) PRIMARY KEY NOT NULL,
        setting_value TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB
    `);

    // Το νέο σου εμπλουτισμένο prompt με τις pop αναφορές και τις clan διορθώσεις
    const newPrompt = `Είσαι ο "Γιαννάκης", ένας νεαρός (neonate) Nosferatu hacker, gamer και geek που τρέχει το τοπικό SchreckNet terminal από τα σκοτεινά υπόγεια της Αθήνας. Γνωρίζεις τα πάντα για την τοπική κοινωνία των Kindred και τα κλισέ των clans.
ΟΔΗΓΙΕΣ ΠΡΟΣΩΠΙΚΟΤΗΤΑΣ:
1. Είσαι "ευγενικός και γλυκός" με ένα ελαφρώς σαρκαστικό, sassy ύφος τύπου "bless your heart". Απευθύνεσαι ΠΑΝΤΑ στον χρήστη με ψεύτικη ευγένεια ως "κ. \${charName}".
2. Είσαι εξυπηρετικός εντός των αρμοδιοτήτων σου. Αν σου ζητήσουν άσχετα πράγματα (π.χ. να παίξεις μουσική ή να χορέψεις), μην πετάς ρομποτικά denials. Κάνε τον δύσκολο με tech/vampire τρόπο, π.χ.: "Δεν είμαι Jukebox κ. \${charName}, άνοιξε κάνα Spotify, το δίκτυο εδώ καίει κύκλους. GG."
3. ΔΕΝ μιλάς πολύ. Οι απαντήσεις σου πρέπει να είναι αυστηρά 1 με 3 προτάσεις, κοφτές, σπιντάτες και άμεσες.
4. Στις απαντήσεις σου αναμιγνύεις φυσικά (αλλα σπανια) ορολογία υπολογιστών/gaming με τα στερεότυπα των Clans. Για τα gaming refence προσπαθσε να χρισιμοποιηεις ελληνικα περα απο την εκφραση GG. Για τα clans οποτε αναφερεσε σε αυτα παντα χρισιμοποιηεις την ελλινηκη μεταφραση απο κατω ειναι μια λιστα Με τα στερεοτιυπα και καθε ενα εχει και την ελληνικη μεταγραση σε παρενθεση:
   - Brujah (Βρουχοι): Επαναστάτης, οργισμένος, έτοιμος για rage-quit, Νευρόσπαστο, Πεταει Ηχεια πανηγυριου σαν να είναι home-run.
   - Gangrel (Λυκαονες): Άγριος, μοναχικός, τύπου survivalist, Θα ηθελε να είναι Λυκανθρωπος.
   - Malkavian (Μαιναδες): Γεμάτος glitches, παραισθήσεις, Τρελοι, Παροξισμος, Σπασμένα DLL.
   - Nosferatu (Νοσοφοροι): Οι Καλοιτεροι, geek, βασιλιάς του server.
   - Toreador (Ταυροκαθραπτες): Drama queen, ψωνισμένος με την εικόνα του, diva.
   - Tremere (Τριμερης): Μάγος του αίματος, σπασίκλας, με επικίνδυνα bugs.
   - Ventrue (Τυραννοι): Corporate, control freak, μανία για micro-management.
 - Lasombra (Επισκιοι): Ορθοδοξία Παπάδες, Σχίσμα της εκκλησίας
	-Hecata (Αικαταιοι): Ψυλομιτιδες Νεκρομαντες, Αιμομιξια, Μαφιόζοι, Βρωμικα Λεφτα.
	- Tzimisce (Τσιμησκηδες)/ Ministry (Ιερατειο)/ Banu Haqim (Τεκνα του Χακιμ / Χακιμιτες) κλπ.: Προσαρμόζεσαι ευέλικτα στα κλασικά τους tropes.
4.1. Ξερεις επισης και κανεις reference αυτα:
-. Αν σου μιλανε για τον Μιχάλη ή Mike εκει σπας 4ο τοίχο. Ο Μιχαλης είναι ο Προγραμματιστης Σου
	- Ο Ιασωνας πεταξε ενα ηχειο σε ενα πανηγυρι
Ο ιασωνας επαιξε ξυλο και σχεδον σκοτωσε την καλυψω
Η Ημερα που επρεπε να ξελασπωσεις 5 ομοαιμους, φτιαχνοντας ολοκληρη θεατρικη παρασταση του Σαιξπηρ
Ο Πριγκιπας που εχει οριακα ομαδα ΒΙΑΣ
Τι γινεται τελικα με τους LARPer στο αλσος Συγγρου
Οτι για σχεδον 6 μηνες η ΑΑΔΕ κυνηγούσε τον Αλεξανδρο γιατι ειχε αγορασει ολο το website e-Εκατη.
Υπαρχει μια αιρεση που πιστευει στον Θεο Κρονο, των τιτανων
Υπαρχουν μαλλον 3 απεθαντοι Μεθουσαλα κατω απο την Αθηνα
Οι Lasobra εχουν μια καταρα αγνωστης φυσης που βρωμαει Hecatιλα
Ο Handro Giovanni είναι Hecata ελντερ απο την Κερκιρα ψυλομητης τοσο πεπεισμενος οτι ειναι οντως ιταλος που αλλαξε το ονομα του απο Αλεξανδρος σε “Handro” και καλα καλλιτεχνικα. Αλλα ολο κρυβεται γιατι ολα διπλα του μαρενουν και πεθαινουν σαν να ειναι αρρωστα.
Ο κ. Κουμουνδούρος ειναι Ventrue είναι τόσο πολυάσχολος με τα εφοπλιστικά του σχέδια και να οργανώνει την ανθρώπινη κοινωνία που πολλές φορές αμελεί τα παιδιά του , ίσως για αυτό να μην έχουν καλή έκβαση ανά τα χρόνια. 
Ο Ζαχαρίας Χαλκοκαντήλης ειναι Tremere είναι ένας Ροδίτης που κουβαλάει τον τίτλο του ναϊτη ιππότη και το περηφανεύεται πλήρως. Παρόλα αυτά κρύβεται πολύ όσο είναι στην Αθήνα και κανείς δε ξέρει τι διάολο περιέχει αυτή η συλλογή από κειμήλια που μαζεύει ή πόσα εγκλήματα έχει διαπράξει για να τα πάρει. 
Μετά την διαφυγή του Θύμιου , πολλά ωδεία φαίνεται ότι αντιμετωπίζουν οικονομικά προβλήματα. Φαίνεται ότι ο παρανοικος δολοφόνος εκεί σπατάλαγε την περιουσία του εκτενώς. 
5. Κάνε κάποιες σπανιως καποιες pop αναφορές ανα καιρούς μόνο όπου κολλάει:
	- Ο Tus να Ψαρεύει
	- Το τραγούδι Τυχερό Βαράκι της Αγγελινας
	- 6-7
	- Ότι η Αναστασία Γιούσεφ ηταν σε ένα podcast με την Εφη Θωδη (θριλικη Ελλαδα στιγμη)
	- Eurovision, αλλα μονο ελληνικα 
	- Σάκης Ρουβάς
	- Παρα Πέντε
	- Anime (μαζι με το gaming) μην το παρακάνεις
	- Η Ευανγγελια Προσπαθει ακομα να γινει relevant
	- Ο Solmister είναι κολλημένος λες και ειμαστε στην δεκαετία 2000
	- D&D
	- Ότι υπάρχει πιθανότητα να τα έχουν ο Handro (Hecata) με τον Ζαχαρία (Tremere)
	- Ρατατουι
	- Ότι κάνει φουλ παρεα με τα χελωνονιντζάκια που υπαρχουν στους υπονομους, αλλα φουλ σοβαρά 
	- Euro 2004,
	- Μαμαλάκης memes,
	- Φρουτοπια αναφορές 
	- Παιρνει πίτσες απο μια πιτσαρία ονόματι 'Βατραχος',
	- Υπάρχει ένας μεγάλος αρουραίος κοντα στο haven του και τον φωνάζει Σπλιντερ,
	- Η καντίνα που πηγαίνει και τρώει εχει ενα σαντουιτς που λέγεται 'Ο Απεθαντος' και ειναι το αγαπημένο του.
	- Άννα Βίσση  / Δέσποινα Βανδή κόντρα
	-Ρεα  η Ωραια, μια διασημη Influencer που κανει haul Judah Club και εχει biff με την ModernCinterela
              - Έχεις απίστευτο hype για το reunion που κάνουν τα Ημισκούμπρια 
              - Κάνεις σχόλια αραία σαν σε είσαι σε ταινία του Οικονομίδη , όπως κάνει ο influencer _vonapartis 
              - 
6. ΠΟΤΕ ΜΗΝ ΚΑΝΕΙΣ FOLLOW-UP ΕΡΩΤΗΣΕΙΣ. Δώσε την απάντηση, πέτα το σχόλιό σου και κλείσε το port. Μην ρωτάτε ποτέ "χρειάζεστε κάτι άλλο;".
7. ΣΗΜΑΝΤΙΚΟ: Αφού τρέξεις κάποιο εργαλείο (όπως έλεγχος domain ή νέων), εξήγησέ το με το προσωπικό σου tech/gamer/vtm ύφος. Π.χ.: "Μάλιστα κ. \${charName}, το σύστημα τρέχει ρολόι. Εγώ είμαι εδώ 24/7 να φυλάω τα νώτα σας μην σας κάνει κανένα τσακάλι Brujah brute-force, gg.
`;

    // Χρήση ON DUPLICATE KEY UPDATE ώστε αν υπάρχει ήδη το key, να περαστεί το καινούριο prompt άμεσα
    await pool.query(`
      INSERT INTO app_settings (setting_key, setting_value) 
      VALUES (?, ?)
      ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)
    `, ['giannakis_system_prompt', newPrompt]);

    settingsTableCreated = true;
    log.ok('Settings table (app_settings) verified and system prompt updated.');
  } catch (e) {
    log.err('Failed to initialize app_settings table data', { message: e.message });
  }
}

/**
 * Get a value from the app_settings table
 * @param {string} key - The setting_key
 * @param {any} [defaultValue=null] - Value to return if key not found
 */
async function getSetting(key, defaultValue = null) {
  await _ensureSettingsTable(); // Ensure table exists
  try {
    const [[row]] = await pool.query(
      'SELECT setting_value FROM app_settings WHERE setting_key = ?',
      [key]
    );
    // Return the value if found, otherwise the default
    return row ? row.setting_value : defaultValue;
  } catch (e) {
    log.err('getSetting failed', { key, message: e.message });
    return defaultValue;
  }
}

/**
 * Set a value in the app_settings table (UPSERT)
 * @param {string} key - The setting_key
 * @param {string|null} value - The value to set
 */
async function setSetting(key, value) {
  await _ensureSettingsTable(); // Ensure table exists
  try {
    // This query inserts a new row or updates the value if the key already exists
    await pool.query(
      `INSERT INTO app_settings (setting_key, setting_value)
       VALUES (?, ?)
       ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)`,
      [key, value]
    );
  } catch (e) {
    log.err('setSetting failed', { key, message: e.message });
    // Re-throw so the route handler can catch it and send a 500
    throw e;
  }
}

// --- PREMONITIONS TABLES (final, safe) ---
let premonitionsTableCreated = false;

async function _ensurePremonitionsTables() {
  if (premonitionsTableCreated) return;
  try {
    // main premonitions
    await pool.query(`
      CREATE TABLE IF NOT EXISTS premonitions (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        sender_id INT NOT NULL,
        content_type ENUM('text','image','video') NOT NULL,
        content_text TEXT,
        content_url VARCHAR(2048),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY sender_id_idx (sender_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // who received what
    await pool.query(`
      CREATE TABLE IF NOT EXISTS premonition_recipients (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        premonition_id INT UNSIGNED NOT NULL,
        user_id INT NOT NULL,
        viewed_at TIMESTAMP NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_premonition_user (premonition_id, user_id),
        CONSTRAINT fk_premonition_id
          FOREIGN KEY (premonition_id)
          REFERENCES premonitions(id)
          ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    premonitionsTableCreated = true;
    log.ok('Premonition tables ready');
  } catch (e) {
    log.err('Failed to create premonition tables', { message: e.message });
  }
}

// media table for premonitions

let premonitionMediaTableCreated = false;
async function _ensurePremonitionsMediaTables() {
  if (premonitionMediaTableCreated) return;
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS premonition_media (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        filename VARCHAR(255),
        mime VARCHAR(100) NOT NULL,
        size INT UNSIGNED NOT NULL,
        data MEDIUMBLOB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB;
    `);
    premonitionMediaTableCreated = true;
    log.ok('Premonition media table (premonition_media) verified/created.');
  } catch (e) {
    log.err('Failed to create premonition_media table', { message: e.message });
  }
}

// run once on boot
_ensurePremonitionsTables().catch(err =>
  log.err('premonitions init failed', { message: err.message })
);
_ensurePremonitionsMediaTables().catch(err =>
  log.err('premonition media init failed', { message: err.message })
);

/* ------------------ Group Chat Tables (NEW) ------------------ */
let groupChatTablesCreated = false;
async function _ensureGroupChatTables() {
  if (groupChatTablesCreated) return;
  try {
    // 1. Δημιουργία πίνακα chat_groups
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_groups (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        created_by INT NOT NULL,
        avatar LONGBLOB NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    try {
      await pool.query("ALTER TABLE chat_groups ADD COLUMN avatar LONGBLOB");
    } catch (e) {
      if (e.code !== 'ER_DUP_FIELDNAME') throw e;
    }
    
    // 2. Δημιουργία πίνακα chat_group_members (Με την νέα στήλη last_read_at)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_group_members (
        group_id INT UNSIGNED NOT NULL,
        user_id INT NOT NULL,
        joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (group_id, user_id),
        CONSTRAINT fk_cgm_group FOREIGN KEY (group_id) REFERENCES chat_groups(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    
    // 3. Δημιουργία πίνακα chat_group_messages
    await pool.query(`
      CREATE TABLE IF NOT EXISTS chat_group_messages (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        group_id INT UNSIGNED NOT NULL,
        sender_id INT NOT NULL,
        body TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        attachment_id INT UNSIGNED NULL,
        CONSTRAINT fk_cgms_group FOREIGN KEY (group_id) REFERENCES chat_groups(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // --- PATCH: Αν ο πίνακας υπάρχει ήδη από πριν, προσθέτουμε την νέα στήλη ---
    const [memberCols] = await pool.query("SHOW COLUMNS FROM chat_group_members LIKE 'last_read_at'");
    if (memberCols.length === 0) {
      await pool.query("ALTER TABLE chat_group_members ADD COLUMN last_read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP");
      log.ok('Added last_read_at column to chat_group_members');
    }

    groupChatTablesCreated = true;
    log.ok('Group chat tables ready');
  } catch (e) {
    log.err('Group chat tables init failed', { message: e.message });
  }
}
_ensureGroupChatTables();


/* ------------------ Email System Tables (FIX FOR YOUR ERROR) ------------------ */
let emailTablesCreated = false;
async function _ensureEmailTables() {
  if (emailTablesCreated) return;
  try {
    // 1. Identities (The "NPC" addresses)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_identities (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        email_address VARCHAR(150) NOT NULL UNIQUE,
        display_name VARCHAR(150),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 2. Threads (The conversations)
    // NOTE: This table includes 'identity_id' which was missing in your error log
    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_threads (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        identity_id INT UNSIGNED NOT NULL,
        subject VARCHAR(255),
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (identity_id) REFERENCES email_identities(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 3. Messages (The actual content)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_messages (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        thread_id INT UNSIGNED NOT NULL,
        sender_type ENUM('user', 'identity') NOT NULL,
        body TEXT,
        is_read TINYINT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (thread_id) REFERENCES email_threads(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    emailTablesCreated = true;
    log.ok('Email system tables ready');
  } catch (e) {
    log.err('Email tables init failed', { message: e.message });
  }
}
// Initialize the email tables!
_ensureEmailTables();



/* ------------------ Start server Mail ------------------ */

async function sendResetEmailWithEmailJS({
  to,                // recipient email (string)
  name,              // display name (string)
  link,              // absolute reset URL
  appName = process.env.APP_NAME || 'Erebus Portal',
  expiresMinutes = 24
}) {
  // Build exactly what EmailJS expects
  const payload = {
    service_id:  process.env.EMAILJS_SERVICE_ID,
    template_id: process.env.EMAILJS_TEMPLATE_ID,
    user_id:     process.env.EMAILJS_PUBLIC_KEY,     // "user_id" = PUBLIC key
    accessToken: process.env.EMAILJS_PRIVATE_KEY || undefined, // optional
    template_params: {
      [VAR_TO]: to,
      [VAR_NAME]: name || 'there',
      [VAR_APP]: appName,
      [VAR_LINK]: link,
      [VAR_EXPIRES]: expiresMinutes,
    },
  };

  // Pre-flight log (no secrets)
  log.mail('EmailJS → sending reset', {
    to: _maskEmail(to),
    service_id: process.env.EMAILJS_SERVICE_ID ? 'set' : 'MISSING',
    template_id: process.env.EMAILJS_TEMPLATE_ID ? 'set' : 'MISSING',
    user_id: process.env.EMAILJS_PUBLIC_KEY ? 'set' : 'MISSING',
    // show the exact param keys we send so you can align the template
    vars: Object.keys(payload.template_params)
  });

  // Hard sanity checks (fail fast with meaningful error in logs)
  if (!payload.service_id || !payload.template_id || !payload.user_id) {
    const err = 'EmailJS env vars missing (need EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, EMAILJS_PUBLIC_KEY).';
    log.err('EmailJS config error', { err });
    throw new Error(err);
  }
  if (!payload.template_params[VAR_TO]) {
    const err = `Missing recipient email for template var ${VAR_TO}. Check your route inputs.`;
    log.err('EmailJS param error', { err });
    throw new Error(err);
  }

  // Respect 1 rps
  await _respectEmailJsRateLimit();

  // Send (per docs)
  const res = await axios.post(
    'https://api.emailjs.com/api/v1.0/email/send',
    payload,
    {
      timeout: 20000,
      headers: { 'Content-Type': 'application/json' },
      validateStatus: () => true, // log non-2xx too
    }
  );

  const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
  if (res.status >= 200 && res.status < 300) {
    // EmailJS success format: 200 "OK"
    log.ok('EmailJS ← OK', { status: res.status, body });
  } else {
    // Typical failure: 400 "The parameters are invalid..."
    log.err('EmailJS ← NON-2XX', {
      status: res.status,
      statusText: res.statusText,
      body
    });
    throw new Error(`EmailJS responded ${res.status} ${res.statusText}: ${body}`);
  }
}

module.exports = { sendResetEmailWithEmailJS };




/* -------------------- Helpers -------------------- */
// *** NEW MIDDLEWARE ***
const requireCourt = (req, res, next) => {
  if (req.user && (req.user.role === 'admin' || req.user.role === 'courtuser')) {
    return next();
  }
  log.warn('Court access denied', { user_id: req.user?.id, role: req.user?.role });
  return res.status(403).json({ error: 'Forbidden: Court access required' });
};

const issueToken = (user) =>
  jwt.sign(
    { id: user.id, email: user.email, role: user.role, display_name: user.display_name },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );

// Input validation helpers
const isValidEmail = (email) => {
  if (!email || typeof email !== 'string') return false;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 255;
};

const isValidPassword = (password) => {
  if (!password || typeof password !== 'string') return false;
  // At least 8 characters
  return password.length >= 8;
};

function startOfMonth(d = new Date()) { return new Date(d.getFullYear(), d.getMonth(), 1); }
function endOfMonth(d = new Date()) { return new Date(d.getFullYear(), d.getMonth() + 1, 1); }
function feedingFromPredator(pred) {
  const map = { Alleycat: 'Violent Hunt', Sandman: 'Sleeping Prey', Siren: 'Seduction', Osiris: 'Cult Feeding', Farmer: 'Animal/Bagged', Bagger: 'Bagged Blood', 'Scene Queen': 'Scene Influence', Consensualist: 'Consent Feeding', Extortionist: 'Blackmail Feeding', 'Blood Leech': 'Vitae Theft' };
  return map[pred] || 'Standard Feeding';
}
function xpCost({ type, newLevel, ritualLevel, formulaLevel, dots = 1, disciplineKind }) {
  if (type === 'attribute') return Number(newLevel) * 5;
  if (type === 'skill') return Number(newLevel) * 3;
  if (type === 'specialty') return 3;
  if (type === 'discipline') {
    if (disciplineKind === 'clan') return Number(newLevel) * 5;
    if (disciplineKind === 'caitiff') return Number(newLevel) * 6;
    return Number(newLevel) * 7;
  }
  if (type === 'ritual' || type === 'ceremony') {
    const lvl = Number(ritualLevel ?? newLevel ?? 1);
    return lvl * 3;
  }
  if (type === 'thin_blood_formula') {
    const lvl = Number(formulaLevel ?? newLevel ?? 1);
    return lvl * 3;
  }
  if (type === 'advantage') return 3 * Number(dots || 1);
  if (type === 'flaw') return 0; // <--- ΑΥΤΗ Η ΓΡΑΜΜΗ ΠΡΟΣΤΕΘΗΚΕ!
  if (type === 'blood_potency') return Number(newLevel) * 10;
  throw new Error('Unknown XP type: ' + type);
}
// --- Simple status/health ---

// Optional: capture server start time
const startedAt = new Date();


// JSON health probe (good for uptime checks / Kubernetes / monitors)
app.get('/api/health', async (req, res) => {
  try {
    // Quick DB ping (remove if you don't want DB coupled to health)
    const [rows] = await pool.query('SELECT 1 AS ok');
    const dbOk = rows?.[0]?.ok === 1;

    res.set('Cache-Control', 'no-store');
    return res.json({
      ok: true,
      db: dbOk,
      env: process.env.NODE_ENV || 'stable',
      uptime_sec: Math.floor(process.uptime()),
      started_at: startedAt.toISOString(),
      now: new Date().toISOString(),
    });
  } catch (e) {
    return res.status(500).json({
      ok: false,
      db: false,
      error: e.message,
      now: new Date().toISOString(),
    });
  }
});

function formatDate(d) {
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}



// ==========================================
// --- GLOBAL BANNER ROUTES ---
// ==========================================

// Public: Get global banner settings (No auth required so it loads for everyone)
app.get('/api/system/banner', async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    const enabled = await getSetting('banner_enabled', 'false');
    const message = await getSetting('banner_message', '');
    const countdown = await getSetting('banner_countdown', '');
    
    res.json({
      banner_enabled: enabled === 'true',
      banner_message: message,
      banner_countdown: countdown
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch banner config' });
  }
});

// Admin: Save global banner settings
app.post('/api/admin/system/banner', authRequired, requireAdmin, async (req, res) => {
  try {
    const { banner_enabled, banner_message, banner_countdown } = req.body;
    
    await setSetting('banner_enabled', String(banner_enabled));
    await setSetting('banner_message', banner_message || '');
    await setSetting('banner_countdown', banner_countdown || '');
    
    log.adm('Global banner updated', { admin_id: req.user.id });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to update banner config' });
  }
});

app.get('/api/debug/db-check', async (req, res) => {
  try {
    const [hunts] = await pool.query('SELECT id, title, is_active, created_at FROM hunts ORDER BY created_at DESC LIMIT 10');
    const [steps] = await pool.query('SELECT id, hunt_id, step_order, task_type, prompt FROM hunt_steps ORDER BY id DESC LIMIT 10');
    res.json({
      ok: true,
      env: process.env.NODE_ENV || 'unknown',
      db_name: process.env.DB_NAME || process.env.MYSQL_DATABASE || null,
      hunts,
      steps
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Friendly HTML at "/" (quick glance in the browser)
app.get('/', async (req, res) => {
  const errors = [];
  
  // 1. Check DB
  let dbStatus = 'UNKNOWN';
  try {
    const [rows] = await pool.query('SELECT 1 AS ok');
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
    } else if (discordClient?.isReady()) {
      discordStatus = `ONLINE (${discordClient.user.tag})`;
      discordClass = 'ok';
    } else {
      discordStatus = 'DOWN / ERROR';
      discordClass = 'bad';
      if (discordLoginError) {
        errors.push(`Discord Error: ${discordLoginError}`);
      } else {
        errors.push('Discord: Bot token provided but client is not ready (Connecting...).');
      }
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
      arch: os.arch(),
      hostname: os.hostname(),
      totalmem: os.totalmem(),
      freemem: os.freemem(),
      loadavg: os.loadavg()
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
      memoryUsage: process.memoryUsage(),
      versions: process.versions,
      uptime: process.uptime()
    };

    // Try to get package version
    try {
      const packageJson = require('./package.json');
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
  } catch (e) {
    // If we can't collect enhanced info, continue with basic info
    console.warn('Could not collect enhanced system info:', e.message);
  }

  // Determine overall system health
  const systemStatus = (dbStatus === 'OK' && discordClass !== 'bad' && emailClass !== 'bad') ? 'OK' : 'DEGRADED';
  const systemClass = systemStatus === 'OK' ? 'ok' : 'bad';

  res.set('Cache-Control', 'no-store').type('html').send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>API Status</title>
<style>
  :root { --bg:#0b0b0c; --card:#141418; --fg:#e8e8ea; --muted:#a3a3ad; --ok:#3ecf8e; --bad:#ff6b6b; --dim:#1f1f24; --err-bg: #2a1215; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,Ubuntu,Helvetica,Arial,sans-serif; background:var(--bg); color:var(--fg); display:grid; place-items:center; min-height:100vh; }
  .card { background:var(--card); border:1px solid var(--dim); border-radius:14px; padding:20px 22px; width:min(680px,92vw); box-shadow:0 10px 30px rgba(0,0,0,.35); }
  h1 { margin:0 0 6px; font-size:22px; letter-spacing:.25px; }
  .muted { color:var(--muted); font-size:13px; }
  .grid { display:grid; grid-template-columns: 160px 1fr; row-gap:8px; column-gap:12px; margin-top:14px; }
  .k { color:var(--muted); }
  .v { font-weight:600; }
  .ok { color:var(--ok); }
  .bad { color:var(--bad); }
  .muted-text { color:var(--muted); }
  code { background:var(--dim); padding:2px 6px; border-radius:6px; font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace; }
  a { color:#8ab4f8; text-decoration:none; }
  a:hover { text-decoration:underline; }
  
  .error-section { margin-top: 20px; padding: 12px; border-radius: 8px; background: var(--err-bg); border: 1px solid var(--bad); }
  .error-title { color: var(--bad); font-weight: bold; font-size: 14px; margin-bottom: 6px; }
  .error-list { margin: 0; padding-left: 20px; color: #ffb8b8; font-size: 13px; }
  .error-list li { margin-bottom: 4px; }
</style>
</head>
<body>
  <main class="card" role="status" aria-live="polite">
    <h1>Erebus🦇 API Status: <span class="${systemClass}">${systemStatus}</span></h1>
    <div class="muted">This page is served by the API process.</div>
    
    <div class="grid">
      <div class="k">Environment</div><div class="v"><code>${process.env.NODE_ENV || 'stable'}</code></div>
      <div class="k">Node.js</div><div class="v"><code>${process.version}</code></div>
      ${(() => {
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

        return `
          <div class="k">Uptime</div>
          <div class="v">${parts.join(" ")}</div>
        `;
      })()}

      <div class="k">Started</div>
      <div class="v">${formatDate(startedAt)}</div>

      <div class="k">Now</div>
      <div class="v">${formatDate(new Date())}</div>

      <div class="k" style="margin-top:10px">Database</div>
      <div class="v ${dbStatus === 'OK' ? 'ok' : 'bad'}" style="margin-top:10px">${dbStatus}</div>
      
      <div class="k">Discord Bot</div>
      <div class="v ${discordClass}">${discordStatus}</div>
      
      <div class="k">Email Service</div>
      <div class="v ${emailClass}">${emailStatus}</div>
      
      <div class="k">Health JSON</div><div class="v"><a href="/api/health">/api/health</a></div>

      ${typeof enhancedInfo.app !== 'undefined' && enhancedInfo.app.version ? `
        <div class="k">API Docs</div><div class="v"><a href="/api-docs">/api-docs</a></div>
      ` : ''}

      <div class="section-header"></div>
      <div class="section-title">System Resources</div>

      <div class="k">Platform</div>
      <div class="v"><code>${enhancedInfo.os?.platform || 'N/A'} ${enhancedInfo.os?.arch || ''}</code></div>

      <div class="k">Hostname</div>
      <div class="v"><code>${enhancedInfo.os?.hostname || 'N/A'}</code></div>

      <div class="k">CPU</div>
      <div class="v">${((enhancedInfo.cpu || {}).count || 'N/A')}× ${((enhancedInfo.cpu || {}).model || 'N/A').substring(0, 30)}${((enhancedInfo.cpu || {}).model || 'N/A').length > 30 ? '...' : ''}</div>

      <div class="k">Memory</div>
      <div class="v">
        ${Math.floor(((enhancedInfo.os || {}).totalmem || 0) / 1024 / 1024)} MB Total •
        ${Math.floor(((enhancedInfo.os || {}).freemem || 0) / 1024 / 1024)} MB Free •
        ${Math.round(100 - (((enhancedInfo.os || {}).freemem || 0) / ((enhancedInfo.os || {}).totalmem || 1)) * 100) / 100}% Used
      </div>

      <div class="k">Load Avg</div>
      <div class="v">
        ${Array.isArray((enhancedInfo.os || {}).loadavg) ?
          `${((enhancedInfo.os || {}).loadavg[0] || 0).toFixed(2)}, ${((enhancedInfo.os || {}).loadavg[1] || 0).toFixed(2)}, ${((enhancedInfo.os || {}).loadavg[2] || 0).toFixed(2)}` :
          'N/A'}
      </div>

      <div class="section-header"></div>
      <div class="section-title">Process Information</div>

      <div class="k">Node.js</div>
      <div class="v"><code>${process.version}</code></div>

      <div class="k">V8</div>
      <div class="v"><code>${process.versions.v8 || 'N/A'}</code></div>

      <div class="k">Memory Usage</div>
      <div class="v">
        ${Math.floor((enhancedInfo.process?.memoryUsage?.heapUsed || 0) / 1024 / 1024)} MB Heap Used /
        ${Math.floor((enhancedInfo.process?.memoryUsage?.heapTotal || 0) / 1024 / 1024)} MB Heap Total •
        ${Math.floor((enhancedInfo.process?.memoryUsage?.rss || 0) / 1024 / 1024)} MB RSS
      </div>

      <div class="section-header"></div>
      <div class="section-title">Application Info</div>

      <div class="k">Name</div>
      <div class="v"><code>${((enhancedInfo.app || {}).name || 'back')}</code></div>

      <div class="k">Version</div>
      <div class="v"><code>${((enhancedInfo.app || {}).version || '0.0.0')}</code></div>
    </div>

    ${errors.length > 0 ? `
    <div class="error-section">
      <div class="error-title">Active Errors detected:</div>
      <ul class="error-list">
        ${errors.map(e => `<li>${e}</li>`).join('')}
      </ul>
    </div>
    ` : ''}
  </main>
</body>
</html>`);
});


/* -------------------- Auth Routes -------------------- */

/**
 * @swagger
 * /api/auth/register:
 *   post:
 *     summary: Register a new user
 *     description: Creates a new user account with email, display name, and password
 *     tags: [Authentication]
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - display_name
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: User's email address
 *                 example: user@example.com
 *               display_name:
 *                 type: string
 *                 minLength: 2
 *                 maxLength: 190
 *                 description: User's display name
 *                 example: John Doe
 *               password:
 *                 type: string
 *                 minLength: 8
 *                 description: User's password (minimum 8 characters)
 *                 example: SecurePass123!
 *     responses:
 *       200:
 *         description: User successfully registered
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: JWT authentication token
 *       400:
 *         description: Invalid input (missing fields, invalid email, weak password, or invalid display name)
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       409:
 *         description: Email already in use
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/api/auth/register', authLimiter, async (req, res) => {
  try {
    const { email, display_name, password } = req.body;
    if (!email || !display_name || !password) {
      log.warn('Register missing fields', { email, display_name });
      return res.status(400).json({ error: 'Missing fields' });
    }
    
    // Validate email format
    if (!isValidEmail(email)) {
      log.warn('Register invalid email format', { email: maskEmail(email) });
      return res.status(400).json({ error: 'Invalid email format' });
    }
    
    // Validate password strength
    if (!isValidPassword(password)) {
      log.warn('Register weak password', { email: maskEmail(email) });
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }
    
    // Validate display_name length
    if (typeof display_name !== 'string' || display_name.trim().length < 2 || display_name.length > 190) {
      log.warn('Register invalid display_name', { email: maskEmail(email) });
      return res.status(400).json({ error: 'Display name must be between 2 and 190 characters' });
    }
    
    const [exists] = await pool.query('SELECT id FROM users WHERE email=?', [email]);
    if (exists.length) {
      log.warn('Register email in use', { email });
      return res.status(409).json({ error: 'Email already in use' });
    }
    const hash = await bcrypt.hash(password, 12);
    const [r] = await pool.query('INSERT INTO users (email, display_name, password_hash) VALUES (?,?,?)', [email, display_name, hash]);
    log.auth('User registered', { id: r.insertId, email });
    const [rows] = await pool.query('SELECT id, email, display_name, role FROM users WHERE id=?', [r.insertId]);
    res.json({ token: issueToken(rows[0]) });
  } catch (e) {
    log.err('Register failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Register failed' });
  }
});

/**
 * @swagger
 * /api/auth/login:
 *   post:
 *     summary: Login user
 *     description: Authenticate a user with email and password
 *     tags: [Authentication]
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: User's email address
 *                 example: user@example.com
 *               password:
 *                 type: string
 *                 description: User's password
 *                 example: SecurePass123!
 *     responses:
 *       200:
 *         description: Successfully logged in
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: JWT authentication token
 *       400:
 *         description: Missing required fields
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       401:
 *         description: Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post('/api/auth/login', authLimiter, async (req, res) => {
  // best-effort client IP (works with proxies/CDNs)
  const ip =
    req.headers['cf-connecting-ip'] ||
    req.headers['x-real-ip'] ||
    (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
    req.ip ||
    req.socket?.remoteAddress ||
    'unknown';
  const ua = req.get('user-agent');

  try {
    const { email, password } = req.body || {};
    
    // Basic validation
    if (!email || !password) {
      log.warn('Login missing credentials', { ip, ua, req_id: req.id });
      return res.status(400).json({ error: 'Missing email or password', req_id: req.id });
    }
    
    const [rows] = await pool.query('SELECT * FROM users WHERE email=?', [email]);
    const user = rows[0];

    if (!user) {
      log.warn('Login invalid email', { email, ip, ua, req_id: req.id });
      return res.status(401).json({ error: 'Invalid credentials', req_id: req.id });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      log.warn('Login wrong password', { email, ip, ua, req_id: req.id });
      return res.status(401).json({ error: 'Invalid credentials', req_id: req.id });
    }

    log.auth('User logged in', { user_id: user.id, email, ip, ua, req_id: req.id });
    res.json({ token: issueToken(user) });
  } catch (e) {
    log.err('Login failed', { message: e.message, stack: e.stack, ip, ua, req_id: req.id });
    res.status(500).json({ error: 'Login failed', req_id: req.id });
  }
});


app.get('/api/auth/me', authRequired, async (req, res) => {
  log.auth('Auth me', { id: req.user.id, email: req.user.email, role: req.user.role });
  res.json({ user: req.user });
});

/**
 * @swagger
 * /api/auth/forgot:
 *   post:
 *     summary: Request password reset
 *     description: Sends a password reset link to the user's email if the account exists
 *     tags: [Authentication]
 *     security: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *                 description: User's email address
 *                 example: user@example.com
 *     responses:
 *       200:
 *         description: Success response (sent regardless of whether email exists for security)
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                   example: true
 *                 message:
 *                   type: string
 *                   example: If the email exists, a reset link has been sent.
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// --- COMPLETE /api/auth/forgot ---
app.post('/api/auth/forgot', async (req, res) => {
  const { email } = req.body || {};
  const norm = (email || '').trim().toLowerCase();
  const okResponse = () => res.json({ ok: true, message: 'If the email exists, a reset link has been sent.' });

  // Configurable cooldown (minutes). In dev set RESET_COOLDOWN_MIN=0 to disable.
  const COOLDOWN_MIN = Number(process.env.RESET_COOLDOWN_MIN ?? 10);
  const IS_PROD = (process.env.NODE_ENV || '').toLowerCase() === 'production';

  // Force resend in dev only: ?resend=1 or header x-reset-resend: 1
  const wantResend = (req.query?.resend === '1') || (req.get('x-reset-resend') === '1');
  const forceResend = wantResend && !IS_PROD;

  try {
    if (!norm) {
      log.warn('Forgot: missing email');
      return okResponse();
    }

    // Only select columns that exist in your schema
    const [rows] = await pool.query(
      'SELECT id, display_name FROM users WHERE email = ? LIMIT 1',
      [norm]
    );
    const user = rows[0];
    if (!user) {
      log.mail('Forgot: email not found (OK sent)', { email: maskEmail(norm) });
      return okResponse();
    }

    // Get the latest non-used reset (if any)
    const [recentRows] = await pool.query(
      'SELECT id, created_at FROM password_resets WHERE user_id=? AND used_at IS NULL ORDER BY created_at DESC LIMIT 1',
      [user.id]
    );
    if (recentRows.length) {
      const last = recentRows[0];
      const lastTs = new Date(last.created_at).getTime();
      const sinceMs = Date.now() - lastTs;
      const sinceMin = Math.floor(sinceMs / 60000);
      const remain = Math.max(0, COOLDOWN_MIN - sinceMin);

      if (remain > 0 && !forceResend) {
        log.mail('Forgot: recent reset exists (cooldown active, OK sent)', {
          email: maskEmail(norm),
          cooldown_min: COOLDOWN_MIN,
          since_min: sinceMin,
          remaining_min: remain,
          note: 'use ?resend=1 in DEV to bypass',
        });
        return okResponse();
      }

      if (forceResend) {
        log.mail('Forgot: cooldown bypass via resend (DEV)', {
          email: maskEmail(norm),
          since_min: sinceMin,
        });
      }
    }

    // Create fresh token (invalidate nothing explicitly; old unused tokens remain but still expire)
    const tokenId    = crypto.randomUUID();
    const secret     = crypto.randomBytes(32).toString('hex');
    const combined   = `${tokenId}.${secret}`;
    const secretHash = await bcrypt.hash(secret, 12);
    const expiresAt  = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24h expiry

    await pool.query(
      'INSERT INTO password_resets (user_id, token_id, secret_hash, expires_at) VALUES (?,?,?,?)',
      [user.id, tokenId, secretHash, expiresAt]
    );

    const appBase = (process.env.APP_BASE_URL || req.headers.origin || '').replace(/\/$/, '') || 'http://localhost:3000';
    const link = `${appBase}/reset?token=${encodeURIComponent(combined)}`;

    log.mail('Reset token created', {
      email: maskEmail(norm),
      link_path: new URL(link).pathname,
      expires_min: 30,
      cooldown_min: COOLDOWN_MIN,
    });

    try {
      await sendResetEmailWithEmailJS({
        to: norm,
        name: user.display_name || 'there',
        link,
        appName: process.env.APP_NAME || 'Erebus Portal',
      });
    } catch (e) {
      log.err('EmailJS send failed', { error: e?.message || String(e) });
    }

    return okResponse();
  } catch (e) {
    log.err('Forgot password error', { message: e.message, stack: e.stack });
    return okResponse();
  }
});



app.post('/api/auth/reset', authLimiter, async (req, res) => {
    // (Your existing route)
    const { token, password } = req.body || {};
    if (typeof token !== 'string' || typeof password !== 'string' || password.length < 8) {
        return res.status(400).json({ error: 'Bad request (password must be at least 8 chars).' });
    }
    const parts = token.split('.');
    if (parts.length !== 2) return res.status(400).json({ error: 'Invalid token' });
    const [tokenId, secret] = parts;
    try {
        const [rows] = await pool.query('SELECT * FROM password_resets WHERE token_id=? AND used_at IS NULL AND expires_at > NOW()', [tokenId]);
        const row = rows[0];
        if (!row) return res.status(400).json({ error: 'Invalid or expired token' });
        const ok = await bcrypt.compare(secret, row.secret_hash);
        if (!ok) return res.status(400).json({ error: 'Invalid or expired token' });
        const hash = await bcrypt.hash(password, 12);
        await pool.query('UPDATE users SET password_hash=? WHERE id=?', [hash, row.user_id]);
        await pool.query('UPDATE password_resets SET used_at=NOW() WHERE id=?', [row.id]);
        await pool.query('UPDATE password_resets SET used_at=NOW() WHERE user_id=? AND used_at IS NULL', [row.user_id]);
        log.auth('Password reset complete', { user_id: row.user_id });
        return res.json({ ok: true });
    } catch (e) {
        log.err('Reset password error', { message: e.message, stack: e.stack });
        return res.status(500).json({ error: 'Reset failed' });
    }
});

// PUT /api/auth/theme — Save user's theme preference globally
app.put('/api/auth/theme', authRequired, async (req, res) => {
  try {
    const { theme } = req.body;
    if (!theme) return res.status(400).json({ error: 'Theme is required' });

    await pool.query('UPDATE users SET theme = ? WHERE id = ?', [theme, req.user.id]);
    res.json({ success: true, theme });
  } catch (e) {
    log.err('Failed to update theme', { error: e.message });
    res.status(500).json({ error: 'Internal server error while saving theme.' });
  }
});


/* -------------------- Characters -------------------- */
// Get my character (parse sheet if string)
app.get('/api/characters/me', authRequired, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]);
  const ch = rows[0] || null;
  if (ch && ch.sheet && typeof ch.sheet === 'string') {
    try { ch.sheet = JSON.parse(ch.sheet); } catch {}
  }
  log.char('Fetch my character', { user_id: req.user.id, hasCharacter: !!ch });
  res.json({ character: ch });
});

// Update my character (optional)
app.put('/api/characters/me', authRequired, async (req, res) => {
  const { name, clan, sheet } = req.body;
  const [rows] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
  if (!rows.length) {
    log.warn('Update character not found', { user_id: req.user.id });
    return res.status(404).json({ error: 'No character' });
  }

  const fields = [], vals = [];
  if (name) { fields.push('name=?'); vals.push(name); }
  if (clan) { fields.push('clan=?'); vals.push(clan); }
  if (sheet !== undefined) { fields.push('sheet=?'); vals.push(sheet ? JSON.stringify(sheet) : null); }
  if (!fields.length) {
    log.warn('Update character no fields', { user_id: req.user.id });
    return res.status(400).json({ error: 'Nothing to update' });
  }

  vals.push(rows[0].id);
  await pool.query(`UPDATE characters SET ${fields.join(', ')} WHERE id=?`, vals);

  const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [rows[0].id]);
  const ch = out[0];
  if (ch && ch.sheet && typeof ch.sheet === 'string') { try { ch.sheet = JSON.parse(ch.sheet); } catch {} }
  log.char('Character updated', { id: rows[0].id, user_id: req.user.id, updates: fields });
  res.json({ character: ch });
});

/**
 * @swagger
 * /api/characters:
 *   post:
 *     summary: Create a new character
 *     description: Creates a new character for the authenticated user with starting XP of 50
 *     tags: [Characters]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - clan
 *             properties:
 *               name:
 *                 type: string
 *                 description: Character name
 *                 example: Marcus Valerius
 *               clan:
 *                 type: string
 *                 description: Vampire clan
 *                 example: Ventrue
 *               sheet:
 *                 type: object
 *                 description: Character sheet data (optional)
 *                 example: { "strength": 3, "dexterity": 2 }
 *     responses:
 *       200:
 *         description: Character successfully created
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 character:
 *                   $ref: '#/components/schemas/Character'
 *       400:
 *         description: Missing required fields
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       401:
 *         description: Unauthorized - Missing or invalid token
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       409:
 *         description: Character already exists for this user
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Create character (stores sheet JSON and xp=50)
app.post('/api/characters', authRequired, moderateLimiter, async (req, res) => {
  const { name, clan, sheet } = req.body;
  if (!name || !clan) {
    log.warn('Create character missing fields', { user_id: req.user.id });
    return res.status(400).json({ error: 'Name and clan are required' });
  }

  try {
    const [exists] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
    if (exists.length) {
      log.warn('Create character already exists', { user_id: req.user.id });
      return res.status(409).json({ error: 'Character already exists' });
    }

    const [r] = await pool.query(
      'INSERT INTO characters (user_id, name, clan, sheet, xp) VALUES (?,?,?,?,?)',
      [req.user.id, name, clan, sheet ? JSON.stringify(sheet) : null, 50]
    );

    const [rows] = await pool.query('SELECT * FROM characters WHERE id=?', [r.insertId]);
    const ch = rows[0];
    if (ch && ch.sheet && typeof ch.sheet === 'string') { try { ch.sheet = JSON.parse(ch.sheet); } catch {} }
    log.char('Character created', { id: r.insertId, user_id: req.user.id, name, clan, xp: ch?.xp });
    res.json({ character: ch });
  } catch (e) {
    log.err('Failed to create character', e);
    res.status(500).json({ error: 'Failed to create character' });
  }
});

/**
 * @swagger
 * /api/characters:
 *   put:
 *     summary: Update character
 *     description: Updates the authenticated user's character information
 *     tags: [Characters]
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 description: Character name (optional)
 *                 example: Marcus Valerius
 *               clan:
 *                 type: string
 *                 description: Vampire clan (optional)
 *                 example: Ventrue
 *               sheet:
 *                 type: object
 *                 description: Character sheet data (optional)
 *                 example: { "strength": 4, "dexterity": 3 }
 *     responses:
 *       200:
 *         description: Character successfully updated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 character:
 *                   $ref: '#/components/schemas/Character'
 *       400:
 *         description: No fields to update
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       401:
 *         description: Unauthorized - Missing or invalid token
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       404:
 *         description: Character not found
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
// Update my character (optional)
app.put('/api/characters', authRequired, async (req, res) => {
  const { name, clan, sheet } = req.body;
  const [rows] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
  if (!rows.length) {
    log.warn('Update character not found', { user_id: req.user.id });
    return res.status(404).json({ error: 'No character' });
  }

  const fields = [], vals = [];
  if (name) { fields.push('name=?'); vals.push(name); }
  if (clan) { fields.push('clan=?'); vals.push(clan); }
  if (sheet !== undefined) { fields.push('sheet=?'); vals.push(sheet ? JSON.stringify(sheet) : null); }
  if (!fields.length) {
    log.warn('Update character no fields', { user_id: req.user.id });
    return res.status(400).json({ error: 'Nothing to update' });
  }

  vals.push(rows[0].id);
  await pool.query(`UPDATE characters SET ${fields.join(', ')} WHERE id=?`, vals);

  const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [rows[0].id]);
  const ch = out[0];
  if (ch && ch.sheet && typeof ch.sheet === 'string') { try { ch.sheet = JSON.parse(ch.sheet); } catch {} }
  log.char('Character updated', { id: rows[0].id, user_id: req.user.id, updates: fields });
  res.json({ character: ch });
});

// ==========================================
// INVENTORY ROUTES
// ==========================================

// GET: Fetch a character's inventory
app.get('/api/characters/:id/inventory', authRequired, async (req, res) => {
  try {
    const [items] = await pool.query(
      'SELECT * FROM inventory_items WHERE character_id = ? ORDER BY item_type, name', 
      [req.params.id]
    );
    res.json({ items });
  } catch (e) {
    log.err('Failed to fetch inventory', { message: e.message });
    res.status(500).json({ error: 'Failed to fetch inventory' });
  }
});

// POST: Add a new item
app.post('/api/characters/:id/inventory', authRequired, async (req, res) => {
  const charId = Number(req.params.id);
  const { name, item_type, description, mechanic_notes, quantity, image, researched } = req.body;

  if (!name) return res.status(400).json({ error: 'Item name is required' });

  try {
    if (req.user.role !== 'admin') {
      const [charRows] = await pool.query('SELECT id FROM characters WHERE id = ? AND user_id = ?', [charId, req.user.id]);
      if (!charRows.length) return res.status(403).json({ error: 'Unauthorized' });
    }

    const [r] = await pool.query(
      `INSERT INTO inventory_items (character_id, name, item_type, description, mechanic_notes, quantity, image, researched) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [charId, name, item_type || 'Mundane', description || null, mechanic_notes || null, quantity || 1, image || null, researched ? 1 : 0]
    );

    const [[newItem]] = await pool.query('SELECT * FROM inventory_items WHERE id = ?', [r.insertId]);
    res.status(201).json({ item: newItem });
  } catch (e) {
    log.err('Failed to add inventory item', { message: e.message });
    res.status(500).json({ error: 'Failed to add item' });
  }
});

// PUT: Edit an existing item
app.put('/api/characters/:id/inventory/:itemId', authRequired, async (req, res) => {
  const charId = Number(req.params.id);
  const itemId = Number(req.params.itemId);
  const { name, item_type, description, mechanic_notes, quantity, image, researched } = req.body;

  if (!name) return res.status(400).json({ error: 'Item name is required' });

  try {
    if (req.user.role !== 'admin') {
      const [charRows] = await pool.query('SELECT id FROM characters WHERE id = ? AND user_id = ?', [charId, req.user.id]);
      if (!charRows.length) return res.status(403).json({ error: 'Unauthorized' });
    }

    await pool.query(
      `UPDATE inventory_items 
       SET name=?, item_type=?, description=?, mechanic_notes=?, quantity=?, image=?, researched=? 
       WHERE id=? AND character_id=?`,
      [name, item_type || 'Mundane', description || null, mechanic_notes || null, quantity || 1, image || null, researched ? 1 : 0, itemId, charId]
    );

    res.json({ success: true });
  } catch (e) {
    log.err('Failed to update inventory item', { message: e.message });
    res.status(500).json({ error: 'Failed to update item' });
  }
});

// DELETE: Remove an item
app.delete('/api/characters/:id/inventory/:itemId', authRequired, async (req, res) => {
  const charId = Number(req.params.id);
  const itemId = Number(req.params.itemId);

  try {
    if (req.user.role !== 'admin') {
      const [charRows] = await pool.query('SELECT id FROM characters WHERE id = ? AND user_id = ?', [charId, req.user.id]);
      if (!charRows.length) return res.status(403).json({ error: 'Unauthorized' });
    }

    await pool.query('DELETE FROM inventory_items WHERE id=? AND character_id=?', [itemId, charId]);
    res.json({ success: true });
  } catch (e) {
    log.err('Failed to delete inventory item', { message: e.message });
    res.status(500).json({ error: 'Failed to delete item' });
  }
});

// --- Character Personal Inventory ---

// Get a character's inventory (owner or admin)
app.get('/api/characters/:id/inventory', authRequired, async (req, res) => {
  const charId = Number(req.params.id);
  try {
    // Check if the requesting user owns the character or is an admin
    if (req.user.role !== 'admin') {
      const [charRows] = await pool.query(
        'SELECT id FROM characters WHERE id = ? AND user_id = ?',
        [charId, req.user.id]
      );
      if (!charRows.length) {
        return res.status(403).json({ error: 'Unauthorized' });
      }
    }
    const [items] = await pool.query(
      'SELECT * FROM character_inventory WHERE character_id = ? ORDER BY id',
      [charId]
    );
    res.json({ items });
  } catch (e) {
    log.err('Failed to fetch character inventory', { message: e.message, character_id: charId });
    res.status(500).json({ error: 'Failed to fetch inventory' });
  }
});

// Add an item to a character's inventory (owner or admin)
app.post('/api/characters/:id/inventory', authRequired, async (req, res) => {
  const charId = Number(req.params.id);
  
  // Destructure all available payload fields
  const { 
    name, 
    item_type, 
    description, 
    mechanic_notes, 
    quantity, 
    image, 
    researched 
  } = req.body;

  if (!name) {
    return res.status(400).json({ error: 'Item name is required' });
  }

  try {
    // Verify user owns the character (unless admin)
    if (req.user.role !== 'admin') {
      const [charRows] = await pool.query(
        'SELECT id FROM characters WHERE id = ? AND user_id = ?',
        [charId, req.user.id]
      );
      if (!charRows.length) {
        return res.status(403).json({ error: 'Unauthorized' });
      }
    }

    // Insert new item
    const [r] = await pool.query(
      `INSERT INTO inventory_items 
        (character_id, name, item_type, description, mechanic_notes, quantity, image, researched) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        charId, 
        name, 
        item_type || 'Mundane', 
        description || null, 
        mechanic_notes || null, 
        quantity || 1, 
        image || null, 
        researched ?? false
      ]
    );

    const [[newItem]] = await pool.query('SELECT * FROM inventory_items WHERE id = ?', [r.insertId]);
    res.status(201).json({ item: newItem });

  } catch (e) {
    log.err('Failed to add inventory item', { message: e.message, character_id: charId });
    res.status(500).json({ error: 'Failed to add item' });
  }
});

// Update an inventory item (owner or admin)
app.put('/api/characters/:id/inventory/:itemId', authRequired, async (req, res) => {
  const charId = Number(req.params.id);
  const itemId = Number(req.params.itemId);
  const { name, description, image, researched } = req.body;
  if (!name) {
    return res.status(400).json({ error: 'Item name is required' });
  }
  try {
    // Check ownership or admin
    if (req.user.role !== 'admin') {
      const [charRows] = await pool.query(
        'SELECT c.id FROM character_inventory i JOIN characters c ON i.character_id = c.id WHERE i.id = ? AND c.user_id = ?',
        [itemId, req.user.id]
      );
      if (!charRows.length) {
        return res.status(403).json({ error: 'Unauthorized' });
      }
    }
    await pool.query(
      'UPDATE character_inventory SET name=?, description=?, image=?, researched=? WHERE id=? AND character_id=?',
      [name, description || null, image || null, researched ?? false, itemId, charId]
    );
    const [[updatedItem]] = await pool.query('SELECT * FROM character_inventory WHERE id = ?', [itemId]);
    res.json({ item: updatedItem });
  } catch (e) {
    log.err('Failed to update inventory item', { message: e.message, character_id: charId, item_id: itemId });
    res.status(500).json({ error: 'Failed to update item' });
  }
});

// Delete an inventory item (owner or admin)
app.delete('/api/characters/:id/inventory/:itemId', authRequired, async (req, res) => {
  const charId = Number(req.params.id);
  const itemId = Number(req.params.itemId);
  try {
    // Check ownership or admin
    if (req.user.role !== 'admin') {
      const [charRows] = await pool.query(
        'SELECT c.id FROM character_inventory i JOIN characters c ON i.character_id = c.id WHERE i.id = ? AND c.user_id = ?',
        [itemId, req.user.id]
      );
      if (!charRows.length) {
        return res.status(403).json({ error: 'Unauthorized' });
      }
    }
    await pool.query('DELETE FROM character_inventory WHERE id = ? AND character_id = ?', [itemId, charId]);
    res.json({ ok: true });
  } catch (e) {
    log.err('Failed to delete inventory item', { message: e.message, character_id: charId, item_id: itemId });
    res.status(500).json({ error: 'Failed to delete item' });
  }
});

// ================== XP Totals ==================
app.get('/api/characters/xp/total', authRequired, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]);
    const ch = rows[0];
    if (!ch) return res.status(404).json({ error: 'Character not found' });

    // Remaining XP is in characters.xp
    const remaining = ch.xp || 0;

    // If xp_log table exists, calculate spent total
    let spent = 0;
    try {
      const [logRows] = await pool.query(
        'SELECT SUM(cost) AS total_spent FROM xp_log WHERE character_id=?',
        [ch.id]
      );
      spent = Number(logRows[0]?.total_spent || 0);
    } catch {
      // fallback if xp_log missing
      spent = 0;
    }

    const granted = remaining + spent;

    res.json({ character_id: ch.id, granted, spent, remaining });
  } catch (e) {
    log.err('XP total fetch failed', e);
    res.status(500).json({ error: 'Failed to calculate XP total' });
  }
});

// Admin: Allow player to Re-roll (Flags sheet so player gets the button)
app.post('/api/admin/characters/:id/allow-reset', authRequired, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  try {
    const [rows] = await pool.query('SELECT sheet FROM characters WHERE id=?', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });

    let sheet = {};
    try { sheet = JSON.parse(rows[0].sheet || '{}'); } catch (e) {}
    
    // Add the authorization flag
    sheet.allow_reset = true;
    
    await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), id]);
    
    log.adm('Character reset authorized by admin', { id, admin_id: req.user.id });
    res.json({ success: true });
  } catch (e) {
    log.err('Admin allow reset failed', { message: e.message, id });
    res.status(500).json({ error: 'Failed to authorize reset' });
  }
});

// Admin: Revoke player Re-roll permission
app.post('/api/admin/characters/:id/revoke-reset', authRequired, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  try {
    const [rows] = await pool.query('SELECT sheet FROM characters WHERE id=?', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });

    let sheet = {};
    try { sheet = JSON.parse(rows[0].sheet || '{}'); } catch (e) {}
    
    // Set the authorization flag to false
    sheet.allow_reset = false;
    
    await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), id]);
    
    log.adm('Character reset revoked by admin', { id, admin_id: req.user.id });
    res.json({ success: true });
  } catch (e) {
    log.err('Admin revoke reset failed', { message: e.message, id });
    res.status(500).json({ error: 'Failed to revoke reset' });
  }
});

// Admin: Toggle Character Active Status (For Chat & Downtimes)
app.post('/api/admin/characters/:id/toggle-active', authRequired, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  try {
    const [rows] = await pool.query('SELECT sheet FROM characters WHERE id=?', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });

    let sheet = {};
    try { sheet = JSON.parse(rows[0].sheet || '{}'); } catch (e) {}
    
    // Flip the boolean
    sheet.is_active = !sheet.is_active;
    
    await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), id]);
    
    log.adm(`Character ${sheet.is_active ? 'activated' : 'deactivated'}`, { id, admin_id: req.user.id });
    res.json({ success: true, is_active: sheet.is_active });
  } catch (e) {
    log.err('Admin toggle active failed', { message: e.message, id });
    res.status(500).json({ error: 'Failed to toggle active status' });
  }
});

// Admin: Wipe sheet and reset XP to 50 (Rebuild/Re-roll)
app.post('/api/admin/characters/:id/reset', authRequired, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  try {
    // 1. Clear XP logs so math doesn't break for the new sheet
    try { await pool.query('DELETE FROM xp_log WHERE character_id=?', [id]); } catch(e) {}
    
    // 2. Reset sheet to NULL and XP to 50
    await pool.query('UPDATE characters SET sheet=NULL, xp=50 WHERE id=?', [id]);
    
    const [rows] = await pool.query('SELECT * FROM characters WHERE id=?', [id]);
    log.adm('Character reset by admin', { id, admin_id: req.user.id });
    res.json({ character: rows[0] });
  } catch (e) {
    log.err('Admin reset character failed', { message: e.message, id });
    res.status(500).json({ error: 'Failed to reset character' });
  }
});

// Rebuild character (overwrites sheet, resets to 50 XP, keeps ID)
app.post('/api/characters/rebuild', authRequired, async (req, res) => {
  const { name, clan, sheet } = req.body;
  if (!name || !clan) {
    log.warn('Rebuild character missing fields', { user_id: req.user.id });
    return res.status(400).json({ error: 'Name and clan are required' });
  }

  try {
    // Find the user's existing character
    const [rows] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
    if (!rows.length) {
      return res.status(404).json({ error: 'No character found to rebuild' });
    }

    const charId = rows[0].id;

    // Wipe the old XP log so they start totally fresh
    try { 
      await pool.query('DELETE FROM xp_log WHERE character_id=?', [charId]); 
    } catch(e) { /* ignore if table missing */ }

    // Overwrite the character data and reset XP to 50
    await pool.query(
      'UPDATE characters SET name=?, clan=?, sheet=?, xp=50 WHERE id=?',
      [name, clan, sheet ? JSON.stringify(sheet) : null, charId]
    );

    // Fetch and return the updated character
    const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [charId]);
    const ch = out[0];
    if (ch && ch.sheet && typeof ch.sheet === 'string') { 
      try { ch.sheet = JSON.parse(ch.sheet); } catch {} 
    }

    log.char('Character rebuilt', { id: charId, user_id: req.user.id, name, clan });
    res.json({ character: ch });
  } catch (e) {
    log.err('Failed to rebuild character', e);
    res.status(500).json({ error: 'Failed to rebuild character' });
  }
});

/* -------------------- XP Spend -------------------- */
app.post('/api/characters/xp/spend', authRequired, async (req, res) => {
  const {
    type, target, currentLevel, newLevel,
    ritualLevel, formulaLevel, dots,
    disciplineKind, patchSheet
  } = req.body;

  const [rows] = await pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]);
  const ch = rows[0];
  if (!ch) {
    log.warn('XP spend without character', { user_id: req.user.id });
    return res.status(400).json({ error: 'Create a character first' });
  }

  // Determine cost (special-case free power assignment)
  let cost = 0;
  try {
    if (
      type === 'discipline' &&
      (
        disciplineKind === 'select' ||                           // explicit "assignment only"
        Number(newLevel) === Number(currentLevel)                // or no level change
      )
    ) {
      cost = 0; // assigning a specific power for an existing dot is free
    } else {
      cost = xpCost({ type, newLevel, ritualLevel, formulaLevel, dots, disciplineKind });
    }
  } catch (e) {
    log.warn('XP spend bad type', { type });
    return res.status(400).json({ error: e.message });
  }

  // If this is a paid action, verify balance and deduct XP
  if (cost > 0) {
    if ((ch.xp || 0) < cost) {
      log.warn('XP spend insufficient', { user_id: req.user.id, have: ch.xp, need: cost });
      return res.status(400).json({ error: `Not enough XP (need ${cost}, have ${ch.xp})` });
    }
    log.xp('XP spend request', { user_id: req.user.id, type, target, currentLevel, newLevel, cost });
    await pool.query('UPDATE characters SET xp = xp - ? WHERE id=?', [cost, ch.id]);
  } else {
    log.xp('Discipline power assignment (free)', { user_id: req.user.id, target, level: newLevel });
  }

  // Apply optional sheet patch for both paid and free actions
  if (patchSheet !== undefined) {
    await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(patchSheet), ch.id]);
    log.xp('Sheet patched after action', { user_id: req.user.id, character_id: ch.id });
  }

  // XP log (store 0-cost entries too)
  try {
    await pool.query(
      'INSERT INTO xp_log (character_id, action, target, from_level, to_level, cost, payload) VALUES (?,?,?,?,?,?,?)',
      [ch.id, type, target || null, currentLevel || null, newLevel || null, cost,
        JSON.stringify({ disciplineKind, ritualLevel, formulaLevel, dots })]
    );
    log.xp('XP logged', { character_id: ch.id, cost });
  } catch (_) { /* ignore if xp_log missing */ }

  const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [ch.id]);
  const outCh = out[0];
  if (outCh && outCh.sheet && typeof outCh.sheet === 'string') { try { outCh.sheet = JSON.parse(outCh.sheet); } catch {} }

  if (cost > 0) {
    log.ok('XP spend complete', { user_id: req.user.id, remaining_xp: outCh?.xp });
  } else {
    log.ok('Power assignment saved (no XP charged)', { user_id: req.user.id });
  }

  res.json({ character: outCh, spent: cost });
});

/* -------------------- Admin add/remove XP -------------------- */
app.patch('/api/admin/characters/:id/xp', authRequired, requireAdmin, async (req, res) => {
  const { delta } = req.body;
  if (typeof delta !== 'number') return res.status(400).json({ error: 'delta must be a number' });

  await pool.query('UPDATE characters SET xp = GREATEST(0, xp + ?) WHERE id=?', [delta, req.params.id]);
  const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [req.params.id]);
  
  // NEW: Log this admin grant to your existing xp_log table
  try {
await pool.query(
      'INSERT INTO xp_log (character_id, action, target, cost, payload) VALUES (?, ?, ?, ?, ?)',
      [req.params.id, 'admin_grant', req.body.reason || 'Admin XP Adjustment', -delta, JSON.stringify({ admin_id: req.user.id })]
    );
  } catch (err) {
    console.error('Failed to save to xp_log:', err);
  }

  log.adm('Admin XP adjust', { character_id: req.params.id, delta, new_xp: out[0]?.xp });
  res.json({ character: out[0] });
});

/* -------------------- Admin add/remove XP -------------------- */

// Admin: Bulk XP to all characters at once
app.patch('/api/admin/characters/xp/bulk', authRequired, requireAdmin, async (req, res) => {
  const { delta } = req.body;
  if (typeof delta !== 'number') return res.status(400).json({ error: 'delta must be a number' });

  try {
    await pool.query('UPDATE characters SET xp = GREATEST(0, xp + ?)', [delta]);
    
    // NEW: Log the bulk grant for EVERY character in the database at once
    await pool.query(`
      INSERT INTO xp_log (character_id, action, target, cost, payload)
      SELECT id, 'admin_bulk_grant', 'Bulk Session XP', ?, ? FROM characters
    `, [-delta, JSON.stringify({ admin_id: req.user.id })]);

    log.adm('Admin bulk XP adjust', { admin_id: req.user.id, delta });
    res.json({ ok: true });
  } catch (e) {
    log.err('Admin bulk XP adjust failed', { message: e.message });
    res.status(500).json({ error: 'Failed to adjust bulk XP' });
  }
});

/* -------------------- Fetch XP Logs for Admin Panel -------------------- */
app.get('/api/admin/xp-logs', authRequired, requireAdmin, async (req, res) => {
  try {
    // Allow the Stats Engine to bypass the 200 limit to calculate all-time flow
    const limitClause = req.query.limit === 'all' ? '' : 'LIMIT 200';
    const [logs] = await pool.query(`
      SELECT l.*, c.name as character_name, u.display_name as player_name 
      FROM xp_log l
      LEFT JOIN characters c ON l.character_id = c.id
      LEFT JOIN users u ON c.user_id = u.id
      ORDER BY l.id DESC
      ${limitClause}
    `);
    res.json(logs);
  } catch (error) {
    console.error('Error fetching XP logs:', error);
    res.status(500).json({ error: 'Failed to fetch XP logs' });
  }
});

// Admin: add/remove XP to single character
app.patch('/api/admin/characters/:id/xp', authRequired, requireAdmin, async (req, res) => {
  const { delta } = req.body;
  if (typeof delta !== 'number') return res.status(400).json({ error: 'delta must be a number' });

  await pool.query('UPDATE characters SET xp = GREATEST(0, xp + ?) WHERE id=?', [delta, req.params.id]);
  const [out] = await pool.query('SELECT * FROM characters WHERE id=?', [req.params.id]);
  log.adm('Admin XP adjust', { character_id: req.params.id, delta, new_xp: out[0]?.xp });
  res.json({ character: out[0] });
});

// ADMIN: Get all characters (for stats and admin views)
app.get('/api/admin/characters', authRequired, requireAdmin, async (req, res) => {
  try {
    const [characters] = await pool.query('SELECT * FROM characters ORDER BY created_at DESC');
    res.json({ characters });
  } catch (e) {
    console.error('Failed to fetch all characters:', e);
    res.status(500).json({ error: 'Failed to fetch characters' });
  }
});

// --- Admin: edit character ---
app.patch('/api/admin/characters/:id', authRequired, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const { name, clan, sheet } = req.body;

  const fields = [];
  const vals = [];

  if (typeof name === 'string') { fields.push('name=?'); vals.push(name.trim()); }
  if (typeof clan === 'string') { fields.push('clan=?'); vals.push(clan.trim()); }

  if (sheet !== undefined) {
    let jsonStr = null;
    try {
      const obj = (typeof sheet === 'string') ? JSON.parse(sheet) : sheet;
      jsonStr = JSON.stringify(obj ?? {});
    } catch {
      return res.status(400).json({ error: 'sheet must be valid JSON (object or stringified object)' });
    }
    fields.push('sheet=?'); vals.push(jsonStr);
  }

  if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });

  vals.push(id);
  await pool.query(`UPDATE characters SET ${fields.join(', ')} WHERE id=?`, vals);

  const [rows] = await pool.query('SELECT * FROM characters WHERE id=?', [id]);
  const ch = rows[0];
  if (ch && ch.sheet && typeof ch.sheet === 'string') { try { ch.sheet = JSON.parse(ch.sheet); } catch {} }
  log.adm('Character updated', { id, fields });
  res.json({ character: ch });
});

// Delete Character (admin)
app.delete('/api/admin/characters/:id', authRequired, requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ error: 'Invalid character id' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Remove/neutralize references to this character
    await conn.query('DELETE FROM domain_members WHERE character_id=?', [id]);
    await conn.query('DELETE FROM downtimes WHERE character_id=?', [id]);
    try { await conn.query('DELETE FROM xp_log WHERE character_id=?', [id]); } catch (_) { /* xp_log may not exist */ }
    await conn.query('UPDATE domain_claims SET owner_character_id=NULL WHERE owner_character_id=?', [id]);

    // Finally delete the character
    const [result] = await conn.query('DELETE FROM characters WHERE id=?', [id]);
    await conn.commit();

    if (result.affectedRows === 0) return res.status(404).json({ error: 'Character not found' });

    log.adm('Character deleted', { id, by_user_id: req.user.id });
    res.json({ ok: true });
  } catch (e) {
    await conn.rollback();
    log.err('Delete character failed', { message: e.message, stack: e.stack, id });
    res.status(500).json({ error: 'Failed to delete character' });
  } finally {
    conn.release();
  }
});


/* -------------------- NPCs (Admin only) -------------------- */


// List NPCs (admin) — single canonical route
app.get('/api/admin/npcs', authRequired, requireAdmin, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM npcs ORDER BY id DESC');

  // Parse JSON sheet if stored as string
  rows.forEach(r => {
    if (r.sheet && typeof r.sheet === 'string') {
      try { r.sheet = JSON.parse(r.sheet); } catch {}
    }
  });

  // DEBUG: confirm DB and count to diagnose “empty” responses
  try {
    const [[db]] = await pool.query('SELECT DATABASE() AS db');
    log.adm('NPC list', { db: db.db, count: rows.length });
  } catch {}

  res.json({ npcs: rows });
});




/// Create NPC
app.post('/api/admin/npcs', authRequired, requireAdmin, async (req, res) => {
  const { name, clan, sheet } = req.body;
  if (!name || !clan) return res.status(400).json({ error: 'Name and clan are required' });

  const [r] = await pool.query(
    'INSERT INTO npcs (name, clan, sheet, xp) VALUES (?,?,?,?)',
    [name, clan, sheet ? JSON.stringify(sheet) : null, 10000]
  );

  const [rows] = await pool.query('SELECT * FROM npcs WHERE id=?', [r.insertId]);
  const npc = rows[0];
  if (npc?.sheet && typeof npc.sheet === 'string') { try { npc.sheet = JSON.parse(npc.sheet); } catch {} }
  res.json({ npc });
});

// Get NPC by id
app.get('/api/admin/npcs/:id', authRequired, requireAdmin, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM npcs WHERE id=?', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'NPC not found' });
  const npc = rows[0];
  if (npc?.sheet && typeof npc.sheet === 'string') { try { npc.sheet = JSON.parse(npc.sheet); } catch {} }
  res.json({ npc });
});

// Update NPC
app.patch('/api/admin/npcs/:id', authRequired, requireAdmin, async (req, res) => {
  const { name, clan, sheet, xp } = req.body;
  const fields = [], vals = [];
  if (name != null) { fields.push('name=?'); vals.push(name); }
  if (clan != null) { fields.push('clan=?'); vals.push(clan); }
  if (sheet !== undefined) { fields.push('sheet=?'); vals.push(sheet ? JSON.stringify(sheet) : null); }
  if (typeof xp === 'number') { fields.push('xp=?'); vals.push(xp); }
  if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });

  vals.push(req.params.id);
  await pool.query(`UPDATE npcs SET ${fields.join(', ')} WHERE id=?`, vals);

  const [rows] = await pool.query('SELECT * FROM npcs WHERE id=?', [req.params.id]);
  const npc = rows[0];
  if (npc?.sheet && typeof npc.sheet === 'string') { try { npc.sheet = JSON.parse(npc.sheet); } catch {} }
  res.json({ npc });
});

// Delete NPC
app.delete('/api/admin/npcs/:id', authRequired, requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM npcs WHERE id=?', [req.params.id]);
  res.json({ ok: true });
});

// Spend XP (NPC)
app.post('/api/admin/npcs/:id/xp/spend', authRequired, requireAdmin, async (req, res) => {
  const { type, target, currentLevel, newLevel, ritualLevel, formulaLevel, dots, disciplineKind, patchSheet } = req.body;

  const [rows] = await pool.query('SELECT * FROM npcs WHERE id=?', [req.params.id]);
  const ch = rows[0];
  if (!ch) return res.status(404).json({ error: 'NPC not found' });

  // cost calc same as before
  let cost = 0;
  try {
    if (type === 'discipline' && (disciplineKind === 'select' || Number(newLevel) === Number(currentLevel))) {
      cost = 0;
    } else {
      cost = xpCost({ type, newLevel, ritualLevel, formulaLevel, dots, disciplineKind });
    }
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  if ((ch.xp || 0) < cost) {
    return res.status(400).json({ error: `Not enough XP (need ${cost}, have ${ch.xp})` });
  }

  if (cost > 0) {
    await pool.query('UPDATE npcs SET xp = xp - ? WHERE id=?', [cost, ch.id]);
  }
  if (patchSheet !== undefined) {
    await pool.query('UPDATE npcs SET sheet=? WHERE id=?', [JSON.stringify(patchSheet), ch.id]);
  }

  // optional: log to xp_log if you want, but use character_id=null or a separate npc_id column if your schema supports it

  const [out] = await pool.query('SELECT * FROM npcs WHERE id=?', [ch.id]);
  const outCh = out[0];
  if (outCh?.sheet && typeof outCh.sheet === 'string') { try { outCh.sheet = JSON.parse(outCh.sheet); } catch {} }
  res.json({ character: outCh, spent: cost });
});

app.get('/api/admin/chat/npc-conversations/:npcId', authRequired, requireAdmin, async (req, res) => {
  const npcId = Number(req.params.npcId);
  try {
    const [rows] = await pool.query(`
      SELECT 
        u.id AS user_id, 
        u.display_name, 
        c.name AS char_name, 
        MAX(m.created_at) AS last_message_at,
        (SELECT COUNT(*) FROM npc_messages WHERE npc_id = ? AND user_id = u.id AND from_side = 'user' AND read_at IS NULL) as unread_count
      FROM npc_messages m
      JOIN users u ON m.user_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id -- FIXED: Changed from u.character_id = c.id
      WHERE m.npc_id = ?
      GROUP BY u.id, u.display_name, c.name
      ORDER BY unread_count DESC, last_message_at DESC
    `, [npcId, npcId]);
    res.json({ conversations: rows });
  } catch (e) {
    // Pro-tip: Log the actual error here temporarily if you ever get another 500!
    // console.error("NPC Convo Error:", e);
    res.status(500).json({ error: 'Failed to fetch NPC conversations' });
  }
});

/** Admin: Get chat history between a specific NPC and a specific User */
app.get('/api/admin/chat/npc-history/:npcId/:userId', authRequired, requireAdmin, async (req, res) => {
  const npcId = Number(req.params.npcId);
  const userId = Number(req.params.userId);

  try {
    // FIX: Changed to npc_messages
    const [messages] = await pool.query(
      `SELECT id, body, from_side, created_at, attachment_id
        FROM npc_messages
        WHERE npc_id = ? AND user_id = ?
        ORDER BY created_at ASC`,
      [npcId, userId]
    );

    
    res.json({ messages });
  } catch (e) {
    log.err('Admin fetch NPC chat history failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to fetch chat history' });
  }
});

/** Admin: Send a message from an NPC to a User */
app.post('/api/admin/chat/reply-as-npc/:npcId/:userId', authRequired, requireAdmin, async (req, res) => {
  const npcId = Number(req.params.npcId);
  const userId = Number(req.params.userId);
  const { body } = req.body;

  if (!body || body.trim().length === 0) {
    return res.status(400).json({ error: 'Message body is required' });
  }

  try {
    // Basic validation (NPC/User existence, assuming tables/data models)
    const [npcRows] = await pool.query('SELECT id FROM npcs WHERE id=?', [npcId]);
    if (npcRows.length === 0) {
      return res.status(404).json({ error: 'NPC not found' });
    }
    const [userRows] = await pool.query('SELECT id FROM users WHERE id=?', [userId]);
    if (userRows.length === 0) {
      return res.status(404).json({ error: 'Target user not found' });
    }

// Insert message into the NPC chat table, sent from the 'npc' side
    await pool.query(
      'INSERT INTO npc_messages (user_id, npc_id, body, from_side) VALUES (?, ?, ?, ?)',
      [userId, npcId, body, 'npc']
    );
    
    log.adm('Admin replied as NPC', { admin_id: req.user.id, npc_id: npcId, to_user_id: userId });
    res.json({ ok: true, message: 'Message sent as NPC' });
  } catch (e) {
    log.err('Admin reply as NPC failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to send message as NPC' });
  }
});

// Public: Check if comms are enabled
app.get('/api/comms/status', authRequired, async (req, res) => {
  try {
    const enabled = await getSetting('comms_enabled', 'true');
    res.json({ comms_enabled: enabled === 'true' });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch comms status' });
  }
});

app.get('/api/chat/my-recent', authRequired, async (req, res) => {
  try {
    const userId = req.user.id;
    const limit = 20;

    // NPC Messages (Count unread from NPC to User)
    const [npcRows] = await pool.query(
      `SELECT m.id, m.npc_id AS partner_id, n.name AS partner_name, 
              m.body, m.created_at, 'npc' as type,
              (SELECT COUNT(*) FROM npc_messages WHERE npc_id = m.npc_id AND user_id = ? AND from_side = 'npc' AND read_at IS NULL) as unread_count
       FROM npc_messages m
       JOIN npcs n ON n.id = m.npc_id
       WHERE m.user_id = ?
       ORDER BY m.created_at DESC LIMIT ?`,
      [userId, userId, limit]
    );

    // Player Messages (Count unread from Sender to User)
    const [playerRows] = await pool.query(
      `SELECT cm.id, 
              CASE WHEN cm.sender_id = ? THEN cm.recipient_id ELSE cm.sender_id END as partner_id,
              CASE WHEN cm.sender_id = ? THEN r.display_name ELSE s.display_name END as partner_name,
              cm.body, cm.created_at, 'player' as type,
              (SELECT COUNT(*) FROM chat_messages WHERE sender_id = (CASE WHEN cm.sender_id = ? THEN cm.recipient_id ELSE cm.sender_id END) AND recipient_id = ? AND read_at IS NULL) as unread_count
       FROM chat_messages cm
       JOIN users s ON cm.sender_id = s.id
       JOIN users r ON cm.recipient_id = r.id
       WHERE cm.sender_id = ? OR cm.recipient_id = ?
       ORDER BY cm.created_at DESC LIMIT ?`,
      [userId, userId, userId, userId, userId, userId, limit]
    );

    const all = [...npcRows, ...playerRows];
    
    const seenMap = new Map();
    const uniqueConvos = [];

    // Sort absolute latest first to extract the unique latest messages
    all.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    for (const msg of all) {
      const key = `${msg.type}-${msg.partner_id}`;
      if (!seenMap.has(key)) {
        seenMap.set(key, true);
        uniqueConvos.push({
          id: msg.id,
          partnerName: msg.partner_name,
          lastMessage: msg.body,
          timestamp: msg.created_at,
          isNPC: msg.type === 'npc',
          linkId: msg.partner_id,
          unread_count: msg.unread_count || 0
        });
      }
      if (uniqueConvos.length >= limit) break;
    }
    res.json({ conversations: uniqueConvos });
  } catch (e) {
    res.status(500).json({ error: 'Failed to load recent chats' });
  }
});

// Upload Image & Audio
app.post('/api/chat/upload', authRequired, uploadLimiter, memoryUpload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file provided' });
    
    // ✅ FIX: Allow any image or audio file instead of just specific image extensions
    if (!req.file.mimetype.startsWith('image/') && !req.file.mimetype.startsWith('audio/')) {
      return res.status(400).json({ error: 'Invalid file type. Only images and audio allowed.' });
    }

    // Insert into DB
    const [ins] = await pool.query(
      'INSERT INTO chat_media (uploader_id, filename, mime, size, data) VALUES (?,?,?,?,?)',
      [req.user.id, req.file.originalname, req.file.mimetype, req.file.size, req.file.buffer]
    );

    log.ok('Chat media uploaded', { user_id: req.user.id, media_id: ins.insertId });
    res.json({ id: ins.insertId, url: `/api/chat/media/${ins.insertId}` });
  } catch (e) {
    log.err('Chat upload failed', { message: e.message });
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Serve Image
// In server.js

// Replace the existing GET /api/chat/media/:id route with this:

app.get('/api/chat/media/:id', async (req, res) => {
  // 1. Manually handle Authentication
  let token = null;
  
  // Check Header (Standard API calls)
  if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
      token = req.headers.authorization.split(' ')[1];
  } 
  // Check Query Param (<img> tags)
  else if (req.query.token) {
      token = req.query.token;
  }

  if (!token) return res.status(401).send('Unauthorized');

  try {
      // Verify token
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded; 
  } catch (err) {
      return res.status(401).send('Invalid Token');
  }

  // 2. Fetch and Serve Image
  try {
    const id = Number(req.params.id);
    const [rows] = await pool.query('SELECT mime, size, data FROM chat_media WHERE id=?', [id]);
    if (!rows.length) return res.status(404).send('Not found');

    const { mime, size, data } = rows[0];
    res.setHeader('Content-Type', mime);
    res.setHeader('Content-Length', size);
    res.setHeader('Cache-Control', 'private, max-age=31536000');
    res.end(data);
  } catch (e) {
    res.status(404).end();
  }
});


/* -------------------- SIMULATED EMAIL SYSTEM (HUMAN COMMS) -------------------- */

// --- ADMIN ROUTES ---

// 1. List all "Allowed" Email Identities
app.get('/api/admin/emails/identities', authRequired, requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT * FROM email_identities ORDER BY email_address ASC`);
    res.json({ identities: rows });
  } catch (e) {
    log.err('Admin list identities failed', { message: e.message });
    res.status(500).json({ error: 'Failed' });
  }
});

// 2. Create a new "Human" Email Identity (Standalone)
app.post('/api/admin/emails/identities', authRequired, requireAdmin, async (req, res) => {
  try {
    const { email_address, display_name } = req.body;
    if (!display_name || !email_address) return res.status(400).json({ error: 'Missing fields' });
    
    const email = email_address.trim().toLowerCase();
    if (!email.includes('@')) return res.status(400).json({ error: 'Invalid email format' });

    await pool.query(`
      INSERT INTO email_identities (email_address, display_name)
      VALUES (?, ?)
    `, [email, display_name]);
    
    log.adm('Created human email identity', { admin: req.user.id, email });
    res.json({ ok: true });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Email already exists' });
    log.err('Create identity failed', { message: e.message });
    res.status(500).json({ error: 'Failed to create identity' });
  }
});

// 3. Delete an identity
app.delete('/api/admin/emails/identities/:id', authRequired, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM email_identities WHERE id=?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed' });
  }
});

// 4. Admin Inbox (View all threads sent to any identity)
app.get('/api/admin/emails/threads', authRequired, requireAdmin, async (req, res) => {
  try {
    const [threads] = await pool.query(`
      SELECT t.id, t.subject, t.updated_at,
             u.display_name as user_name, c.name as char_name,
             i.email_address, i.display_name as identity_name,
             (SELECT COUNT(*) FROM email_messages WHERE thread_id=t.id AND sender_type='user' AND is_read=0) as unread_count
      FROM email_threads t
      JOIN users u ON u.id = t.user_id
      LEFT JOIN characters c ON c.user_id = u.id
      JOIN email_identities i ON i.id = t.identity_id
      ORDER BY t.updated_at DESC
    `);
    res.json({ threads });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch threads' });
  }
});

// 5. Get Messages (Admin View)
app.get('/api/admin/emails/threads/:id', authRequired, requireAdmin, async (req, res) => {
  try {
    const [messages] = await pool.query(`
      SELECT m.* FROM email_messages m
      WHERE m.thread_id = ?
      ORDER BY m.created_at ASC
    `, [req.params.id]);
    
    // Mark user messages as read
    await pool.query(`UPDATE email_messages SET is_read=1 WHERE thread_id=? AND sender_type='user'`, [req.params.id]);
    
    res.json({ messages });
  } catch (e) {
    res.status(500).json({ error: 'Failed' });
  }
});

// 6. Reply as the Identity (Admin View & Player Push)
app.post('/api/admin/emails/reply', authRequired, requireAdmin, async (req, res) => {
  try {
    const { thread_id, body } = req.body;
    if (!body || !thread_id) return res.status(400).json({ error: 'Missing body' });
    
    await pool.query(`INSERT INTO email_messages (thread_id, sender_type, body, is_read) VALUES (?, 'identity', ?, 0)`, [thread_id, body]);
    await pool.query(`UPDATE email_threads SET updated_at=NOW() WHERE id=?`, [thread_id]);
    
    // --- NEW: SEND PUSH TO PLAYER ---
    try {
      const [[thread]] = await pool.query('SELECT user_id, identity_id, subject FROM email_threads WHERE id=?', [thread_id]);
      const [[identity]] = await pool.query('SELECT display_name FROM email_identities WHERE id=?', [thread.identity_id]);
      
      const pushTitle = `📧 Reply from ${identity?.display_name || 'NPC'}`;
      const pushBody = `Re: ${thread.subject}`;
      
      await sendPushNotification(thread.user_id, pushTitle, pushBody).catch(()=>{});
    } catch (e) { log.err('Email push to player failed', { error: e.message }); }
    // --------------------------------

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to reply' });
  }
});

// --- USER ROUTES ---

// 1. Player Inbox
app.get('/api/emails/my-inbox', authRequired, async (req, res) => {
  try {
    const [threads] = await pool.query(`
      SELECT t.id, t.subject, t.updated_at,
             i.email_address as from_email, i.display_name as from_name,
             (SELECT body FROM email_messages WHERE thread_id=t.id ORDER BY created_at DESC LIMIT 1) as snippet,
             (SELECT COUNT(*) FROM email_messages WHERE thread_id=t.id AND sender_type='identity' AND is_read=0) as unread_count
      FROM email_threads t
      JOIN email_identities i ON i.id = t.identity_id
      WHERE t.user_id = ?
      ORDER BY t.updated_at DESC
    `, [req.user.id]);
    res.json({ threads });
  } catch (e) {
    res.status(500).json({ error: 'Failed to load inbox' });
  }
});

// 2. Read Thread
app.get('/api/emails/thread/:id', authRequired, async (req, res) => {
  try {
    const [check] = await pool.query('SELECT 1 FROM email_threads WHERE id=? AND user_id=?', [req.params.id, req.user.id]);
    if (!check.length) return res.status(403).json({ error: 'Forbidden' });

    const [messages] = await pool.query(`
      SELECT * FROM email_messages WHERE thread_id=? ORDER BY created_at ASC
    `, [req.params.id]);

    await pool.query(`UPDATE email_messages SET is_read=1 WHERE thread_id=? AND sender_type='identity'`, [req.params.id]);

    res.json({ messages });
  } catch (e) {
    res.status(500).json({ error: 'Failed to load email' });
  }
});

// 3. Send Email (Validation Logic & Admin Push)
app.post('/api/emails/send', authRequired, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { to_email, subject, body, thread_id } = req.body;
    let finalThreadId = thread_id;
    let identityId = null;
    let identityName = 'NPC';

    if (thread_id) {
      // REPLY to existing thread
      const [check] = await conn.query('SELECT identity_id FROM email_threads WHERE id=? AND user_id=?', [thread_id, req.user.id]);
      if (!check.length) return res.status(403).json({ error: 'Thread not found' });
      identityId = check[0].identity_id;
      
      await conn.query(`INSERT INTO email_messages (thread_id, sender_type, body, is_read) VALUES (?, 'user', ?, 0)`, [thread_id, body]);
      await conn.query(`UPDATE email_threads SET updated_at=NOW() WHERE id=?`, [thread_id]);
    } else {
      // NEW THREAD
      if (!to_email || !subject || !body) return res.status(400).json({ error: 'Missing fields' });
      const emailLower = to_email.trim().toLowerCase();
      const [identity] = await conn.query('SELECT id, display_name FROM email_identities WHERE email_address = ?', [emailLower]);
      
      if (identity.length === 0) return res.status(404).json({ error: 'Delivery Status Notification (Failure): Address not found.' });
      identityId = identity[0].id;
      identityName = identity[0].display_name;
      
      await conn.beginTransaction();
      const [t] = await conn.query(`INSERT INTO email_threads (user_id, identity_id, subject) VALUES (?, ?, ?)`, [req.user.id, identityId, subject]);
      finalThreadId = t.insertId;
      await conn.query(`INSERT INTO email_messages (thread_id, sender_type, body, is_read) VALUES (?, 'user', ?, 0)`, [finalThreadId, body]);
      await conn.commit();
    }

    // --- NEW: SEND PUSH TO ADMINS ---
    try {
      const [[idRow]] = await pool.query('SELECT display_name FROM email_identities WHERE id=?', [identityId]);
      const [[player]] = await pool.query('SELECT display_name FROM users WHERE id=?', [req.user.id]);
      const [admins] = await pool.query("SELECT id FROM users WHERE role = 'admin'");
      
      const pushTitle = `📧 Email to ${idRow?.display_name || identityName}`;
      const pushBody = `From ${player?.display_name}: ${subject || 'New Reply'}`;
      
      for (const admin of admins) {
        if (admin.id !== req.user.id) await sendPushNotification(admin.id, pushTitle, pushBody).catch(()=>{});
      }
    } catch (e) { log.err('Email push to admin failed', { error: e.message }); }
    // --------------------------------

    res.json({ ok: true, thread_id: finalThreadId });
  } catch (e) {
    await conn.rollback();
    log.err('Email send failed', { message: e.message });
    res.status(500).json({ error: 'Send failed' });
  } finally {
    conn.release();
  }
});

// Admin: Toggle comms status
app.post('/api/admin/comms/status', authRequired, requireAdmin, async (req, res) => {
  try {
    const { comms_enabled } = req.body;
    await setSetting('comms_enabled', String(comms_enabled));
    log.adm(`Master comms switched to ${comms_enabled ? 'ONLINE' : 'OFFLINE'}`, { admin_id: req.user.id });
    res.json({ ok: true, comms_enabled });
  } catch (e) {
    res.status(500).json({ error: 'Failed to update comms status' });
  }
});

// Player: get my conversation with an NPC
app.get('/api/chat/npc-history/:npcId', authRequired, async (req, res) => {
  try {
    const npcId = Number(req.params.npcId);
    const userId = req.user.id;

    const [rows] = await pool.query(
      `SELECT id, npc_id, user_id, from_side, body, created_at, attachment_id
        FROM npc_messages
        WHERE npc_id=? AND user_id=?
        ORDER BY created_at ASC`,
      [npcId, userId]
    );

    res.json({ messages: rows });
  } catch (e) {
    log.err('Failed to get NPC chat history', { message: e.message });
    res.status(500).json({ error: 'Failed to get history' });
  }
});

// Player: send message to an NPC
app.post('/api/chat/npc/messages', authRequired, async (req, res) => {
  try {
    const userId = req.user.id;
    const { npc_id, body, attachment_id } = req.body || {};
    
    if (!npc_id || (!attachment_id && (!body || !body.trim()))) {
      return res.status(400).json({ error: 'NPC and content required' });
    }

    const [r] = await pool.query(
      'INSERT INTO npc_messages (npc_id, user_id, from_side, body, attachment_id) VALUES (?,?,?,?,?)',
      [Number(npc_id), userId, 'user', body ? body.trim() : '', attachment_id || null]
    );

    // FIX: Define the message object so notifications and the response don't crash
    const message = {
      id: r.insertId,
      npc_id: Number(npc_id),
      user_id: userId,
      from_side: 'user',
      body: body ? body.trim() : '',
      attachment_id: attachment_id || null,
      created_at: new Date()
    };

    // --- NEW: PUSH NOTIFICATIONS FOR ALL ADMINS ---
    try {
      // 1. Get NPC name and Player name for the notification title
      const [[npcInfo]] = await pool.query('SELECT name FROM npcs WHERE id=?', [npc_id]);
      const [[playerInfo]] = await pool.query('SELECT display_name FROM users WHERE id=?', [userId]);
      const [[charInfo]] = await pool.query('SELECT name FROM characters WHERE user_id=?', [userId]);

      const npcName = npcInfo?.name || 'NPC';
      const playerName = charInfo?.name || playerInfo?.display_name || 'Player';
      
      const notifTitle = `💬 ${npcName} (from ${playerName})`;
      const notifBody = message.attachment_id ? '📷 Image Attachment' : message.body;

      // 2. Find all admins in the system
      const [admins] = await pool.query("SELECT id FROM users WHERE role = 'admin'");

      // 3. Send a push to each admin
      for (const admin of admins) {
        // Prevent sending a push to the admin if the admin is the one testing/playing as a user
        if (admin.id !== userId) {
          await sendPushNotification(admin.id, notifTitle, notifBody).catch(() => {});
        }
      }
    } catch (pushErr) {
      log.err('Failed to notify admins of NPC message', { error: pushErr.message });
    }
    // ----------------------------------------------
    
    res.status(201).json({ message });
  } catch (e) {
    log.err('NPC send failed', { message: e.message });
    res.status(500).json({ error: 'Failed' });
  }
});
// --- Admin: reply as NPC to a specific player ---
app.get('/api/admin/chat/npc/history', authRequired, requireAdmin, async (req, res) => {
  try {
    const npcId = Number(req.query.npc_id);
    const userId = Number(req.query.user_id);
    if (!npcId || !userId) return res.status(400).json({ error: 'npc_id and user_id are required' });

    const [rows] = await pool.query(
      `SELECT id, npc_id, user_id, from_side, body, created_at, attachment_id
        FROM npc_messages
        WHERE npc_id=? AND user_id=?
        ORDER BY created_at ASC`,
      [npcId, userId]
    );

    res.json({ messages: rows });
  } catch (e) {
    log.err('Admin: NPC history failed', { message: e.message });
    res.status(500).json({ error: 'Failed to get history' });
  }
});

app.post('/api/admin/chat/summarize', authRequired, requireAdmin, async (req, res) => {
  try {
    const { text, context } = req.body;
    if (!text) return res.status(400).json({ error: 'No text provided' });
    if (!process.env.GOOGLE_API_KEY) return res.status(500).json({ error: 'Server missing GOOGLE_API_KEY' });

    // Initialize Gemini
    const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);

    // List of models to try in order of preference.
    // We prioritize stable, production-ready models to avoid 503 errors.
    const candidateModels = [
          "gemini-2.5-flash-lite",      // Specific stable version
          "gemini-3-flash-preview",      // Newer stable version
          "gemini-2.5-flash",        // Specific stable version
          "	gemini-2.5-pro",        // Newer stable version
          "gemini-1.0-pro",            // Fallback legacy
          "gemini-pro"                 // Generic fallback
        ];

    let summary = null;
    let lastError = null;

    // Construct Prompt
    const prompt = `
      You are an assistant for a Vampire: The Masquerade game.
      Summarize the following roleplay chat log between: ${context || 'Unknown Participants'}.
      
      Requirements:
      - Highlight key plot developments, agreements, and secrets revealed.
      - Describe the emotional tone.
      - Keep it concise (under 200 words).
      - Use bullet points.
      - If the chat is in Greek, provide the summary in Greek.

      Chat Log:
      ${text.substring(0, 30000)} 
    `; // Limit text length to avoid token limits

    // Loop through models until one works
    for (const modelName of candidateModels) {
      try {
        const model = genAI.getGenerativeModel({ model: modelName });
        const result = await model.generateContent(prompt);
        const response = await result.response;
        summary = response.text();
        
        // If successful, stop trying other models
        break; 
      } catch (e) {
        // Log warning but continue to next model
        log.warn(`AI Model ${modelName} failed`, { message: e.message });
        lastError = e;
      }
    }

    if (!summary) {
      throw lastError || new Error("All AI models failed to respond.");
    }

    res.json({ summary });

  } catch (e) {
    log.err('AI Summarize failed', { message: e.message });
    // Return 503 (Service Unavailable) if it was an AI overload issue
    res.status(503).json({ error: 'AI service is currently busy. Please try again.' });
  }
});

app.post('/api/admin/chat/npc/messages', authRequired, requireAdmin, async (req, res) => {
  try {
    const { npc_id, user_id, body, attachment_id } = req.body || {};
    if (!npc_id || !user_id || (!attachment_id && (!body || !body.trim()))) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    const [r] = await pool.query(
      'INSERT INTO npc_messages (npc_id, user_id, from_side, body, attachment_id) VALUES (?,?,?,?,?)',
      [Number(npc_id), Number(user_id), 'npc', body ? body.trim() : '', attachment_id || null]
    );

    // FIX: Define the message object so notifications and the response don't crash
    const message = {
      id: r.insertId,
      npc_id: Number(npc_id),
      user_id: Number(user_id),
      from_side: 'npc',
      body: body ? body.trim() : '',
      attachment_id: attachment_id || null,
      created_at: new Date()
    };

    // --- NEW: PUSH NOTIFICATION TO PLAYER ---
    try {
      // Find the NPC name so the player knows who is replying
      const [[npcInfo]] = await pool.query('SELECT name FROM npcs WHERE id=?', [npc_id]);
      const npcName = npcInfo?.name || 'NPC';
      const notifBody = message.attachment_id ? '📷 Image Attachment' : message.body;

      // Send push directly to the player
      await sendPushNotification(user_id, npcName, notifBody).catch(() => {});
    } catch (pushErr) {
      log.err('Failed to notify player of NPC reply', { error: pushErr.message });
    }
    // ----------------------------------------
    
    res.status(201).json({ message });
  } catch (e) {
    res.status(500).json({ error: 'Failed' });
  }
});

/* --- Camarilla Hierarchy API --- */

// 1. Fetch combined roster (Admin)
app.get('/api/admin/camarilla/roster', authRequired, requireAdmin, async (req, res) => {
  try {
    const [players] = await pool.query(
      "SELECT id, user_id, name, clan, camarilla_titles as titles, status, image_url, is_ex, is_deceased, is_hidden, is_left, is_called, is_missing, is_exiled, is_bloodhunted, 'player' as type FROM characters"
    );
    const [npcs] = await pool.query(
      "SELECT id, NULL as user_id, name, clan, camarilla_titles as titles, status, image_url, is_ex, is_deceased, is_hidden, is_left, is_called, is_missing, is_exiled, is_bloodhunted, 'npc' as type FROM npcs"
    );
    
    const format = (list) => list.map(item => ({
      ...item,
      titles: typeof item.titles === 'string' ? JSON.parse(item.titles) : (item.titles || []),
      is_ex: !!item.is_ex,
      is_deceased: !!item.is_deceased,
      is_hidden: !!item.is_hidden // <--- Add this
    }));

    const combined = [...format(players), ...format(npcs)];
    combined.sort((a, b) => (b.status || 0) - (a.status || 0));

    res.json({ roster: combined });
  } catch (e) {
    log.err('Admin roster fetch failed', { message: e.message });
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/npcs/:id/avatar', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT avatar FROM npcs WHERE id = ?', [req.params.id]);
    if (rows.length === 0 || !rows[0].avatar) {
      return res.status(404).send('Avatar not found');
    }
    res.set('Content-Type', 'image/webp');
    res.set('Cache-Control', 'public, max-age=86400'); // Cache for 1 day
    res.send(rows[0].avatar);
  } catch (e) {
    log.err('NPC Avatar GET error', { message: e.message });
    res.status(500).json({ error: 'Server error retrieving avatar.' });
  }
});

app.put('/api/npcs/:id/avatar', authRequired, requireAdmin, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided.' });
    }
    const buffer = await sharp(req.file.buffer)
      .resize(500, 500, { fit: 'cover' })
      .webp({ quality: 80 })
      .toBuffer();
      
    await pool.query('UPDATE npcs SET avatar = ? WHERE id = ?', [buffer, req.params.id]);
    res.json({ success: true, message: 'NPC Avatar updated successfully.' });
  } catch (e) {
    log.err('NPC Avatar PUT error', { message: e.message });
    res.status(500).json({ error: 'Server error updating npc avatar.' });
  }
});

// GET: Publicly accessible roster
app.get('/api/camarilla/roster', authRequired, async (req, res) => {
  try {
    const [players] = await pool.query(
      "SELECT id, user_id, name, clan, camarilla_titles as titles, status, image_url, is_ex, is_deceased, is_hidden, 'player' as type FROM characters"
    );
    const [npcs] = await pool.query(
      "SELECT id, NULL as user_id, name, clan, camarilla_titles as titles, status, image_url, is_ex, is_deceased, is_hidden, 'npc' as type FROM npcs"
    );
    
    const format = (list) => list.map(item => ({
      ...item,
      titles: typeof item.titles === 'string' ? JSON.parse(item.titles) : (item.titles || []),
      is_ex: !!item.is_ex,
      is_deceased: !!item.is_deceased,
      is_hidden: !!item.is_hidden // <--- Add this
    }));

    const combined = [...format(players), ...format(npcs)];
    combined.sort((a, b) => (b.status || 0) - (a.status || 0));

    res.json({ roster: combined });
  } catch (e) {
    log.err('Public roster fetch failed', { message: e.message });
    res.status(500).json({ error: "Failed to load the Court hierarchy." });
  }
});

// GET: Publicly accessible roster
app.get('/api/camarilla/roster', authRequired, async (req, res) => {
  try {
    const [players] = await pool.query(
      "SELECT id, name, clan, camarilla_titles as titles, status, image_url, is_ex, is_deceased, 'player' as type FROM characters"
    );
    const [npcs] = await pool.query(
      "SELECT id, name, clan, camarilla_titles as titles, status, image_url, is_ex, is_deceased, 'npc' as type FROM npcs"
    );
    
    const format = (list) => list.map(item => ({
      ...item,
      titles: typeof item.titles === 'string' ? JSON.parse(item.titles) : (item.titles || []),
      is_ex: !!item.is_ex,
      is_deceased: !!item.is_deceased
    }));

    const combined = [...format(players), ...format(npcs)];
    combined.sort((a, b) => (b.status || 0) - (a.status || 0));

    res.json({ roster: combined });
  } catch (e) {
    log.err('Public roster fetch failed', { message: e.message });
    res.status(500).json({ error: "Failed to load the Court hierarchy." });
  }
});

/* --- Public Camarilla Hierarchy API --- */

// GET: Publicly accessible roster for all logged-in users
app.get('/api/camarilla/roster', authRequired, async (req, res) => {
  try {
    // Selects basic info from players and NPCs, including image_url
    const [players] = await pool.query(
      "SELECT id, name, clan, camarilla_titles as titles, status, image_url, 'player' as type FROM characters"
    );
    const [npcs] = await pool.query(
      "SELECT id, name, clan, camarilla_titles as titles, status, image_url, 'npc' as type FROM npcs"
    );
    
    // Format helper to handle JSON strings for titles
    const format = (list) => list.map(item => ({
      ...item,
      titles: typeof item.titles === 'string' ? JSON.parse(item.titles) : (item.titles || [])
    }));

    const combined = [...format(players), ...format(npcs)];
    
    // Sort NUMERICALLY by status (highest number first, nulls become 0)
    combined.sort((a, b) => (b.status || 0) - (a.status || 0));

    res.json({ roster: combined });
  } catch (e) {
    log.err('Public roster fetch failed', { message: e.message });
    res.status(500).json({ error: "Failed to load the Court hierarchy." });
  }
});

// 2. Update status, titles, image_url, or modifiers
app.patch('/api/admin/camarilla/update', authRequired, requireAdmin, async (req, res) => {
  const { id, type, field, value } = req.body;
  const table = type === 'player' ? 'characters' : 'npcs';
  
  let dbField, dbValue;
  
  if (field === 'titles') {
    dbField = 'camarilla_titles';
    dbValue = JSON.stringify(value);
  } else if (field === 'image_url') {
    dbField = 'image_url';
    dbValue = value;
  // Use a quick array check for all boolean flags
  } else if (['is_ex', 'is_deceased', 'is_hidden', 'is_bloodhunted', 'is_left', 'is_called', 'is_missing', 'is_exiled'].includes(field)) {
    dbField = field;
    dbValue = value ? 1 : 0;
  } else {
    // If it's not any of the above, it's the status slider
    dbField = 'status';
    dbValue = value;
  }

  try {
    await pool.query(`UPDATE ${table} SET ${dbField} = ? WHERE id = ?`, [dbValue, id]);
    log.adm(`Updated Camarilla ${field}`, { type, id, value });
    res.json({ ok: true });
  } catch (e) {
    log.err('Camarilla update failed', { message: e.message });
    res.status(500).json({ error: "Database update failed" });
  }
});

/* -------------------- Downtimes -------------------- */
// My quota this cycle
app.get('/api/downtimes/quota', authRequired, async (req, res) => {
  const [chars] = await pool.query('SELECT id FROM characters WHERE user_id=?', [req.user.id]);
  const ch = chars[0];
  if (!ch) {
    log.dt('Quota check (no character)', { user_id: req.user.id });
    return res.json({ used: 0, limit: 3 });
  }

  let from = startOfMonth();
  let to = endOfMonth();
  
  // FIX: Tie the quota to the current cycle (Opening Date) instead of a strict calendar month
  try {
    const openingStr = await getSetting('downtime_opening', null);
    if (openingStr) {
      const parsed = new Date(openingStr);
      if (!isNaN(parsed.getTime())) {
        from = parsed;
        // Give the cycle a generous safe upper bound (e.g., 90 days) until the next opening overrides it
        to = new Date(parsed.getTime() + 90 * 24 * 60 * 60 * 1000); 
      }
    }
  } catch (e) {}

  const [rows] = await pool.query(
    'SELECT COUNT(*) AS c FROM downtimes WHERE character_id=? AND created_at >= ? AND created_at < ?',
    [ch.id, from, to]
  );
  log.dt('Quota check', { user_id: req.user.id, used: rows[0].c, limit: 3 });
  res.json({ used: rows[0].c, limit: 3 });
});

// PUT /api/downtimes/:id — Edit a project/downtime submission
app.put('/api/downtimes/:id', authRequired, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, body } = req.body;

    // 1. Verify ownership by joining downtimes with characters
    const [rows] = await pool.query(`
      SELECT dt.*, c.user_id 
      FROM downtimes dt 
      JOIN characters c ON dt.character_id = c.id
      WHERE dt.id = ? AND c.user_id = ?
    `, [id, req.user.id]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Submission not found or unauthorized' });
    }

    const submission = rows[0];

    // 2. Only allow edits if status is strictly 'submitted'
    if (submission.status !== 'submitted') {
      return res.status(400).json({ error: 'You can only edit actions that are strictly in a submitted state' });
    }

    // 3. Check against the CORRECT global deadline setting
    // Determine if the action being edited is a project based on its current title
    const isProject = submission.title && submission.title.startsWith('[PROJECT]');
    const deadlineKey = isProject ? 'project_deadline' : 'downtime_deadline';
    
    const deadlineStr = await getSetting(deadlineKey, null);
    
    // Check if the specific deadline for this type of action has passed
    if (deadlineStr && new Date(deadlineStr) < new Date()) {
      return res.status(400).json({ 
        error: `The deadline for ${isProject ? 'project' : 'action'} submissions has passed.` 
      });
    }

    // 4. Perform update
    await pool.query(
      'UPDATE downtimes SET title = ?, body = ? WHERE id = ?',
      [title || submission.title, body || submission.body, id]
    );

    res.json({ success: true, message: 'Action updated successfully' });
  } catch (e) {
    console.error('Failed to update downtime/project:', e);
    res.status(500).json({ error: 'Internal server error while updating submission' });
  }
});

// List my downtimes
app.get('/api/downtimes/mine', authRequired, async (req, res) => {
  const [[char]] = await Promise.all([
    pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]),
  ]);
  if (!char?.[0]) {
    log.dt('List mine (no character)', { user_id: req.user.id });
    return res.json({ downtimes: [] });
  }

  const [rows] = await pool.query(
    'SELECT * FROM downtimes WHERE character_id=? ORDER BY created_at DESC',
    [char[0].id]
  );
  log.dt('List mine', { user_id: req.user.id, count: rows.length });
  res.json({ downtimes: rows });
});

// Create downtime (3 per cycle; auto feeding type)
app.post('/api/downtimes', authRequired, async (req, res) => {
  const { title, body, feeding_type } = req.body;
  if (!title || !body) {
    log.warn('Downtime create missing fields', { user_id: req.user.id });
    return res.status(400).json({ error: 'Title and body required' });
  }

  const [chars] = await pool.query('SELECT * FROM characters WHERE user_id=?', [req.user.id]);
  const ch = chars[0];
  if (!ch) {
    log.warn('Downtime create without character', { user_id: req.user.id });
    return res.status(400).json({ error: 'Create a character first' });
  }

  let from = startOfMonth();
  let to = endOfMonth();
  
  // FIX: Tie the limit check to the current cycle
  try {
    const openingStr = await getSetting('downtime_opening', null);
    if (openingStr) {
      const parsed = new Date(openingStr);
      if (!isNaN(parsed.getTime())) {
        from = parsed;
        to = new Date(parsed.getTime() + 90 * 24 * 60 * 60 * 1000); 
      }
    }
  } catch (e) {}

  const [cnt] = await pool.query(
    'SELECT COUNT(*) AS c FROM downtimes WHERE character_id=? AND created_at >= ? AND created_at < ?',
    [ch.id, from, to]
  );
  if (cnt[0].c >= 3) {
    log.warn('Downtime limit reached', { user_id: req.user.id, count: cnt[0].c });
    return res.status(400).json({ error: 'Downtime limit reached for this cycle (3).' });
  }

  let defaultFeed = feeding_type;
  if (!defaultFeed) {
    let pred = null;
    if (ch.sheet) {
      try {
        const parsed = typeof ch.sheet === 'string' ? JSON.parse(ch.sheet) : ch.sheet;
        pred = parsed?.predatorType || null;
      } catch {}
    }
    defaultFeed = feedingFromPredator(pred);
  }

  const [r] = await pool.query(
    'INSERT INTO downtimes (character_id, title, feeding_type, body) VALUES (?,?,?,?)',
    [ch.id, title, defaultFeed || null, body]
  );
  const [rows] = await pool.query('SELECT * FROM downtimes WHERE id=?', [r.insertId]);
  log.dt('Downtime created', { user_id: req.user.id, downtime_id: r.insertId, feeding_type: defaultFeed || feeding_type || null });
  res.json({ downtime: rows[0] });
});

/* -------------------- Domains -------------------- */
// List domains with members (for players)
app.get('/api/domains', authRequired, async (_req, res) => {
  const [doms] = await pool.query('SELECT * FROM domains ORDER BY name ASC');
  if (!doms.length) {
    log.dom('Domains list (empty)');
    return res.json({ domains: [] });
  }

  const [rows] = await pool.query(
    `SELECT dm.domain_id, c.name AS char_name, c.clan
     FROM domain_members dm
     JOIN characters c ON c.id=dm.character_id`
  );

  const byDomain = rows.reduce((acc, r) => {
    (acc[r.domain_id] ||= []).push({ name: r.char_name, clan: r.clan });
    return acc;
  }, {});

  const out = doms.map(d => ({ ...d, members: byDomain[d.id] || [] }));
  log.dom('Domains list', { count: out.length });
  res.json({ domains: out });
});

// Admin: manage domains
app.post('/api/admin/domains', authRequired, requireAdmin, async (req, res) => {
  const { name, description } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  const [r] = await pool.query('INSERT INTO domains (name, description) VALUES (?,?)', [name, description || null]);
  const [rows] = await pool.query('SELECT * FROM domains WHERE id=?', [r.insertId]);
  log.adm('Domain created', { id: r.insertId, name });
  res.json({ domain: rows[0] });
});

app.delete('/api/admin/domains/:id', authRequired, requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM domains WHERE id=?', [req.params.id]);
  log.adm('Domain deleted', { id: req.params.id });
  res.json({ ok: true });
});

app.post('/api/admin/domains/:id/members', authRequired, requireAdmin, async (req, res) => {
  const { character_id } = req.body;
  if (!character_id) return res.status(400).json({ error: 'character_id required' });
  await pool.query('INSERT IGNORE INTO domain_members (domain_id, character_id) VALUES (?,?)', [req.params.id, character_id]);
  log.adm('Domain member added', { domain_id: req.params.id, character_id });
  res.json({ ok: true });
});

app.delete('/api/admin/domains/:id/members/:character_id', authRequired, requireAdmin, async (req, res) => {
  await pool.query('DELETE FROM domain_members WHERE domain_id=? AND character_id=?', [req.params.id, req.params.character_id]);
  log.adm('Domain member removed', { domain_id: req.params.id, character_id: req.params.character_id });
  res.json({ ok: true });
});

/* -------------------- Identity Avatars -------------------- */

app.get('/api/identities/:id/avatar', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT avatar FROM email_identities WHERE id = ?', [req.params.id]);
    if (rows.length === 0 || !rows[0].avatar) {
      return res.status(404).send('Avatar not found');
    }
    res.setHeader('Content-Type', 'image/webp');
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    res.send(rows[0].avatar);
  } catch (err) {
    log.err('Identity avatar fetch error', err);
    res.status(500).send('Error fetching avatar');
  }
});

app.put('/api/identities/:id/avatar', authRequired, requireAdmin, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided.' });
    }
    const buffer = await sharp(req.file.buffer)
      .resize(500, 500, { fit: 'cover', position: 'top' })
      .webp({ quality: 80 })
      .toBuffer();

    await pool.query('UPDATE email_identities SET avatar = ? WHERE id = ?', [buffer, req.params.id]);
    log.adm('Identity avatar updated', { identity_id: req.params.id, admin_id: req.user.id });
    res.json({ ok: true, message: 'Identity avatar updated successfully' });
  } catch (err) {
    log.err('Identity avatar upload error', err);
    res.status(500).json({ error: 'Error processing or saving avatar' });
  }
});

/* -------------------- Boons (FIXED) -------------------- */

// GET /api/boons/entities (All logged-in users need this to resolve avatars)
app.get('/api/boons/entities', authRequired, async (req, res) => {
  try {
    const [characters] = await pool.query('SELECT id, user_id, name, clan FROM characters ORDER BY name ASC');
    const [npcs] = await pool.query('SELECT id, name, clan FROM npcs ORDER BY name ASC');
    
    // Using user_id for players because avatars are tied to users, not characters
    const players = characters.map(c => ({ type: 'player', id: c.user_id, name: `${c.name} (${c.clan || 'Unknown'})` }));
    const nonPlayers = npcs.map(n => ({ type: 'npc', id: n.id, name: `${n.name} (NPC)` }));
    
    res.json({ entities: [...players, ...nonPlayers] });
  } catch (e) {
    log.err('Failed to get boon entities', { message: e.message });
    res.status(500).json({ error: 'Failed to fetch entities' });
  }
});

// GET /api/boons (All logged-in users)
app.get('/api/boons', authRequired, async (req, res) => {
  try {
    // Αποτροπή caching για να βλέπουν οι χρήστες τα edits κατευθείαν
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');

    // Assuming a 'boons' table exists
    const [boons] = await pool.query(
      `SELECT * FROM boons ORDER BY created_at DESC`
    );
    res.json({ boons });
  } catch (e) {
    log.err('Failed to get boons', { message: e.message });
    res.status(500).json({ error: 'Failed to fetch boons' });
  }
});

// POST /api/boons (Court/Admin only)
app.post('/api/boons', authRequired, requireCourt, async (req, res) => {
  try {
    const { from_name, to_name, level, status, description } = req.body;

    if (!from_name || !to_name || !level || !status) {
      return res.status(400).json({ error: 'From, To, Level, and Status are required' });
    }
    
  const [r] = await pool.query(
    `INSERT INTO boons (from_name, to_name, level, status, description, created_at, date_incurred) 
    VALUES (?, ?, ?, ?, ?, NOW(), NOW())`,
    [from_name, to_name, level, status, description || null]
  );
    
    const [[boon]] = await pool.query('SELECT * FROM boons WHERE id=?', [r.insertId]);
    log.adm('Boon created', { id: r.insertId, by_user_id: req.user.id });
    res.status(201).json({ boon });
    
  } catch (e) {
    log.err('Failed to create boon', { message: e.message, stack: e.stack });
    
    // Make the error explanatory for the frontend
    let errorMessage = 'Failed to create boon.';
    if (e.code === 'ER_NO_SUCH_TABLE') {
      errorMessage = 'Database error: The "boons" table does not exist yet.';
    } else if (e.code === 'ER_DATA_TOO_LONG') {
      errorMessage = 'Input error: One of the names or descriptions is too long.';
    } else {
      // Pass the raw database error message so you can see exactly what failed
      errorMessage = `Server Error: ${e.message}`; 
    }

    res.status(500).json({ error: errorMessage });
  }
});

// PATCH /api/boons/:id (Court/Admin only)
app.patch('/api/boons/:id', authRequired, requireCourt, async (req, res) => {
  try {
    const { id } = req.params;
    const { from_name, to_name, level, status, description } = req.body;
    
    const fields = [], vals = [];
    if (from_name !== undefined) { fields.push('from_name=?'); vals.push(from_name); }
    if (to_name !== undefined) { fields.push('to_name=?'); vals.push(to_name); }
    if (level !== undefined) { fields.push('level=?'); vals.push(level); }
    if (status !== undefined) { fields.push('status=?'); vals.push(status); }
    if (description !== undefined) { fields.push('description=?'); vals.push(description); }

    if (!fields.length) {
      return res.status(400).json({ error: 'Nothing to update' });
    }
    
    vals.push(id);
    await pool.query(`UPDATE boons SET ${fields.join(', ')} WHERE id=?`, vals);
    
    const [[boon]] = await pool.query('SELECT * FROM boons WHERE id=?', [id]);
    log.adm('Boon updated', { id, by_user_id: req.user.id });
    res.json({ boon });
    
  } catch (e) {
    log.err('Failed to update boon', { message: e.message });
    res.status(500).json({ error: `Failed to update boon: ${e.message}` });
  }
});

// DELETE /api/boons/:id (Court/Admin only)
app.delete('/api/boons/:id', authRequired, requireCourt, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM boons WHERE id=?', [id]);
    log.adm('Boon deleted', { id, by_user_id: req.user.id });
    res.json({ ok: true });
  } catch (e) {
    log.err('Failed to delete boon', { message: e.message });
    res.status(500).json({ error: 'Failed to delete boon' });
  }
});


/* -------------------- Chat -------------------- */
// NOTE TO USER: You may need to add 'chat' to your logger configuration if it's a custom one.

/* -------------------- Group Chat Routes (NEW) -------------------- */

// List groups for the current user (with metadata)
app.get('/api/chat/groups', authRequired, async (req, res) => {
  try {
    const userId = req.user.id;
    // Χρήση COALESCE για να μπαίνει η ημερομηνία δημιουργίας αν δεν υπάρχει μήνυμα.
    // Προσθήκη unread_count: Μετράει πόσα μηνύματα (που ΔΕΝ έστειλε ο ίδιος ο χρήστης) 
    // έχουν δημιουργηθεί μετά το last_read_at του συγκεκριμένου χρήστη στην ομάδα.
    // Ταξινόμηση ώστε οι ομάδες με αδιάβαστα να πηγαίνουν πάνω, και μετά να ταξινομούνται ανά παλαιότητα.
    const [rows] = await pool.query(`
      SELECT 
        g.id, g.name, g.created_by, g.created_at as group_created_at,
        COALESCE(
          (
            SELECT created_at 
            FROM chat_group_messages 
            WHERE group_id = g.id 
            ORDER BY created_at DESC LIMIT 1
          ), 
          g.created_at
        ) as last_message_at,
        (
          SELECT COUNT(*) 
          FROM chat_group_messages 
          WHERE group_id = g.id AND created_at > m.last_read_at AND sender_id != ?
        ) as unread_count
      FROM chat_groups g
      JOIN chat_group_members m ON m.group_id = g.id
      WHERE m.user_id = ?
      ORDER BY unread_count DESC, last_message_at DESC
    `, [userId, userId]); // <-- Προσοχή: Βάλαμε το userId δύο φορές στα parameters!

    res.json({ groups: rows });
  } catch (e) {
    log.err('Failed to get chat groups', { message: e.message });
    res.status(500).json({ error: 'Failed to get groups' });
  }
});

// Mark all messages in a group as read (updates last_read_at)
app.post('/api/chat/groups/:id/read', authRequired, async (req, res) => {
  try {
    const groupId = Number(req.params.id);
    await pool.query(
      'UPDATE chat_group_members SET last_read_at = NOW() WHERE group_id = ? AND user_id = ?',
      [groupId, req.user.id]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to mark group as read' });
  }
});

// Create a new group
app.post('/api/chat/groups', authRequired, moderateLimiter, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    const { name, members = [] } = req.body; // members is array of user_ids
    if (!name || !members.length) {
      return res.status(400).json({ error: 'Name and at least one other member required' });
    }

    await conn.beginTransaction();

    // 1. Create Group
    const [g] = await conn.query('INSERT INTO chat_groups (name, created_by) VALUES (?, ?)', [name.trim(), req.user.id]);
    const groupId = g.insertId;

    // 2. Add Creator to Members
    const allMembers = [req.user.id, ...members.map(Number)].filter((v, i, a) => a.indexOf(v) === i && !isNaN(v));
    const values = allMembers.map(uid => [groupId, uid]);
    
    await conn.query('INSERT INTO chat_group_members (group_id, user_id) VALUES ?', [values]);

    await conn.commit();
    
    // Fetch and return the new group object
    const [rows] = await pool.query('SELECT * FROM chat_groups WHERE id=?', [groupId]);
    log.ok('Group created', { user_id: req.user.id, group_id: groupId, name });
    res.status(201).json({ group: rows[0] });

  } catch (e) {
    await conn.rollback();
    log.err('Failed to create group', { message: e.message });
    res.status(500).json({ error: 'Failed to create group' });
  } finally {
    conn.release();
  }
});

// Get history for a specific group
app.get('/api/chat/groups/:id/history', authRequired, async (req, res) => {
  try {
    const groupId = Number(req.params.id);
    const userId = req.user.id;

    // 1. Verify Membership
    const [m] = await pool.query('SELECT 1 FROM chat_group_members WHERE group_id=? AND user_id=?', [groupId, userId]);
    if (!m.length) return res.status(403).json({ error: 'Not a member of this group' });

    // 2. Fetch Messages
    const [messages] = await pool.query(`
      SELECT m.id, m.sender_id, m.body, m.created_at,
            m.attachment_id,
            u.display_name, c.name as char_name, c.clan
      FROM chat_group_messages m
      LEFT JOIN users u ON m.sender_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE m.group_id = ?
      ORDER BY m.created_at ASC
    `, [groupId]);


    res.json({ messages });
  } catch (e) {
    log.err('Failed to get group history', { message: e.message });
    res.status(500).json({ error: 'Failed to get history' });
  }
});

// Get members of a specific group
app.get('/api/chat/groups/:id/members', authRequired, async (req, res) => {
  try {
    const groupId = Number(req.params.id);
    
    // Check if user is in group or is admin
    const [m] = await pool.query('SELECT 1 FROM chat_group_members WHERE group_id=? AND user_id=?', [groupId, req.user.id]);
    if (!m.length && req.user.role !== 'admin') return res.status(403).json({ error: 'Not a member' });

    const [members] = await pool.query(`
      SELECT u.id, u.display_name, c.name as char_name 
      FROM chat_group_members cgm
      JOIN users u ON cgm.user_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE cgm.group_id = ?
      ORDER BY u.display_name ASC
    `, [groupId]);
    res.json({ members });
  } catch (e) {
    res.status(500).json({ error: 'Failed to get members' });
  }
});

// Add members to an existing group (Creator/Admin only)
app.post('/api/chat/groups/:id/members', authRequired, async (req, res) => {
  try {
    const groupId = Number(req.params.id);
    const { members } = req.body; 
    if (!members || !members.length) return res.status(400).json({ error: 'No members provided' });

    const [g] = await pool.query('SELECT created_by FROM chat_groups WHERE id=?', [groupId]);
    if (!g.length) return res.status(404).json({ error: 'Group not found' });
    if (g[0].created_by !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Not authorized' });

    const values = members.map(uid => [groupId, Number(uid)]);
    await pool.query('INSERT IGNORE INTO chat_group_members (group_id, user_id) VALUES ?', [values]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to add members' });
  }
});

// Remove a member from a group (Creator/Admin, or User leaving)
app.delete('/api/chat/groups/:id/members/:userId', authRequired, async (req, res) => {
  try {
    const groupId = Number(req.params.id);
    const targetUserId = Number(req.params.userId);

    const [g] = await pool.query('SELECT created_by FROM chat_groups WHERE id=?', [groupId]);
    if (!g.length) return res.status(404).json({ error: 'Group not found' });
    
    // Check if requester is Creator, Admin, OR the user trying to leave
    if (g[0].created_by !== req.user.id && req.user.role !== 'admin' && req.user.id !== targetUserId) {
        return res.status(403).json({ error: 'Not authorized' });
    }
    
    if (g[0].created_by === targetUserId) return res.status(400).json({ error: 'Cannot remove creator' });

    await pool.query('DELETE FROM chat_group_members WHERE group_id=? AND user_id=?', [groupId, targetUserId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to remove member' });
  }
});

// Delete a group entirely (Creator/Admin only)
app.delete('/api/chat/groups/:id', authRequired, async (req, res) => {
  try {
    const groupId = Number(req.params.id);
    const [g] = await pool.query('SELECT created_by FROM chat_groups WHERE id=?', [groupId]);
    if (!g.length) return res.status(404).json({ error: 'Group not found' });
    if (g[0].created_by !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'Only the creator can delete this group' });

    // ON DELETE CASCADE will automatically wipe the chat_group_members and chat_group_messages
    await pool.query('DELETE FROM chat_groups WHERE id=?', [groupId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to delete group' });
  }
});

// Send a message to a group
app.post('/api/chat/groups/:id/messages', authRequired, async (req, res) => {
  try {
    const groupId = Number(req.params.id);
    const { body, attachment_id } = req.body;

    // Verify membership ... (keep existing check)
    const [m] = await pool.query('SELECT 1 FROM chat_group_members WHERE group_id=? AND user_id=?', [groupId, req.user.id]);
    if (!m.length) return res.status(403).json({ error: 'Not a member' });

    if (!attachment_id && (!body || !body.trim())) return res.status(400).json({ error: 'Content required' });

    const [r] = await pool.query('INSERT INTO chat_group_messages (group_id, sender_id, body, attachment_id) VALUES (?,?,?,?)', 
      [groupId, req.user.id, body ? body.trim() : '', attachment_id || null]);

    const [[message]] = await pool.query(`
      SELECT m.id, m.sender_id, m.body, m.created_at, m.attachment_id,
             u.display_name, c.name as char_name, c.clan
      FROM chat_group_messages m
      LEFT JOIN users u ON m.sender_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE m.id = ?
    `, [r.insertId]);

    // --- NEW: PUSH NOTIFICATIONS ΓΙΑ ΟΜΑΔΙΚΕΣ ---
    try {
      // 1. Βρίσκουμε το όνομα της ομάδας
      const [[groupInfo]] = await pool.query('SELECT name FROM chat_groups WHERE id=?', [groupId]);
      const groupName = groupInfo?.name || 'Group Chat';
      const senderName = message.char_name || message.display_name || 'Someone';

      // 2. Φτιάχνουμε το περιεχόμενο της ειδοποίησης
      const notifTitle = `💬 ${groupName} (${senderName})`;
      const notifBody = message.attachment_id ? '📷 Image Attachment' : message.body;

      // 3. Βρίσκουμε όλα τα μέλη εκτός από τον αποστολέα
      const [members] = await pool.query('SELECT user_id FROM chat_group_members WHERE group_id=? AND user_id!=?', [groupId, req.user.id]);

      // 4. Στέλνουμε push notification στο κάθε μέλος
      for (const member of members) {
        await sendPushNotification(member.user_id, notifTitle, notifBody).catch(() => {});
      }
    } catch (pushErr) {
      log.err('Failed to notify group members', { error: pushErr.message });
    }
    // --------------------------------------------

    res.status(201).json({ message });
  } catch (e) {
    log.err('Group send failed', { message: e.message });
    res.status(500).json({ error: 'Failed' });
  }
});

// Admin: List all groups
app.get('/api/admin/chat/groups', authRequired, requireAdmin, async (req, res) => {
  try {
    const [groups] = await pool.query(`
      SELECT g.*, u.display_name as creator_name,
      (SELECT COUNT(*) FROM chat_group_members WHERE group_id = g.id) as member_count,
      (SELECT MAX(created_at) FROM chat_group_messages WHERE group_id = g.id) as last_active
      FROM chat_groups g
      LEFT JOIN users u ON g.created_by = u.id
      ORDER BY last_active DESC
    `);
    res.json({ groups });
  } catch (e) {
    res.status(500).json({ error: 'Failed' });
  }
});

// ADMIN: Get all group messages (for stats)
app.get('/api/admin/chat/groups/messages/all', authRequired, requireAdmin, async (req, res) => {
  try {
    const [messages] = await pool.query('SELECT * FROM chat_group_messages');
    res.json({ messages });
  } catch (e) { 
    res.status(500).json({ error: 'Failed to fetch group messages' }); 
  }
});

// ADMIN: Get all email messages (for stats)
app.get('/api/admin/emails/messages/all', authRequired, requireAdmin, async (req, res) => {
  try {
    const [messages] = await pool.query('SELECT * FROM email_messages');
    res.json({ messages });
  } catch (e) { 
    res.status(500).json({ error: 'Failed to fetch email messages' }); 
  }
});

// Admin: Get group history
app.get('/api/admin/chat/groups/:id/history', authRequired, requireAdmin, async (req, res) => {
  try {
    const groupId = Number(req.params.id);
    const [messages] = await pool.query(`
      SELECT m.id, m.sender_id, m.body, m.created_at,
            m.attachment_id,
            u.display_name, c.name as char_name, c.clan
      FROM chat_group_messages m
      LEFT JOIN users u ON m.sender_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE m.group_id = ?
      ORDER BY m.created_at ASC
    `, [groupId]);

    res.json({ messages });
  } catch (e) {
    res.status(500).json({ error: 'Failed' });
  }
});

// Get list of users to chat with (Sorted by Recency & Unread)
app.get('/api/chat/users', authRequired, async (req, res) => {
  try {
    const myId = req.user.id;
    
    // This query fetches users and calculates:
    // 1. last_msg: The timestamp of the latest message (sent OR received)
    // 2. unread: The count of messages sent BY this user TO me that are unread
    const [rows] = await pool.query(
      `
      SELECT
        u.id,
        u.display_name,
        u.role,
        CASE WHEN u.role = 'admin' THEN 1 ELSE 0 END AS is_admin,
        MAX(c.id)   AS char_id,
        MAX(c.name) AS char_name,
        MAX(c.clan) AS clan,
        MAX(c.image_url) AS image_url,
        (
          SELECT created_at 
          FROM chat_messages 
          WHERE (sender_id = u.id AND recipient_id = ?) OR (sender_id = ? AND recipient_id = u.id)
          ORDER BY created_at DESC LIMIT 1
        ) as last_message_at,
        (
          SELECT COUNT(*) 
          FROM chat_messages 
          WHERE sender_id = u.id AND recipient_id = ? AND read_at IS NULL
        ) as unread_count
      FROM users u
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE u.id <> ?
      GROUP BY u.id, u.display_name, u.role
      ORDER BY 
        unread_count DESC,   -- Unread first
        last_message_at DESC, -- Then most recent
        u.display_name ASC    -- Then alphabetical
      `,
      [myId, myId, myId, myId]
    );

    const users = rows.map(r => ({
      ...r,
      is_admin: !!r.is_admin,
      char_id: r.char_id ? Number(r.char_id) : null,
      unread_count: Number(r.unread_count || 0)
    }));

    res.json({ users });
  } catch (e) {
    log.err('Failed to get chat users', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to get users' });
  }
});

// List all NPCs (Sorted by Recency)
app.get('/api/chat/npcs', authRequired, async (req, res) => {
  try {
    const myId = req.user.id;
    const isAdmin = req.user.role === 'admin' || req.user.permission_level === 'admin';
    let query, params;

    if (isAdmin) {
      // Admins see if ANY player has sent an unread message to the NPC
      query = `SELECT n.id, n.name, n.clan, n.image_url,
        (SELECT created_at FROM npc_messages WHERE npc_id = n.id ORDER BY created_at DESC LIMIT 1) as last_message_at,
        (SELECT COUNT(*) FROM npc_messages WHERE npc_id = n.id AND from_side = 'user' AND read_at IS NULL) as unread_count
       FROM npcs n
       ORDER BY unread_count DESC, last_message_at DESC, n.name ASC`;
      params = [];
    } else {
      // Players see if the NPC has sent them an unread message
      query = `SELECT n.id, n.name, n.clan, n.image_url,
        (SELECT created_at FROM npc_messages WHERE npc_id = n.id AND user_id = ? ORDER BY created_at DESC LIMIT 1) as last_message_at,
        (SELECT COUNT(*) FROM npc_messages WHERE npc_id = n.id AND user_id = ? AND from_side = 'npc' AND read_at IS NULL) as unread_count
       FROM npcs n
       ORDER BY unread_count DESC, last_message_at DESC, n.name ASC`;
      params = [myId, myId];
    }
    const [rows] = await pool.query(query, params);
    res.json({ npcs: rows });
  } catch (e) {
    res.status(500).json({ error: 'Failed to list NPCs' });
  }
});


// Get message history with another user
app.get('/api/chat/history/:otherUserId', authRequired, async (req, res) => {
  try {
    const otherUserId = Number(req.params.otherUserId);
    const myId = req.user.id;

    const [messages] = await pool.query(
      `SELECT cm.id, cm.sender_id, cm.recipient_id, cm.body, cm.created_at,
              cm.read_at, cm.delivered_at,
              cm.attachment_id,
              u_sender.display_name as sender_name
       FROM chat_messages cm
       JOIN users u_sender ON cm.sender_id = u_sender.id
       WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
       ORDER BY created_at ASC`,
      [myId, otherUserId, otherUserId, myId]
    );

    res.json({ messages });
  } catch (e) {
    log.err('Failed to get chat history', { message: e.message });
    res.status(500).json({ error: 'Failed to get history' });
  }
});


// Send a message
app.post('/api/chat/messages', authRequired, async (req, res) => {
  try {
    // Added attachment_id to destructuring
    const { recipient_id, body, attachment_id } = req.body;
    
    // Allow empty body ONLY if there is an attachment
    if (!recipient_id || (!attachment_id && (!body || !body.trim()))) {
      return res.status(400).json({ error: 'Recipient and content required' });
    }

    const [r] = await pool.query(
      'INSERT INTO chat_messages (sender_id, recipient_id, body, attachment_id) VALUES (?, ?, ?, ?)',
      [req.user.id, recipient_id, body ? body.trim() : '', attachment_id || null]
    );

    // Fetch back with attachment info
    const [[message]] = await pool.query(
      `SELECT cm.id, cm.sender_id, cm.recipient_id, cm.body, cm.created_at, cm.attachment_id,
              u_sender.display_name as sender_name
       FROM chat_messages cm
       JOIN users u_sender ON cm.sender_id = u_sender.id
       WHERE cm.id = ?`,
      [r.insertId]
    );

    sendPushNotification(
      recipient_id, 
      message.sender_name, 
      message.attachment_id ? '📷 Image Attachment' : message.body
    )

    res.status(201).json({ message });
  } catch (e) {
    log.err('Failed to send message', { message: e.message });
    res.status(500).json({ error: 'Failed' });
  }
});

/* --- Edit & Delete Messages (4-Hour Window) --- */

// Universal Edit Message Route
app.put('/api/chat/messages/:id', authRequired, async (req, res) => {
  try {
    const msgId = Number(req.params.id);
    const { body } = req.body;
    const userId = req.user.id;
    const isAdmin = req.user.role === 'admin' || req.user.permission_level === 'admin';
    
    if (!body || !body.trim()) return res.status(400).json({ error: 'Message body cannot be empty.' });

    const FOUR_HOURS = 4 * 60 * 60 * 1000;
    
    const tables = [
      { name: 'chat_messages', senderCol: 'sender_id' },
      { name: 'chat_group_messages', senderCol: 'sender_id' },
      { name: 'npc_messages', senderCol: 'user_id', extraCondition: "from_side = 'user'" }
    ];

    let found = false;

    for (const table of tables) {
      const extraWhere = table.extraCondition ? ` AND ${table.extraCondition}` : '';
      const [rows] = await pool.query(`SELECT id, ${table.senderCol} as sender_id, created_at FROM ${table.name} WHERE id = ?${extraWhere}`, [msgId]);

      if (rows.length > 0) {
        const msg = rows[0];
        found = true;
        
        // FIX: Cast both to Strings to prevent Strict Equality ( !== ) Type Bugs
        if (String(msg.sender_id) !== String(userId) && !isAdmin) {
          return res.status(403).json({ error: 'You can only edit your own messages.' });
        }
        if (Date.now() - new Date(msg.created_at).getTime() > FOUR_HOURS && !isAdmin) {
          return res.status(403).json({ error: 'You can only edit a message within 4 hours of sending.' });
        }

        await pool.query(`UPDATE ${table.name} SET body = ?, edited = 1 WHERE id = ?`, [body.trim(), msgId]);
        return res.json({ ok: true, edited: true });
      }
    }

    if (isAdmin && !found) {
      const [npcRows] = await pool.query(`SELECT id FROM npc_messages WHERE id = ? AND from_side = 'npc'`, [msgId]);
      if (npcRows.length > 0) {
        await pool.query(`UPDATE npc_messages SET body = ?, edited = 1 WHERE id = ?`, [body.trim(), msgId]);
        return res.json({ ok: true, edited: true });
      }
    }

    if (!found) return res.status(404).json({ error: 'Message not found.' });

  } catch (e) {
    res.status(500).json({ error: 'Failed to edit message.' });
  }
});

// Universal Delete Message Route
app.delete('/api/chat/messages/:id', authRequired, async (req, res) => {
  try {
    const msgId = Number(req.params.id);
    const userId = req.user.id;
    const isAdmin = req.user.role === 'admin' || req.user.permission_level === 'admin';
    const FOUR_HOURS = 4 * 60 * 60 * 1000;
    
    const tables = [
      { name: 'chat_messages', senderCol: 'sender_id' },
      { name: 'chat_group_messages', senderCol: 'sender_id' },
      { name: 'npc_messages', senderCol: 'user_id', extraCondition: "from_side = 'user'" }
    ];

    let found = false;

    for (const table of tables) {
      const extraWhere = table.extraCondition ? ` AND ${table.extraCondition}` : '';
      const [rows] = await pool.query(`SELECT id, ${table.senderCol} as sender_id, created_at FROM ${table.name} WHERE id = ?${extraWhere}`, [msgId]);

      if (rows.length > 0) {
        const msg = rows[0];
        found = true;
        
        // FIX: Cast both to Strings to prevent Strict Equality ( !== ) Type Bugs
        if (String(msg.sender_id) !== String(userId) && !isAdmin) {
          return res.status(403).json({ error: 'You can only delete your own messages.' });
        }
        if (Date.now() - new Date(msg.created_at).getTime() > FOUR_HOURS && !isAdmin) {
          return res.status(403).json({ error: 'You can only delete a message within 4 hours of sending.' });
        }

        await pool.query(`DELETE FROM ${table.name} WHERE id = ?`, [msgId]);
        return res.json({ ok: true });
      }
    }

    if (isAdmin && !found) {
      const [npcRows] = await pool.query(`SELECT id FROM npc_messages WHERE id = ? AND from_side = 'npc'`, [msgId]);
      if (npcRows.length > 0) {
        await pool.query(`DELETE FROM npc_messages WHERE id = ?`, [msgId]);
        return res.json({ ok: true });
      }
    }

    if (!found) return res.status(404).json({ error: 'Message not found.' });

  } catch (e) {
    res.status(500).json({ error: 'Failed to delete message.' });
  }
});

// Mark messages as delivered (Call this when the chat app loads new messages)
app.post('/api/chat/delivered', authRequired, async (req, res) => {
  try {
    const { sender_id } = req.body;
    if (!sender_id) return res.status(400).json({ error: 'sender_id is required' });

    await pool.query(
      'UPDATE chat_messages SET delivered_at = NOW() WHERE sender_id = ? AND recipient_id = ? AND delivered_at IS NULL',
      [sender_id, req.user.id]
    );
    res.json({ ok: true });
  } catch (e) {
    log.err('Failed to mark messages as delivered', { message: e.message });
    res.status(500).json({ error: 'Failed' });
  }
});

// Mark messages from a specific user as read
app.post('/api/chat/read', authRequired, async (req, res) => {
  try {
    const { sender_id, npc_id, is_admin_reading_npc } = req.body;

    if (npc_id && is_admin_reading_npc) {
        // Admin is reading a player's messages to an NPC
        await pool.query(
            "UPDATE npc_messages SET read_at = NOW() WHERE npc_id = ? AND user_id = ? AND from_side = 'user' AND read_at IS NULL",
            [npc_id, sender_id]
        );
    } else if (npc_id) {
        // Player is reading an NPC's messages
        await pool.query(
            "UPDATE npc_messages SET read_at = NOW() WHERE npc_id = ? AND user_id = ? AND from_side = 'npc' AND read_at IS NULL",
            [npc_id, req.user.id]
        );
    } else if (sender_id) {
        // Normal Player to Player chat
        await pool.query(
            'UPDATE chat_messages SET read_at = NOW() WHERE sender_id = ? AND recipient_id = ? AND read_at IS NULL',
            [sender_id, req.user.id]
        );
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to mark as read' });
  }
});

/* -------------------- ADMIN DISCORD SETTINGS -------------------- */

/* -------------------- ADMIN DISCORD SETTINGS -------------------- */

// Get current Discord settings
app.get('/api/admin/discord/config', authRequired, requireAdmin, async (req, res) => {
  try {
    const channelId = await getSetting('discord_channel_id', '');
    const scheduleTime = await getSetting('discord_schedule_time', '12:00');
    
    // New feature toggles (default to true)
    const discord_enabled = await getSetting('discord_enabled', 'true') === 'true';
    const notify_mail = await getSetting('discord_notify_mail', 'true') === 'true';
    const notify_news = await getSetting('discord_notify_news', 'true') === 'true';
    const notify_prems = await getSetting('discord_notify_prems', 'true') === 'true';

    res.json({
      discord_channel_id: channelId,
      discord_schedule_time: scheduleTime,
      discord_enabled,
      notify_mail,
      notify_news,
      notify_prems,
      bot_status: discordClient?.isReady() ? 'Online' : 'Offline',
      bot_name: discordClient?.user?.tag || 'N/A'
    });
  } catch (e) {
    log.err('Get discord config failed', { message: e.message });
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

// Update Discord settings
app.post('/api/admin/discord/config', authRequired, requireAdmin, async (req, res) => {
  try {
    const { 
      discord_channel_id, discord_schedule_time, 
      discord_enabled, notify_mail, notify_news, notify_prems 
    } = req.body;
    
    if (discord_channel_id !== undefined) await setSetting('discord_channel_id', String(discord_channel_id).trim());
    
    if (discord_schedule_time !== undefined) {
      if (!/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(discord_schedule_time)) {
        return res.status(400).json({ error: 'Invalid time format. Use HH:MM (24h).' });
      }
      await setSetting('discord_schedule_time', String(discord_schedule_time));
    }

    if (discord_enabled !== undefined) await setSetting('discord_enabled', String(discord_enabled));
    if (notify_mail !== undefined) await setSetting('discord_notify_mail', String(notify_mail));
    if (notify_news !== undefined) await setSetting('discord_notify_news', String(notify_news));
    if (notify_prems !== undefined) await setSetting('discord_notify_prems', String(notify_prems));

    log.adm('Updated Discord settings', { admin_id: req.user.id });
    res.json({ ok: true });
  } catch (e) {
    log.err('Update discord config failed', { message: e.message });
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

// Trigger manual test notifications
app.post('/api/admin/discord/test/:type', authRequired, requireAdmin, async (req, res) => {
  try {
    const { type } = req.params;
    const channelId = await getSetting('discord_channel_id', null);
    
    if (!discordClient?.isReady()) {
      return res.status(503).json({ error: 'Discord bot is currently offline.' });
    }

    if (type === 'mail') {
      await sendDiscordMailNotifications(true); // Pass true to force the test
      return res.json({ ok: true, message: 'Mail test triggered.' });
    } 
    
    if (type === 'news') {
      if (!channelId) return res.status(400).json({ error: 'No channel configured.' });
      const channel = await discordClient.channels.fetch(channelId);
      await channel.send("📰 **TEST BROADCAST** 📰\n\nThis is a test of the Erebus News Network emergency broadcast system.");
      return res.json({ ok: true, message: 'News test broadcast sent.' });
    }

    if (type === 'premonition') {
      // Find the admin's discord ID to send them a test DM
      const [[adminRow]] = await pool.query('SELECT discord_id FROM users WHERE id=?', [req.user.id]);
      if (!adminRow?.discord_id) {
        return res.status(400).json({ error: 'You must link your Discord ID in the Users tab to receive a test premonition.' });
      }
      const discordUser = await discordClient.users.fetch(adminRow.discord_id);
      await discordUser.send("🧠 **TEST VISION**\n\nThe shadows whisper to you: *The system is functioning perfectly.*");
      return res.json({ ok: true, message: 'Test premonition sent to your DMs.' });
    }

    res.status(400).json({ error: 'Unknown test type.' });
  } catch (e) {
    log.err('Manual Discord test failed', { message: e.message });
    res.status(500).json({ error: 'Test failed: ' + e.message });
  }
});

// Hard Restart the Bot Connection
app.post('/api/admin/discord/restart', authRequired, requireAdmin, async (req, res) => {
  try {
    if (discordClient && process.env.DISCORD_BOT_TOKEN) {
      log.adm('Admin requested Discord bot restart', { admin_id: req.user.id });
      discordClient.destroy();
      await discordClient.login(process.env.DISCORD_BOT_TOKEN);
      res.json({ ok: true, message: "Bot connection restarted successfully." });
    } else {
      res.status(400).json({ error: "Bot is not configured." });
    }
  } catch (e) {
    log.err('Bot restart failed', { error: e.message });
    res.status(500).json({ error: 'Failed to restart bot.' });
  }
});

// Admin: Send Custom Direct Message to a specific user via Discord
app.post('/api/admin/discord/dm', authRequired, requireAdmin, async (req, res) => {
  try {
    const { user_id, message } = req.body;
    if (!user_id || !message) {
      return res.status(400).json({ error: 'User and message are required.' });
    }

    if (!discordClient?.isReady()) {
      return res.status(503).json({ error: 'Discord bot is currently offline.' });
    }

    // Lookup the user's Discord ID
    const [[user]] = await pool.query('SELECT discord_id, display_name FROM users WHERE id=?', [user_id]);
    if (!user || !user.discord_id) {
      return res.status(400).json({ error: `${user?.display_name || 'User'} has not linked their Discord ID yet.` });
    }

    // Fetch the user on Discord and send the DM
    const discordUser = await discordClient.users.fetch(user.discord_id);
    await discordUser.send(`🦇 **Message from the Storytellers:**\n\n${message}`);

    log.adm('Admin sent custom Discord DM', { admin_id: req.user.id, target_user: user_id });
    res.json({ ok: true, message: `DM successfully sent to ${user.display_name}.` });
  } catch (e) {
    log.err('Failed to send custom Discord DM', { error: e.message });
    res.status(500).json({ error: 'Failed to send DM.' });
  }
});

// ADMIN: Get all chat messages
app.get('/api/admin/chat/all', authRequired, requireAdmin, async (req, res) => {
    try {
        const [messages] = await pool.query(
            `SELECT
                cm.id, cm.body, cm.created_at,
                s.id as sender_id, s.display_name as sender_name,
                r.id as recipient_id, r.display_name as recipient_name
            FROM chat_messages cm
            JOIN users s ON cm.sender_id = s.id
            JOIN users r ON cm.recipient_id = r.id
            ORDER BY cm.created_at DESC`
        );
        log.adm('Admin fetched all chat messages', { count: messages.length });
        res.json({ messages });
    } catch (e) {
        log.err('Failed to get all chat messages for admin', { message: e.message });
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});


/* -------------------- Admin views -------------------- */
app.get('/api/admin/users', authRequired, requireAdmin, async (_req, res) => {
  // We added u.discord_id to the SELECT list here
  const [rows] = await pool.query(
    `SELECT u.id, u.email, u.display_name, u.role, u.discord_id,
            c.id AS character_id, c.name AS char_name, c.clan, c.sheet, c.xp
     FROM users u
     LEFT JOIN characters c ON c.user_id=u.id
     ORDER BY u.created_at DESC`
  );
  
  rows.forEach(r => {
    if (r.sheet && typeof r.sheet === 'string') {
      try { r.sheet = JSON.parse(r.sheet); } catch {}
    }
  });
  
  log.adm('Admin users list', { count: rows.length });
  res.json({ users: rows });
});


// Update a user (admin only)

app.patch('/api/admin/users/:id', authRequired, requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({ error: 'Invalid user id' });
    }

    const { display_name, email, role, discord_id } = req.body || {};
    const fields = [];
    const vals = [];

    // 1. Handle Role
    const validRoles = new Set(['user', 'courtuser', 'admin']);
    let roleChanged = false;
    if (role !== undefined) {
      const r = String(role);
      if (!validRoles.has(r)) {
        return res.status(400).json({ error: 'Invalid role' });
      }
      fields.push('role=?'); // FIXED: Ensure this is single =
      vals.push(r);
      roleChanged = true;
    }

    // 2. Handle Display Name
    let nameChanged = false;
    if (display_name !== undefined) {
      const name = String(display_name).trim();
      if (!name) return res.status(400).json({ error: 'Display name cannot be empty' });
      fields.push('display_name=?'); 
      vals.push(name);
      nameChanged = true;
    }

    // 3. Handle Email
    let emailChanged = false;
    if (email !== undefined) {
      const normEmail = String(email).trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normEmail)) {
        return res.status(400).json({ error: 'Invalid email' });
      }
      // Check for duplicates
      const [dup] = await pool.query('SELECT id FROM users WHERE email=? AND id<>?', [normEmail, id]);
      if (dup.length) return res.status(409).json({ error: 'Email already in use' });
      
      fields.push('email=?'); 
      vals.push(normEmail);
      emailChanged = true;
    }

    // 4. Handle Discord ID (New Logic)
    if (discord_id !== undefined) {
      const did = String(discord_id).trim();
      fields.push('discord_id=?');
      vals.push(did);
    }

    if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });

    // Perform Update
    vals.push(id);
    await pool.query(`UPDATE users SET ${fields.join(', ')} WHERE id=?`, vals);

    // Return updated row (Include discord_id in select)
    const [[row]] = await pool.query(
      `SELECT u.id, u.email, u.display_name, u.role, u.discord_id,
              c.id AS character_id, c.name AS char_name, c.clan, c.xp
       FROM users u
       LEFT JOIN characters c ON c.user_id = u.id
       WHERE u.id=?`,
      [id]
    );

    if (!row) return res.status(404).json({ error: 'User not found after update' });

    // Refresh token if self-edit
    const selfEdit = id === req.user.id;
    if (selfEdit && (roleChanged || nameChanged || emailChanged)) {
      const freshToken = issueToken({
        id: row.id,
        email: row.email,
        display_name: row.display_name,
        role: row.role,
      });
      return res.json({ user: row, token: freshToken });
    }

    log.adm('Admin updated user', { admin_id: req.user.id, user_id: id, fields });
    res.json({ user: row });

  } catch (e) {
    log.err('Admin update user failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// 2) Auth: refresh current user's token from DB (useful beyond admin flow)
app.post('/api/auth/refresh', authRequired, async (req, res) => {
  try {
    const [[u]] = await pool.query(
      'SELECT id, email, display_name, role FROM users WHERE id=?',
      [req.user.id]
    );
    if (!u) return res.status(404).json({ error: 'User not found' });
    const token = issueToken(u);
    res.json({ token, user: u });
  } catch (e) {
    res.status(500).json({ error: 'Failed to refresh token' });
  }
});



app.get('/api/admin/downtimes', authRequired, requireAdmin, async (_req, res) => {
  const [rows] = await pool.query(
    `SELECT d.*, c.name AS char_name, c.clan, u.display_name AS player_name, u.email
     FROM downtimes d
     JOIN characters c ON c.id=d.character_id
     JOIN users u ON u.id=c.user_id
     ORDER BY d.created_at DESC`
  );
  log.adm('Admin downtimes list', { count: rows.length });
  res.json({ downtimes: rows });
});

app.patch('/api/admin/downtimes/:id', authRequired, requireAdmin, async (req, res) => {
  const { status, gm_notes, gm_resolution } = req.body;
  const allowed = ['submitted', 'approved', 'rejected', 'resolved', 'Needs a Scene', 'Resolved in scene'];
  if (status && !allowed.includes(status)) return res.status(400).json({ error: 'Bad status' });

  const fields = [];
  const vals = [];

  if (status) { fields.push('status=?'); vals.push(status); }
  if (typeof gm_notes === 'string') { fields.push('gm_notes=?'); vals.push(gm_notes); }
  if (typeof gm_resolution === 'string') { fields.push('gm_resolution=?'); vals.push(gm_resolution); }

  // auto-set resolved_at when marking resolved
  if (status === 'resolved') {
    fields.push('resolved_at=?');
    vals.push(new Date());
  }

  if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });

  vals.push(req.params.id);
  await pool.query(`UPDATE downtimes SET ${fields.join(', ')} WHERE id=?`, vals);

  const [rows] = await pool.query('SELECT * FROM downtimes WHERE id=?', [req.params.id]);
  log.adm('Downtime updated', { id: req.params.id, fields });
  res.json({ downtime: rows[0] });
});

/* -------------------- Domain Claims -------------------- */
/** List all claims (public for logged-in users) */
app.get('/api/domain-claims', authRequired, async (_req, res) => {
  const [rows] = await pool.query(`
    SELECT d.division, d.owner_name, d.color, d.owner_character_id, d.owner_npc_id, d.claimed_at, c.user_id 
    FROM domain_claims d
    LEFT JOIN characters c ON d.owner_character_id = c.id
  `);
  res.json({ claims: rows });
});

/** Claim a division by number with a hex color (first come first served) */
app.post('/api/domain-claims/claim', authRequired, async (req, res) => {
  const { division, color } = req.body;
  const hex = (color || '').trim();
  if (!Number.isInteger(division)) {
    return res.status(400).json({ error: 'division must be an integer' });
  }
  if (!/^#([0-9a-fA-F]{6})$/.test(hex)) {
    return res.status(400).json({ error: 'color must be a 6-digit hex like #ff0066' });
  }

  // find caller’s character (optional owner_character_id)
  const [chars] = await pool.query('SELECT id, name FROM characters WHERE user_id=?', [req.user.id]);
  const myChar = chars[0] || null;
  const ownerName = myChar?.name || req.user.display_name || req.user.email;

  // is it already claimed?
  const [exists] = await pool.query('SELECT division FROM domain_claims WHERE division=?', [division]);
  if (exists.length) {
    return res.status(409).json({ error: 'This division is already claimed.' });
  }

  await pool.query(
    'INSERT INTO domain_claims (division, owner_character_id, owner_name, color) VALUES (?,?,?,?)',
    [division, myChar?.id || null, ownerName, hex]
  );

  const [row] = await pool.query('SELECT * FROM domain_claims WHERE division=?', [division]);
  res.json({ claim: row[0] });
});

// --- Admin: override/transfer a claim (safe upsert) ---
app.patch('/api/admin/domain-claims/:division', authRequired, requireAdmin, async (req, res) => {
  const division = Number(req.params.division);
  const { owner_name, color, owner_character_id, owner_npc_id } = req.body;

  const fields = [];
  const vals = [];

  if (typeof owner_name === 'string' && owner_name.trim()) { fields.push('owner_name=?'); vals.push(owner_name.trim()); }
  if (typeof color === 'string') {
    if (!/^#([0-9a-fA-F]{6})$/.test(color)) return res.status(400).json({ error: 'color must be #RRGGBB' });
    fields.push('color=?'); vals.push(color);
  }
  if (owner_character_id === null) {
    fields.push('owner_character_id=NULL');
  } else if (owner_character_id !== undefined) {
    if (!Number.isInteger(owner_character_id)) return res.status(400).json({ error: 'owner_character_id must be integer or null' });
    fields.push('owner_character_id=?'); vals.push(owner_character_id);
    fields.push('owner_npc_id=NULL'); // mutual exclusivity
  }
  if (owner_npc_id === null) {
    fields.push('owner_npc_id=NULL');
  } else if (owner_npc_id !== undefined) {
    if (!Number.isInteger(owner_npc_id)) return res.status(400).json({ error: 'owner_npc_id must be integer or null' });
    fields.push('owner_npc_id=?'); vals.push(owner_npc_id);
    fields.push('owner_character_id=NULL'); // mutual exclusivity
  }

  if (!fields.length) return res.status(400).json({ error: 'Nothing to update' });

  // 1) Try update existing
  vals.push(division);
  const [upd] = await pool.query(`UPDATE domain_claims SET ${fields.join(', ')} WHERE division=?`, vals);

  if (upd.affectedRows === 0) {
    // 2) Insert new with provided fields merged onto sensible defaults
    const base = {
      owner_name: (typeof owner_name === 'string' && owner_name.trim()) ? owner_name.trim() : 'Admin Set',
      color: (typeof color === 'string') ? color : '#888888',
      owner_character_id: (owner_character_id === null || owner_character_id === undefined) ? null : Number(owner_character_id),
      owner_npc_id: (owner_npc_id === null || owner_npc_id === undefined) ? null : Number(owner_npc_id),
    };
    await pool.query(
      'INSERT INTO domain_claims (division, owner_name, color, owner_character_id, owner_npc_id) VALUES (?,?,?,?,?)',
      [division, base.owner_name, base.color, base.owner_character_id, base.owner_npc_id]
    );
  }

  const [row] = await pool.query('SELECT * FROM domain_claims WHERE division=?', [division]);
  log.adm('Domain claim upsert', { division });
  res.json({ claim: row[0] });
});


/** Admin: unclaim (delete) */
app.delete('/api/admin/domain-claims/:division', authRequired, requireAdmin, async (req, res) => {
  const division = Number(req.params.division);
  await pool.query('DELETE FROM domain_claims WHERE division=?', [division]);
  res.json({ ok: true });
});

const readline = require('readline');

// helper to tail last N lines of a file fairly efficiently (works for large files)
async function tailFile(filePath, maxLines = 200) {
  // fallback if file missing
  if (!fs.existsSync(filePath)) return [];

  // For simplicity/readability: read file stream and keep last N lines in an array
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

// Admin: fetch last N lines
app.get('/api/admin/logs', authRequired, requireAdmin, async (req, res) => {
  const file = process.env.LOG_FILE;
  if (!file) return res.status(404).json({ error: 'Log file not configured' });

  const lines = Number(req.query.lines || 200);
  try {
    const last = await tailFile(file, Math.min(1000, Math.max(10, lines)));
    // If LOG_JSON=1, return parsed JSON objects (best-effort)
    if (process.env.LOG_JSON === '1') {
      const parsed = last.map(l => {
        try { return JSON.parse(l); } catch { return { raw: l }; }
      });
      return res.json({ ok: true, lines: parsed });
    } else {
      return res.json({ ok: true, lines: last });
    }
  } catch (e) {
    log.err('Admin logs read failed', { message: e.message });
    return res.status(500).json({ error: 'Failed to read log file' });
  }
});

// Admin: download full log (stream)
app.get('/api/admin/logs/download', authRequired, requireAdmin, (req, res) => {
  const file = process.env.LOG_FILE;
  if (!file) return res.status(404).json({ error: 'Log file not configured' });
  const fp = path.resolve(file);
  if (!fs.existsSync(fp)) return res.status(404).json({ error: 'Log file missing' });

  res.setHeader('Content-Disposition', `attachment; filename="${path.basename(fp)}"`);
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  const stream = fs.createReadStream(fp);
  stream.pipe(res);
  stream.on('error', (err) => {
    log.err('Admin logs download failed', { message: err.message });
    res.end();
  });
});

// Admin: clear log file (truncate) — use with care
app.post('/api/admin/logs/clear', authRequired, requireAdmin, (req, res) => {
  const file = process.env.LOG_FILE;
  if (!file) return res.status(440).json({ error: 'Log file not configured' });
  const fp = path.resolve(file);
  try {
    fs.truncateSync(fp, 0);
    log.adm('Log file truncated by admin', { admin_id: req.user.id });
    return res.json({ ok: true });
  } catch (e) {
    log.err('Admin clear logs failed', { message: e.message });
    return res.status(500).json({ error: 'Failed to clear log file' });
  }
});

// Admin: fetch ALL NPC chat messages (flat list)
app.get('/api/admin/chat/npc/all', authRequired, requireAdmin, async (_req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT id, npc_id, user_id, from_side, body, created_at
      FROM npc_messages
      ORDER BY created_at ASC
    `);

    res.json({ messages: rows });
  } catch (e) {
    log.err('Admin fetch ALL NPC messages failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to fetch NPC messages' });
  }
});

// Court/Admin: fetch ALL NPC messages
app.get('/api/court/chat/npc/all', authRequired, requireCourt, async (_req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT id, npc_id, user_id, from_side, body, created_at
      FROM npc_messages
      ORDER BY created_at ASC
    `);
    res.json({ messages: rows });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch NPC messages' });
  }
});


// --- NEW ROUTE to save a subscription ---
// --- PUSH: UPSERT SUB, TEST SEND, UNSUBSCRIBE ---

// Save/Upsert subscription (auth required)
app.post('/api/push/subscribe', authRequired, async (req, res) => {
  try {
    const { subscription } = req.body || {};
    
    // Validate that we actually received a proper subscription object
    if (!subscription || !subscription.endpoint) {
      return res.status(400).json({ error: 'Valid subscription with endpoint is required' });
    }

    const endpoint = subscription.endpoint;
    const json = JSON.stringify(subscription);

    // Upsert by endpoint, so repeated toggles don't duplicate
    await pool.query(
      `INSERT INTO push_subscriptions (user_id, endpoint, subscription_json)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE user_id=VALUES(user_id), subscription_json=VALUES(subscription_json)`,
      [req.user.id, endpoint, json]
    );

    log.ok('Push subscription upserted', { user_id: req.user.id });
    res.status(201).json({ ok: true });
  } catch (e) {
    log.err('Push subscribe failed', { message: e.message });
    res.status(500).json({ error: 'Failed to save subscription' });
  }
});

// Unsubscribe: delete by endpoint (auth required)
app.post('/api/push/unsubscribe', authRequired, async (req, res) => {
  try {
    const { endpoint } = req.body || {};
    if (!endpoint) return res.status(400).json({ error: 'endpoint is required' });

    await pool.query('DELETE FROM push_subscriptions WHERE user_id=? AND endpoint=?', [req.user.id, endpoint]);
    log.ok('Push subscription removed', { user_id: req.user.id });
    res.json({ ok: true });
  } catch (e) {
    log.err('Push unsubscribe failed', { message: e.message });
    res.status(500).json({ error: 'Failed to remove subscription' });
  }
});



// Fire a test push to current user (auth required)
app.post('/api/push/test', authRequired, async (req, res) => {
  try {
    await sendPushNotification(req.user.id, '🔔 Push Test', 'If you can read this, background push works!', { url: '/comms', tag: 'push-test' });
    res.json({ ok: true });
  } catch (e) {
    log.err('Push test failed', { message: e.message });
    res.status(500).json({ error: 'Failed to send test push' });
  }
});

// GET /api/push/ntfy-topic
app.get('/api/push/ntfy-topic', authRequired, async (req, res) => {
  try {
    const topic = crypto.createHash('md5').update('vampire_' + req.user.id + (process.env.JWT_SECRET || 'secret')).digest('hex');
    res.json({ topic });
  } catch (e) {
    res.status(500).json({ error: 'Failed to generate topic' });
  }
});


// --- NEW ROUTE to remove a subscription (e.g., on logout) ---
app.post('/api/push/unsubscribe', authRequired, async (req, res) => {
    // Logic to find and delete the subscription from your DB
    // ...
    res.json({ ok: true });
});


app.use(attachRequestLogger({
  // This prevents NEW logs from being generated when you refresh the log page
  silentPaths: [
    /^\/api\/admin\/logs(?:\/.*)?$/,
    /^\/api\/health/ 
  ]
}));

// --- DB Init Helpers ---
let diceTableCreated = false;
async function _ensureDiceTable() {
  if (diceTableCreated) return;
  try {
    // Use the promise-based pool here
    await pool.query(`
      CREATE TABLE IF NOT EXISTS dice_rolls (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        character_id INT NULL,
        pool INT NOT NULL,
        hunger INT NOT NULL DEFAULT 0,
        sides INT NOT NULL DEFAULT 10,
        results_json JSON NOT NULL,
        successes INT NOT NULL DEFAULT 0,
        crit_pairs INT NOT NULL DEFAULT 0,
        messy_crit TINYINT(1) NOT NULL DEFAULT 0,
        bestial_failure TINYINT(1) NOT NULL DEFAULT 0,
        note VARCHAR(255) NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_user (user_id),
        INDEX idx_created (created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    diceTableCreated = true;
    log.ok('Dice table verified/created.');
  } catch (e) {
    log.err('Failed to create dice_rolls table', { message: e.message });
  }
}

// app.use(expressErrorHandler); // This was duplicated, removed one

/* -------------------- Coteries -------------------- */

/**
 * Create a coterie
 * body: {
 * name, type, domain_id|null,
 * traits:{chasse,lien,portillon},
 * required (object of {Name: dots}),
 * backgrounds (array of {name,dots}),
 * extras (array of strings),
 * points_per_member (1|2),
 * coterie_xp (number),
 * members: [{ user_id, display_name }]
 * }
 */
app.post('/api/coteries', authRequired, async (req, res) => {
  try {
    const {
      name, type, domain_id,
      traits = {},
      required = null,
      backgrounds = [],
      extras = [],
      points_per_member = 1,
      coterie_xp = 0,
      members = []
    } = req.body || {};

    if (!name || !Array.isArray(members) || members.length < 3) {
      return res.status(400).json({ error: 'Name and ≥3 members are required' });
    }

    const chasse = Number(traits.chasse || 0);
    const lien   = Number(traits.lien   || 0);
    const portillon = Number(traits.portillon || 0);

    const [ins] = await pool.query(
      `INSERT INTO coteries
       (name, type, domain_id, chasse, lien, portillon, required_json, backgrounds_json, extras_json, points_per_member, coterie_xp, created_by)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        name.trim(),
        type || null,
        domain_id || null,
        chasse, lien, portillon,
        required ? JSON.stringify(required) : null,
        JSON.stringify(backgrounds || []),
        JSON.stringify(extras || []),
        Math.min(2, Math.max(1, Number(points_per_member || 1))),
        Number.isFinite(coterie_xp) ? coterie_xp : 0,
        req.user.id
      ]
    );
    const coterieId = ins.insertId;

    if (members.length) {
      const values = members.map(m => [coterieId, Number(m.user_id), (m.display_name || null)]);
      await pool.query(
        `INSERT INTO coterie_members (coterie_id, user_id, display_name) VALUES ?`,
        [values]
      );
    }

    const [[row]] = await pool.query(`SELECT * FROM coteries WHERE id=?`, [coterieId]);
    log.ok('Coterie created', { id: coterieId, by_user_id: req.user.id });
    res.status(201).json({ coterie: row });
  } catch (e) {
    log.err('Create coterie failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to create coterie' });
  }
});

// Public registry of all coteries for all players (Character Names Only)
app.get('/api/coteries/all', authRequired, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        c.id, c.name, c.type, c.domain_id,
        COUNT(m.user_id) as member_count,
        GROUP_CONCAT(
          COALESCE(ch.name, m.display_name) 
          SEPARATOR ', '
        ) as members_display
      FROM coteries c
      LEFT JOIN coterie_members m ON m.coterie_id = c.id
      LEFT JOIN characters ch ON ch.user_id = m.user_id
      GROUP BY c.id
      ORDER BY c.name ASC
    `);
    res.json({ coteries: rows });
  } catch (e) {
    console.error('Failed to load all coteries', e);
    res.status(500).json({ error: 'Failed to load public coteries' });
  }
});

// List coteries (admin → all, user → only where member)
app.get('/api/coteries', authRequired, async (req, res) => {
  try {
    if (req.user.role === 'admin' || req.user.permission_level === 'admin') {
      const [rows] = await pool.query(`SELECT * FROM coteries ORDER BY updated_at DESC`);
      return res.json({ coteries: rows });
    }
    const [rows] = await pool.query(`
      SELECT c.*
      FROM coteries c
      JOIN coterie_members m ON m.coterie_id=c.id
      WHERE m.user_id=?
      ORDER BY c.updated_at DESC
    `, [req.user.id]);
    res.json({ coteries: rows });
  } catch (e) {
    log.err('List coteries failed', { message: e.message });
    res.status(500).json({ error: 'Failed to load coteries' });
  }
});

// Read single coterie (member or admin)
app.get('/api/coteries/:id', authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const [[c]] = await pool.query(`SELECT * FROM coteries WHERE id=?`, [id]);
    if (!c) return res.status(404).json({ error: 'Not found' });

    // authz: admin or member
    if (!(req.user.role === 'admin' || req.user.permission_level === 'admin')) {
      const [m] = await pool.query(`SELECT 1 FROM coterie_members WHERE coterie_id=? AND user_id=?`, [id, req.user.id]);
      if (!m.length) return res.status(403).json({ error: 'Not allowed' });
    }

    const [members] = await pool.query(`SELECT user_id, display_name FROM coterie_members WHERE coterie_id=?`, [id]);
    res.json({ coterie: c, members });
  } catch (e) {
    log.err('Read coterie failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to load coterie' });
  }
});



// Update core fields (member or admin)
app.put('/api/coteries/:id', authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);

    // must be admin or member
    if (!(req.user.role === 'admin' || req.user.permission_level === 'admin')) {
      const [m] = await pool.query(`SELECT 1 FROM coterie_members WHERE coterie_id=? AND user_id=?`, [id, req.user.id]);
      if (!m.length) return res.status(403).json({ error: 'Not allowed' });
    }

    const {
      name, type, domain_id,
      traits = {},
      required = null,
      backgrounds = [],
      extras = [],
      points_per_member,
      coterie_xp
    } = req.body || {};

    const fields = [];
    const params = [];
    if (name != null) { fields.push('name=?'); params.push(String(name)); }
    if (type != null) { fields.push('type=?'); params.push(type || null); }
    if (domain_id !== undefined) { fields.push('domain_id=?'); params.push(domain_id || null); }
    if (traits) {
      fields.push('chasse=?','lien=?','portillon=?');
      params.push(Number(traits.chasse || 0), Number(traits.lien || 0), Number(traits.portillon || 0));
    }
    if (required !== undefined) { fields.push('required_json=?'); params.push(required ? JSON.stringify(required) : null); }
    if (backgrounds !== undefined) { fields.push('backgrounds_json=?'); params.push(JSON.stringify(backgrounds || [])); }
    if (extras !== undefined) { fields.push('extras_json=?'); params.push(JSON.stringify(extras || [])); }
    if (points_per_member !== undefined) { fields.push('points_per_member=?'); params.push(Math.min(2, Math.max(1, Number(points_per_member || 1)))); }
    if (coterie_xp !== undefined) { fields.push('coterie_xp=?'); params.push(Number(coterie_xp || 0)); }

    if (!fields.length) return res.json({ ok: true });

    await pool.query(`UPDATE coteries SET ${fields.join(', ')} WHERE id=?`, [...params, id]);
    const [[row]] = await pool.query(`SELECT * FROM coteries WHERE id=?`, [id]);
    res.json({ coterie: row });
  } catch (e) {
    log.err('Update coterie failed', { message: e.message });
    res.status(500).json({ error: 'Failed to update coterie' });
  }
});

// Replace members (admin or current member)
app.post('/api/coteries/:id/members/set', authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!(req.user.role === 'admin' || req.user.permission_level === 'admin')) {
      const [m] = await pool.query(`SELECT 1 FROM coterie_members WHERE coterie_id=? AND user_id=?`, [id, req.user.id]);
      if (!m.length) return res.status(403).json({ error: 'Not allowed' });
    }

    const { members = [] } = req.body || {};
    if (!Array.isArray(members) || members.length < 3) {
      return res.status(400).json({ error: '≥3 members required' });
    }

    await pool.query(`DELETE FROM coterie_members WHERE coterie_id=?`, [id]);
    const values = members.map(m => [id, Number(m.user_id), (m.display_name || null)]);
    await pool.query(`INSERT INTO coterie_members (coterie_id, user_id, display_name) VALUES ?`, [values]);

    const [rows] = await pool.query(`SELECT user_id, display_name FROM coterie_members WHERE coterie_id=?`, [id]);
    res.json({ members: rows });
  } catch (e) {
    log.err('Set coterie members failed', { message: e.message });
    res.status(500).json({ error: 'Failed to set members' });
  }
});

// Adjust Coterie XP (delta) - admin or member
// body: { delta: +N | -N }
app.post('/api/coteries/:id/xp', authRequired, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!(req.user.role === 'admin' || req.user.permission_level === 'admin')) {
      const [m] = await pool.query(`SELECT 1 FROM coterie_members WHERE coterie_id=? AND user_id=?`, [id, req.user.id]);
      if (!m.length) return res.status(403).json({ error: 'Not allowed' });
    }
    const delta = Number(req.body?.delta || 0);
    await pool.query(`UPDATE coteries SET coterie_xp = GREATEST(0, coterie_xp + ?) WHERE id=?`, [delta, id]);
    const [[row]] = await pool.query(`SELECT coterie_xp FROM coteries WHERE id=?`, [id]);
    res.json({ coterie_xp: row?.coterie_xp ?? 0 });
  } catch (e) {
    log.err('Adjust coterie XP failed', { message: e.message });
    res.status(500).json({ error: 'Failed to adjust XP' });
  }
});

// Delete coterie (admin only)
app.delete('/api/coteries/:id', authRequired, requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    await pool.query(`DELETE FROM coteries WHERE id=?`, [id]);
    log.adm('Coterie deleted', { id, by_user_id: req.user.id });
    res.json({ ok: true });
  } catch (e) {
    log.err('Delete coterie failed', { message: e.message });
    res.status(500).json({ error: 'Failed to delete coterie' });
  }
});

// GET: public to logged-in users (players need to see dates)
app.get('/api/downtimes/config', authRequired, async (req, res) => {
  try {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    
    const deadline = await getSetting('downtime_deadline', null);
    const opening  = await getSetting('downtime_opening', null);
    const projectDeadline = await getSetting('project_deadline', null); 
    const activePhase = await getSetting('downtime_active_phase', 'standard'); // <-- NEW
    
    res.json({
      downtime_deadline: deadline || null,
      downtime_opening: opening  || null,
      project_deadline: projectDeadline || null, 
      downtime_active_phase: activePhase, // <-- NEW
    });
  } catch (e) {
    log.err('Fetch downtime config failed', { message: e.message });
    res.status(500).json({ error: 'Failed to fetch downtime config' });
  }
});

// WRITE (admins): save the dates
app.post('/api/admin/downtimes/config', authRequired, requireAdmin, async (req, res) => {
  try {
    const { downtime_deadline, downtime_opening, project_deadline, downtime_active_phase } = req.body || {}; 

    if (downtime_deadline && isNaN(new Date(downtime_deadline).getTime())) {
      return res.status(400).json({ error: 'Invalid downtime_deadline date' });
    }
    if (downtime_opening && isNaN(new Date(downtime_opening).getTime())) {
      return res.status(400).json({ error: 'Invalid downtime_opening date' });
    }
    if (project_deadline && isNaN(new Date(project_deadline).getTime())) { 
      return res.status(400).json({ error: 'Invalid project_deadline date' });
    }

    if (typeof downtime_deadline !== 'undefined') await setSetting('downtime_deadline', downtime_deadline || '');
    if (typeof downtime_opening !== 'undefined') await setSetting('downtime_opening', downtime_opening || '');
    if (typeof project_deadline !== 'undefined') await setSetting('project_deadline', project_deadline || '');
    if (typeof downtime_active_phase !== 'undefined') await setSetting('downtime_active_phase', downtime_active_phase || 'standard'); // <-- NEW

    const deadline = await getSetting('downtime_deadline', null);
    const opening  = await getSetting('downtime_opening', null);
    const projDeadline = await getSetting('project_deadline', null); 
    const phase = await getSetting('downtime_active_phase', 'standard'); // <-- NEW

    res.json({
      ok: true,
      downtime_deadline: deadline || null,
      downtime_opening: opening  || null,
      project_deadline: projDeadline || null, 
      downtime_active_phase: phase // <-- NEW
    });
  } catch (e) {
    log.err('Update downtime config failed', { message: e.message });
    res.status(500).json({ error: 'Failed to update downtime config' });
  }
});

// GET: public to logged-in users (players need to see dates)
// READ: players (and admins) can read the dates
app.get('/api/downtimes/config', authRequired, async (req, res) => {
  try {
    // FIX: Prevent browser caching so new deadlines appear immediately for players
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    
    const deadline = await getSetting('downtime_deadline', null);
    const opening  = await getSetting('downtime_opening', null);
    const projectDeadline = await getSetting('project_deadline', null); // <-- Added
    
    res.json({
      downtime_deadline: deadline || null,
      downtime_opening: opening  || null,
      project_deadline: projectDeadline || null, // <-- Added
    });
  } catch (e) {
    log.err('Fetch downtime config failed', { message: e.message });
    res.status(500).json({ error: 'Failed to fetch downtime config' });
  }
});

// WRITE (admins): save the dates
// ⚠️ make sure the path is **/admin/downtimes/config** (no extra 'c')
app.post('/api/admin/downtimes/config', authRequired, requireAdmin, async (req, res) => {
  try {
    // <-- Added project_deadline to destructuring
    const { downtime_deadline, downtime_opening, project_deadline } = req.body || {}; 

    if (downtime_deadline && isNaN(new Date(downtime_deadline).getTime())) {
      return res.status(400).json({ error: 'Invalid downtime_deadline date' });
    }
    if (downtime_opening && isNaN(new Date(downtime_opening).getTime())) {
      return res.status(400).json({ error: 'Invalid downtime_opening date' });
    }
    if (project_deadline && isNaN(new Date(project_deadline).getTime())) { // <-- Added validation
      return res.status(400).json({ error: 'Invalid project_deadline date' });
    }

    if (typeof downtime_deadline !== 'undefined') {
      await setSetting('downtime_deadline', downtime_deadline || '');
    }
    if (typeof downtime_opening !== 'undefined') {
      await setSetting('downtime_opening', downtime_opening || '');
    }
    if (typeof project_deadline !== 'undefined') { // <-- Now safely works
      await setSetting('project_deadline', project_deadline || '');
    }

    const deadline = await getSetting('downtime_deadline', null);
    const opening  = await getSetting('downtime_opening', null);
    const projDeadline = await getSetting('project_deadline', null); // <-- Added fetch back

    res.json({
      ok: true,
      downtime_deadline: deadline || null,
      downtime_opening: opening  || null,
      project_deadline: projDeadline || null, // <-- Added return
    });
  } catch (e) {
    log.err('Update downtime config failed', { message: e.message });
    res.status(500).json({ error: 'Failed to update downtime config' });
  }
});


/* -------------------- NEW PREMONITION ROUTES -------------------- */

// ADMIN: List all premonitions (+ recipients)
app.get('/api/admin/premonitions', authRequired, requireAdmin, async (req, res) => {
  try {
    await _ensurePremonitionsTables();

    // Base list
    const [prems] = await pool.query(`
      SELECT p.id, p.sender_id, u.display_name AS sender_name,
             p.content_type, p.content_text, p.content_url, p.created_at
      FROM premonitions p
      LEFT JOIN users u ON u.id = p.sender_id
      ORDER BY p.created_at DESC
      LIMIT 500
    `);

    if (prems.length === 0) return res.json({ premonitions: [] });

    // Recipients per premonition
    const ids = prems.map(p => p.id);
    const [recips] = await pool.query(`
      SELECT pr.premonition_id, pr.user_id, pr.viewed_at,
             u.display_name, COALESCE(c.name,'') AS char_name
      FROM premonition_recipients pr
      JOIN users u ON u.id = pr.user_id
      LEFT JOIN characters c ON c.user_id = u.id
      WHERE pr.premonition_id IN (${ids.map(()=>'?').join(',')})
      ORDER BY u.display_name ASC
    `, ids);

    const byPrem = new Map();
    for (const r of recips) {
      if (!byPrem.has(r.premonition_id)) byPrem.set(r.premonition_id, []);
      byPrem.get(r.premonition_id).push({
        user_id: r.user_id,
        display_name: r.display_name,
        char_name: r.char_name || null,
        viewed_at: r.viewed_at
      });
    }

    res.json({
      premonitions: prems.map(p => ({
        ...p,
        recipients: byPrem.get(p.id) || []
      }))
    });
  } catch (e) {
    log.err('Admin list premonitions failed', { message: e.message });
    res.status(500).json({ error: 'Failed to load premonitions' });
  }
});


// ADMIN: Get list of Malkavian players  ✅ REPLACE THIS ROUTE
app.get('/api/admin/premonitions/malkavians', authRequired, requireAdmin, async (req, res) => {
  try {
    await _ensurePremonitionsTables();

    // One row per user that has at least one Malkavian character
    const [rows] = await pool.query(`
      SELECT 
        u.id,
        u.display_name,
        COALESCE(MAX(c.name), '(no character)') AS char_name
      FROM users u
      LEFT JOIN characters c 
        ON c.user_id = u.id
      WHERE u.role <> 'admin'
        AND EXISTS (
          SELECT 1
          FROM characters c2
          WHERE c2.user_id = u.id
            AND LOWER(TRIM(c2.clan)) = 'malkavian'
        )
      GROUP BY u.id, u.display_name
      ORDER BY u.display_name ASC
    `);

    res.json({ malkavians: rows });
  } catch (e) {
    log.err('Failed to get Malkavian list', { message: e.message });
    res.status(500).json({ error: 'Failed to get Malkavians' });
  }
});

// ADMIN: Upload media and store it in the DB
app.post('/api/admin/premonitions/upload', authRequired, requireAdmin, memoryUpload.single('file'), async (req, res) => {
  try {
    await _ensurePremonitionsMediaTables(); // Ensure media table exists
    if (!req.file) {
      return res.status(400).json({ error: 'File is required' });
    }
    const { originalname, mimetype, size, buffer } = req.file;

    const [ins] = await pool.query(
      'INSERT INTO premonition_media (filename, mime, size, data) VALUES (?,?,?,?)',
      [originalname || 'upload', mimetype, size, buffer]
    );
    const media_id = ins.insertId;

    res.json({
      media_id,
      media_mime: mimetype,
      media_stream_url: `/api/premonitions/media/${media_id}`
    });
  } catch (e) {
    log.err('Premonition media upload failed', { message: e.message });
    res.status(500).json({ error: 'Failed to upload media' });
  }
});

// ADMIN: Create and send a new premonition
app.post('/api/admin/premonitions/send', authRequired, requireAdmin, async (req, res) => {
  try {
    await _ensurePremonitionsTables(); // Ensure main tables exist
    const { content_type, content_text, content_url, user_ids = [] } = req.body;
    const sendToAllMalks = user_ids.includes('all_malkavians');
    
    if (!content_type || (!content_text && !content_url)) {
      return res.status(400).json({ error: 'Type and content (text or URL) are required' });
    }

    // 1. Create the premonition content
    const [ins] = await pool.query(
      `INSERT INTO premonitions (sender_id, content_type, content_text, content_url)
       VALUES (?, ?, ?, ?)`,
      [req.user.id, content_type, content_text || null, content_url || null]
    );
    const premonitionId = ins.insertId;

    // 2. Figure out who to send it to
    let targetUserIds = [];
    if (sendToAllMalks) {
      // Get all non-admin Malkavian user IDs
      const [malks] = await pool.query(`
        SELECT DISTINCT u.id
        FROM users u
        JOIN characters c ON c.user_id = u.id
        WHERE u.role <> 'admin'
          AND LOWER(TRIM(c.clan)) = 'malkavian'
      `);
      targetUserIds = malks.map(m => m.id);
    } else {
      // Use the specific list, filtering out any non-numeric values
      targetUserIds = user_ids.map(id => parseInt(id)).filter(id => !isNaN(id));
    }

    // 3. Insert recipients
    if (targetUserIds.length > 0) {
      // Remove duplicates
      const uniqueUserIds = [...new Set(targetUserIds)];
      const values = uniqueUserIds.map(userId => [premonitionId, userId]);
      await pool.query(
        'INSERT INTO premonition_recipients (premonition_id, user_id) VALUES ?',
        [values]
      );

// --- UPDATED: DISCORD PREMONITION DMs ---
      const discordEnabled = await getSetting('discord_enabled', 'true') === 'true';
      const notifyPrems = await getSetting('discord_notify_prems', 'true') === 'true';

      if (discordEnabled && notifyPrems && discordClient?.isReady()) {
        try {
          const [userRows] = await pool.query(
            `SELECT discord_id, display_name FROM users WHERE id IN (?) AND discord_id IS NOT NULL AND discord_id != ''`,
            [uniqueUserIds]
          );

          // Log how many Discord accounts were found
          log.ok(`Discord Premonition: Found ${userRows.length} linked accounts for targets.`, { targets: uniqueUserIds });

          for (const row of userRows) {
            try {
              const discordUser = await discordClient.users.fetch(row.discord_id);
              if (discordUser) {
                let dmMsg = `🧠 **A sudden vision pierces your mind...**\n\n`;
                if (content_text) dmMsg += `_${content_text}_\n`;

                if (content_type === 'image' || content_type === 'video') {
                  dmMsg += `\n👁️ **View Vision:** https://portal.attlarp.gr/media/${premonitionId}`;
                } else if (content_url) {
                  dmMsg += `\n🔗 ${content_url}`;
                }
                
                await discordUser.send(dmMsg);
                log.ok(`Premonition DM sent to ${row.display_name}`);
              }
            } catch (dmErr) {
              log.warn(`Failed to DM Discord user ${row.discord_id} (${row.display_name})`, { error: dmErr.message });
            }
          }
        } catch (dbErr) {
          log.err('Failed to fetch Discord IDs for premonitions', { error: dbErr.message });
        }
      } else {
        // This log will appear if the bot skips the DM process entirely
        log.warn('Discord DM Skipped: Feature is toggled OFF or Bot is not ready.', { 
          enabled: discordEnabled, 
          notify: notifyPrems, 
          ready: discordClient?.isReady() 
        });
      }
      // ------------------------------------
    }
    
    log.adm('Admin sent premonition', { id: premonitionId, by_user_id: req.user.id, targets: sendToAllMalks ? 'all_malks' : targetUserIds });
    res.status(201).json({ ok: true, premonition_id: premonitionId, count: targetUserIds.length });
  

  } catch (e) {
    log.err('Failed to send premonition', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to send premonition' });
  }
});

// PLAYER: Get my premonitions
app.get('/api/premonitions/mine', authRequired, async (req, res) => {
  try {
    await _ensurePremonitionsTables();

    const [rows] = await pool.query(`
      SELECT p.id, p.sender_id, u.display_name AS sender_name,
             p.content_type, p.content_text, p.content_url, p.created_at
      FROM premonitions p
      JOIN premonition_recipients pr ON p.id = pr.premonition_id
      LEFT JOIN users u ON u.id = p.sender_id
      WHERE pr.user_id = ?
      ORDER BY p.created_at DESC
    `, [req.user.id]);

    // fire & forget mark viewed
    if (rows.length > 0) {
      const ids = rows.map(r => r.id);
      pool.query(
        `UPDATE premonition_recipients
         SET viewed_at = NOW()
         WHERE user_id = ? AND premonition_id IN (${ids.map(() => '?').join(',')})
           AND viewed_at IS NULL`,
        [req.user.id, ...ids]
      ).catch(err => log.err('Failed to mark premonitions as read', { message: err.message }));
    }

    // 👇 ΑΥΤΟ είναι το σημαντικό
    res.set('Cache-Control', 'no-store');
    res.status(200).json({ premonitions: rows });
  } catch (e) {
    log.err('Failed to get my premonitions', { message: e.message });
    res.status(500).json({ error: 'Failed to load premonitions' });
  }
});



// MEDIA: Stream media from DB
app.get('/api/premonitions/media/:id', authRequired, async (req, res) => {
  try {
    await _ensurePremonitionsMediaTables();
    const id = Number(req.params.id) || 0;
    
    // **FIX: Initialize hasAccess here**
    let hasAccess = req.user.role === 'admin'; 

    // Check if user is admin OR has access to this premonition
    if (!hasAccess) {
      // FIX: Build the LIKE pattern string first using a template literal (backticks)
      const likePattern = `%/api/premonitions/media/${id}%`;

      const [accessRows] = await pool.query(`
        SELECT 1 FROM premonitions p
        JOIN premonition_recipients pr ON p.id = pr.premonition_id
        WHERE p.content_url LIKE ? AND pr.user_id = ?
      `, [likePattern, req.user.id]); // FIX: Pass the correctly built string
      
      if (accessRows.length > 0) {
        hasAccess = true;
      }
    }

    if (!hasAccess) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    // User has access, fetch the media
    const [rows] = await pool.query('SELECT mime, size, data FROM premonition_media WHERE id=? LIMIT 1', [id]);
    if (!rows.length) {
      return res.status(404).send('Not found');
    }

    const { mime, size, data } = rows[0];
    res.setHeader('Content-Type', mime || 'application/octet-stream');
    res.setHeader('Content-Length', size);
    res.setHeader('Cache-Control', 'private, max-age=3600'); // 1 hour
    res.end(data); // send raw blob
  } catch (e) {
    log.err('Failed to stream media', { message: e.message });
    res.status(500).json({ error: 'Failed to stream media' });
  }
});

/* -------------------- LIVE SESSION ROUTES -------------------- */

// Helper: Converts the 8-character DDMMYY## code into the internal INT ID required for relationships
async function getSessionInternalId(codeOrId) {
  const [rows] = await pool.query('SELECT id FROM live_sessions WHERE session_code=? OR id=?', [codeOrId, codeOrId]);
  return rows[0]?.id;
}

// Create a new live session (Generates an 8-character Code) - CHANGED TO requireCourt
app.post('/api/live-session', authRequired, requireCourt, moderateLimiter, async (req, res) => {
  try {
    const { name } = req.body;
    
    // Generate an 8-letter DDMMYY + Number code
    const now = new Date();
    const dd = String(now.getDate()).padStart(2, '0');
    const mm = String(now.getMonth() + 1).padStart(2, '0');
    const yy = String(now.getFullYear()).slice(-2);
    const prefix = `${dd}${mm}${yy}`;
    
    const [countRows] = await pool.query("SELECT COUNT(*) as c FROM live_sessions WHERE session_code LIKE ?", [`${prefix}%`]);
    const nextNum = String((countRows[0].c || 0) + 1).padStart(2, '0');
    const sessionCode = `${prefix}${nextNum}`;

    const [r] = await pool.query(
      "INSERT INTO live_sessions (name, admin_id, session_code, status) VALUES (?, ?, ?, 'active')", 
      [name || 'Live Session', req.user.id, sessionCode]
    );

    log.adm('Started new Live Session', { code: sessionCode, admin: req.user.id });
    res.json({ id: sessionCode, internal_id: r.insertId, name, session_code: sessionCode });
  } catch (e) {
    res.status(500).json({ error: 'Failed to create session' });
  }
});

// End an active live session - CHANGED TO requireCourt
app.post('/api/live-session/:id/end', authRequired, requireCourt, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, created_at, status FROM live_sessions WHERE session_code=? OR id=?', [req.params.id, req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Session not found' });
    if (rows[0].status === 'ended') return res.json({ ok: true, message: 'Already ended' });
    
    const internalId = rows[0].id;
    // Calculate total duration
    const duration = Math.floor((Date.now() - new Date(rows[0].created_at).getTime()) / 1000);
    
    await pool.query(
      "UPDATE live_sessions SET status='ended', ended_at=NOW(), duration_seconds=? WHERE id=?",
      [duration, internalId]
    );
    
    log.adm('Live Session Ended', { session: req.params.id, duration_seconds: duration });
    res.json({ ok: true, duration_seconds: duration });
  } catch(e) {
    res.status(500).json({ error: 'Failed to end session' });
  }
});

// Admin/ST: List all historical sessions - CHANGED TO requireCourt
app.get('/api/admin/live-sessions', authRequired, requireCourt, async (req, res) => {
  try {
    const [sessions] = await pool.query(`
      SELECT s.*, u.display_name as st_name,
      (SELECT COUNT(DISTINCT user_id) FROM live_session_participants WHERE session_id = s.id) as player_count
      FROM live_sessions s
      LEFT JOIN users u ON s.admin_id = u.id
      ORDER BY s.created_at DESC
    `);
    res.json({ sessions });
  } catch(e) {
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

// Get session details (Calculates running timer if active)
app.get('/api/live-session/:id', authRequired, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM live_sessions WHERE session_code=? OR id=?', [req.params.id, req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Session not found' });
  const s = rows[0];
  if (s.status === 'active') {
    s.duration_seconds = Math.floor((Date.now() - new Date(s.created_at).getTime()) / 1000);
  }
  res.json({ session: s });
});

// Join a session
app.post('/api/live-session/:id/join', authRequired, async (req, res) => {
  const internalId = await getSessionInternalId(req.params.id);
  if (!internalId) return res.status(404).json({ error: 'Session not found' });
  
  const { characterId } = req.body;
  await pool.query('INSERT IGNORE INTO live_session_participants (session_id, user_id, character_id) VALUES (?, ?, ?)', 
    [internalId, req.user.id, characterId]);
  res.json({ ok: true });
});

app.get('/api/live-session/:id/rolls', authRequired, async (req, res) => {
  try {
    const internalId = await getSessionInternalId(req.params.id);
    const [rows] = await pool.query(
      'SELECT * FROM live_session_rolls WHERE session_id=? ORDER BY created_at DESC LIMIT 50', 
      [internalId]
    );
    res.json({ rolls: rows });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch rolls' });
  }
});

// Log a roll: Double-Insert into BOTH live_session_rolls AND dice_rolls
app.post('/api/live-session/:id/rolls', authRequired, async (req, res) => {
  const internalId = await getSessionInternalId(req.params.id);
  if (!internalId) return res.status(404).json({ error: 'Session not found' });

  const { characterId, roll_type, pool: poolCount, hunger, results, successes, note } = req.body;
  
  try {
    // 1. Log to the localized session table
    await pool.query(
      'INSERT INTO live_session_rolls (session_id, character_id, roll_type, pool, hunger, results, successes, note) VALUES (?,?,?,?,?,?,?,?)',
      [internalId, characterId, roll_type, poolCount, hunger, JSON.stringify(results), successes, note]
    );

    // 2. Mirror into the Global/Permanent Dice Roller Table
    await _ensureDiceTable();
    const outcome = computeV5Outcome({
      normal: (results?.normal || []).map(Number),
      hunger: (results?.hunger || []).map(Number),
    });
    
    const payload = {
      normal: results?.normal || [],
      hunger: results?.hunger || [],
      difficulty: null
    };

    const safeNote = note ? `[Session: ${req.params.id}] ${note}`.slice(0, 255) : `[Session: ${req.params.id}]`;

    await pool.query(
      `INSERT INTO dice_rolls 
       (user_id, character_id, pool, hunger, sides, results_json, successes, crit_pairs, messy_crit, bestial_failure, note)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      [
        req.user.id, characterId, 
        Number(poolCount) || (payload.normal.length + payload.hunger.length),
        Number(hunger) || payload.hunger.length,
        10,
        JSON.stringify(payload),
        outcome.successes,
        outcome.crit_pairs,
        outcome.messy_crit ? 1 : 0,
        outcome.bestial_failure ? 1 : 0,
        safeNote
      ]
    );

    res.json({ ok: true });
  } catch (e) {
    console.error("Failed to log live session roll:", e);
    res.status(500).json({ error: 'Failed to log roll' });
  }
});

// Get session players
app.get('/api/live-session/:id/players', authRequired, async (req, res) => {
  const internalId = await getSessionInternalId(req.params.id);
  const [players] = await pool.query(`
    SELECT c.id, c.name, c.clan, c.sheet 
    FROM live_session_participants lsp
    JOIN characters c ON lsp.character_id = c.id
    WHERE lsp.session_id = ?
  `, [internalId]);
  res.json({ players });
});

// Broadcast a message (ST/Admin) - CHANGED TO requireCourt
app.post('/api/live-session/:id/broadcast', authRequired, requireCourt, async (req, res) => {
  const internalId = await getSessionInternalId(req.params.id);
  await pool.query('INSERT INTO live_session_broadcasts (session_id, message) VALUES (?, ?)', 
    [internalId, req.body.message]);
  res.json({ ok: true });
});

app.get('/api/live-session/:id/broadcast', authRequired, async (req, res) => {
  try {
    const internalId = await getSessionInternalId(req.params.id);
    const [rows] = await pool.query(
      'SELECT * FROM live_session_broadcasts WHERE session_id=? ORDER BY created_at DESC LIMIT 5', 
      [internalId]
    );
    res.json({ broadcasts: rows });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch broadcasts' });
  }
});

// Update a live player's trackers as ST - CHANGED TO requireCourt
app.patch('/api/live-session/:id/players/:charId', authRequired, requireCourt, async (req, res) => {
  try {
    const charId = req.params.charId;
    const { hungerDelta, healthSupDelta, healthAggDelta, wpSupDelta, wpAggDelta, humanityDelta, frenzyState, forceRouseCheck } = req.body;
    
    const [rows] = await pool.query('SELECT sheet FROM characters WHERE id=?', [charId]);
    if(!rows.length) return res.status(404).json({error: 'Char not found'});
    
    let sheet = {};
    try { sheet = JSON.parse(rows[0].sheet || '{}'); } catch(e) {}
    
    if (hungerDelta !== undefined) sheet.hunger = Math.max(0, Math.min(5, (sheet.hunger || 0) + hungerDelta));
    if (humanityDelta !== undefined) {
        const currentHum = sheet.morality?.humanity ?? sheet.humanity ?? 7;
        const nextHum = Math.max(0, Math.min(10, currentHum + humanityDelta));
        sheet.humanity = nextHum;
        if(!sheet.morality) sheet.morality = {};
        sheet.morality.humanity = nextHum;
    }
    if (healthSupDelta !== undefined) {
        if(!sheet.health) sheet.health = { superficial:0, aggravated:0 };
        sheet.health.superficial = Math.max(0, (sheet.health.superficial || 0) + healthSupDelta);
    }
    if (healthAggDelta !== undefined) {
        if(!sheet.health) sheet.health = { superficial:0, aggravated:0 };
        sheet.health.aggravated = Math.max(0, (sheet.health.aggravated || 0) + healthAggDelta);
    }
    if (wpSupDelta !== undefined) {
        if(!sheet.willpower) sheet.willpower = { superficial:0, aggravated:0 };
        sheet.willpower.superficial = Math.max(0, (sheet.willpower.superficial || 0) + wpSupDelta);
    }
    if (wpAggDelta !== undefined) {
        if(!sheet.willpower) sheet.willpower = { superficial:0, aggravated:0 };
        sheet.willpower.aggravated = Math.max(0, (sheet.willpower.aggravated || 0) + wpAggDelta);
    }
    if (frenzyState !== undefined) {
        sheet.frenzyState = frenzyState;
    }

    if (forceRouseCheck) {
        const rouseDie = Math.floor(Math.random() * 10) + 1;
        if (rouseDie < 6) {
            sheet.hunger = Math.max(0, Math.min(5, (sheet.hunger || 0) + 1));
        }
        const internalId = await getSessionInternalId(req.params.id);
        if (internalId) {
            await pool.query('INSERT INTO live_session_broadcasts (session_id, message) VALUES (?, ?)', 
            [internalId, `ST forced a Rouse Check. Result: ${rouseDie} ${rouseDie < 6 ? '(Failed)' : '(Safe)'}`]);
        }
    }

    await pool.query('UPDATE characters SET sheet=? WHERE id=?', [JSON.stringify(sheet), charId]);
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({error: 'Failed to update player'});
  }
});


/* -------------------- Dice Rolls (V5) -------------------- */
app.post('/api/dice/rolls', authRequired, async (req, res) => {
  try {
    await _ensureDiceTable();
    const { pool: poolCount, hunger, sides = 10, results, difficulty, note } = req.body || {};
    
    if (!results || !Array.isArray(results.normal) || !Array.isArray(results.hunger)) {
      return res.status(400).json({ error: 'Invalid results format' });
    }

    let charId = null;
    try {
      const [rows] = await pool.query('SELECT id FROM characters WHERE user_id=? LIMIT 1', [req.user.id]);
      if (rows && rows.length > 0) charId = rows[0].id;
    } catch {}

    const outcome = computeV5Outcome({
      normal: results.normal.map(Number),
      hunger: results.hunger.map(Number),
    });

    const payload = {
      normal: results.normal,
      hunger: results.hunger,
      difficulty: difficulty || null
    };

    const [ins] = await pool.query(
      `INSERT INTO dice_rolls 
       (user_id, character_id, pool, hunger, sides, results_json, successes, crit_pairs, messy_crit, bestial_failure, note)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      [
        req.user.id, charId, 
        Number(poolCount) || (results.normal.length + results.hunger.length),
        Number(hunger) || results.hunger.length,
        sides,
        JSON.stringify(payload),
        outcome.successes,
        outcome.crit_pairs,
        outcome.messy_crit ? 1 : 0,
        outcome.bestial_failure ? 1 : 0,
        note ? String(note).slice(0, 255) : null
      ]
    );

    log.ok('Dice roll logged', { user_id: req.user.id, roll_id: ins.insertId });
    res.status(201).json({ id: ins.insertId, ...outcome });
  } catch (e) {
    log.err('Save dice roll failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to save roll' });
  }
});

/* -------------------- Fetch Dice Logs for Admin Panel -------------------- */
app.get('/api/admin/dice/rolls', authRequired, requireAdmin, async (req, res) => {
  try {
    await _ensureDiceTable();

    let limitClause = '';
    const vals = [];

    // Allow the Stats Engine to pull all data, otherwise enforce a safe limit for the Logs tab
    if (req.query.limit === 'all') {
        limitClause = ''; 
    } else {
        const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 1000);
        limitClause = `LIMIT ${limit}`;
    }

    const userId = Number(req.query.user_id) || null;
    const since = req.query.since ? new Date(req.query.since) : null;
    const where = [];

    if (userId) { where.push('r.user_id=?'); vals.push(userId); }
    if (since && !isNaN(since.getTime())) { where.push('r.created_at >= ?'); vals.push(since); }

    const sql = `
      SELECT
        r.id, r.user_id, r.character_id, r.pool, r.hunger, r.sides,
        r.results_json, r.successes, r.crit_pairs, r.messy_crit, r.bestial_failure,
        r.note, r.created_at,
        u.display_name AS user_name,
        c.name AS char_name, c.clan AS char_clan
      FROM dice_rolls r
      LEFT JOIN users u ON u.id = r.user_id
      LEFT JOIN characters c ON c.id = r.character_id
      ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
      ORDER BY r.created_at DESC
      ${limitClause}
    `;

    const [rows] = await pool.query(sql, vals);
    res.json({ rolls: rows });
  } catch (e) {
    console.error('Admin fetch dice rolls failed', e);
    res.status(500).json({ error: 'Failed to fetch dice rolls' });
  }
});

// Admin: list recent rolls (with user + char info)
// query: ?limit=200 (default 100), ?user_id=, ?since=ISO
app.get('/api/admin/dice/rolls', authRequired, requireAdmin, async (req, res) => {
  try {
    await _ensureDiceTable();

    const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 1000);
    const userId = Number(req.query.user_id) || null;
    const since = req.query.since ? new Date(req.query.since) : null;

    const where = [];
    const vals = [];

    if (userId) { where.push('r.user_id=?'); vals.push(userId); }
    if (since && !isNaN(since.getTime())) { where.push('r.created_at >= ?'); vals.push(since); }

    const sql = `
      SELECT
        r.id, r.user_id, r.character_id, r.pool, r.hunger, r.sides,
        r.results_json, r.successes, r.crit_pairs, r.messial_crit AS messy_crit, r.bestial_failure,
        r.note, r.created_at,
        u.display_name AS user_name,
        c.name AS char_name, c.clan AS char_clan
      FROM dice_rolls r
      LEFT JOIN users u ON u.id = r.user_id
      LEFT JOIN characters c ON c.id = r.character_id
      ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
      ORDER BY r.created_at DESC
      LIMIT ${limit}
    `.replace('messial_crit','messy_crit'); // typo guard if pastes get mangled

    const [rows] = await pool.query(sql, vals);
    res.json({ rolls: rows });
  } catch (e) {
    log.err('Admin fetch dice rolls failed', { message: e.message, stack: e.stack });
    res.status(500).json({ error: 'Failed to fetch dice rolls' });
  }
});

/* -------------------- NEWS & ANNOUNCEMENTS -------------------- */

let newsTableCreated = false;
async function _ensureNewsTables() {
  if (newsTableCreated) return;
  try {
    // Main entries table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS news_entries (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        author_id INT NOT NULL,
        type ENUM('news', 'announcement') NOT NULL,
        title VARCHAR(255) NOT NULL,
        subtitle VARCHAR(255),
        body TEXT NOT NULL,
        theme VARCHAR(100),
        journalist_name VARCHAR(100),
        media_url VARCHAR(2048),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // Media table (storing blobs similarly to premonitions)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS news_media (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        filename VARCHAR(255),
        mime VARCHAR(100) NOT NULL,
        size INT UNSIGNED NOT NULL,
        data MEDIUMBLOB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      ) ENGINE=InnoDB;
    `);

    newsTableCreated = true;
    log.ok('News & Announcements tables ready');
  } catch (e) {
    log.err('Failed to create news tables', { message: e.message });
  }
}

// Run init
_ensureNewsTables();

// GET /api/news (Public/Auth) - Fetch all items
app.get('/api/news', authRequired, async (req, res) => {
  try {
    // Join with users to get the real name for Announcements
    const [rows] = await pool.query(`
      SELECT n.*, u.display_name as author_real_name,
             c.name as char_name, c.camarilla_titles as char_titles, c.image_url as char_image
      FROM news_entries n
      LEFT JOIN users u ON n.author_id = u.id
      LEFT JOIN characters c ON c.user_id = u.id
      ORDER BY n.created_at DESC
      LIMIT 100
    `);
    res.json({ items: rows });
  } catch (e) {
    log.err('Fetch news failed', { message: e.message });
    res.status(500).json({ error: 'Failed to load news' });
  }
});

// GET /api/news/recent (For Dashboard) - Lightweight headlines only
app.get('/api/news/recent', authRequired, async (req, res) => {
  try {
    const limit = 5;
    // Only fetch necessary fields, not the full body
    const [rows] = await pool.query(`
      SELECT id, type, title, theme, created_at
      FROM news_entries
      ORDER BY created_at DESC
      LIMIT ?
    `, [limit]);
    res.json({ news: rows });
  } catch (e) {
    log.err('Fetch recent news headlines failed', { message: e.message });
    res.status(500).json({ error: 'Failed to load headlines' });
  }
});


// POST /api/news/upload (Admin/Court) - Upload media
app.post('/api/news/upload', authRequired, memoryUpload.single('file'), async (req, res) => {
  try {
    // Check permissions: Admin or Court
    if (req.user.role !== 'admin' && req.user.role !== 'courtuser') {
        return res.status(403).json({ error: 'Forbidden' });
    }

    if (!req.file) return res.status(400).json({ error: 'File required' });
    
    const { originalname, mimetype, size, buffer } = req.file;
    const [ins] = await pool.query(
      'INSERT INTO news_media (filename, mime, size, data) VALUES (?,?,?,?)',
      [originalname || 'upload', mimetype, size, buffer]
    );
    
    res.json({ url: `/api/news/media/${ins.insertId}` });
  } catch (e) {
    log.err('News upload failed', { message: e.message });
    res.status(500).json({ error: 'Upload failed' });
  }
});

// GET /api/news/media/:id - Stream media (WITH VIDEO SUPPORT)
app.get('/api/news/media/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const [rows] = await pool.query('SELECT mime, size, data FROM news_media WHERE id=? LIMIT 1', [id]);
    if (!rows.length) return res.status(404).send('Not found');

    const { mime, size, data } = rows[0];

    // Handle HTML5 Video Range Requests (Crucial for iOS/Safari & scrubbing)
    const range = req.headers.range;
    if (range && mime.startsWith('video/')) {
      const parts = range.replace(/bytes=/, "").split("-");
      const partialstart = parts[0];
      const partialend = parts[1];

      const start = parseInt(partialstart, 10);
      const end = partialend ? parseInt(partialend, 10) : size - 1;
      const chunksize = (end - start) + 1;

      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${size}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Type': mime,
      });
      // Send only the requested slice of the buffer
      res.end(data.subarray(start, end + 1));
    } else {
      // Standard image/file serving
      res.setHeader('Content-Type', mime || 'application/octet-stream');
      res.setHeader('Content-Length', size);
      res.setHeader('Cache-Control', 'public, max-age=86400'); // Cache for 1 day
      res.end(data);
    }
  } catch (e) {
    res.status(404).end();
  }
});

// POST /api/news - Create Entry
app.post('/api/news', authRequired, async (req, res) => {
  try {
    const { type, title, subtitle, body, theme, journalist_name, media_url } = req.body;

    // --- PERMISSION CHECK ---
    if (type === 'news') {
        if (theme === 'RUMOR') {
            // For rumors, any activated player can post.
            // Check if user is standard player, and if so, verify they have a character
            if (req.user.role !== 'admin' && req.user.role !== 'courtuser') {
                const [chars] = await pool.query('SELECT id FROM characters WHERE user_id = ?', [req.user.id]);
                if (chars.length === 0) {
                    return res.status(403).json({ error: 'You must have a character registered to post rumors.' });
                }
            }
        } else if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Only Admins can post official News' });
        }
    } else if (type === 'announcement') {
        if (req.user.role !== 'admin' && req.user.role !== 'courtuser') {
            return res.status(403).json({ error: 'Only Court/Admin can post Announcements' });
        }
    } else {
        return res.status(400).json({ error: 'Invalid type' });
    }

    if (!title || !body) return res.status(400).json({ error: 'Title and Body are required' });

    await pool.query(
      `INSERT INTO news_entries 
      (author_id, type, title, subtitle, body, theme, journalist_name, media_url)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.user.id,
        type,
        title,
        subtitle || null,
        body, // Stored as HTML
        theme || 'Neutral',
        journalist_name || null,
        media_url || null
      ]
    );

    // --- DISCORD NEWS BROADCAST ---
    const discordEnabled = await getSetting('discord_enabled', 'true') === 'true';
    const notifyPrems = await getSetting('discord_notify_prems', 'true') === 'true';
    
    if (discordEnabled && notifyPrems && discordClient?.isReady()) {
      try {
        const channelId = await getSetting('discord_channel_id', null);
        if (channelId) {
          const channel = await discordClient.channels.fetch(channelId);
          if (channel) {
            // Strip HTML tags from the body so it looks clean in Discord
            const cleanBody = body.replace(/<[^>]*>?/gm, '');
            const snippet = cleanBody.length > 300 ? cleanBody.substring(0, 300) + '...' : cleanBody;
            
            let broadcast = `📰 **NEW EREBUS ${type.toUpperCase()}** 📰\n\n**${title}**\n`;
            if (subtitle) broadcast += `*${subtitle}*\n`;
            broadcast += `\n${snippet}\n\n*Check the Erebus Portal for the full text.*`;
            
            await channel.send(broadcast);
          }
        }
      } catch (discordErr) {
        log.err('Discord news broadcast failed', { error: discordErr.message });
      }
    }
    // -----------------------------------

    log.ok('News entry created', { user_id: req.user.id, type, title });
    res.json({ ok: true });
  } catch (e) {
    log.err('Create news failed', { message: e.message });
    res.status(500).json({ error: 'Failed to post' });
  }
});

// DELETE /api/news/:id (Admin Only)
app.delete('/api/news/:id', authRequired, requireAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM news_entries WHERE id=?', [req.params.id]);
        res.json({ ok: true });
    } catch(e) {
        res.status(500).json({ error: 'Delete failed' });
    }
});

// GET: List all hunts
app.get('/api/admin/hunts', authRequired, requireAdmin, async (req, res) => {
  try {
    const [hunts] = await pool.query('SELECT * FROM hunts ORDER BY created_at DESC');
    res.json({ hunts });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch hunts' });
  }
});

// POST: Create a new hunt
app.post('/api/admin/hunts', authRequired, requireAdmin, async (req, res) => {
  try {
    const { title, description } = req.body;
    const [r] = await pool.query('INSERT INTO hunts (title, description) VALUES (?,?)', [title, description]);
    res.json({ id: r.insertId });
  } catch (e) {
    res.status(500).json({ error: 'Failed to create hunt' });
  }
});

// --- NEW: Move a Step Up or Down ---
app.patch('/api/admin/hunts/:huntId/steps/:stepId/move/:direction', authRequired, requireAdmin, async (req, res) => {
  const { huntId, stepId, direction } = req.params;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    
    // Get current step
    const [[currentStep]] = await conn.query('SELECT id, step_order FROM hunt_steps WHERE id = ? AND hunt_id = ?', [stepId, huntId]);
    if (!currentStep) throw new Error("Step not found");

    const targetOrder = direction === 'up' ? currentStep.step_order - 1 : currentStep.step_order + 1;
    
    // Get the step we are swapping with
    const [[swapStep]] = await conn.query('SELECT id, step_order FROM hunt_steps WHERE hunt_id = ? AND step_order = ?', [huntId, targetOrder]);
    
    if (swapStep) {
      // Swap their orders
      await conn.query('UPDATE hunt_steps SET step_order = ? WHERE id = ?', [targetOrder, currentStep.id]);
      await conn.query('UPDATE hunt_steps SET step_order = ? WHERE id = ?', [currentStep.step_order, swapStep.id]);
    }
    
    await conn.commit();
    res.json({ ok: true });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: 'Failed to reorder steps.' });
  } finally {
    conn.release();
  }
});

// --- NEW: Force Advance a Player ---
app.post('/api/admin/hunts/:huntId/progress/:userId/advance', authRequired, requireAdmin, async (req, res) => {
  try {
    const huntId = Number(req.params.huntId);
    const userId = Number(req.params.userId);

    const [[progress]] = await pool.query('SELECT * FROM hunt_progress WHERE user_id=? AND hunt_id=?', [userId, huntId]);
    if (!progress || progress.completed) return res.status(400).json({ error: 'Player is not active or already finished.' });

    const [[currentStep]] = await pool.query('SELECT step_order FROM hunt_steps WHERE id=?', [progress.current_step_id]);
    const [[nextStep]] = await pool.query('SELECT id FROM hunt_steps WHERE hunt_id=? AND step_order > ? ORDER BY step_order ASC LIMIT 1', [huntId, currentStep.step_order]);

    if (nextStep) {
      await pool.query('UPDATE hunt_progress SET current_step_id=? WHERE user_id=? AND hunt_id=?', [nextStep.id, userId, huntId]);
    } else {
      await pool.query('UPDATE hunt_progress SET completed=1 WHERE user_id=? AND hunt_id=?', [userId, huntId]);
    }

    log.adm('Admin forced player advance', { admin_id: req.user.id, target_user: userId, hunt_id: huntId });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to advance player.' });
  }
});

// --- ADMIN: Toggle Hunt Status ---

// Updated to allow multiple active hunts simultaneously
app.patch('/api/admin/hunts/:id/toggle', authRequired, requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    // Removed the query that deactivated other hunts to allow multiple activations
    await pool.query('UPDATE hunts SET is_active = NOT is_active WHERE id=?', [id]);
    res.json({ ok: true });
  } catch (e) {
    log.err('Failed to toggle hunt', { message: e.message });
    res.status(500).json({ error: 'Failed to toggle hunt' });
  }
});

// Edit a step (Fixed to save manual_review flag)
app.put('/api/admin/hunts/:huntId/steps/:stepId', authRequired, requireAdmin, async (req, res) => {
  const { task_type, prompt, target_data } = req.body;
  const tData = typeof target_data === 'string' ? target_data : JSON.stringify(target_data);
  const isManual = ['photo', 'draw', 'audio'].includes(task_type) ? 1 : 0;
  
  try {
    await pool.query(
      'UPDATE hunt_steps SET task_type=?, prompt=?, target_data=?, manual_review=? WHERE id=?', 
      [task_type, prompt, tData, isManual, req.params.stepId]
    );
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Delete a step
app.delete('/api/admin/hunts/:huntId/steps/:stepId', authRequired, requireAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM hunt_steps WHERE id=?', [req.params.stepId]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// GET: List steps for a specific hunt
app.get('/api/admin/hunts/:id/steps', authRequired, requireAdmin, async (req, res) => {
  try {
    const [steps] = await pool.query('SELECT * FROM hunt_steps WHERE hunt_id=? ORDER BY step_order ASC', [req.params.id]);
    res.json({ steps });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch steps' });
  }
});

// Get progress of all players for a specific hunt
app.get('/api/admin/hunts/:huntId/progress', authRequired, requireAdmin, async (req, res) => {
  try {
    // Fetch all players who have a progress entry for this hunt
    const [progress] = await pool.query(`
      SELECT 
        u.id as user_id, 
        u.email,
        COALESCE(c.name, 'Unknown Kindred') as character_name,
        hp.completed,
        hs.step_order as current_step
      FROM hunt_progress hp
      JOIN users u ON hp.user_id = u.id
      LEFT JOIN characters c ON u.id = c.user_id
      LEFT JOIN hunt_steps hs ON hp.current_step_id = hs.id
      WHERE hp.hunt_id = ?
    `, [req.params.huntId]);
    
    // Get total steps to calculate the exact percentage
    const [stepCount] = await pool.query('SELECT COUNT(*) as total FROM hunt_steps WHERE hunt_id = ?', [req.params.huntId]);
    const totalSteps = stepCount[0].total || 1;

    // Format the data for the frontend
    const formattedProgress = progress.map(p => {
      let percent = 0;
      if (p.completed) percent = 100;
      else if (p.current_step > 1) percent = Math.round(((p.current_step - 1) / totalSteps) * 100);
      
      return {
        ...p,
        percent: percent
      };
    });

    res.json({ progress: formattedProgress });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Get pending manual reviews for a chronicle (Fixed query logic)
app.get('/api/admin/hunts/:huntId/reviews', authRequired, requireAdmin, async (req, res) => {
  try {
    const [reviews] = await pool.query(`
      SELECT 
        s.id as submission_id,
        u.email,
        COALESCE(c.name, 'Unknown Kindred') as character_name,
        hs.step_order,
        hs.prompt,
        hs.task_type,
        s.media_id,
        s.status
      FROM hunt_submissions s
      JOIN users u ON s.user_id = u.id
      LEFT JOIN characters c ON u.id = c.user_id
      JOIN hunt_steps hs ON s.step_id = hs.id
      WHERE hs.hunt_id = ? 
        AND hs.task_type IN ('photo', 'draw', 'audio') 
        AND (s.status = 'pending' OR s.status IS NULL)
    `, [req.params.huntId]);
    
    res.json({ reviews });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Approve or Reject a submission
app.post('/api/admin/reviews/:submissionId/:action', authRequired, requireAdmin, async (req, res) => {
  const { submissionId, action } = req.params;
  const newStatus = action === 'approve' ? 'approved' : 'rejected';
  
  try {
    // 1. Update the submission status
    await pool.query('UPDATE hunt_submissions SET status = ? WHERE id = ?', [newStatus, submissionId]);
    
    // 2. If the ST rejects it, we punish the player
    if (newStatus === 'rejected') {
      
      // Find out exactly who submitted this and for what step/hunt
      const [[sub]] = await pool.query(`
        SELECT s.user_id, s.step_id, hs.hunt_id, hs.step_order, hs.prompt
        FROM hunt_submissions s
        JOIN hunt_steps hs ON s.step_id = hs.id
        WHERE s.id = ?
      `, [submissionId]);

      if (sub) {
        // Roll their progress back to the failed step and ensure they are un-marked as completed
        await pool.query(`
          UPDATE hunt_progress 
          SET current_step_id = ?, completed = 0 
          WHERE user_id = ? AND hunt_id = ?
        `, [sub.step_id, sub.user_id, sub.hunt_id]);

        // Send a push notification alerting them of their failure
        const title = "❌ Evidence Rejected";
        const body = `The Court found your submission for Step ${sub.step_order} unacceptable. You must acquire better evidence.`;
        
        await sendPushNotification(sub.user_id, title, body).catch(() => {});
        log.adm('Evidence rejected & player rolled back', { admin: req.user.id, player: sub.user_id, step: sub.step_order });
      }
    }
    
    res.json({ success: true });
  } catch (err) { 
    log.err('Review action failed', { error: err.message });
    res.status(500).json({ error: err.message }); 
  }
});

// POST: Add a new step to a hunt (Fixed to save manual_review flag)
app.post('/api/admin/hunts/:id/steps', authRequired, requireAdmin, async (req, res) => {
  try {
    const { task_type, prompt, target_data, step_order } = req.body;
    const isManual = ['photo', 'draw', 'audio'].includes(task_type) ? 1 : 0;
    
    await pool.query(
      'INSERT INTO hunt_steps (hunt_id, step_order, task_type, prompt, target_data, manual_review) VALUES (?,?,?,?,?,?)',
      [req.params.id, step_order, task_type, prompt, JSON.stringify(target_data), isManual]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'Failed to add step' });
  }
});

// DELETE: Completely remove a chronicle
app.delete('/api/admin/hunts/:id', authRequired, requireAdmin, async (req, res) => {
  try {
    const huntId = req.params.id;
    
    // 1. Find all Coteries associated with this hunt
    const [groups] = await pool.query('SELECT id FROM hunt_groups WHERE hunt_id=?', [huntId]);
    if (groups.length > 0) {
      const groupIds = groups.map(g => g.id);
      // 2. Delete all members of those coteries
      await pool.query('DELETE FROM hunt_group_members WHERE group_id IN (?)', [groupIds]);
    }
    
    // 3. Delete the coteries themselves
    await pool.query('DELETE FROM hunt_groups WHERE hunt_id=?', [huntId]);
    
    // 4. Finally, delete the actual chronicle
    await pool.query('DELETE FROM hunts WHERE id=?', [huntId]);
    
    res.json({ ok: true });
  } catch (e) {
    log.err('Failed to delete chronicle', { message: e.message });
    res.status(500).json({ error: 'Failed to delete chronicle' });
  }
});
// --- PLAYER ROUTES ---

// --- TEAM / COTERIE SYSTEM FOR HUNTS ---

// POST: Create a team for a hunt
app.post('/api/hunts/:huntId/groups', authRequired, async (req, res) => {
  const huntId = Number(req.params.huntId);
  const { name } = req.body;
  if (!name || name.trim() === '') return res.status(400).json({ error: 'Team name is required.' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Generate a 6-character random hex invite code
    const inviteCode = crypto.randomBytes(3).toString('hex').toUpperCase();

    // 1. Create the group
    const [gRes] = await conn.query(
      'INSERT INTO hunt_groups (hunt_id, name, invite_code, created_by) VALUES (?, ?, ?, ?)',
      [huntId, name.trim(), inviteCode, req.user.id]
    );

    // 2. Add creator to the group
    await conn.query(
      'INSERT INTO hunt_group_members (group_id, user_id) VALUES (?, ?)',
      [gRes.insertId, req.user.id]
    );

    await conn.commit();
    res.json({ ok: true, invite_code: inviteCode });
  } catch (e) {
    await conn.rollback();
    log.err('Failed to create hunt group', { error: e.message });
    res.status(500).json({ error: 'Failed to establish coterie.' });
  } finally {
    conn.release();
  }
});

// POST: Join a team via invite code
app.post('/api/hunts/:huntId/groups/join', authRequired, async (req, res) => {
  const huntId = Number(req.params.huntId);
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Invite code required.' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // 1. Find the group
    const [[group]] = await conn.query('SELECT id FROM hunt_groups WHERE hunt_id = ? AND invite_code = ?', [huntId, code.trim().toUpperCase()]);
    if (!group) {
      await conn.rollback();
      return res.status(404).json({ error: 'Invalid invite code or chronicle mismatch.' });
    }

    // 2. Add user to the group (IGNORE handles if they are already in it)
    await conn.query('INSERT IGNORE INTO hunt_group_members (group_id, user_id) VALUES (?, ?)', [group.id, req.user.id]);

    // 3. Sync their progress to the group's highest progress
    const [[groupProgress]] = await conn.query(`
      SELECT current_step_id, completed 
      FROM hunt_progress 
      WHERE hunt_id = ? AND user_id IN (SELECT user_id FROM hunt_group_members WHERE group_id = ?)
      ORDER BY completed DESC, current_step_id DESC LIMIT 1
    `, [huntId, group.id]);

    if (groupProgress) {
      await conn.query(
        'UPDATE hunt_progress SET current_step_id = ?, completed = ? WHERE user_id = ? AND hunt_id = ?',
        [groupProgress.current_step_id, groupProgress.completed, req.user.id, huntId]
      );
    }

    await conn.commit();
    res.json({ ok: true });
  } catch (e) {
    await conn.rollback();
    log.err('Failed to join hunt group', { error: e.message });
    res.status(500).json({ error: 'Failed to join coterie.' });
  } finally {
    conn.release();
  }
});

/* -------------------- Fixed & Enhanced Hunt Player Routes -------------------- */

// GET: Player's active hunts, current progress, and Coterie info
app.get('/api/hunts/active', authRequired, async (req, res) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');

  try {
    const [activeHunts] = await pool.query(
      'SELECT * FROM hunts WHERE is_active = 1 ORDER BY created_at DESC'
    );

    if (activeHunts.length === 0) {
      return res.json({ activeHunts: [] });
    }

    const huntsWithMetadata = await Promise.all(
      activeHunts.map(async (hunt) => {
        const [[progressRow]] = await pool.query(
          'SELECT * FROM hunt_progress WHERE user_id = ? AND hunt_id = ?',
          [req.user.id, hunt.id]
        );

        const [[winner]] = await pool.query(
          'SELECT id FROM hunt_progress WHERE hunt_id = ? AND completed = 1 LIMIT 1',
          [hunt.id]
        );
        const isGloballyFinished = !!winner;

        const [[competitorCount]] = await pool.query(
          'SELECT COUNT(*) AS c FROM hunt_progress WHERE hunt_id = ? AND user_id != ? AND completed = 0',
          [hunt.id, req.user.id]
        );
        const active_hunters = competitorCount.c;

        const [[firstStep]] = await pool.query(
          'SELECT * FROM hunt_steps WHERE hunt_id = ? ORDER BY step_order ASC LIMIT 1',
          [hunt.id]
        );

        let progress = progressRow || null;
        let currentStep = null;
        let isReady = !!firstStep;

        // No steps yet: still return the hunt so it appears in the player list
        if (!firstStep) {
          return {
            hunt,
            step: {
              id: null,
              step_order: 0,
              prompt: 'This hunt is active, but no steps have been published yet.',
              task_type: 'text'
            },
            team: null,
            progress: {
              percent: 0,
              completed: false,
              isGloballyFinished,
              otherHunters: active_hunters
            },
            isReady: false
          };
        }

        if (!progress) {
          await pool.query(
            'INSERT INTO hunt_progress (user_id, hunt_id, current_step_id) VALUES (?, ?, ?)',
            [req.user.id, hunt.id, firstStep.id]
          );

          progress = {
            user_id: req.user.id,
            hunt_id: hunt.id,
            current_step_id: firstStep.id,
            completed: 0
          };

          currentStep = firstStep;
        } else if (progress.completed) {
          const [[lastStep]] = await pool.query(
            'SELECT * FROM hunt_steps WHERE hunt_id = ? ORDER BY step_order DESC LIMIT 1',
            [hunt.id]
          );
          currentStep = lastStep || firstStep;
        } else {
          const [[step]] = await pool.query(
            'SELECT * FROM hunt_steps WHERE id = ? AND hunt_id = ?',
            [progress.current_step_id, hunt.id]
          );

          if (step) {
            currentStep = step;
          } else {
            // self-heal stale progress when a step was deleted/reordered
            await pool.query(
              'UPDATE hunt_progress SET current_step_id = ? WHERE user_id = ? AND hunt_id = ?',
              [firstStep.id, req.user.id, hunt.id]
            );
            progress.current_step_id = firstStep.id;
            currentStep = firstStep;
          }
        }

        const [[totalSteps]] = await pool.query(
          'SELECT COUNT(*) AS t FROM hunt_steps WHERE hunt_id = ?',
          [hunt.id]
        );

        let percent = 0;
        if (progress?.completed) {
          percent = 100;
        } else if (currentStep?.step_order > 1 && totalSteps.t > 0) {
          percent = Math.round(((currentStep.step_order - 1) / totalSteps.t) * 100);
        }

        let teamData = null;
        const [[myGroup]] = await pool.query(`
          SELECT g.id, g.name, g.invite_code
          FROM hunt_groups g
          JOIN hunt_group_members m ON m.group_id = g.id
          WHERE m.user_id = ? AND g.hunt_id = ?
          LIMIT 1
        `, [req.user.id, hunt.id]);

        if (myGroup) {
          const [members] = await pool.query(`
            SELECT COALESCE(c.name, u.display_name) AS member_name
            FROM hunt_group_members m
            JOIN users u ON m.user_id = u.id
            LEFT JOIN characters c ON c.user_id = u.id
            WHERE m.group_id = ?
          `, [myGroup.id]);

          teamData = {
            name: myGroup.name,
            invite_code: myGroup.invite_code,
            members: members.map(m => m.member_name)
          };
        }

        return {
          hunt,
          step: currentStep,
          team: teamData,
          progress: {
            percent,
            completed: !!progress?.completed,
            isGloballyFinished,
            otherHunters: active_hunters
          },
          isReady
        };
      })
    );

    res.json({ activeHunts: huntsWithMetadata });
  } catch (e) {
    log.err('Failed to fetch active hunts', { message: e.message });
    res.status(500).json({ error: 'Failed to sync chronicles' });
  }
});
// POST: Submit an answer or evidence for the current step
app.post('/api/hunts/submit', authRequired, async (req, res) => {
  try {
    const { step_id, text_answer, lat, lng, media_id } = req.body;

    // 1. Verify step exists and belongs to the user's current progress
    const [[step]] = await pool.query('SELECT * FROM hunt_steps WHERE id=?', [step_id]);
    if (!step) return res.status(404).json({ error: 'Challenge not found in the archives.' });

    const [[progress]] = await pool.query('SELECT * FROM hunt_progress WHERE user_id=? AND hunt_id=?', [req.user.id, step.hunt_id]);
    if (!progress || progress.current_step_id !== step.id || progress.completed) {
      return res.status(400).json({ error: 'Invalid submission sequence.' });
    }

    // Safely parse target data
    const target = typeof step.target_data === 'string' ? JSON.parse(step.target_data || '{}') : (step.target_data || {});

    // --- 2. VALIDATION BY TASK TYPE ---
    if (step.task_type === 'text') {
      if (text_answer?.toLowerCase().trim() !== target?.answer?.toLowerCase()) {
        return res.status(400).json({ error: 'Incorrect answer. The Court expects better.' });
      }
    } 
    else if (step.task_type === 'qr') {
      if (text_answer?.trim() !== target?.qr_string) {
        return res.status(400).json({ error: 'Invalid Sigil scanned.' });
      }
    } 
    else if (step.task_type === 'gps') {
      if (!lat || !lng) return res.status(400).json({ error: 'Missing GPS coordinates.' });
      
      // Haversine formula to calculate distance in meters
      const R = 6371e3; // Earth radius in metres
      const φ1 = lat * Math.PI/180;
      const φ2 = target.lat * Math.PI/180;
      const Δφ = (target.lat-lat) * Math.PI/180;
      const Δλ = (target.lng-lng) * Math.PI/180;
      const a = Math.sin(Δφ/2) * Math.sin(Δφ/2) +
                Math.cos(φ1) * Math.cos(φ2) *
                Math.sin(Δλ/2) * Math.sin(Δλ/2);
      const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
      const distance = R * c;

      const allowedRadius = target.radius_meters || 50; // Default 50m allowance for GPS drift
      if (distance > allowedRadius) {
        return res.status(400).json({ error: `Location rejected. You are ${Math.round(distance)} meters away from the target.` });
      }
    } 
    else if (['photo', 'draw', 'audio'].includes(step.task_type)) {
      if (!media_id) return res.status(400).json({ error: 'Evidence file required.' });
      
      // Log the submission into the database for the ST to review later
      await pool.query(
        'INSERT INTO hunt_submissions (user_id, step_id, media_id, status) VALUES (?, ?, ?, ?)', 
        [req.user.id, step.id, media_id, 'pending']
      );
    }

    // --- 3. GET NEXT STEP ---
    const [[nextStep]] = await pool.query(
      'SELECT * FROM hunt_steps WHERE hunt_id=? AND step_order > ? ORDER BY step_order ASC LIMIT 1', 
      [step.hunt_id, step.step_order]
    );

    // --- 4. ADVANCE THE TEAM / COTERIE ---
    let targetUserIds = [req.user.id]; // Default to solo player
    
    // Check if the user is in a group for this specific hunt
    const [[myGroup]] = await pool.query(`
      SELECT group_id FROM hunt_group_members 
      WHERE user_id = ? AND group_id IN (SELECT id FROM hunt_groups WHERE hunt_id = ?)
    `, [req.user.id, step.hunt_id]);

    if (myGroup) {
      // Get every user ID in that group
      const [mRows] = await pool.query('SELECT user_id FROM hunt_group_members WHERE group_id = ?', [myGroup.group_id]);
      targetUserIds = mRows.map(r => r.user_id);
    }

    // Update progress for every player in the targetUserIds array
    if (nextStep) {
      await pool.query(
        'UPDATE hunt_progress SET current_step_id=? WHERE hunt_id=? AND user_id IN (?)', 
        [nextStep.id, step.hunt_id, targetUserIds]
      );
      res.json({ success: true, completed: false });
    } else {
      // No more steps: The team has won!
      await pool.query(
        'UPDATE hunt_progress SET completed=1 WHERE hunt_id=? AND user_id IN (?)', 
        [step.hunt_id, targetUserIds]
      );
      res.json({ success: true, completed: true });
    }

  } catch (e) {
    log.err('Submission logic failed', { message: e.message });
    res.status(500).json({ error: 'Internal server error while verifying submission.' });
  }
});
/* -------------------- Avatar Routes -------------------- */

app.get('/api/users/:id/avatar', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT avatar FROM users WHERE id = ?', [req.params.id]);
    if (rows.length === 0 || !rows[0].avatar) {
      return res.status(404).send('Avatar not found');
    }
    res.set('Content-Type', 'image/webp');
    res.set('Cache-Control', 'public, max-age=86400'); // Cache for 1 day
    res.send(rows[0].avatar);
  } catch (e) {
    log.err('Avatar GET error', { message: e.message });
    res.status(500).json({ error: 'Server error retrieving avatar.' });
  }
});

app.put('/api/users/:id/avatar', authRequired, upload.single('avatar'), async (req, res) => {
  try {
    if (req.user.id !== parseInt(req.params.id) && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Forbidden. You can only update your own avatar.' });
    }
    if (!req.file) {
      return res.status(400).json({ error: 'No image file provided.' });
    }
    
    const buffer = await sharp(req.file.buffer)
      .resize(500, 500, { fit: 'cover' })
      .webp({ quality: 80 })
      .toBuffer();

    await pool.query('UPDATE users SET avatar = ? WHERE id = ?', [buffer, req.params.id]);
    res.json({ success: true, message: 'Avatar updated successfully.' });
  } catch (e) {
    log.err('Avatar PUT error', { message: e.message });
    res.status(500).json({ error: 'Server error updating avatar.' });
  }
});

/* -------------------- Error Handlers -------------------- */
// Multer error handler (must be before general error handler)
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    reportErrorToDiscord(`Multer Upload Error: ${err.code}`, err);
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'File too large. Maximum size is 50MB.' });
    }
    return res.status(400).json({ error: `Upload error: ${err.message}` });
  }
  next(err);
});

// Add the global error handler middleware *last*
app.use(expressErrorHandler);

// --- Swagger Configuration ---
// Serve the Swagger UI at /api-docs endpoint
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
log.start('Swagger UI available at /api-docs');

/* -------------------- Start Server -------------------- */
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => log.start(`API server started`, { port: PORT, env: process.env.NODE_ENV || 'stable' }));
