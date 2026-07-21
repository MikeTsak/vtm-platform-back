require('dotenv').config();
const { Client, GatewayIntentBits, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, ComponentType } = require('discord.js');
const { log } = require('./logger');
const pool = require('./db');
const { getSetting } = require('./utils/settings');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const axios = require('axios');
const sharp = require('sharp');
const TextToSVG = require('text-to-svg');

const LOG_CHANNEL_ID = process.env.LOG_CHANNEL_ID || '1338600871302860882';
let textToSVG = null;
try { textToSVG = TextToSVG.loadSync('./public/fonts/impact.ttf'); } catch (e) { log.err('Meme font failed', e); }
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
  if (message.mentions.has(discordClient.user, { ignoreRoles: true, ignoreEveryone: true })) {
    try {
      // Check if AI is enabled in settings
      const aiEnabled = await getSetting('giannakis_ai_enabled', 'true');
      if (aiEnabled !== 'true' && aiEnabled !== '1' && aiEnabled !== true) {
        return message.reply("The AI Node is currently offline for maintenance.");
      }

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
