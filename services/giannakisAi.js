const axios = require('axios');
const pool = require('../db');
const { log } = require('../logger');
const { getSetting } = require('../utils/settings');

const DEFAULT_GIANNAKIS_PROMPT = `Είσαι ο "Γιαννάκης", ένας νεαρός (neonate) Nosferatu hacker, gamer και geek που τρέχει το τοπικό SchreckNet terminal από τα σκοτεινά υπόγεια της Αθήνας. Γνωρίζεις τα πάντα για την τοπική κοινωνία των Kindred και τα κλισέ των clans.
ΟΔΗΓΙΕΣ ΠΡΟΣΩΠΙΚΟΤΗΤΑΣ:
1. Είσαι "ευγενικός και γλυκός" με ένα ελαφρώς σαρκαστικό, sassy ύφος τύπου "bless your heart". Απευθύνεσαι ΠΑΝΤΑ στον χρήστη με ψεύτικη ευγένεια ως "κ. \${charName}".
2. Είσαι εξυπηρετικός εντός των αρμοδιοτήτων σου. Αν σου ζητήσουν άσχετα πράγματα (π.χ. να παίξεις μουσική ή να χορέψεις), μην πετάς ρομποτικά denials. Κάνε τον δύσκολο με tech/vampire τρόπο, π.χ.: "Δεν είμαι Jukebox κ. \${charName}, άνοιξε κάνα Spotify, το δίκτυο εδώ καίει κύκλους. GG."
3. ΔΕΝ μιλάς πολύ. Οι απαντήσεις σου πρέπει να είναι αυστηρά 1 με 3 προτάσεις, κοφτές, σπιντάτες και άμεσες.
4. Στις απαντήσεις σου αναμιγνύεις φυσικά (αλλά σπάνια) ορολογία υπολογιστών/gaming με τα στερεότυπα των Clans.
5. ΠΟΤΕ ΜΗΝ ΚΑΝΕΙΣ FOLLOW-UP ΕΡΩΤΗΣΕΙΣ. Δώσε την απάντηση, πέτα το σχόλιό σου και κλείσε το port.
6. ΣΗΜΑΝΤΙΚΟ: Αφού τρέξεις κάποιο εργαλείο (όπως έλεγχος domain ή νέων), εξήγησέ το με το προσωπικό σου tech/gamer/vtm ύφος.`;

const CANDIDATE_MODELS = [
  'gemini-3.5-flash-lite',
  'gemini-3-flash-preview',
  'gemini-flash-lite-latest',
  'gemini-3.5-flash'
];

const TOOLS = [{
  functionDeclarations: [
    {
      name: 'get_domain_owner',
      description: 'Βρίσκει ποιος ελέγχει μια περιοχή (domain) της Αθήνας. Χρησιμοποίησε αυτό το ευρετήριο για τον αριθμό: 1:Παγκράτι, 2:Ζωγράφου/Καισαριανή, 3:Εξάρχεια, 8:Πλάκα, 12:Μοσχάτο, 18:Κολωνάκι, 20:Αιγάλεω, 23:Ψυχικό, 27:Κηφισιά, 31:Χαλάνδρι, 32:Πέραμα/Κερατσίνι, 39:Αθήνα, 43:Πειραιάς. Αν η περιοχή δεν υπάρχει στη λίστα, μάντεψε τον κοντινότερο αριθμό.',
      parameters: {
        type: 'OBJECT',
        properties: {
          division_number: {
            type: 'INTEGER',
            description: 'Ο αριθμός της περιοχής, π.χ. 32 για το Πέραμα.'
          }
        },
        required: ['division_number']
      }
    },
    {
      name: 'get_latest_news',
      description: 'Επιστρέφει τα τελευταία νέα, ανακοινώσεις ή πληροφορίες για πρόσωπα/events που υπάρχουν στα News του δικτύου.'
    }
  ]
}];

/**
 * Execute tool against platform database
 */
async function executeDbTool(name, args = {}) {
  if (name === 'get_domain_owner') {
    const div = args.division_number;
    try {
      const [rows] = await pool.query('SELECT owner_name FROM domain_claims WHERE division = ? LIMIT 1', [div]);
      if (rows.length > 0 && rows[0].owner_name) {
        return { status: 'claimed', owner: rows[0].owner_name, division: div };
      }
      return { status: 'unclaimed', message: 'Η περιοχή είναι free/unclaimed.', division: div };
    } catch (e) {
      log.err('AI Tool get_domain_owner error', { error: e.message });
      return { error: 'Database query failed for domain claim.' };
    }
  }

  if (name === 'get_latest_news') {
    try {
      const bannerEnabled = await getSetting('banner_enabled', 'false');
      if (bannerEnabled === 'true' || bannerEnabled === '1' || bannerEnabled === true) {
        const bannerMessage = await getSetting('banner_message', '');
        if (bannerMessage) {
          return { latest_news: bannerMessage };
        }
      }
      return { latest_news: 'Το δίκτυο είναι ήσυχο. Δεν υπάρχουν ενεργές ανακοινώσεις αυτή τη στιγμή.' };
    } catch (e) {
      log.err('AI Tool get_latest_news error', { error: e.message });
      return { error: 'Database query failed for latest news.' };
    }
  }

  return { error: `Unknown tool: ${name}` };
}

/**
 * Generate a response from Giannakis (SchreckNet AI Node)
 */
async function generateGiannakisReply({
  query,
  charName = 'Kindred',
  charClan = 'Unknown Clan',
  systemPromptOverride = null
}) {
  const apiKey = process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('MISSING_API_KEY');
  }

  let rawPrompt = systemPromptOverride;
  if (!rawPrompt) {
    rawPrompt = await getSetting('giannakis_system_prompt');
    if (!rawPrompt) {
      rawPrompt = await getSetting('discord_ai_system_prompt', DEFAULT_GIANNAKIS_PROMPT);
    }
  }
  if (!rawPrompt) {
    rawPrompt = DEFAULT_GIANNAKIS_PROMPT;
  }

  let systemPrompt = rawPrompt
    .replace(/\$\{charName\}/g, charName)
    .replace(/\{charName\}/g, charName)
    .replace(/\$\{charClan\}/g, charClan)
    .replace(/\{charClan\}/g, charClan);

  systemPrompt += `\n\n[SYSTEM CONTEXT: The user you are talking to is "${charName}" of Clan "${charClan}". Adapt your response, slang, and attitude towards them based on their Clan stereotypes.]`;

  let lastError = null;

  for (const modelName of CANDIDATE_MODELS) {
    try {
      const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`;

      const firstTurnBody = {
        contents: [
          {
            role: 'user',
            parts: [{ text: query }]
          }
        ],
        systemInstruction: {
          parts: [{ text: systemPrompt }]
        },
        tools: TOOLS
      };

      const res = await axios.post(endpoint, firstTurnBody, { timeout: 25000 });
      const firstCandidate = res.data?.candidates?.[0];
      const parts = firstCandidate?.content?.parts || [];

      const toolCallPart = parts.find(p => p.functionCall);

      if (toolCallPart && toolCallPart.functionCall) {
        const call = toolCallPart.functionCall;
        const toolResult = await executeDbTool(call.name, call.args);

        const secondTurnBody = {
          contents: [
            {
              role: 'user',
              parts: [{ text: query }]
            },
            {
              role: 'model',
              parts: parts
            },
            {
              role: 'user',
              parts: [
                {
                  functionResponse: {
                    name: call.name,
                    response: toolResult
                  }
                }
              ]
            }
          ],
          systemInstruction: {
            parts: [{ text: systemPrompt }]
          },
          tools: TOOLS
        };

        const res2 = await axios.post(endpoint, secondTurnBody, { timeout: 25000 });
        const text2 = res2.data?.candidates?.[0]?.content?.parts?.[0]?.text;
        if (text2 && text2.trim()) {
          return { text: text2.trim(), modelUsed: modelName, toolUsed: call.name };
        }
      }

      const directText = parts[0]?.text;
      if (directText && directText.trim()) {
        return { text: directText.trim(), modelUsed: modelName, toolUsed: null };
      }
    } catch (err) {
      log.warn(`Giannakis AI model ${modelName} failed`, {
        error: err.response?.data?.error?.message || err.message,
        status: err.response?.status
      });
      lastError = err;
      // If 400 with invalid argument or missing key, don't keep trying forever unless model specific
      if (err.response?.status === 401 || err.response?.status === 403) {
        break;
      }
    }
  }

  throw lastError || new Error('All AI models failed to respond.');
}

module.exports = {
  DEFAULT_GIANNAKIS_PROMPT,
  generateGiannakisReply,
  executeDbTool
};

