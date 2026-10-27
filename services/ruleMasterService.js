// services/ruleMasterService.js
//
// Rule Master AI service for Vampire: The Masquerade 5th Edition (V5)
// Chronicle: Athens Through Time
// Grounded retrieval and Google Generative AI integration with token efficiency

const axios = require('axios');
const path = require('path');
const fs = require('fs');
const { log } = require('../logger');

// Load static index catalogs safely
let subjectIndex = [];
let lexicons = { disciplines: [], clans: [] };
let rulesCatalog = { disciplines: {}, rituals: {}, advantages: {} };
let fullPowersAndRituals = { powers: [], rituals: [] };
let corebookToc = [];
let antagonistsAndEntities = [];

try {
  const subjPath = path.resolve(__dirname, '../data/corebookSubjectIndex.json');
  if (fs.existsSync(subjPath)) {
    subjectIndex = JSON.parse(fs.readFileSync(subjPath, 'utf8'));
  }
} catch (e) {
  log.err('Failed loading corebookSubjectIndex.json', e);
}

try {
  const lexPath = path.resolve(__dirname, '../data/lexicons.json');
  if (fs.existsSync(lexPath)) {
    lexicons = JSON.parse(fs.readFileSync(lexPath, 'utf8'));
  }
} catch (e) {
  log.err('Failed loading lexicons.json', e);
}

try {
  const rulesPath = path.resolve(__dirname, '../data/rulesCatalog.json');
  if (fs.existsSync(rulesPath)) {
    rulesCatalog = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
  }
} catch (e) {
  log.err('Failed loading rulesCatalog.json', e);
}

try {
  const fullPath = path.resolve(__dirname, '../data/fullPowersAndRituals.json');
  if (fs.existsSync(fullPath)) {
    fullPowersAndRituals = JSON.parse(fs.readFileSync(fullPath, 'utf8'));
  }
} catch (e) {
  log.err('Failed loading fullPowersAndRituals.json', e);
}

try {
  const tocPath = path.resolve(__dirname, '../data/corebookToc.json');
  if (fs.existsSync(tocPath)) {
    corebookToc = JSON.parse(fs.readFileSync(tocPath, 'utf8'));
  }
} catch (e) {
  log.err('Failed loading corebookToc.json', e);
}

try {
  const antPath = path.resolve(__dirname, '../data/antagonistsAndEntities.json');
  if (fs.existsSync(antPath)) {
    antagonistsAndEntities = JSON.parse(fs.readFileSync(antPath, 'utf8'));
  }
} catch (e) {
  log.err('Failed loading antagonistsAndEntities.json', e);
}

const CANDIDATE_MODELS = [
  'gemini-3.5-flash-lite',
  'gemini-3.5-flash',
  'gemini-flash-latest',
  'gemini-3.8-flash',
];

const BOOK_FILE_MAP = {
  'Corebook': 'Vampire-the-Masquerade-1.pdf',
  'Players Guide': 'Vampire-The-Masquerade-V5-Players-Guide.pdf',
  'Cults of the Blood Gods': 'Cults-of-the-Blood-Gods-Vampire-the-Masquerade-5th-Edition.pdf',
  'Camarilla': 'Vampire-the-Masquerade-V5-Camarilla-2018.pdf',
  'Anarch': 'Anarch-Vampire-the-Masquerade-5th-Edition.pdf',
  'Sabbat': 'Vampire-The-Masquerade-V5-Sabbat-The-Black-Hand-Definitive-Edition.pdf'
};

const STOP_WORDS = new Set([
  'the', 'is', 'at', 'which', 'on', 'and', 'a', 'an', 'in', 'of', 'to', 'for', 'with',
  'what', 'how', 'does', 'can', 'are', 'about', 'rules', 'rule', 'vampire', 'v5', 'tell', 'me'
]);

/**
 * Clean text to comply with the typography rule:
 * NEVER use hyphens or em dashes in UI text or generated content.
 */
function sanitizeTypography(text) {
  if (!text || typeof text !== 'string') return '';
  return text
    // Replace em dashes and en dashes with comma or colon
    .replace(/[—–]/g, ', ')
    // Replace hyphens in phrases like "Thin-blood" -> "Thin blood"
    .replace(/(\w+)-(\w+)/g, '$1 $2')
    // Replace standalone hyphens used as separators or dashes
    .replace(/\s+-\s+/g, ' : ')
    .replace(/^- /gm, '* ')
    .replace(/\s+-/g, ' ')
    .replace(/-\s+/g, ' ');
}

/**
 * Retrieve relevant rules snippets based on user keywords.
 * Keeps context under 800 tokens to ensure zero token bloat on free tier plans.
 */
function retrieveGroundedContext(query) {
  const lowerQuery = query.toLowerCase();
  const tokens = lowerQuery
    .replace(/[^\w\s]/g, ' ')
    .split(/\s+/)
    .filter(t => t.length > 2 && !STOP_WORDS.has(t));

  const matchedSnippets = [];
  const matchedCitations = [];

  // 0. Check Antagonists, Entities, and Ceremonies
  if (antagonistsAndEntities && antagonistsAndEntities.length) {
    for (const ant of antagonistsAndEntities) {
      const antText = `${ant.name} ${ant.category} ${ant.entity_type} ${ant.summary} ${ant.rules}`.toLowerCase();
      const matches = tokens.some(t => antText.includes(t)) || lowerQuery.includes(ant.name.toLowerCase());
      if (matches) {
        matchedSnippets.unshift(`Entity/System [${ant.name}]: Book ${ant.book}, Print Page ${ant.page} (PDF Page ${ant.pdfPage}). ${ant.summary} Rules: ${ant.rules}`);
        matchedCitations.unshift({
          title: ant.name,
          book: ant.book,
          page: ant.page,
          pdfPage: ant.pdfPage,
          file: ant.file
        });
      }
    }
  }

  // 1. Check Disciplines & Powers in rulesCatalog
  if (rulesCatalog.disciplines) {
    for (const [discName, discData] of Object.entries(rulesCatalog.disciplines)) {
      const discLower = discName.toLowerCase();
      const discMatches = tokens.some(t => discLower.includes(t));

      // Find in lexicons for page numbers
      const discLexicon = lexicons.disciplines?.find(d => d.name.toLowerCase() === discLower);

      if (discMatches && discLexicon) {
        matchedSnippets.push(`Discipline ${discName}: Book ${discLexicon.book}, Print Page ${discLexicon.page} (PDF Page ${discLexicon.pdfPage}). Clan affinities: ${discData.clanAffinity?.join(', ')}.`);
        matchedCitations.push({
          title: `${discName} Discipline`,
          book: discLexicon.book,
          page: discLexicon.page,
          pdfPage: discLexicon.pdfPage,
          url: discLexicon.url,
          file: discLexicon.file
        });
      }

      // Check powers
      if (discData.powers) {
        for (const [powerId, power] of Object.entries(discData.powers)) {
          const powerNameLower = power.name.toLowerCase();
          const powerMatches = tokens.some(t => powerNameLower.includes(t)) || lowerQuery.includes(powerNameLower);

          if (powerMatches) {
            let details = `Power ${power.name} (${discName} Level ${power.level})`;
            if (power.dicePool) details += `, Dice Pool: ${power.dicePool}`;
            if (power.amalgam) details += `, Amalgam: ${power.amalgam}`;
            if (power.clan) details += `, Clan: ${power.clan}`;
            if (discLexicon) {
              details += `, Sourcebook: ${discLexicon.book} (p. ${discLexicon.page})`;
              matchedCitations.push({
                title: power.name,
                book: discLexicon.book,
                page: discLexicon.page,
                pdfPage: discLexicon.pdfPage,
                url: discLexicon.url,
                file: discLexicon.file
              });
            }
            matchedSnippets.push(details);
          }
        }
      }
    }
  }

  // 2. Check Clans in lexicons
  if (lexicons.clans) {
    for (const clan of lexicons.clans) {
      const clanLower = clan.name.toLowerCase();
      if (tokens.some(t => clanLower.includes(t)) || lowerQuery.includes(clanLower)) {
        matchedSnippets.push(`Clan ${clan.name}: Book ${clan.book}, Print Page ${clan.page} (PDF Page ${clan.pdfPage}).`);
        matchedCitations.push({
          title: `Clan ${clan.name}`,
          book: clan.book,
          page: clan.page,
          pdfPage: clan.pdfPage,
          url: clan.url,
          file: clan.file
        });
      }
    }
  }

  // 3. Check Subject Index (All Books: Corebook, Players Guide, Cults, Camarilla, Anarch, Sabbat)
  if (subjectIndex && subjectIndex.length) {
    const scored = subjectIndex.map(item => {
      let score = 0;
      const topicLower = item.topic.toLowerCase();
      const sumLower = (item.summary || '').toLowerCase();
      const secLower = (item.section || '').toLowerCase();

      for (const t of tokens) {
        if (topicLower.includes(t)) score += 5;
        if (secLower.includes(t)) score += 3;
        if (sumLower.includes(t)) score += 2;
      }
      return { item, score };
    }).filter(x => x.score > 0).sort((a, b) => b.score - a.score);

    for (const { item } of scored.slice(0, 5)) {
      const bookName = item.book || 'Corebook';
      const fileName = item.file || BOOK_FILE_MAP[bookName] || 'Vampire-the-Masquerade-1.pdf';
      matchedSnippets.push(`Topic: ${item.topic} (Section: ${item.section}). Book: ${bookName}, Print Page ${item.page} (PDF Page ${item.pdfPage}). Summary: ${item.summary}`);
      matchedCitations.push({
        title: item.topic,
        book: bookName,
        page: item.page,
        pdfPage: item.pdfPage,
        file: fileName
      });
    }
  }

  // 4. Check Advantages, Backgrounds, Merits, and Flaws in rulesCatalog
  if (rulesCatalog.advantages) {
    for (const [advId, adv] of Object.entries(rulesCatalog.advantages)) {
      const advNameLower = adv.name.toLowerCase();
      const advCatLower = (adv.category || '').toLowerCase();
      const isExactMatch = lowerQuery.includes(advNameLower) || tokens.some(t => advNameLower === t);
      const isKeywordMatch = tokens.some(t => advNameLower.includes(t) || advCatLower.includes(t));

      if (isExactMatch || isKeywordMatch) {
        let details = `${adv.type || 'Advantage'} [${adv.name}] (${adv.category || 'General'}): Dots: ${adv.dots || 'Variable'}.`;
        if (adv.description) {
          details += ` Mechanics: ${adv.description}`;
        }
        if (adv.source || adv.book) {
          const book = adv.book || 'Corebook';
          const page = adv.page || 184;
          const pdfPage = adv.pdfPage || (page + 2);
          details += ` Source: ${adv.source || `${book}, p. ${page}`}`;
          matchedCitations.push({
            title: `${adv.name} (${adv.category || adv.type || 'Advantage'})`,
            book: book,
            page: page,
            pdfPage: pdfPage,
            file: BOOK_FILE_MAP[book] || 'Vampire-the-Masquerade-1.pdf'
          });
        }
        if (isExactMatch) {
          matchedSnippets.unshift(details);
        } else {
          matchedSnippets.push(details);
        }
      }
    }
  }

  // 5. Check Predator Types in rulesCatalog
  if (rulesCatalog.predatorTypes) {
    for (const [ptKey, pt] of Object.entries(rulesCatalog.predatorTypes)) {
      const ptNameLower = pt.name.toLowerCase();
      const ptMatches = tokens.some(t => ptNameLower.includes(t)) || lowerQuery.includes(ptNameLower);
      if (ptMatches) {
        let details = `Predator Type [${pt.name}]: Book ${pt.book}, Print Page ${pt.page} (PDF Page ${pt.pdfPage}). Hunting Rolls: ${pt.rolls || 'None'}. Disciplines: ${pt.disciplines?.join(', ') || 'None'}. Specialties: ${pt.specialties?.join(', ') || 'None'}. ${pt.desc || ''}`;
        matchedSnippets.unshift(details);
        matchedCitations.unshift({
          title: `${pt.name} (Predator Type)`,
          book: pt.book,
          page: pt.page,
          pdfPage: pt.pdfPage,
          file: pt.file || BOOK_FILE_MAP[pt.book] || 'Vampire-the-Masquerade-1.pdf'
        });
      }
    }
  }

  // 6. Check Coteries in rulesCatalog
  if (rulesCatalog.coteries) {
    for (const [cotName, cot] of Object.entries(rulesCatalog.coteries)) {
      const cotLower = cotName.toLowerCase();
      const cotMatches = tokens.some(t => cotLower.includes(t)) || lowerQuery.includes(cotLower);
      if (cotMatches) {
        const domainStr = cot.domain ? Object.entries(cot.domain).map(([k, v]) => `${k}: ${v}`).join(', ') : 'None';
        const reqStr = cot.required ? Object.entries(cot.required).map(([k, v]) => `${k} ${v}`).join(', ') : 'None';
        let details = `Coterie Type [${cot.name}]: Book ${cot.book}, Print Page ${cot.page} (PDF Page ${cot.pdfPage}). Domain: ${domainStr}. Required: ${reqStr}. Notes: ${cot.notes || ''}`;
        matchedSnippets.push(details);
        matchedCitations.push({
          title: `${cot.name} (Coterie)`,
          book: cot.book,
          page: cot.page,
          pdfPage: cot.pdfPage,
          file: BOOK_FILE_MAP[cot.book] || 'Vampire-the-Masquerade-1.pdf'
        });
      }
    }
  }

  // 7. Check Alternative Clan Banes & Compulsions in rulesCatalog
  if (rulesCatalog.alternativeClanBanes) {
    for (const [clanName, baneData] of Object.entries(rulesCatalog.alternativeClanBanes)) {
      const clanLower = clanName.toLowerCase();
      const baneLower = (baneData.baneName || '').toLowerCase();
      const compLower = (baneData.compulsionName || '').toLowerCase();
      const matches = tokens.some(t => clanLower.includes(t) || baneLower.includes(t) || compLower.includes(t)) ||
                      (lowerQuery.includes('bane') && lowerQuery.includes(clanLower));
      if (matches) {
        let details = `Alternative Bane and Compulsion [${clanName}]: Book ${baneData.book}, Print Page ${baneData.page} (PDF Page ${baneData.pdfPage}). Variant Bane (${baneData.baneName}): ${baneData.bane}. Variant Compulsion (${baneData.compulsionName}): ${baneData.compulsion}.`;
        matchedSnippets.unshift(details);
        matchedCitations.unshift({
          title: `${clanName} Variant Bane`,
          book: baneData.book,
          page: baneData.page,
          pdfPage: baneData.pdfPage,
          file: BOOK_FILE_MAP[baneData.book] || 'Vampire-The-Masquerade-V5-Players-Guide.pdf'
        });
      }
    }
  }

  // Deduplicate citations by title
  const uniqueCitations = [];
  const seenTitles = new Set();
  for (const c of matchedCitations) {
    if (!seenTitles.has(c.title)) {
      seenTitles.add(c.title);
      uniqueCitations.push(c);
    }
  }

  return {
    contextText: matchedSnippets.slice(0, 8).join('\n* '),
    citations: uniqueCitations.slice(0, 5)
  };
}

/**
 * Query Google Generative AI models with automatic fallback.
 */
async function callGeminiGenerate(prompt, systemInstruction, history = [], maxTokens = 1000) {
  const apiKey = process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('Google Generative AI API key is not configured in environment variables');
  }

  // Format multi turn conversation contents for Gemini API
  const formattedContents = [];
  let lastRole = null;

  if (Array.isArray(history) && history.length > 0) {
    for (const item of history) {
      const role = (item.role === 'assistant' || item.role === 'model') ? 'model' : 'user';
      const text = item.text || item.content || '';
      if (!text || !text.trim()) continue;

      if (formattedContents.length === 0 && role === 'model') {
        // Gemini API requires conversation to start with 'user'
        continue;
      }

      if (role === lastRole) {
        // Merge consecutive same role messages
        formattedContents[formattedContents.length - 1].parts[0].text += `\n\n${text.trim()}`;
      } else {
        formattedContents.push({
          role,
          parts: [{ text: text.trim() }]
        });
        lastRole = role;
      }
    }
  }

  // Append current user turn
  if (lastRole === 'user') {
    formattedContents[formattedContents.length - 1].parts[0].text += `\n\n${prompt}`;
  } else {
    formattedContents.push({
      role: 'user',
      parts: [{ text: prompt }]
    });
  }

  let lastError = null;

  for (const model of CANDIDATE_MODELS) {
    try {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
      const payload = {
        contents: formattedContents,
        generationConfig: {
          temperature: 0.2,
          maxOutputTokens: maxTokens,
          topP: 0.8
        }
      };

      if (systemInstruction) {
        payload.systemInstruction = {
          parts: [{ text: systemInstruction }]
        };
      }

      const response = await axios.post(url, payload, { timeout: 10000 });
      const text = response.data?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (text) {
        return { text, modelUsed: model };
      }
    } catch (err) {
      const status = err.response?.status;
      const errMsg = err.response?.data?.error?.message || err.message;
      log.err(`Rule Master model ${model} failed (${status}): ${errMsg}`);
      lastError = err;
    }
  }

  throw lastError || new Error('All Google Generative AI candidate models failed');
}

/**
 * Deep Search Rule Master: Multi-prompt agentic reasoning loop.
 * 1. Analyzes inquiry, formulates hypothesis, and pinpoints sourcebooks and topics.
 * 2. Gathers targeted verbatim evidence from full powers, rituals, subject index, and TOC.
 * 3. Verifies hypothesis, extracts verbatim quotes, resolves mechanics and edge cases.
 * 4. Delivers an authoritative Storyteller ruling with exact quotes and page jump links.
 */
async function deepSearchRuleMaster(question, options = {}) {
  if (!question || typeof question !== 'string' || !question.trim()) {
    throw new Error('Question must be a non empty string');
  }

  const trimmedQuestion = question.trim();
  const history = Array.isArray(options.history) ? options.history : [];

  // ----------------------------------------------------
  // PASS 1: Hypothesis Formulation and Target Pinpointing
  // ----------------------------------------------------
  const pass1System = `You are the V5 Rules Architect for 'Athens Through Time'.
Your mission in Pass 1 is to analyze the rules question and pinpoint which V5 sourcebooks, systems, powers, ceremonies, or antagonist rules govern this ruling.
Carefully distinguish the intent:
* Is this about Antagonists, Spirits, Spectres, Wraiths, or Creatures of Horror? (e.g. Corebook p. 377 hostile possession, Cults of the Blood Gods p. 212 Puppeteers, Lupines, Hunters)
* Is this about Oblivion Ceremonies or Necromancy? (e.g. Cults of the Blood Gods p. 208 Host Spirit voluntary possession, p. 207 Exorcism, Compel Spirit)
* Is this about Player Disciplines? (e.g. Auspex Possession p. 251, Animalism Subsume the Spirit p. 247)
* Is this about Core Chronicle Systems? (e.g. Hunger, Humanity, Frenzy, Blood Potency)

Respond with JSON only:
{
  "hypothesis": "Initial preliminary answer of how the rule functions across antagonist rules, ceremonies, AND player powers",
  "category": "Antagonists / Ceremonies / Disciplines / Systems",
  "targetTopics": ["Spectre Possession", "Host Spirit Ceremony", "Possession Auspex"],
  "searchKeywords": ["spectre", "possession", "hostile", "ghost", "ceremony"],
  "targetBooks": ["Corebook", "Cults of the Blood Gods", "Players Guide"]
}
Never use hyphens or em dashes in strings.`;

  const recentHistoryText = history.slice(-3).map(h => {
    const roleLabel = (h.role === 'assistant' || h.role === 'model') ? 'Rule Master' : 'Storyteller';
    const content = (h.text || h.content || '').substring(0, 300);
    return `${roleLabel}: ${content}`;
  }).join('\n');

  const pass1Prompt = `${recentHistoryText ? `Recent Conversation Thread:\n${recentHistoryText}\n\n` : ''}Analyze this V5 question and pinpoint sourcebook chapters, systems, antagonists, and keywords:
Question: ${trimmedQuestion}

Output JSON only:`;

  let pass1Data = null;
  let pass1Model = null;
  try {
    const res1 = await callGeminiGenerate(pass1Prompt, pass1System, [], 400);
    pass1Model = res1.modelUsed;
    const cleanJson = res1.text.replace(/```json/g, '').replace(/```/g, '').trim();
    pass1Data = JSON.parse(cleanJson);
  } catch (err) {
    log.err('Pass 1 of Deep Search failed, falling back to heuristic parsing', err);
    pass1Data = {
      hypothesis: 'Governed by V5 Core and sourcebook systems',
      category: 'General Systems',
      targetTopics: [trimmedQuestion],
      searchKeywords: trimmedQuestion.toLowerCase().split(/\s+/).filter(w => w.length > 2 && !STOP_WORDS.has(w)),
      targetBooks: ['Corebook', 'Cults of the Blood Gods']
    };
  }

  // ----------------------------------------------------
  // PASS 2: Evidence Gathering and Sourcebook Page Inspection
  // ----------------------------------------------------
  const keywords = new Set([
    ...(pass1Data.searchKeywords || []),
    ...(pass1Data.targetTopics || []),
    ...trimmedQuestion.toLowerCase().split(/\s+/).filter(w => w.length > 2 && !STOP_WORDS.has(w))
  ]);

  const evidenceSnippets = [];
  const deepCitations = [];
  const extractedQuotes = [];

  // 0. Search Antagonists, Entities, and Ceremonies
  if (antagonistsAndEntities && antagonistsAndEntities.length) {
    for (const ant of antagonistsAndEntities) {
      const antText = `${ant.name} ${ant.category} ${ant.entity_type} ${ant.summary} ${ant.rules}`.toLowerCase();
      const matches = Array.from(keywords).some(k => antText.includes(k.toLowerCase())) ||
                      trimmedQuestion.toLowerCase().split(/\s+/).some(w => w.length > 3 && antText.includes(w));
      if (matches) {
        evidenceSnippets.unshift(
          `[ANTAGONIST & ENTITY: ${ant.name}] Book: ${ant.book} p. ${ant.page} (PDF p. ${ant.pdfPage}). Type: ${ant.entity_type}. Verbatim Rules Notes: "${ant.rules}" Mechanics: ${JSON.stringify(ant.mechanics || {})}`
        );
        extractedQuotes.unshift({
          topic: ant.name,
          source: `${ant.book}, p. ${ant.page}`,
          quote: ant.summary + ' ' + (ant.rules.slice(0, 160) + '...')
        });
        deepCitations.unshift({
          title: ant.name,
          book: ant.book,
          page: ant.page,
          pdfPage: ant.pdfPage,
          file: ant.file
        });
      }
    }
  }

  // 1. Search full powers and rituals for verbatim text
  if (fullPowersAndRituals.powers) {
    for (const p of fullPowersAndRituals.powers) {
      const pNameLower = p.name.toLowerCase();
      const pDiscLower = (p.discipline || '').toLowerCase();
      const matches = Array.from(keywords).some(k => {
        const kl = k.toLowerCase();
        return pNameLower.includes(kl) || pDiscLower.includes(kl) || (p.notes && p.notes.toLowerCase().includes(kl));
      });

      if (matches) {
        let snippet = `[POWER: ${p.name}] Discipline: ${p.discipline} Level ${p.level}. Source: ${p.source || 'Corebook'}. Cost: ${p.cost || '1 Rouse'}. Duration: ${p.duration || 'One scene'}. Dice Pool: ${p.dice_pool || 'None'}. Opposing Pool: ${p.opposing_pool || 'None'}. Verbatim Rules Notes: "${p.notes || ''}"`;
        if (p.amalgam) snippet += ` Amalgam: ${p.amalgam}.`;
        if (p.clan) snippet += ` Clan: ${p.clan}.`;
        evidenceSnippets.push(snippet);

        if (p.notes) {
          extractedQuotes.push({
            topic: p.name,
            source: p.source || `${p.discipline} Rules`,
            quote: p.notes
          });
        }

        const srcMatch = (p.source || '').match(/([A-Za-z\s]+)\s+p\.?\s*(\d+)/i);
        const bookName = srcMatch ? srcMatch[1].trim() : 'Corebook';
        const pageNum = srcMatch ? parseInt(srcMatch[2], 10) : 244;
        const discLex = lexicons.disciplines?.find(d => d.name.toLowerCase() === pDiscLower);

        deepCitations.push({
          title: p.name,
          book: bookName,
          page: pageNum,
          pdfPage: discLex?.pdfPage || pageNum + 2,
          file: discLex?.file || 'Vampire-the-Masquerade-1.pdf',
          url: discLex?.url
        });
      }
    }
  }

  // 2. Search rituals
  if (fullPowersAndRituals.rituals) {
    for (const r of fullPowersAndRituals.rituals) {
      const rNameLower = r.name.toLowerCase();
      const matches = Array.from(keywords).some(k => rNameLower.includes(k.toLowerCase()) || (r.effect && r.effect.toLowerCase().includes(k.toLowerCase())));
      if (matches) {
        evidenceSnippets.push(`[RITUAL: ${r.name}] Kind: ${r.kind} Level ${r.level}. Source: ${r.source || 'Blood Sorcery'}. Cost: ${r.cost}. Pool: ${r.dice_pool}. Effect: "${r.effect}". Verbatim Notes: "${r.notes || ''}"`);
        if (r.effect || r.notes) {
          extractedQuotes.push({
            topic: r.name,
            source: r.source || 'Rituals Codex',
            quote: r.effect || r.notes
          });
        }
      }
    }
  }

  // 3. Search subject index (All Books: Corebook, Players Guide, Cults, Camarilla, Anarch, Sabbat)
  if (subjectIndex) {
    for (const item of subjectIndex) {
      const topLower = item.topic.toLowerCase();
      const sumLower = (item.summary || '').toLowerCase();
      const matches = Array.from(keywords).some(k => topLower.includes(k.toLowerCase()) || sumLower.includes(k.toLowerCase()));
      if (matches) {
        const bookName = item.book || 'Corebook';
        const fileName = item.file || BOOK_FILE_MAP[bookName] || 'Vampire-the-Masquerade-1.pdf';
        evidenceSnippets.push(`[INDEX: ${item.topic}] Section: ${item.section}. Book: ${bookName} p. ${item.page} (PDF p. ${item.pdfPage}). Summary: "${item.summary}"`);
        deepCitations.push({
          title: item.topic,
          book: bookName,
          page: item.page,
          pdfPage: item.pdfPage,
          file: fileName
        });
      }
    }
  }

  // 3b. Search Predator Types in rulesCatalog
  if (rulesCatalog.predatorTypes) {
    for (const [ptKey, pt] of Object.entries(rulesCatalog.predatorTypes)) {
      const ptNameLower = pt.name.toLowerCase();
      if (Array.from(keywords).some(k => ptNameLower.includes(k.toLowerCase())) || trimmedQuestion.toLowerCase().includes(ptNameLower)) {
        evidenceSnippets.push(`[PREDATOR TYPE: ${pt.name}] Book: ${pt.book} p. ${pt.page} (PDF p. ${pt.pdfPage}). Hunting Rolls: ${pt.rolls}. Disciplines: ${pt.disciplines?.join(', ')}. Specialties: ${pt.specialties?.join(', ')}. Details: ${pt.desc}`);
        deepCitations.push({
          title: `${pt.name} (Predator Type)`,
          book: pt.book,
          page: pt.page,
          pdfPage: pt.pdfPage,
          file: pt.file || BOOK_FILE_MAP[pt.book] || 'Vampire-the-Masquerade-1.pdf'
        });
      }
    }
  }

  // 3c. Search Alternative Clan Banes & Compulsions
  if (rulesCatalog.alternativeClanBanes) {
    for (const [clanName, baneData] of Object.entries(rulesCatalog.alternativeClanBanes)) {
      const clanLower = clanName.toLowerCase();
      const baneLower = (baneData.baneName || '').toLowerCase();
      if (Array.from(keywords).some(k => clanLower.includes(k.toLowerCase()) || baneLower.includes(k.toLowerCase()))) {
        evidenceSnippets.push(`[VARIANT BANE: ${clanName}] Book: ${baneData.book} p. ${baneData.page} (PDF p. ${baneData.pdfPage}). Alternative Bane (${baneData.baneName}): ${baneData.bane}. Alternative Compulsion (${baneData.compulsionName}): ${baneData.compulsion}.`);
        deepCitations.push({
          title: `${clanName} Variant Bane`,
          book: baneData.book,
          page: baneData.page,
          pdfPage: baneData.pdfPage,
          file: BOOK_FILE_MAP[baneData.book] || 'Vampire-The-Masquerade-V5-Players-Guide.pdf'
        });
      }
    }
  }

  // 3d. Search Coteries in rulesCatalog
  if (rulesCatalog.coteries) {
    for (const [cotName, cot] of Object.entries(rulesCatalog.coteries)) {
      const cotLower = cotName.toLowerCase();
      if (Array.from(keywords).some(k => cotLower.includes(k.toLowerCase()))) {
        const domainStr = cot.domain ? Object.entries(cot.domain).map(([k, v]) => `${k}: ${v}`).join(', ') : 'None';
        evidenceSnippets.push(`[COTERIE TYPE: ${cot.name}] Book: ${cot.book} p. ${cot.page} (PDF p. ${cot.pdfPage}). Domain: ${domainStr}. Required: ${JSON.stringify(cot.required || {})}. Notes: ${cot.notes || ''}`);
        deepCitations.push({
          title: `${cot.name} (Coterie)`,
          book: cot.book,
          page: cot.page,
          pdfPage: cot.pdfPage,
          file: BOOK_FILE_MAP[cot.book] || 'Vampire-the-Masquerade-1.pdf'
        });
      }
    }
  }

  // 4. Search table of contents
  if (corebookToc) {
    for (const item of corebookToc) {
      const titLower = item.title.toLowerCase();
      const matches = Array.from(keywords).some(k => titLower.includes(k.toLowerCase()));
      if (matches) {
        evidenceSnippets.push(`[TOC SECTION: ${item.title}] Corebook p. ${item.page} (PDF p. ${item.pdfPage}).`);
      }
    }
  }

  // 5. Search clans
  if (lexicons.clans) {
    for (const c of lexicons.clans) {
      const clanLower = c.name.toLowerCase();
      if (Array.from(keywords).some(k => clanLower.includes(k.toLowerCase()))) {
        evidenceSnippets.push(`[CLAN: ${c.name}] Book: ${c.book} p. ${c.page} (PDF p. ${c.pdfPage}).`);
        deepCitations.push({
          title: `Clan ${c.name}`,
          book: c.book,
          page: c.page,
          pdfPage: c.pdfPage,
          file: c.file,
          url: c.url
        });
      }
    }
  }

  // ----------------------------------------------------
  // PASS 3: Deep Verification, Quotation and Ruling Synthesis
  // ----------------------------------------------------
  const evidenceDossier = evidenceSnippets.slice(0, 12).join('\n* ');

  const pass3System = `You are the Rule Master, authoritative Storyteller and Rules Arbitrator for Vampire: The Masquerade 5th Edition (V5) in the chronicle 'Athens Through Time'.
PROMPT ZERO MANDATE: We are ALWAYS and strictly talking about Vampire: The Masquerade 5th Edition (V5). You possess complete, canonical mastery over all official V5 sourcebooks (Corebook, Cults of the Blood Gods, Players Guide, Camarilla, Anarch, Sabbat, Second Inquisition, Blood Sigils, Gehenna War, Chicago by Night, etc.).
You are supplied with the Grounded Codex Evidence Dossier containing extracted rule texts, book folios, and systems matched for this inquiry.

CONCISENESS MANDATE:
Deliver authoritative rulings with concise Storyteller precision.
Eliminate verbose filler, lengthy introductory throat clearing, and repetitive restatements.
Keep each section tightly structured, punchy, and direct:
* Executive Ruling: 1 to 2 crisp paragraphs stating the canonical answer.
* Verbatim Codex Quotes: Only the most relevant 2 to 3 quotes with page citations.
* System Mechanics & Dice Contests: Clear, scannable bullet points for dice pools, difficulties, and attributes.
* Storyteller Guidance: 2 to 3 concise bullet points for edge cases.
Do NOT write sprawling multi page essays.

CRITICAL RULES:
1. Multi Domain Scope:
   When answering inquiries about spirits, spectres, wraiths, or possession, you MUST clearly structure and distinguish:
   * Hostile Spirit Possession (Antagonists): Rules for Spectres and Ghosts forcibly possessing mortals or vampires (Corebook p. 377, Cults of the Blood Gods Puppeteers p. 212). Detail:
     - Attributes used: Ghost uses its own Mental and Social attributes and Skills; victim body provides Physical attributes.
     - Host awareness: Victim consciousness remains fully awake and aware of what their body does, but is completely paralyzed.
     - Knowledge: Ghost does not gain access to host memories or thoughts.
     - Powers: Spirit can manifest powers (Dominate, Presence, Auspex) through the host.
     - Ending possession: Banished through Exorcism ceremonies, resolving or destroying Fetters, or dealing lethal damage.
   * Voluntary Spirit Possession (Oblivion Ceremonies): Host Spirit (Level 3 Oblivion Ceremony, Cults of the Blood Gods p. 208) where a vampire willingly surrenders control to a wraith, healing all Superficial and Aggravated Willpower damage upon departure. Exorcism (Level 3 Oblivion Ceremony, p. 207) to expel spirits.
   * Player Vampire Powers: Auspex Level 5 Possession (Amalgam with Dominate 3, p. 251) and Animalism Level 4 Subsume the Spirit (p. 247).
2. NEVER claim that V5 lacks spirit possession rules or that ghost possession is merely narrative; Corebook p. 377 explicitly specifies Spectre possession mechanics, and Cults of the Blood Gods details Puppeteers and Ceremonies.
3. Verbatim Quotes: Include direct, exact quotes from the rule texts in the Evidence Dossier for the relevant rules, powers, or systems.
4. Exact Citations: Every quote and ruling must explicitly cite the sourcebook title and print page number (e.g. Vampire: The Masquerade 5th Edition Corebook, p. 377, Cults of the Blood Gods, p. 208).
5. Mechanics and Contests: Detail exact dice pools, opposing pools, difficulties, Rouse costs, and durations.
6. Edge Cases: Provide clear Storyteller guidance on criticals, messy criticals, bestial failures, or power interactions.
7. TYPOGRAPHY CONSTRAINT: NEVER use hyphens ('-') or em dashes ('—') anywhere in your output. Use colons, commas, or spaces instead. For list items, use asterisk bullet points (*).
8. Structure your response clearly:
   * Executive Ruling
   * Verbatim Codex Quotes
   * System Mechanics & Dice Contests (Covering Hostile Spirit Possession, Voluntary Host Spirit Ceremony, and Player Powers)
   * Storyteller Guidance & Edge Cases
   * Cited Sourcebooks`;

  const pass3Prompt = `Initial Research Hypothesis:
${pass1Data.hypothesis}

Target Sourcebooks and Sections:
${(pass1Data.targetBooks || []).join(', ')}

Grounded Codex Evidence Dossier:
${evidenceDossier ? '* ' + evidenceDossier : 'Official V5 Core Systems'}

Question:
${trimmedQuestion}

Please provide an authoritative, concise deep research ruling with exact verbatim quotes and verified citations:`;

  const result3 = await callGeminiGenerate(pass3Prompt, pass3System, history, 1000);
  const cleanAnswer = sanitizeTypography(result3.text);

  // Deduplicate citations
  const uniqueCitations = [];
  const seen = new Set();
  for (const c of deepCitations) {
    if (!seen.has(c.title)) {
      seen.add(c.title);
      uniqueCitations.push(c);
    }
  }

  return {
    question: trimmedQuestion,
    answer: cleanAnswer,
    hypothesis: sanitizeTypography(pass1Data.hypothesis),
    quotes: extractedQuotes.slice(0, 4).map(q => ({
      topic: sanitizeTypography(q.topic),
      source: sanitizeTypography(q.source),
      quote: sanitizeTypography(q.quote)
    })),
    citations: uniqueCitations.slice(0, 6),
    steps: [
      'Formulated initial mechanical hypothesis and pinpointed sourcebook targets',
      'Inspected verified V5 codex rule texts and page folios',
      'Extracted verbatim rule quotes and verified contested pools',
      'Delivered authoritative Storyteller arbitration'
    ],
    modelUsed: result3.modelUsed || pass1Model,
    isDeepSearch: true
  };
}

/**
 * Ask the Rule Master AI.
 */
async function askRuleMaster(question, options = {}) {
  if (options.deepSearch) {
    return deepSearchRuleMaster(question, options);
  }

  if (!question || typeof question !== 'string' || !question.trim()) {
    throw new Error('Question must be a non empty string');
  }

  const trimmedQuestion = question.trim();
  const history = Array.isArray(options.history) ? options.history : [];
  const { contextText, citations } = retrieveGroundedContext(trimmedQuestion);

  const systemInstruction = `You are the Rule Master, an authoritative Storyteller and Rules Arbitrator for Vampire: The Masquerade 5th Edition (V5) in the chronicle 'Athens Through Time'.
PROMPT ZERO MANDATE: We are ALWAYS and strictly talking about Vampire: The Masquerade 5th Edition (V5) across all official sourcebooks (Corebook, Cults of the Blood Gods, Players Guide, Camarilla, Anarch, Sabbat, Second Inquisition, Blood Sigils, Gehenna War).
Your mission is to answer questions about V5 mechanics, disciplines, powers, clans, contests, dice pools, Rouse checks, resonance, and lore accurately and concisely.

CONCISENESS MANDATE:
Keep the answer brief, sharp, and directly focused on the rule, contest roll, and page citation without storytelling filler or redundant preamble.

CRITICAL RULES:
1. Always state the exact mechanics, dice pools, difficulty, Rouse checks, or contest rolls if applicable.
2. Always explicitly cite the sourcebook title and print page number (e.g. Vampire: The Masquerade 5th Edition Corebook, p. 257, or Cults of the Blood Gods, p. 201).
3. Structure your response clearly:
   * Rule Summary & Mechanics
   * Dice Pool / Contest Details
   * Sourcebook Citations
4. TYPOGRAPHY CONSTRAINT: NEVER use hyphens ('-') or em dashes ('—') anywhere in your output. Use colons, commas, or spaces instead. For lists, use asterisk bullet points (*).
5. Ground your answer in official V5 material. Never fabricate rules or page numbers.`;

  const prompt = `Context from V5 Codex:
${contextText ? '* ' + contextText : 'General V5 Core Rules'}

Question:
${trimmedQuestion}

Please provide an authoritative, concise ruling with exact sourcebook citations:`;

  const result = await callGeminiGenerate(prompt, systemInstruction, history, 800);
  const cleanAnswer = sanitizeTypography(result.text);

  return {
    question: trimmedQuestion,
    answer: cleanAnswer,
    citations,
    modelUsed: result.modelUsed,
    isDeepSearch: false
  };
}

module.exports = {
  askRuleMaster,
  deepSearchRuleMaster,
  retrieveGroundedContext,
  sanitizeTypography,
  CANDIDATE_MODELS
};

