const axios = require('axios');
const cheerio = require('cheerio');

(async () => {
  try {
    const { data } = await axios.get('https://vtm.paradoxwikis.com/Salubri');
    const $ = cheerio.load(data);
    console.log('--- PAGE TITLE ---');
    console.log($('title').text());
    console.log('--- BODY FIRST 500 CHARS ---');
    console.log($('body').html().substring(0, 500));
    console.log('--- PARAGRAPHS ---');
    $('.mw-parser-output > p').each((i, el) => {
      console.log(`P ${i}:`, $(el).text().trim());
    });
  } catch(e) {
    console.error(e.message);
  }
})();
