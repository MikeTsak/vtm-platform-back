// utils/discordMarkdown.js
//
// Converts rich-text HTML (from news and rumor editors) into Discord-compatible
// Markdown for channel broadcasts and DMs. Supports bold, italic, underline,
// strikethrough, blockquotes, code, headers, links, and lists, handling
// Discord's strict whitespace requirements and message length constraints.

const cheerio = require('cheerio');

/**
 * Shifts whitespace outside formatting delimiters so Discord renders them correctly.
 * Example: wrapWithMarkdown(' hello ', '**') -> ' **hello** '
 */
function wrapWithMarkdown(text, delimiter) {
  if (!text) return '';
  if (!text.trim()) return text;

  const match = text.match(/^(\s*)([\s\S]*?)(\s*)$/);
  if (!match) return `${delimiter}${text}${delimiter}`;

  const [, leading, content, trailing] = match;
  if (!content) return text;

  return `${leading}${delimiter}${content}${delimiter}${trailing}`;
}

/**
 * Recursively converts a cheerio DOM node into Discord Markdown.
 */
function convertNode(node) {
  if (!node) return '';

  if (node.type === 'text') {
    let text = node.data || '';
    // Normalize non-breaking spaces
    return text.replace(/\u00A0/g, ' ');
  }

  if (node.type === 'comment') return '';

  const tag = (node.name || '').toLowerCase();

  let inner = '';
  if (node.children && node.children.length > 0) {
    inner = node.children.map(child => convertNode(child)).join('');
  }

  switch (tag) {
    case 'b':
    case 'strong':
      return wrapWithMarkdown(inner, '**');

    case 'i':
    case 'em':
      return wrapWithMarkdown(inner, '*');

    case 'u':
    case 'ins':
      return wrapWithMarkdown(inner, '__');

    case 's':
    case 'strike':
    case 'del':
      return wrapWithMarkdown(inner, '~~');

    case 'code':
      return wrapWithMarkdown(inner, '`');

    case 'pre': {
      const trimmed = inner.trim();
      return trimmed ? `\n\`\`\`\n${trimmed}\n\`\`\`\n` : '';
    }

    case 'blockquote': {
      const trimmed = inner.trim();
      if (!trimmed) return '';
      const lines = trimmed.split('\n');
      return '\n' + lines.map(line => `> ${line}`).join('\n') + '\n\n';
    }

    case 'h1': {
      const trimmed = inner.trim();
      return trimmed ? `\n# ${trimmed}\n\n` : '';
    }
    case 'h2': {
      const trimmed = inner.trim();
      return trimmed ? `\n## ${trimmed}\n\n` : '';
    }
    case 'h3': {
      const trimmed = inner.trim();
      return trimmed ? `\n### ${trimmed}\n\n` : '';
    }
    case 'h4':
    case 'h5':
    case 'h6': {
      const trimmed = inner.trim();
      return trimmed ? `\n#### ${trimmed}\n\n` : '';
    }

    case 'p':
    case 'div':
      return inner ? `\n${inner}\n` : '\n';

    case 'br':
      return '\n';

    case 'ul':
    case 'ol':
      return inner ? `\n${inner}\n` : '';

    case 'li': {
      const trimmed = inner.trim();
      return trimmed ? `- ${trimmed}\n` : '';
    }

    case 'a': {
      const href = (node.attribs?.href || '').trim();
      const text = inner.trim();
      if (!href) return inner;
      if (!text || text === href) return href;
      return `[${text}](${href})`;
    }

    default:
      return inner;
  }
}

/**
 * Converts rich-text HTML into Discord Markdown.
 *
 * @param {string} html
 * @returns {string}
 */
function htmlToDiscordMarkdown(html) {
  if (!html || typeof html !== 'string') return '';

  const $ = cheerio.load(html, null, false);
  const root = $.root()[0];

  let markdown = '';
  if (root && root.children) {
    markdown = root.children.map(child => convertNode(child)).join('');
  } else {
    markdown = html;
  }

  // Normalize newlines and whitespace
  markdown = markdown.replace(/\r\n/g, '\n');
  // Collapse 3+ consecutive newlines to 2
  markdown = markdown.replace(/\n{3,}/g, '\n\n');

  return markdown.trim();
}

/**
 * Safely truncates Discord Markdown to a maximum length while ensuring
 * open formatting tags (bold, italic, strikethrough, underline, code) are closed.
 *
 * @param {string} text
 * @param {number} maxLength
 * @returns {string}
 */
function truncateDiscordMarkdown(text, maxLength = 1500) {
  if (!text || text.length <= maxLength) return text || '';

  let cutIndex = maxLength;
  const lastSpace = text.lastIndexOf(' ', maxLength);
  const lastNewline = text.lastIndexOf('\n', maxLength);
  const preferredBreak = Math.max(lastSpace, lastNewline);
  if (preferredBreak > maxLength - 100) {
    cutIndex = preferredBreak;
  }

  let truncated = text.slice(0, cutIndex).trimEnd();

  // Close unclosed code blocks
  const codeBlockCount = (truncated.match(/```/g) || []).length;
  if (codeBlockCount % 2 !== 0) {
    truncated += '\n```';
  } else {
    const withoutBlocks = truncated.replace(/```[\s\S]*?```/g, '');
    const inlineCodeCount = (withoutBlocks.match(/(?<!`)`(?!`)/g) || []).length;
    if (inlineCodeCount % 2 !== 0) {
      truncated += '`';
    }
  }

  // Close unclosed strikethrough
  const strikeCount = (truncated.match(/~~/g) || []).length;
  if (strikeCount % 2 !== 0) {
    truncated += '~~';
  }

  // Close unclosed underline
  const underlineCount = (truncated.match(/__/g) || []).length;
  if (underlineCount % 2 !== 0) {
    truncated += '__';
  }

  // Close unclosed asterisks (bold/italic)
  const asteriskCount = (truncated.match(/\*/g) || []).length;
  if (asteriskCount % 2 !== 0) {
    const doubleAsteriskCount = (truncated.match(/\*\*/g) || []).length;
    if (doubleAsteriskCount % 2 !== 0) {
      truncated += '**';
    } else {
      truncated += '*';
    }
  } else {
    const doubleAsteriskCount = (truncated.match(/\*\*/g) || []).length;
    if (doubleAsteriskCount % 2 !== 0) {
      truncated += '**';
    }
  }

  return truncated + '...';
}

module.exports = {
  wrapWithMarkdown,
  htmlToDiscordMarkdown,
  truncateDiscordMarkdown,
};

