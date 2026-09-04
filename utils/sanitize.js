// utils/sanitize.js
//
// Server-side HTML sanitisation for user-authored rich text (news, rumors,
// announcements, banner messages). This is defence-in-depth: the frontend also
// sanitises on render, but content must never be *stored* with active markup
// because it is also consumed by non-browser clients (Discord broadcasts,
// future API consumers, emails).
//
// Rumors can be created by any player with an active character, so treat every
// `body` as hostile.

const sanitizeHtml = require('sanitize-html');

const RICH_TEXT_OPTIONS = {
  allowedTags: [
    'p', 'br', 'hr', 'div', 'span', 'blockquote', 'pre', 'code',
    'b', 'strong', 'i', 'em', 'u', 's', 'strike', 'del', 'ins', 'sub', 'sup', 'mark', 'small',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li',
    'a', 'img',
    'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'caption',
    'figure', 'figcaption',
  ],
  allowedAttributes: {
    a: ['href', 'title', 'target', 'rel'],
    img: ['src', 'alt', 'title', 'width', 'height'],
    td: ['colspan', 'rowspan'],
    th: ['colspan', 'rowspan'],
  },
  // No inline styles, classes or ids -> no CSS-based redressing / data exfil.
  allowedSchemes: ['http', 'https', 'mailto', 'tel'],
  allowedSchemesByTag: { img: ['http', 'https'] },
  allowProtocolRelative: false,
  disallowedTagsMode: 'discard',
  transformTags: {
    a: sanitizeHtml.simpleTransform('a', { rel: 'noopener noreferrer nofollow', target: '_blank' }, true),
  },
};

/**
 * Sanitise an untrusted rich-text HTML string before persisting it.
 * @param {unknown} dirty
 * @returns {string}
 */
function sanitizeRichText(dirty) {
  if (dirty === null || dirty === undefined) return '';
  if (typeof dirty !== 'string') return '';
  return sanitizeHtml(dirty, RICH_TEXT_OPTIONS);
}

/**
 * Strip *all* markup, leaving plain text (for titles, subtitles, names...).
 * @param {unknown} dirty
 * @returns {string}
 */
function stripTags(dirty) {
  if (dirty === null || dirty === undefined) return '';
  if (typeof dirty !== 'string') return '';
  return sanitizeHtml(dirty, { allowedTags: [], allowedAttributes: {} });
}

module.exports = { sanitizeRichText, stripTags, RICH_TEXT_OPTIONS };
