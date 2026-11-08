import { describe, it, expect } from 'vitest';
const { htmlToDiscordMarkdown, truncateDiscordMarkdown, wrapWithMarkdown } = require('../utils/discordMarkdown');

describe('Discord Markdown conversion', () => {
  it('converts bold tags to Discord double asterisks', () => {
    expect(htmlToDiscordMarkdown('<b>Hello World</b>')).toBe('**Hello World**');
    expect(htmlToDiscordMarkdown('<strong>Strong Text</strong>')).toBe('**Strong Text**');
  });

  it('converts italic tags to Discord single asterisks', () => {
    expect(htmlToDiscordMarkdown('<i>Italic Text</i>')).toBe('*Italic Text*');
    expect(htmlToDiscordMarkdown('<em>Emphasized Text</em>')).toBe('*Emphasized Text*');
  });

  it('converts strikethrough tags to Discord tildes', () => {
    expect(htmlToDiscordMarkdown('<s>Crossed out text</s>')).toBe('~~Crossed out text~~');
    expect(htmlToDiscordMarkdown('<strike>Strike text</strike>')).toBe('~~Strike text~~');
    expect(htmlToDiscordMarkdown('<del>Deleted text</del>')).toBe('~~Deleted text~~');
  });

  it('converts underline tags to Discord double underscores', () => {
    expect(htmlToDiscordMarkdown('<u>Underlined text</u>')).toBe('__Underlined text__');
    expect(htmlToDiscordMarkdown('<ins>Inserted text</ins>')).toBe('__Inserted text__');
  });

  it('handles nested combinations', () => {
    expect(htmlToDiscordMarkdown('<b><i>Bold and Italic</i></b>')).toBe('***Bold and Italic***');
    expect(htmlToDiscordMarkdown('<b><s>Bold and Strikethrough</s></b>')).toBe('**~~Bold and Strikethrough~~**');
    expect(htmlToDiscordMarkdown('<u><b>Underline Bold</b></u>')).toBe('__**Underline Bold**__');
  });

  it('shifts whitespace outside formatting delimiters for Discord validity', () => {
    expect(wrapWithMarkdown(' hello ', '**')).toBe(' **hello** ');
    expect(htmlToDiscordMarkdown('This is <b> bold </b> and <i> italic </i>')).toBe('This is  **bold**  and  *italic*');
  });

  it('converts blockquotes to Discord quotes', () => {
    const input = '<blockquote>Whispered in shadows</blockquote>';
    expect(htmlToDiscordMarkdown(input)).toBe('> Whispered in shadows');
  });

  it('converts headers to Discord markdown headers', () => {
    expect(htmlToDiscordMarkdown('<h2>Court Decree</h2>')).toBe('## Court Decree');
    expect(htmlToDiscordMarkdown('<h3>Sub Decree</h3>')).toBe('### Sub Decree');
  });

  it('converts unordered lists to Discord bullet points', () => {
    const input = '<ul><li>First whisper</li><li>Second whisper</li></ul>';
    expect(htmlToDiscordMarkdown(input)).toBe('- First whisper\n- Second whisper');
  });

  it('converts links to Discord markdown links', () => {
    const input = '<a href="https://portal.attlarp.gr/rumors">View Rumor</a>';
    expect(htmlToDiscordMarkdown(input)).toBe('[View Rumor](https://portal.attlarp.gr/rumors)');
  });

  it('preserves line breaks and paragraph separation', () => {
    const input = '<p>First paragraph</p><p>Second paragraph</p>';
    expect(htmlToDiscordMarkdown(input)).toBe('First paragraph\n\nSecond paragraph');
  });

  it('handles Greek characters and unicode correctly', () => {
    const greek = '<p>Ήταν δύο παραμυθάδες, ο ένας <b>tremere</b> και ο άλλος <s>ventrue</s>.</p>';
    expect(htmlToDiscordMarkdown(greek)).toBe('Ήταν δύο παραμυθάδες, ο ένας **tremere** και ο άλλος ~~ventrue~~.');
  });
});

describe('truncateDiscordMarkdown', () => {
  it('returns text as-is when under maxLength', () => {
    const text = '**Short text**';
    expect(truncateDiscordMarkdown(text, 100)).toBe('**Short text**');
  });

  it('safely closes unclosed bold delimiter', () => {
    const text = '**Very long bold text that must be cut off cleanly**';
    const truncated = truncateDiscordMarkdown(text, 25);
    expect(truncated).toContain('**...');
    expect((truncated.match(/\*\*/g) || []).length % 2).toBe(0);
  });

  it('safely closes unclosed strikethrough delimiter', () => {
    const text = '~~Very long crossed out text that goes beyond the limit~~';
    const truncated = truncateDiscordMarkdown(text, 25);
    expect(truncated).toContain('~~...');
    expect((truncated.match(/~~/g) || []).length % 2).toBe(0);
  });

  it('safely closes unclosed underline delimiter', () => {
    const text = '__Very long underlined text that goes beyond the limit__';
    const truncated = truncateDiscordMarkdown(text, 25);
    expect(truncated).toContain('__...');
    expect((truncated.match(/__/g) || []).length % 2).toBe(0);
  });
});

