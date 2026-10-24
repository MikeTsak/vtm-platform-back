import { describe, it, expect } from 'vitest';
import { handleMemeReply, resolveMemeImages } from '../discordWorker.js';

describe('Discord Meme Reply and Image Resolution', () => {
  describe('handleMemeReply', () => {
    it('bypasses meme reply interceptor when user issues &meme command', async () => {
      const mockRefMsg = {
        id: 'ref-msg-1',
        author: { id: 'bot-123' },
        content: '🎨 Meme created by: <@user_alice>'
      };

      const mockMessage = {
        content: '&meme When the ST smiles',
        author: { id: 'user_bob' },
        reference: { messageId: 'ref-msg-1' },
        channel: {
          messages: {
            cache: new Map([['ref-msg-1', mockRefMsg]])
          }
        }
      };

      const client = { user: { id: 'bot-123' } };

      const handled = await handleMemeReply(mockMessage, client);
      expect(handled).toBe(false);
    });

    it('bypasses meme reply interceptor for case-insensitive &MEME command with leading whitespace', async () => {
      const mockRefMsg = {
        id: 'ref-msg-2',
        author: { id: 'bot-123' },
        content: '🎨 Meme created by: <@user_alice>'
      };

      const mockMessage = {
        content: '   &MEME Another caption',
        author: { id: 'user_bob' },
        reference: { messageId: 'ref-msg-2' },
        channel: {
          messages: {
            cache: new Map([['ref-msg-2', mockRefMsg]])
          }
        }
      };

      const client = { user: { id: 'bot-123' } };

      const handled = await handleMemeReply(mockMessage, client);
      expect(handled).toBe(false);
    });

    it('intercepts normal conversational replies to bot memes and notifies creator', async () => {
      let replyPayload = null;
      const mockRefMsg = {
        id: 'ref-msg-3',
        author: { id: 'bot-123' },
        content: '🎨 Meme created by: <@user_alice>'
      };

      const mockMessage = {
        content: 'hahaha so accurate',
        author: { id: 'user_bob' },
        reference: { messageId: 'ref-msg-3' },
        channel: {
          messages: {
            cache: new Map([['ref-msg-3', mockRefMsg]])
          }
        },
        reply: async (payload) => {
          replyPayload = payload;
          return { id: 'reply-notif-1' };
        }
      };

      const client = { user: { id: 'bot-123' } };

      const handled = await handleMemeReply(mockMessage, client);
      expect(handled).toBe(true);
      expect(replyPayload).toBeDefined();
      expect(replyPayload.content).toBe('<@user_alice>, you have a new reply to your meme!');
    });

    it('returns false when message is not a reply', async () => {
      const mockMessage = {
        content: '&meme Standalone message',
        author: { id: 'user_bob' },
        reference: null
      };

      const handled = await handleMemeReply(mockMessage, { user: { id: 'bot-123' } });
      expect(handled).toBe(false);
    });
  });

  describe('resolveMemeImages', () => {
    it('uses direct attachments when present on the command message', async () => {
      const mockMessage = {
        attachments: new Map([
          ['att-1', { url: 'https://cdn.example.com/cat.jpg', name: 'cat.jpg', contentType: 'image/jpeg' }]
        ]),
        reference: null
      };

      const { imageTargets, referencedMessage } = await resolveMemeImages(mockMessage);
      expect(referencedMessage).toBeNull();
      expect(imageTargets).toHaveLength(1);
      expect(imageTargets[0].url).toBe('https://cdn.example.com/cat.jpg');
    });

    it('falls back to referenced message attachments when command message has none', async () => {
      const mockRefMsg = {
        id: 'ref-msg-10',
        attachments: new Map([
          ['att-ref-1', { url: 'https://cdn.example.com/dog.png', name: 'dog.png', contentType: 'image/png' }]
        ])
      };

      const mockMessage = {
        attachments: new Map(),
        reference: { messageId: 'ref-msg-10' },
        channel: {
          messages: {
            cache: new Map([['ref-msg-10', mockRefMsg]])
          }
        }
      };

      const { imageTargets, referencedMessage } = await resolveMemeImages(mockMessage);
      expect(referencedMessage).toBe(mockRefMsg);
      expect(imageTargets).toHaveLength(1);
      expect(imageTargets[0].url).toBe('https://cdn.example.com/dog.png');
    });

    it('extracts image from referenced message embeds (Tenor or embedded image)', async () => {
      const mockRefMsg = {
        id: 'ref-msg-20',
        attachments: new Map(),
        embeds: [
          {
            image: { url: 'https://media.tenor.com/sample_image.gif' }
          }
        ]
      };

      const mockMessage = {
        attachments: new Map(),
        reference: { messageId: 'ref-msg-20' },
        channel: {
          messages: {
            cache: new Map([['ref-msg-20', mockRefMsg]])
          }
        }
      };

      const { imageTargets, referencedMessage } = await resolveMemeImages(mockMessage);
      expect(referencedMessage).toBe(mockRefMsg);
      expect(imageTargets).toHaveLength(1);
      expect(imageTargets[0].url).toBe('https://media.tenor.com/sample_image.gif');
      expect(imageTargets[0].contentType).toBe('image/gif');
    });

    it('extracts image from referenced message direct text URLs', async () => {
      const mockRefMsg = {
        id: 'ref-msg-30',
        attachments: new Map(),
        embeds: [],
        content: 'Check out this meme template: https://i.imgur.com/example.webp'
      };

      const mockMessage = {
        attachments: new Map(),
        reference: { messageId: 'ref-msg-30' },
        channel: {
          messages: {
            cache: new Map([['ref-msg-30', mockRefMsg]])
          }
        }
      };

      const { imageTargets, referencedMessage } = await resolveMemeImages(mockMessage);
      expect(referencedMessage).toBe(mockRefMsg);
      expect(imageTargets).toHaveLength(1);
      expect(imageTargets[0].url).toBe('https://i.imgur.com/example.webp');
      expect(imageTargets[0].contentType).toBe('image/webp');
    });

    it('returns empty array when neither message nor referenced message contains an image', async () => {
      const mockRefMsg = {
        id: 'ref-msg-40',
        attachments: new Map(),
        embeds: [],
        content: 'Just plain text with no image'
      };

      const mockMessage = {
        attachments: new Map(),
        reference: { messageId: 'ref-msg-40' },
        channel: {
          messages: {
            cache: new Map([['ref-msg-40', mockRefMsg]])
          }
        }
      };

      const { imageTargets, referencedMessage } = await resolveMemeImages(mockMessage);
      expect(referencedMessage).toBe(mockRefMsg);
      expect(imageTargets).toHaveLength(0);
    });

    it('fetches referenced message via channel.messages.fetch if not in cache', async () => {
      const mockRefMsg = {
        id: 'ref-msg-fetch',
        attachments: new Map([
          ['att-fetched', { url: 'https://cdn.example.com/fetched.gif', name: 'fetched.gif', contentType: 'image/gif' }]
        ])
      };

      let fetchedId = null;
      const mockMessage = {
        attachments: new Map(),
        reference: { messageId: 'ref-msg-fetch' },
        channel: {
          messages: {
            cache: new Map(),
            fetch: async (id) => {
              fetchedId = id;
              return mockRefMsg;
            }
          }
        }
      };

      const { imageTargets, referencedMessage } = await resolveMemeImages(mockMessage);
      expect(fetchedId).toBe('ref-msg-fetch');
      expect(referencedMessage).toBe(mockRefMsg);
      expect(imageTargets).toHaveLength(1);
      expect(imageTargets[0].url).toBe('https://cdn.example.com/fetched.gif');
    });
  });

  describe('UI Typography compliance', () => {
    it('ensures bot reply messages contain no hyphens or em-dashes', () => {
      const promptError = '🦇 Provide some text! Example: `&meme When the ST smiles`';
      const noImageError = '🦇 You need to attach an image or reply to a message containing an image to make a meme!';

      expect(promptError).not.toContain('-');
      expect(promptError).not.toContain('—');
      expect(promptError).not.toContain('–');

      expect(noImageError).not.toContain('-');
      expect(noImageError).not.toContain('—');
      expect(noImageError).not.toContain('–');
    });
  });
});
