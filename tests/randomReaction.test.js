import { describe, it, expect, vi } from 'vitest';
import {
  parseRandomReactionArgs,
  pickRandomWinners,
  formatRandomReactionResult,
  handleRandomReactionCommand
} from '../discordWorker.js';

describe('Discord &random reaction Command', () => {
  describe('parseRandomReactionArgs', () => {
    it('returns null for non-command content', () => {
      expect(parseRandomReactionArgs('hello world')).toBeNull();
      expect(parseRandomReactionArgs('&roll 5 1')).toBeNull();
      expect(parseRandomReactionArgs('')).toBeNull();
      expect(parseRandomReactionArgs(null)).toBeNull();
    });

    it('parses discord message URL and winner count', () => {
      const url = 'https://discord.com/channels/123456789012345678/234567890123456789/345678901234567890';
      const parsed = parseRandomReactionArgs(`&random reaction ${url} 3`);
      expect(parsed).toEqual({
        isCommand: true,
        channelId: '234567890123456789',
        messageId: '345678901234567890',
        winnerCount: 3
      });
    });

    it('parses discord message URL without count (defaults to 1)', () => {
      const url = 'https://discordapp.com/channels/123456789012345678/234567890123456789/345678901234567890';
      const parsed = parseRandomReactionArgs(`&random reactions ${url}`);
      expect(parsed).toEqual({
        isCommand: true,
        channelId: '234567890123456789',
        messageId: '345678901234567890',
        winnerCount: 1
      });
    });

    it('parses count before message URL', () => {
      const url = 'https://canary.discord.com/channels/123456789012345678/234567890123456789/345678901234567890';
      const parsed = parseRandomReactionArgs(`&random reaction 2 ${url}`);
      expect(parsed).toEqual({
        isCommand: true,
        channelId: '234567890123456789',
        messageId: '345678901234567890',
        winnerCount: 2
      });
    });

    it('parses raw message ID and count', () => {
      const parsed = parseRandomReactionArgs('&random reaction 345678901234567890 5');
      expect(parsed).toEqual({
        isCommand: true,
        channelId: null,
        messageId: '345678901234567890',
        winnerCount: 5
      });
    });

    it('parses raw message ID with count first', () => {
      const parsed = parseRandomReactionArgs('&random reaction 4 345678901234567890');
      expect(parsed).toEqual({
        isCommand: true,
        channelId: null,
        messageId: '345678901234567890',
        winnerCount: 4
      });
    });

    it('parses raw message ID alone and defaults count to 1', () => {
      const parsed = parseRandomReactionArgs('&random reaction 345678901234567890');
      expect(parsed).toEqual({
        isCommand: true,
        channelId: null,
        messageId: '345678901234567890',
        winnerCount: 1
      });
    });

    it('extracts messageId from reply reference if user types only &random reaction 2', () => {
      const reference = { messageId: '987654321098765432', channelId: '111222333444555666' };
      const parsed = parseRandomReactionArgs('&random reaction 2', reference);
      expect(parsed).toEqual({
        isCommand: true,
        channelId: '111222333444555666',
        messageId: '987654321098765432',
        winnerCount: 2
      });
    });

    it('extracts messageId from reply reference with count defaulted to 1 when no arguments given', () => {
      const reference = { messageId: '987654321098765432', channelId: '111222333444555666' };
      const parsed = parseRandomReactionArgs('&random reaction', reference);
      expect(parsed).toEqual({
        isCommand: true,
        channelId: '111222333444555666',
        messageId: '987654321098765432',
        winnerCount: 1
      });
    });

    it('returns missing messageId when neither argument nor reference provides one', () => {
      const parsed = parseRandomReactionArgs('&random reaction');
      expect(parsed).toEqual({
        isCommand: true,
        channelId: null,
        messageId: null,
        winnerCount: 1
      });
    });
  });

  describe('pickRandomWinners', () => {
    it('returns empty array when participants array is empty', () => {
      expect(pickRandomWinners([], 2)).toEqual([]);
      expect(pickRandomWinners(null, 1)).toEqual([]);
    });

    it('picks exactly 1 winner when count is 1', () => {
      const participants = [
        { id: '1', username: 'alpha' },
        { id: '2', username: 'beta' },
        { id: '3', username: 'gamma' }
      ];
      const winners = pickRandomWinners(participants, 1);
      expect(winners).toHaveLength(1);
      expect(participants).toContainEqual(winners[0]);
    });

    it('picks N unique winners without duplicates', () => {
      const participants = [
        { id: '1', username: 'alpha' },
        { id: '2', username: 'beta' },
        { id: '3', username: 'gamma' },
        { id: '4', username: 'delta' }
      ];
      const winners = pickRandomWinners(participants, 3);
      expect(winners).toHaveLength(3);
      const uniqueIds = new Set(winners.map(w => w.id));
      expect(uniqueIds.size).toBe(3);
    });

    it('caps winner count to available participants if requested count is larger', () => {
      const participants = [
        { id: '1', username: 'alpha' },
        { id: '2', username: 'beta' }
      ];
      const winners = pickRandomWinners(participants, 5);
      expect(winners).toHaveLength(2);
      expect(new Set(winners.map(w => w.id)).size).toBe(2);
    });
  });

  describe('formatRandomReactionResult', () => {
    it('formats single winner message correctly without hyphens or em-dashes', () => {
      const winners = [{ id: '1001', username: 'alice' }];
      const participants = [
        { id: '1001', username: 'alice' },
        { id: '1002', username: 'bob' }
      ];

      const text = formatRandomReactionResult(winners, participants);

      expect(text).toContain('🎉 We have a winner! 🎉');
      expect(text).toContain('Congratulations! The winner of this random draw is:');
      expect(text).toContain('1: <@1001>');
      expect(text).toContain('Participants (2):');
      expect(text).toContain('1: alice');
      expect(text).toContain('2: bob');
      expect(text).not.toContain('<@1002>'); // bob must not be tagged
      expect(text).not.toMatch(/[-—]/); // strictly no hyphens or em-dashes
    });

    it('formats multiple winners message correctly without hyphens or em-dashes', () => {
      const winners = [
        { id: '1001', username: 'alice' },
        { id: '1002', username: 'bob' }
      ];
      const participants = [
        { id: '1001', username: 'alice' },
        { id: '1002', username: 'bob' },
        { id: '1003', username: 'charlie' }
      ];

      const text = formatRandomReactionResult(winners, participants);

      expect(text).toContain('🎉 We have winners! 🎉');
      expect(text).toContain('Congratulations! The winners of this random draw are:');
      expect(text).toContain('1: <@1001>');
      expect(text).toContain('2: <@1002>');
      expect(text).toContain('Participants (3):');
      expect(text).toContain('1: alice');
      expect(text).toContain('2: bob');
      expect(text).toContain('3: charlie');
      expect(text).not.toContain('<@1003>'); // charlie must not be tagged
      expect(text).not.toMatch(/[-—]/); // strictly no hyphens or em-dashes
    });

    it('uses guild member displayName or user displayName when available', () => {
      const winners = [{ id: '1001', username: 'alice_user', displayName: 'Alice Global' }];
      const participants = [
        { id: '1001', username: 'alice_user', displayName: 'Alice Global' },
        { id: '1002', username: 'bob_user' }
      ];
      const mockGuild = {
        members: {
          cache: new Map([
            ['1001', { displayName: 'Ventrue Primogen Alice' }]
          ])
        }
      };

      const text = formatRandomReactionResult(winners, participants, mockGuild);
      expect(text).toContain('1: Ventrue Primogen Alice');
      expect(text).toContain('2: bob_user');
      expect(text).not.toMatch(/[-—]/);
    });
  });

  describe('handleRandomReactionCommand', () => {
    it('replies with instructions when messageId cannot be found', async () => {
      let replyCalledWith = null;
      const mockMessage = {
        content: '&random reaction',
        author: { id: 'user_requester' },
        reference: null,
        channel: {
          id: 'chan_1',
          sendTyping: vi.fn().mockResolvedValue(true)
        },
        reply: vi.fn().mockImplementation(async (payload) => {
          replyCalledWith = payload;
          return payload;
        })
      };

      const handled = await handleRandomReactionCommand(mockMessage, {}, { delayMs: 0 });
      expect(handled).toBe(true);
      expect(replyCalledWith.content).toContain('Please specify a Discord message link or message ID');
      expect(replyCalledWith.content).not.toMatch(/[-—]/);
    });

    it('sends two messages: first drawing announcement, then winners announcement with emojis', async () => {
      let replyCalledWith = null;
      let channelSendCalledWith = null;

      const user1 = { id: 'user_1', username: 'Alice', bot: false };
      const user2 = { id: 'user_2', username: 'Bob', bot: false };
      const botUser = { id: 'bot_99', username: 'HelperBot', bot: true };

      const reactionA = {
        users: {
          fetch: vi.fn().mockResolvedValue(new Map([
            ['user_1', user1],
            ['bot_99', botUser]
          ]))
        }
      };
      const reactionB = {
        users: {
          fetch: vi.fn().mockResolvedValue(new Map([
            ['user_1', user1],
            ['user_2', user2]
          ]))
        }
      };

      const mockTargetMessage = {
        id: 'msg_target_123',
        reactions: {
          cache: new Map([
            ['thumb', reactionA],
            ['heart', reactionB]
          ])
        },
        guild: {
          members: {
            cache: new Map()
          }
        }
      };

      const mockMessage = {
        content: '&random reaction msg_target_123 2',
        author: { id: 'requester_42' },
        reference: null,
        channel: {
          id: 'chan_main',
          sendTyping: vi.fn().mockResolvedValue(true),
          messages: {
            fetch: vi.fn().mockResolvedValue(mockTargetMessage)
          },
          send: vi.fn().mockImplementation(async (payload) => {
            channelSendCalledWith = payload;
            return payload;
          })
        },
        reply: vi.fn().mockImplementation(async (payload) => {
          replyCalledWith = payload;
          return payload;
        })
      };

      const handled = await handleRandomReactionCommand(mockMessage, {}, { delayMs: 0 });
      expect(handled).toBe(true);

      // Message 1 (reply to requester):
      expect(mockMessage.reply).toHaveBeenCalled();
      expect(replyCalledWith.content).toContain('A random draw has been requested by <@requester_42>. Drawing now...');
      expect(replyCalledWith.content).not.toMatch(/[-—]/);

      // Message 2 (channel announcement):
      expect(mockMessage.channel.send).toHaveBeenCalled();
      expect(channelSendCalledWith.content).toContain('🎉 We have winners! 🎉');
      expect(channelSendCalledWith.content).toContain('Participants (2):');
      expect(channelSendCalledWith.content).toContain('1: <@');
      expect(channelSendCalledWith.content).toContain('2: <@');
      expect(channelSendCalledWith.allowedMentions.users).toHaveLength(2);
      expect(channelSendCalledWith.allowedMentions.parse).toBeUndefined();
      expect(channelSendCalledWith.content).not.toMatch(/[-—]/);
    });

    it('falls back to channel.send if message.reply throws', async () => {
      let channelSendCalledWith = null;

      const user1 = { id: 'user_1', username: 'Alice', bot: false };
      const reactionA = {
        users: {
          fetch: vi.fn().mockResolvedValue(new Map([['user_1', user1]]))
        }
      };

      const mockTargetMessage = {
        id: 'msg_target_456',
        reactions: {
          cache: new Map([['thumb', reactionA]])
        },
        guild: null
      };

      const mockMessage = {
        content: '&random reaction msg_target_456 1',
        reference: null,
        channel: {
          id: 'chan_main',
          sendTyping: vi.fn().mockResolvedValue(true),
          messages: {
            fetch: vi.fn().mockResolvedValue(mockTargetMessage)
          },
          send: vi.fn().mockImplementation(async (payload) => {
            channelSendCalledWith = payload;
            return payload;
          })
        },
        reply: vi.fn().mockRejectedValue(new Error('DiscordAPIError: Invalid Form Body'))
      };

      const handled = await handleRandomReactionCommand(mockMessage, {}, { delayMs: 0 });
      expect(handled).toBe(true);
      expect(mockMessage.reply).toHaveBeenCalled();
      expect(mockMessage.channel.send).toHaveBeenCalled();
      expect(channelSendCalledWith.content).toContain('Congratulations! The winner of this random draw is:');
      expect(channelSendCalledWith.content).toContain('1: <@user_1>');
    });

    it('handles message with no reactions gracefully', async () => {
      let replyCalledWith = null;
      const mockTargetMessage = {
        id: 'msg_target_empty',
        reactions: {
          cache: new Map()
        }
      };

      const mockMessage = {
        content: '&random reaction msg_target_empty 1',
        reference: null,
        channel: {
          id: 'chan_main',
          sendTyping: vi.fn().mockResolvedValue(true),
          messages: {
            fetch: vi.fn().mockResolvedValue(mockTargetMessage)
          }
        },
        reply: vi.fn().mockImplementation(async (payload) => {
          replyCalledWith = payload;
          return payload;
        })
      };

      const handled = await handleRandomReactionCommand(mockMessage, {}, { delayMs: 0 });
      expect(handled).toBe(true);
      expect(replyCalledWith.content).toBe('No reactions found on that message.');
      expect(replyCalledWith.content).not.toMatch(/[-—]/);
    });

    it('catches critical unexpected exceptions and notifies channel without hanging', async () => {
      let replyCalledWith = null;
      const mockMessage = {
        content: '&random reaction 123456789012345678 1',
        reference: null,
        channel: {
          id: 'chan_main',
          sendTyping: vi.fn().mockResolvedValue(true),
          messages: {
            fetch: vi.fn().mockRejectedValue(new Error('Discord network timeout'))
          }
        },
        reply: vi.fn().mockImplementation(async (payload) => {
          replyCalledWith = payload;
          return payload;
        })
      };

      // Force an unexpected error inside channel fetch to trigger outer catch
      const badClient = {
        channels: {
          fetch: vi.fn().mockRejectedValue(new Error('Gateway fatal socket drop'))
        }
      };

      const handled = await handleRandomReactionCommand(mockMessage, badClient, { delayMs: 0 });
      expect(handled).toBe(true);
      expect(replyCalledWith.content).toContain('Could not find that message');
      expect(replyCalledWith.content).not.toMatch(/[-—]/);
    });
  });
});
