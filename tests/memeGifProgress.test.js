import { describe, it, expect } from 'vitest';
import { estimateGifProcessingSeconds } from '../discordWorker.js';

describe('Discord Meme GIF handling', () => {
  it('estimates sensible processing times based on frames and dimensions', () => {
    // 1 frame fallback / static gif
    const singleFrame = estimateGifProcessingSeconds(1, 400, 300);
    expect(singleFrame).toBe(3);

    // 25 frames standard resolution
    const smallGif = estimateGifProcessingSeconds(25, 400, 300);
    expect(smallGif).toBeGreaterThanOrEqual(3);
    expect(smallGif).toBeLessThanOrEqual(5);

    // 60 frames medium resolution
    const mediumGif = estimateGifProcessingSeconds(60, 500, 400);
    expect(mediumGif).toBeGreaterThanOrEqual(5);
    expect(mediumGif).toBeLessThanOrEqual(8);

    // 150 frames high resolution
    const largeGif = estimateGifProcessingSeconds(150, 600, 500);
    expect(largeGif).toBeGreaterThanOrEqual(12);
  });

  it('formats progress status message strictly without hyphens or em-dashes', () => {
    const estimatedSeconds = estimateGifProcessingSeconds(45, 480, 360);
    const messageText = `It is a GIF, so it will take a little longer to make. Estimated time: about ${estimatedSeconds} seconds.`;

    expect(messageText).not.toContain('-');
    expect(messageText).not.toContain('—');
    expect(messageText).not.toContain('–');
    expect(messageText).toMatch(/Estimated time: about \d+ seconds\./);
  });
});
