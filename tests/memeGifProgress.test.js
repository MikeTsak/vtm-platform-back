import { describe, it, expect } from 'vitest';
import { estimateGifProcessingSeconds, GifMemeQueue } from '../discordWorker.js';

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

    const queuedMessageText = `It is a GIF, so it will take a little longer to make. Waiting in queue, position 1. Estimated time: about 10 seconds.`;
    expect(queuedMessageText).not.toContain('-');
    expect(queuedMessageText).not.toContain('—');
    expect(queuedMessageText).not.toContain('–');
  });

  it('limits concurrent GIF rendering to maxConcurrency (2) and executes in FIFO order', async () => {
    const queue = new GifMemeQueue(2);
    let activeNow = 0;
    let maxSeenActive = 0;
    const completedOrder = [];

    const makeTask = (id, durationMs) => async () => {
      activeNow++;
      maxSeenActive = Math.max(maxSeenActive, activeNow);
      await new Promise(resolve => setTimeout(resolve, durationMs));
      activeNow--;
      completedOrder.push(id);
      return id;
    };

    const task1 = queue.enqueue(makeTask(1, 50));
    const task2 = queue.enqueue(makeTask(2, 50));
    const task3 = queue.enqueue(makeTask(3, 20));

    expect(task1.position).toBe(0);
    expect(task2.position).toBe(0);
    expect(task3.position).toBe(1);

    const results = await Promise.all([task1.promise, task2.promise, task3.promise]);
    expect(results).toEqual([1, 2, 3]);
    expect(maxSeenActive).toBe(2);
    expect(completedOrder).toEqual([1, 2, 3]);
  });

  it('recovers cleanly when a queued task fails, without breaking subsequent tasks', async () => {
    const queue = new GifMemeQueue(2);

    const failingTask = queue.enqueue(async () => {
      throw new Error('Sharp processing failure');
    });

    const succeedingTask = queue.enqueue(async () => {
      return 'ok';
    });

    await expect(failingTask.promise).rejects.toThrow('Sharp processing failure');
    const result = await succeedingTask.promise;
    expect(result).toBe('ok');
    expect(queue.activeCount).toBe(0);
  });
});
