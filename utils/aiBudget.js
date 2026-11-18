// utils/aiBudget.js
//
// Shared AI kill switch (app_settings.ai_disabled) and daily/per-minute budget
// cap across Giannakis AI, Rule Master AI, and chat summarization.

const { getSetting } = require('./settings');
const { log } = require('../logger');

const usage = { day: '', dayCount: 0, minuteStart: 0, minuteCount: 0 };

function resetWindowsIfNeeded(now = Date.now()) {
  const day = new Date(now).toISOString().slice(0, 10);
  if (usage.day !== day) {
    usage.day = day;
    usage.dayCount = 0;
  }
  if (now - usage.minuteStart >= 60_000) {
    usage.minuteStart = now;
    usage.minuteCount = 0;
  }
}

function getLimits() {
  return {
    dailyMax: Math.max(1, Number(process.env.AI_DAILY_LIMIT) || 200),
    minuteMax: Math.max(1, Number(process.env.AI_MINUTE_LIMIT) || 12),
  };
}

function getAiBudgetStatus() {
  resetWindowsIfNeeded();
  const { dailyMax, minuteMax } = getLimits();
  return {
    day: usage.day,
    dayCount: usage.dayCount,
    dailyMax,
    minuteCount: usage.minuteCount,
    minuteMax,
  };
}

async function assertAiEnabled() {
  const aiDisabled = await getSetting('ai_disabled', 'false');
  if (aiDisabled === 'true' || aiDisabled === '1') {
    throw new Error('AI_DISABLED');
  }
}

function checkAndRecordAiBudget(source = 'ai') {
  resetWindowsIfNeeded();
  const { dailyMax, minuteMax } = getLimits();
  if (usage.dayCount >= dailyMax || usage.minuteCount >= minuteMax) {
    log.warn('AI budget cap reached', { source, day: usage.day, dayCount: usage.dayCount, dailyMax });
    throw new Error('AI_RATE_LIMIT');
  }
  usage.dayCount += 1;
  usage.minuteCount += 1;
}

module.exports = { assertAiEnabled, checkAndRecordAiBudget, getAiBudgetStatus };
