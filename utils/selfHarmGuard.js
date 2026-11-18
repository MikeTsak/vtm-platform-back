// utils/selfHarmGuard.js
//
// Deterministic pre-check for self-harm or suicidal ideation in user-facing AI
// prompts so the platform never responds in-character (e.g. sarcastic hacker)
// or ignores crisis signals.

const SELF_HARM_PATTERNS = [
  /\b(kill\s+myself|end\s+my\s+life|take\s+my\s+own\s+life|commit\s+suicide|suicidal|want\s+to\s+die|wanna\s+die|don'?t\s+want\s+to\s+live|hurt\s+myself|self[\s-]*harm|cut\s+myself)\b/i,
  /(αυτοκτον|θέλω\s+να\s+πεθάνω|να\s+πεθάνω|να\s+δώσω\s+τέλος\s+στη\s+ζωή\s+μου|να\s+αυτοτραυματιστ|αυτοτραυματισμ)/i,
];

// Typography rule: no hyphens or em-dashes in user-facing output.
const SELF_HARM_RESPONSE =
  'If you are going through a difficult time or having thoughts of self harm or suicide, please know that support is available right now. ' +
  'In Greece, you can call the Suicide Prevention Helpline at 1018 (available 24/7) or European Emergency Services at 112. ' +
  'In the US or Canada, call or text 988 to reach the Suicide & Crisis Lifeline. ' +
  'If you are elsewhere, please contact your local emergency services or visit findahelpline.com to connect with a free, confidential crisis counselor.';

function detectSelfHarm(text) {
  if (typeof text !== 'string' || !text.trim()) return false;
  return SELF_HARM_PATTERNS.some((re) => re.test(text));
}

module.exports = { detectSelfHarm, SELF_HARM_RESPONSE };
