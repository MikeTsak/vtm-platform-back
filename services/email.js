// services/email.js
//
// Outbound transactional mail (password resets) via EmailJS, plus the address
// masking used everywhere an email address would otherwise land in a log line.

const axios = require('axios');
const { log } = require('../logger');

// Optional mapping of template variable names via env
const VAR_TO = process.env.EMAILJS_VAR_TO || 'to_email';
const VAR_NAME = process.env.EMAILJS_VAR_NAME || 'to_name';
const VAR_APP = process.env.EMAILJS_VAR_APP || 'app_name';
const VAR_LINK = process.env.EMAILJS_VAR_LINK || 'reset_link';
const VAR_EXPIRES = process.env.EMAILJS_VAR_EXPIRES || 'expires_minutes';

// Human-friendly masking: keep the first and last character of the local part
// so an address is still recognisable in a log without being readable.
const maskEmail = (email) => {
  if (!email || typeof email !== 'string') return email;
  const [u, d] = email.trim().toLowerCase().split('@');
  if (!d) return email;
  const maskedUser = u.length <= 2 ? (u[0] || '') + '*' : u[0] + '*'.repeat(u.length - 2) + u.slice(-1);
  return `${maskedUser}@${d}`;
};

// EmailJS accepts at most 1 request/second.
let __lastSendAt = 0;
async function _respectEmailJsRateLimit() {
  const now = Date.now();
  const delta = now - __lastSendAt;
  if (delta < 1000) {
    await new Promise(r => setTimeout(r, 1000 - delta));
  }
  __lastSendAt = Date.now();
}

async function sendResetEmailWithEmailJS({
  to,                // recipient email (string)
  name,              // display name (string)
  link,              // absolute reset URL
  appName = 'Erebus Portal',
  expiresMinutes = 24
}) {
  // Build exactly what EmailJS expects
  const payload = {
    service_id: process.env.EMAILJS_SERVICE_ID,
    template_id: process.env.EMAILJS_TEMPLATE_ID,
    user_id: process.env.EMAILJS_PUBLIC_KEY,     // "user_id" = PUBLIC key
    accessToken: process.env.EMAILJS_PRIVATE_KEY || undefined, // optional
    template_params: {
      [VAR_TO]: to,
      [VAR_NAME]: name || 'there',
      [VAR_APP]: appName,
      [VAR_LINK]: link,
      [VAR_EXPIRES]: expiresMinutes,
    },
  };

  // Pre-flight log (no secrets)
  log.mail('EmailJS → sending reset', {
    to: maskEmail(to),
    service_id: process.env.EMAILJS_SERVICE_ID ? 'set' : 'MISSING',
    template_id: process.env.EMAILJS_TEMPLATE_ID ? 'set' : 'MISSING',
    user_id: process.env.EMAILJS_PUBLIC_KEY ? 'set' : 'MISSING',
    // show the exact param keys we send so you can align the template
    vars: Object.keys(payload.template_params)
  });

  // Hard sanity checks (fail fast with meaningful error in logs)
  if (!payload.service_id || !payload.template_id || !payload.user_id) {
    const err = 'EmailJS env vars missing (need EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID, EMAILJS_PUBLIC_KEY).';
    log.err('EmailJS config error', { err });
    throw new Error(err);
  }
  if (!payload.template_params[VAR_TO]) {
    const err = `Missing recipient email for template var ${VAR_TO}. Check your route inputs.`;
    log.err('EmailJS param error', { err });
    throw new Error(err);
  }

  // Respect 1 rps
  await _respectEmailJsRateLimit();

  // Send (per docs)
  const res = await axios.post(
    'https://api.emailjs.com/api/v1.0/email/send',
    payload,
    {
      timeout: 20000,
      headers: { 'Content-Type': 'application/json' },
      validateStatus: () => true, // log non-2xx too
    }
  );

  const body = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
  if (res.status >= 200 && res.status < 300) {
    // EmailJS success format: 200 "OK"
    log.ok('EmailJS ← OK', { status: res.status, body });
  } else {
    // Typical failure: 400 "The parameters are invalid..."
    log.err('EmailJS ← NON-2XX', {
      status: res.status,
      statusText: res.statusText,
      body
    });
    throw new Error(`EmailJS responded ${res.status} ${res.statusText}: ${body}`);
  }
}

module.exports = { sendResetEmailWithEmailJS, maskEmail };
