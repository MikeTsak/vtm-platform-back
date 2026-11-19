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

const cleanEnv = (v) => (v == null ? '' : String(v).trim());

async function sendResetEmailWithEmailJS({
  to,                // recipient email (string)
  name,              // display name (string)
  link,              // absolute reset URL
  appName = 'Erebus Portal',
  expiresMinutes = 1440
}) {
  const serviceId = cleanEnv(process.env.EMAILJS_SERVICE_ID);
  const templateId = cleanEnv(process.env.EMAILJS_TEMPLATE_ID);
  const publicKey = cleanEnv(process.env.EMAILJS_PUBLIC_KEY);
  const privateKey = cleanEnv(process.env.EMAILJS_PRIVATE_KEY);

  // Build exactly what EmailJS expects with comprehensive aliases
  const payload = {
    service_id: serviceId,
    template_id: templateId,
    user_id: publicKey,     // "user_id" = PUBLIC key
    accessToken: privateKey || undefined, // required when EmailJS strict mode is enabled
    template_params: {
      to_email: to,
      email: to,
      user_email: to,
      to: to,
      recipient: to,
      [VAR_TO]: to,

      to_name: name || 'there',
      name: name || 'there',
      user_name: name || 'there',
      [VAR_NAME]: name || 'there',

      app_name: appName,
      [VAR_APP]: appName,

      reset_link: link,
      link: link,
      reset_url: link,
      url: link,
      [VAR_LINK]: link,

      expires_minutes: expiresMinutes,
      expires_hours: Math.round(expiresMinutes / 60) || 24,
      [VAR_EXPIRES]: expiresMinutes,
    },
  };

  // Pre-flight log (no secrets)
  log.mail('EmailJS → sending reset', {
    to: maskEmail(to),
    service_id: serviceId ? 'set' : 'MISSING',
    template_id: templateId ? 'set' : 'MISSING',
    user_id: publicKey ? 'set' : 'MISSING',
    private_key: privateKey ? 'set' : 'MISSING',
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
    const snippet = String(body || '').trim().slice(0, 300);
    log.err('EmailJS ← NON-2XX', {
      status: res.status,
      statusText: res.statusText,
      body: snippet
    });
    throw new Error(`EmailJS responded ${res.status}${res.statusText ? ` ${res.statusText}` : ''}: ${snippet || 'Unknown error'}`);
  }
}

module.exports = { sendResetEmailWithEmailJS, maskEmail };
