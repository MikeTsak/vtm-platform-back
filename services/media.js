// services/media.js
//
// Image plumbing shared by every avatar/upload route: sniffing a buffer's real
// content type, and the client for the external image CDN.

const { VampireImageClient } = require('../utils/mikes-php-image-handler');

// Sniff from magic bytes rather than trusting a client-supplied filename or
// Content-Type. Defaults to webp because that is what the CDN returns for
// anything it has re-encoded.
function getMimeType(buffer) {
  if (!buffer || buffer.length < 4) return 'image/webp';
  if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) return 'image/jpeg';
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) return 'image/png';
  if (buffer.length > 11 && buffer.toString('utf8', 8, 12) === 'WEBP') return 'image/webp';
  return 'image/webp'; // default fallback
}

const imageClient = new VampireImageClient({
  baseUrl: 'https://img.miketsak.gr',
  apiKey: process.env.IMAGE_API_KEY,
});

module.exports = { getMimeType, imageClient };
