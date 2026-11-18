// utils/cdnMedia.js
//
// Shared helpers for CDN media validation, extension sniffing, and fallback
// detection when a migrated CDN URL is dead (401/404) or mislabeled (e.g. a
// video uploaded with a .jpg extension).

const MIME_TO_EXT = {
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'image/gif': 'gif',
  'video/mp4': 'mp4',
  'video/quicktime': 'mov',
  'video/webm': 'webm',
  'video/ogg': 'ogv',
  'audio/mpeg': 'mp3',
  'audio/mp3': 'mp3',
  'audio/wav': 'wav',
  'audio/ogg': 'ogg',
  'audio/aac': 'aac',
};

const reachabilityCache = new Map(); // url -> { ok: boolean, expiresAt: number }
const OK_TTL_MS = 10 * 60 * 1000;
const FAIL_TTL_MS = 2 * 60 * 1000;

function hasNonEmptyBlob(data) {
  if (Buffer.isBuffer(data)) return data.length > 0;
  if (typeof data === 'string') return data.length > 0;
  return false;
}

function isMismatchedVideoImageUrl(url, mime) {
  if (!url || !mime) return false;
  const m = String(mime).toLowerCase();
  if (!m.startsWith('video/') && !m.startsWith('audio/')) return false;
  return /\.(jpe?g|png|webp|gif)(\?|$)/i.test(String(url));
}

function sniffExtFromBuffer(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return null;
  if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) return 'jpg';
  if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4e && buffer[3] === 0x47) return 'png';
  if (buffer.toString('ascii', 0, 3) === 'GIF') return 'gif';
  if (buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP') return 'webp';
  if (buffer.toString('ascii', 4, 8) === 'ftyp') {
    const brand = buffer.toString('ascii', 8, 12);
    if (brand === 'qt  ') return 'mov';
    return 'mp4';
  }
  if (buffer[0] === 0x1a && buffer[1] === 0x45 && buffer[2] === 0xdf && buffer[3] === 0xa3) return 'webm';
  if (buffer.toString('ascii', 0, 4) === 'OggS') return 'ogg';
  if (buffer.toString('ascii', 0, 3) === 'ID3' || (buffer[0] === 0xff && (buffer[1] & 0xe0) === 0xe0)) return 'mp3';
  return null;
}

function extFromMimeOrBuffer(buffer, mime, originalName = '') {
  const sniffed = sniffExtFromBuffer(buffer);
  if (sniffed) return sniffed;
  const m = String(mime || '').split(';')[0].trim().toLowerCase();
  if (MIME_TO_EXT[m]) return MIME_TO_EXT[m];
  const rawExt = String(originalName || '').split('.').pop().toLowerCase().replace(/[^a-z0-9]/g, '');
  if (rawExt && rawExt !== String(originalName || '').toLowerCase()) return rawExt;
  return 'bin';
}

async function isCdnUrlReachable(url, mime) {
  if (!url || !/^https?:\/\//i.test(String(url))) return false;
  if (isMismatchedVideoImageUrl(url, mime)) return false;

  const now = Date.now();
  const cached = reachabilityCache.get(url);
  if (cached && cached.expiresAt > now) return cached.ok;

  if (reachabilityCache.size > 1000) {
    for (const [k, v] of reachabilityCache) {
      if (v.expiresAt <= now) reachabilityCache.delete(k);
    }
  }

  let ok = false;
  try {
    const res = await fetch(url, {
      method: 'HEAD',
      redirect: 'manual',
      signal: AbortSignal.timeout(2500),
    });
    ok = res.status >= 200 && res.status < 300;
  } catch {
    ok = false;
  }

  reachabilityCache.set(url, { ok, expiresAt: now + (ok ? OK_TTL_MS : FAIL_TTL_MS) });
  return ok;
}

async function deleteCdnAsset(imageClient, url, log) {
  if (!imageClient || typeof imageClient.deleteImage !== 'function' || !url) return;
  try {
    const parsed = new URL(String(url));
    if (parsed.hostname !== 'img.miketsak.gr' || !parsed.pathname.includes('/uploads/')) return;
    const filename = pathBasename(parsed.pathname);
    if (filename) await imageClient.deleteImage(filename);
  } catch (err) {
    if (log?.warn) log.warn('CDN orphan cleanup failed', { url, error: err.message });
  }
}

function pathBasename(p) {
  const parts = String(p || '').split('/').filter(Boolean);
  return parts.length ? parts[parts.length - 1] : '';
}

module.exports = {
  hasNonEmptyBlob,
  isMismatchedVideoImageUrl,
  extFromMimeOrBuffer,
  isCdnUrlReachable,
  deleteCdnAsset,
};
