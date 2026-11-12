// utils/dither.js
//
// Thermal printers have no grey: each dot is burned or not. Atkinson
// dithering turns a greyscale image into pure black/white dots that still
// read as shading. It spreads only 6/8 of each pixel's error, so it keeps
// contrast instead of turning photos muddy (thermal heads print dark anyway).

// gray: Uint8Array of width*height values 0..255. Returns a new array of 0/255.
function atkinson(gray, width, height) {
  const px = Float32Array.from(gray);
  const out = new Uint8Array(px.length);
  const spread = [[1, 0], [2, 0], [-1, 1], [0, 1], [1, 1], [0, 2]];
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const i = y * width + x;
      const v = px[i] < 128 ? 0 : 255;
      out[i] = v;
      const err = (px[i] - v) / 8;
      for (const [dx, dy] of spread) {
        const nx = x + dx;
        const ny = y + dy;
        if (nx >= 0 && nx < width && ny < height) px[ny * width + nx] += err;
      }
    }
  }
  return out;
}

module.exports = { atkinson };
