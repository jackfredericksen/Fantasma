#!/usr/bin/env node

/**
 * Generate simple PNG icon placeholders
 * These are minimal valid PNG files with a purple gradient background
 */

const fs = require('fs');
const path = require('path');

const ASSETS_DIR = path.join(__dirname, '..', 'assets');

// Minimal PNG header + IHDR + sRGB + IDAT + IEND
// Creates a simple colored square
function createSimplePng(size) {
  // For simplicity, we'll create a 1x1 pixel PNG with the brand purple color
  // and let the browser scale it
  // In production, use sharp, jimp, or canvas to create proper icons

  // PNG signature
  const signature = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

  // IHDR chunk (13 bytes of data)
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(size, 0);  // width
  ihdrData.writeUInt32BE(size, 4);  // height
  ihdrData.writeUInt8(8, 8);         // bit depth
  ihdrData.writeUInt8(2, 9);         // color type (RGB)
  ihdrData.writeUInt8(0, 10);        // compression
  ihdrData.writeUInt8(0, 11);        // filter
  ihdrData.writeUInt8(0, 12);        // interlace

  const ihdr = createChunk('IHDR', ihdrData);

  // Create image data - simple purple fill
  // Each row has: filter byte (0) + RGB for each pixel
  const rowLength = 1 + size * 3; // filter byte + RGB per pixel
  const rawData = Buffer.alloc(rowLength * size);

  for (let y = 0; y < size; y++) {
    const rowStart = y * rowLength;
    rawData[rowStart] = 0; // filter type: none

    for (let x = 0; x < size; x++) {
      const pixelStart = rowStart + 1 + x * 3;
      // Gradient purple to blue
      const ratio = (x + y) / (2 * size);
      rawData[pixelStart] = Math.round(139 - 80 * ratio);     // R (139 -> 59)
      rawData[pixelStart + 1] = Math.round(92 + 38 * ratio);  // G (92 -> 130)
      rawData[pixelStart + 2] = Math.round(246 - 10 * ratio); // B (246 -> 236)
    }
  }

  // Compress the data using zlib
  const zlib = require('zlib');
  const compressedData = zlib.deflateSync(rawData);

  const idat = createChunk('IDAT', compressedData);

  // IEND chunk (no data)
  const iend = createChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([signature, ihdr, idat, iend]);
}

function createChunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);

  const typeBuffer = Buffer.from(type, 'ascii');
  const crcData = Buffer.concat([typeBuffer, data]);

  // Calculate CRC32
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(crcData), 0);

  return Buffer.concat([length, typeBuffer, data, crc]);
}

// CRC32 implementation
function crc32(buffer) {
  let crc = 0xFFFFFFFF;
  const table = getCrc32Table();

  for (let i = 0; i < buffer.length; i++) {
    crc = (crc >>> 8) ^ table[(crc ^ buffer[i]) & 0xFF];
  }

  return (crc ^ 0xFFFFFFFF) >>> 0;
}

let crc32Table = null;
function getCrc32Table() {
  if (crc32Table) return crc32Table;

  crc32Table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    crc32Table[i] = c;
  }
  return crc32Table;
}

// Generate icons
const sizes = [16, 48, 128];

if (!fs.existsSync(ASSETS_DIR)) {
  fs.mkdirSync(ASSETS_DIR, { recursive: true });
}

sizes.forEach(size => {
  const png = createSimplePng(size);
  const filename = `icon${size}.png`;
  fs.writeFileSync(path.join(ASSETS_DIR, filename), png);
  console.log(`Generated ${filename}`);
});

console.log('\nPNG icons generated successfully!');
