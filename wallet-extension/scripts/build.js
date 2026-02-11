#!/usr/bin/env node

/**
 * Build script for Fantasma Wallet extension
 */

const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.dirname(__dirname);
const DIST_DIR = path.join(ROOT_DIR, 'dist');
const ASSETS_DIR = path.join(ROOT_DIR, 'assets');

/**
 * Generate PNG icon from SVG template
 */
function generateIcons() {
  const sizes = [16, 48, 128];

  // SVG template
  const createSvg = (size) => `<?xml version="1.0" encoding="UTF-8"?>
<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#8b5cf6"/>
      <stop offset="100%" style="stop-color:#3b82f6"/>
    </linearGradient>
  </defs>
  <rect width="${size}" height="${size}" rx="${size * 0.2}" fill="url(#grad)"/>
  <text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle"
        font-family="system-ui, -apple-system, sans-serif"
        font-size="${size * 0.6}" font-weight="700" fill="white">F</text>
</svg>`;

  // Ensure assets directory exists
  if (!fs.existsSync(ASSETS_DIR)) {
    fs.mkdirSync(ASSETS_DIR, { recursive: true });
  }

  // Write SVG files (browsers can use SVG icons)
  sizes.forEach(size => {
    const svg = createSvg(size);
    const filename = `icon${size}.svg`;
    fs.writeFileSync(path.join(ASSETS_DIR, filename), svg);
    console.log(`Generated ${filename}`);
  });

  // Also create PNG placeholders (in production, convert SVG to PNG)
  sizes.forEach(size => {
    const pngPath = path.join(ASSETS_DIR, `icon${size}.png`);
    if (!fs.existsSync(pngPath)) {
      // Create a simple placeholder - in production use canvas or imagemagick
      console.log(`Note: ${pngPath} needs to be generated from SVG`);
    }
  });
}

/**
 * Copy files to dist
 */
function build() {
  console.log('Building Fantasma Wallet extension...\n');

  // Generate icons
  generateIcons();

  // Create dist directory
  if (fs.existsSync(DIST_DIR)) {
    fs.rmSync(DIST_DIR, { recursive: true });
  }
  fs.mkdirSync(DIST_DIR, { recursive: true });

  // Copy manifest
  fs.copyFileSync(
    path.join(ROOT_DIR, 'manifest.json'),
    path.join(DIST_DIR, 'manifest.json')
  );
  console.log('Copied manifest.json');

  // Copy src directory
  copyDir(path.join(ROOT_DIR, 'src'), path.join(DIST_DIR, 'src'));
  console.log('Copied src/');

  // Copy assets
  copyDir(ASSETS_DIR, path.join(DIST_DIR, 'assets'));
  console.log('Copied assets/');

  // Copy locales
  copyDir(path.join(ROOT_DIR, '_locales'), path.join(DIST_DIR, '_locales'));
  console.log('Copied _locales/');

  console.log('\nBuild complete! Extension is in dist/');
  console.log('Load it in Chrome: chrome://extensions -> Load unpacked -> select dist/');
}

/**
 * Recursively copy directory
 */
function copyDir(src, dest) {
  if (!fs.existsSync(src)) return;

  fs.mkdirSync(dest, { recursive: true });

  const entries = fs.readdirSync(src, { withFileTypes: true });

  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

// Run build
build();

// Watch mode
if (process.argv.includes('--watch')) {
  console.log('\nWatching for changes...');

  const chokidar = require('chokidar');

  const watcher = chokidar.watch([
    path.join(ROOT_DIR, 'src'),
    path.join(ROOT_DIR, 'manifest.json'),
    path.join(ROOT_DIR, '_locales')
  ], {
    persistent: true,
    ignoreInitial: true
  });

  watcher.on('change', (filePath) => {
    console.log(`\nFile changed: ${filePath}`);
    build();
  });

  watcher.on('add', (filePath) => {
    console.log(`\nFile added: ${filePath}`);
    build();
  });
}
