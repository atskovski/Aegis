'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'main.js'), 'utf8');
const network = fs.readFileSync(path.join(__dirname, '..', 'src', 'core', 'network.js'), 'utf8');

test('JavaScript policy uses supported WebPreferences API', () => {
  assert.equal(source.includes('setJavaScriptEnabled'), false, 'unsupported webContents.setJavaScriptEnabled must not be used');
  assert.match(source, /javascript:\s*Boolean\(tab\.javascriptEnabled\)/);
});

test('live JavaScript toggle rebuilds only the tab renderer', () => {
  assert.match(source, /async function replaceTabView\(tab, javascriptEnabled\)/);
  assert.match(source, /session:\s*tab\.privateSession/);
  assert.match(source, /replaceTabView\(tab, Boolean\(enabled\)\)/);
});


test('Electron 44 navigation events use the version-safe details adapter', () => {
  assert.match(source, /navigationUrl\(event, legacyDetails\)/);
  assert.doesNotMatch(source, /on\('will-navigate', \(event, url\)/);
  assert.doesNotMatch(source, /on\('will-redirect', \(event, url\)/);
});

test('network routing supports macOS system proxy mode', () => {
  assert.match(network, /setProxy\(\{ mode: 'system' \}\)/);
  assert.match(network, /resolveProxy\(target\)/);
  assert.match(network, /resolveHost\(host\)/);
  assert.match(network, /ses\.fetch\(target/);
});
