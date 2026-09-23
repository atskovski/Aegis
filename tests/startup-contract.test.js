'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '..', 'src', 'main.js'), 'utf8');
const launcher = fs.readFileSync(path.join(__dirname, '..', 'Run-Aegis.command'), 'utf8');

test('internal aegis protocol is registered for default and private tab sessions', () => {
  assert.match(source, /registerInternalProtocol\(protocol, 'default UI session'\)/);
  assert.match(source, /registerInternalProtocol\(privateSession\.protocol, `private tab \$\{id\}`\)/);
  assert.match(source, /targetProtocol\.isProtocolHandled\('aegis'\)/);
  assert.match(source, /targetProtocol\.handle\('aegis', internalProtocolHandler\)/);
});

test('browser chrome becomes visible before first private tab initialization', () => {
  const showAt = source.indexOf('mainWindow.show();');
  const firstTabAt = source.indexOf("await withTimeout(createTab(smokeUrl, true, Boolean(process.env.AEGIS_SMOKE_TEST_URL))");
  assert.ok(showAt > 0 && firstTabAt > showAt, 'window must be shown before first tab initialization');
});

test('startup has explicit milestones and smoke-test exit', () => {
  assert.match(source, /Browser window opened successfully/);
  assert.match(source, /First private tab initialized/);
  assert.match(source, /AEGIS_SMOKE_TEST/);
  assert.match(source, /AEGIS_SMOKE_TEST_URL/);
  assert.match(source, /External website smoke test passed/);
});

test('launcher pins the official Electron archive and uses layered macOS verification', () => {
  assert.match(launcher, /electron-v\$ELECTRON_VERSION-darwin-\$ELECTRON_ARCH\.zip/);
  assert.match(launcher, /6b728f5dcfae74f3f936f2bca5b3cd9b9659ffea464f67939f004acb55425a85/);
  assert.match(launcher, /015b52631d92187b552ff4e047255f596a7af4707e388a5890951f0b2645764e/);
  assert.match(launcher, /shasum -a 256/);
  assert.match(launcher, /codesign --verify --deep --verbose=2/);
  assert.match(launcher, /codesign --verify --deep --strict --verbose=2/);
  assert.match(launcher, /Proceeding because the engine was freshly extracted from the exact SHA-256-pinned official Electron archive/);
  assert.match(launcher, /extract_verified_engine/);
  assert.match(launcher, /ELECTRON_RUN_AS_NODE=1/);
  assert.match(launcher, /The Terminal window stays open while Aegis is running/);
  assert.match(launcher, /requires macOS 13 Ventura or newer/);
});

test('zoom isolation uses Electron 44 runtime API, not an unsupported WebPreference', () => {
  assert.match(source, /webContents\.setZoomMode\('isolated'\)/);
  assert.doesNotMatch(source, /zoomMode:\s*'isolated'/);
});


test('invalid TLS certificates fail closed without a bypass path', () => {
  assert.match(source, /app\.on\('certificate-error'/);
  assert.match(source, /callback\(false\)/);
  assert.match(source, /preventDefault\(\)/);
});
