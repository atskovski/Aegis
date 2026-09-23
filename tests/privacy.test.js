'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildGenericUA, isRiskyDownload, makeTabStats, permissionKeys, permissionAllowed, permissionDecision } = require('../src/core/privacy');

test('generic UA hides Electron token and uses reduced Chromium version', () => {
  const ua = buildGenericUA('152.0.7977.130');
  assert.match(ua, /Chrome\/152\.0\.0\.0/);
  assert.match(ua, /Macintosh/);
  assert.doesNotMatch(ua, /Electron/);
});

test('flags executable downloads', () => {
  assert.equal(isRiskyDownload('installer.dmg'), true);
  assert.equal(isRiskyDownload('payload.command'), true);
  assert.equal(isRiskyDownload('report.pdf'), false);
});

test('stats start at zero', () => {
  const stats = makeTabStats();
  assert.equal(stats.blockedTrackers, 0);
  assert.equal(stats.thirdPartyCookiesBlocked, 0);
});

test('maps media permissions to camera and microphone', () => {
  assert.deepEqual(permissionKeys('media', { mediaTypes: ['video', 'audio'] }), ['camera', 'microphone']);
  assert.deepEqual(permissionKeys('geolocation'), ['geolocation']);
  assert.deepEqual(permissionKeys('media', { mediaType: 'audio' }), ['microphone']);
});

test('site permission overrides global permission default', () => {
  const settings = {
    permissionDefaults: { camera: 'block' },
    sitePermissions: { 'https://example.com': { camera: 'allow' } }
  };
  assert.equal(permissionAllowed(settings, 'https://example.com', 'camera'), true);
  assert.equal(permissionAllowed(settings, 'https://other.example', 'camera'), false);
});


test('permission decision asks globally and explicit site rules win', () => {
  const settings = {
    permissionDefaults: { camera: 'ask' },
    sitePermissions: { 'https://example.com': { camera: 'allow' } }
  };
  assert.equal(permissionDecision(settings, 'https://elsewhere.test', 'camera'), 'ask');
  assert.equal(permissionDecision(settings, 'https://example.com', 'camera'), 'allow');
});
