'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { makeSiteIntelligence, recordSiteSignal, recordNetworkEvent, publicSiteIntelligence, buildSiteAuditScript, resetSiteIntelligence } = require('../src/core/site-intelligence');
const { sanitizeSettings } = require('../src/core/settings');

test('site intelligence records sensitive access locally and summarizes it', () => {
  const tab = { url: 'https://example.com/', siteIntelligence: makeSiteIntelligence('https://example.com/', 'https://example.com') };
  assert.equal(recordSiteSignal(tab, { category: 'geolocation', action: 'requested', source: 'permission' }), true);
  assert.equal(recordSiteSignal(tab, { category: 'geolocation', action: 'blocked', source: 'permission' }), true);
  const out = publicSiteIntelligence(tab);
  assert.equal(out.totals.categories, 1);
  assert.equal(out.totals.blocked, 1);
  assert.equal(out.signals[0].label, 'Location');
  assert.equal(out.signals[0].blocked, 1);
});

test('audit monotonic counts do not double-add repeated reports', () => {
  const tab = { siteIntelligence: makeSiteIntelligence() };
  recordSiteSignal(tab, { category: 'canvas', action: 'observed', source: 'audit', count: 1 });
  recordSiteSignal(tab, { category: 'canvas', action: 'observed', source: 'audit', count: 2 });
  recordSiteSignal(tab, { category: 'canvas', action: 'observed', source: 'audit', count: 5 });
  assert.equal(publicSiteIntelligence(tab).signals[0].attempts, 5);
});

test('site intelligence resets on a new page identity', () => {
  const tab = { siteIntelligence: makeSiteIntelligence() };
  recordSiteSignal(tab, { category: 'cookies', action: 'read', source: 'audit', count: 1 });
  resetSiteIntelligence(tab, 'https://duckduckgo.com/', 'https://duckduckgo.com');
  assert.equal(publicSiteIntelligence(tab).totals.categories, 0);
  assert.equal(tab.siteIntelligence.origin, 'https://duckduckgo.com');
});

test('audit script observes permissions, storage and fingerprint surfaces without Electron access', () => {
  const script = buildSiteAuditScript({ bindingName: '__aegisAudit_test' });
  for (const token of ['getUserMedia', 'getCurrentPosition', 'clipboardRead', 'requestDevice', 'cookie read', 'getImageData', 'webgl', 'highEntropyUA', 'getBattery', 'getGamepads', 'RTCPeerConnection', 'formPayment', 'fileUpload', 'MutationObserver']) {
    assert.match(script, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
  assert.doesNotMatch(script, /require\(|ipcRenderer|electron/i);
});

test('site privacy intelligence is enabled by default and sanitizable', () => {
  assert.equal(sanitizeSettings({}).siteIntelligence, true);
  assert.equal(sanitizeSettings({ siteIntelligence: false }).siteIntelligence, false);
});


test('site intelligence records a hostname-only third-party network ledger', () => {
  const tab = { siteIntelligence: makeSiteIntelligence('https://example.com/', 'https://example.com') };
  recordNetworkEvent(tab, { url: 'https://tracker.example.net/pixel?id=secret', blocked: true, category: 'tracker', resourceType: 'image' });
  recordNetworkEvent(tab, { url: 'https://cdn.example.org/app.js?token=secret', blocked: false, category: 'third-party', resourceType: 'script' });
  const out = publicSiteIntelligence(tab);
  assert.equal(out.network.uniqueThirdParties, 2);
  assert.equal(out.network.blockedUnique, 1);
  assert.equal(out.network.allowedUnique, 1);
  assert.equal(out.network.hosts[0].host, 'tracker.example.net');
  assert.doesNotMatch(JSON.stringify(out.network), /secret|pixel\?|token=/);
});

test('form-intent and expanded identity surfaces are available without reading values', () => {
  const script = buildSiteAuditScript({ bindingName: '__aegisAudit_test' });
  for (const token of ['formEmail','formPassword','formPayment','formAddress','formPhone','fileUpload','networkInfo','timezone','languages','webrtc']) assert.match(script, new RegExp(token));
  assert.doesNotMatch(script, /\.value\b|getAttribute\(['\"]value/);
});
