'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { CATEGORY_DOMAINS } = require('../src/core/blocklist');
const { cosmeticCss, buildPagePrivacyScript, isKnownScriptTrackerUrl } = require('../src/core/content-filter');
const { DEFAULT_SETTINGS, sanitizeSettings, profileDefaults } = require('../src/core/settings');
const { candidateAddresses, routePrivacyStatus, makeCheck, summarizeChecks } = require('../src/core/security-suite');
const { buildAntiFingerprintScript } = require('../src/core/fingerprint');

const ROOT = path.join(__dirname, '..');

test('Guardian filtering covers benchmark escape families', () => {
  for (const host of ['imasdk.googleapis.com','amazon-adsystem.com','doubleverify.com','analytics.tiktok.com','redditstatic.com']) {
    assert.ok(Object.values(CATEGORY_DOMAINS).flat().includes(host), host);
  }
  assert.equal(isKnownScriptTrackerUrl('https://imasdk.googleapis.com/js/sdkloader/ima3.js'), true);
  assert.equal(isKnownScriptTrackerUrl('https://example.com/app.js'), false);
});

test('Guardian ships a conservative cosmetic filtering layer', () => {
  const css = cosmeticCss();
  for (const token of ['.adsbygoogle', '.video-ad', '.native-ad', '[data-ad-slot]', 'doubleclick.net']) assert.match(css, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(css, /display:\s*none\s*!important/);
});

test('page privacy preload exposes GPC and guards ad/device surfaces', () => {
  const src = buildPagePrivacyScript({ maximum: true, privacyApiGuard: true, blockTrackingBeacons: true });
  for (const token of ['globalPrivacyControl','joinAdInterestGroup','runAdAuction','queryLocalFonts','sendBeacon','requestStorageAccess','OfflineAudioContext']) assert.match(src, new RegExp(token));
  assert.doesNotThrow(() => new Function(src));
});

test('strict fingerprint script normalizes high-entropy surfaces', () => {
  const src = buildAntiFingerprintScript({ seed:'ephemeral-tab-seed', chromiumMajor:'152', profile:'strict', disableServiceWorkers:false });
  for (const token of ['hardwareConcurrency','deviceMemory','globalPrivacyControl','1440','900','webgl_debug_renderer_info','queryLocalFonts']) assert.match(src, new RegExp(token, 'i'));
  assert.doesNotMatch(src, /AegisPrivacyBrowser/);
  assert.doesNotThrow(() => new Function(src));
});

test('hardened defaults enable Guardian controls and larger text', () => {
  assert.equal(DEFAULT_SETTINGS.cosmeticFiltering, true);
  assert.equal(DEFAULT_SETTINGS.privacyApiGuard, true);
  assert.equal(DEFAULT_SETTINGS.blockTrackingBeacons, true);
  assert.equal(DEFAULT_SETTINGS.appearance.textScale, 'large');
  const cleaned = sanitizeSettings({ appearance:{ textScale:'xlarge' } });
  assert.equal(cleaned.appearance.textScale, 'xlarge');
  assert.equal(profileDefaults('maximum').privacyApiGuard, true);
});

test('security suite distinguishes warnings and information from failures', () => {
  assert.equal(routePrivacyStatus('direct').status, 'warning');
  assert.equal(routePrivacyStatus('system').status, 'warning');
  assert.equal(routePrivacyStatus('socks5', { ok:true, fallback:false }).status, 'pass');
  assert.deepEqual(candidateAddresses(['candidate:1 1 udp 123 192.168.1.2 5000 typ host','candidate:2 1 udp 123 abc.local 5001 typ host']), ['192.168.1.2','abc.local']);
  const summary = summarizeChecks([
    makeCheck('a','A','pass','ok'), makeCheck('b','B','warning','caveat'), makeCheck('c','C','info','known limit')
  ]);
  assert.equal(summary.pass, 1); assert.equal(summary.warning, 1); assert.equal(summary.info, 1); assert.equal(summary.fail, 0);
});

test('brand and PRD assets are present', () => {
  for (const rel of ['docs/PRD.md','docs/BRAND.md','assets/brand/aegis-mark.svg','assets/brand/aegis-lockup.svg','src/ui/assets/aegis-mark.svg']) {
    assert.equal(fs.existsSync(path.join(ROOT, rel)), true, rel);
  }
});
