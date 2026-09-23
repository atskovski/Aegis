'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseFilterRules } = require('../src/core/filter-rules');
const { cosmeticCss, buildPagePrivacyScript, looksFirstPartyAnalytics, isKnownScriptTrackerUrl } = require('../src/core/content-filter');

test('custom filter rules accept ABP-style cosmetic selectors', () => {
  const rules = parseFilterRules('||tracker.example^\nexample.com##.sponsor\n##.ad-bait\n#@#.ad-bait');
  assert.deepEqual(rules.block, ['tracker.example']);
  assert.deepEqual(rules.cosmetic, ['.sponsor']);
  assert.deepEqual(rules.cosmeticAllow, ['.ad-bait']);
});

test('cosmetic CSS includes built-in ad containers and custom selectors', () => {
  const css = cosmeticCss(['.custom-ad']);
  assert.match(css, /adsbygoogle/);
  assert.match(css, /\.custom-ad/);
  assert.match(css, /display:none!important/);
});

test('content filtering recognizes common ad SDK and first-party analytics paths', () => {
  assert.equal(isKnownScriptTrackerUrl('https://imasdk.googleapis.com/js/sdkloader/ima3.js'), true);
  assert.equal(looksFirstPartyAnalytics('https://example.com/matomo.js', 'script'), true);
  assert.equal(looksFirstPartyAnalytics('https://example.com/app.js', 'script'), false);
});

test('page privacy preload contains privacy API and beacon guards', () => {
  const source = buildPagePrivacyScript({ maximum: true, privacyApiGuard: true, blockTrackingBeacons: true });
  assert.match(source, /joinAdInterestGroup/);
  assert.match(source, /queryLocalFonts/);
  assert.match(source, /sendBeacon/);
  assert.match(source, /Dynamic eval blocked by Aegis Maximum protection/);
});
