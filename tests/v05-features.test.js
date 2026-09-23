'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseFilterRules, matchFilterRules } = require('../src/core/filter-rules');
const { TrackerLearner } = require('../src/core/tracker-learning');
const { unwrapTrackingRedirect, cleanNavigationUrl } = require('../src/core/url');
const { analyzeUrl } = require('../src/core/safety');
const { youtubeVideoId } = require('../src/core/sponsor');
const { sanitizeSettings } = require('../src/core/settings');

test('local filter rules support block and allow hostname rules', () => {
  const rules = parseFilterRules('||tracker.example^\n@@||safe.tracker.example^');
  assert.equal(matchFilterRules('https://ads.tracker.example/x.js', rules), 'block');
  assert.equal(matchFilterRules('https://safe.tracker.example/x.js', rules), 'allow');
});

test('behavioral tracker learner requires recurrence across sites', () => {
  const l = new TrackerLearner();
  assert.equal(l.observe('https://metrics.vendor.test/a', 'https://one.example/'), false);
  assert.equal(l.observe('https://metrics.vendor.test/a', 'https://two.example/', { cookie: true }), false);
  l.observe('https://metrics.vendor.test/a', 'https://three.example/', { cookie: true });
  assert.equal(l.isLikelyTracker('metrics.vendor.test'), true);
});

test('tracking redirect unwrapping and parameter cleaning are conservative', () => {
  const wrapped = 'https://www.google.com/url?q=https%3A%2F%2Fexample.com%2Fstory%3Futm_source%3Dx%26id%3D7';
  assert.equal(unwrapTrackingRedirect(wrapped).startsWith('https://example.com/story'), true);
  assert.equal(cleanNavigationUrl(wrapped).includes('utm_source'), false);
  assert.equal(cleanNavigationUrl(wrapped).includes('id=7'), true);
});

test('local safety intelligence flags suspicious destinations', () => {
  assert.ok(analyzeUrl('https://user:pass@paypa1.com:8443/').warnings.length >= 2);
  assert.equal(analyzeUrl('https://duckduckgo.com/').warnings.length, 0);
});

test('SponsorBlock helper recognizes YouTube IDs without network access', () => {
  assert.equal(youtubeVideoId('https://www.youtube.com/watch?v=abcDEF123'), 'abcDEF123');
  assert.equal(youtubeVideoId('https://youtu.be/xyz987'), 'xyz987');
});

test('v0.5 defaults start on DuckDuckGo and enable fail-closed fixed proxy routing', () => {
  const s = sanitizeSettings({});
  assert.equal(s.homePage, 'https://duckduckgo.com/');
  assert.equal(s.proxy.failClosedFixedProxy, true);
  assert.equal(s.cookieAutoDelete, true);
  assert.equal(s.heuristicTrackingProtection, true);
});
