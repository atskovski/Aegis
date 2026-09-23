'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { stripTrackingParams, normalizeInput, isThirdParty, shouldUpgradeHttp } = require('../src/core/url');

test('strips common tracking parameters but preserves ordinary params', () => {
  const out = stripTrackingParams('https://example.com/p?a=1&utm_source=x&fbclid=y');
  assert.equal(out, 'https://example.com/p?a=1');
});

test('normalizes a hostname to https', () => assert.equal(normalizeInput('example.com'), 'https://example.com'));
test('normalizes search terms', () => assert.equal(normalizeInput('private search'), 'https://duckduckgo.com/?q=private%20search'));
test('detects third party domains', () => assert.equal(isThirdParty('https://cdn.tracker.com/x','https://news.example.com/'), true));
test('same-site subdomain is not treated as third party', () => assert.equal(isThirdParty('https://cdn.example.com/x','https://news.example.com/'), false));
test('upgrades ordinary HTTP', () => assert.equal(shouldUpgradeHttp('http://example.com'), true));
test('does not force localhost to HTTPS', () => assert.equal(shouldUpgradeHttp('http://localhost:3000'), false));
