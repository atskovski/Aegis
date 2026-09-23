'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { navigationUrl, navigationIsMainFrame, shouldAllowInternalNavigation, failedHttpsCanOfferHttp } = require('../src/core/navigation');

test('Electron 44 navigation details object yields its URL', () => {
  assert.equal(navigationUrl({ url: 'https://example.com/', isMainFrame: true }), 'https://example.com/');
  assert.equal(navigationIsMainFrame({ url: 'https://example.com/', isMainFrame: true }), true);
});

test('legacy Electron navigation URL signature still works', () => {
  assert.equal(navigationUrl({}, 'https://example.com/'), 'https://example.com/');
});

test('remote pages cannot navigate into privileged aegis pages', () => {
  assert.equal(shouldAllowInternalNavigation('https://example.com/', 'aegis://app/start.html'), false);
  assert.equal(shouldAllowInternalNavigation('aegis://app/error.html', 'aegis://app/start.html'), true);
  assert.equal(shouldAllowInternalNavigation('https://example.com/', 'https://openai.com/'), true);
});

test('failed HTTPS connections may offer explicit HTTP recovery for connection errors', () => {
  assert.equal(failedHttpsCanOfferHttp('https://example.com/', -105), true);
  assert.equal(failedHttpsCanOfferHttp('https://example.com/', -3), false);
  assert.equal(failedHttpsCanOfferHttp('http://example.com/', -105), false);
});
