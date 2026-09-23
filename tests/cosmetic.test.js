'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { SAFE_GENERIC_SELECTORS, AGGRESSIVE_SELECTORS, buildCosmeticCss } = require('../src/core/cosmetic');

test('safe cosmetic rules cover common ad containers without generic content selectors', () => {
  assert.ok(SAFE_GENERIC_SELECTORS.includes('.adsbygoogle'));
  assert.ok(SAFE_GENERIC_SELECTORS.some((x) => x.includes('doubleclick.net')));
  assert.equal(SAFE_GENERIC_SELECTORS.includes('.ad'), false);
});

test('maximum mode adds aggressive cosmetic selectors', () => {
  const safe = buildCosmeticCss({ aggressive: false });
  const max = buildCosmeticCss({ aggressive: true });
  assert.match(safe, /adsbygoogle/);
  assert.doesNotMatch(safe, /\[class~="ad"\]/);
  assert.match(max, /\[class~="ad"\]/);
  assert.ok(AGGRESSIVE_SELECTORS.length > 0);
});
