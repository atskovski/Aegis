'use strict';

const SAFE_GENERIC_SELECTORS = Object.freeze([
  '.adsbygoogle', '.ad-banner', '.ad_banner', '.ad-slot', '.ad_slot', '.ad-container', '.ad_container',
  '.advertisement', '.advertising', '.sponsored-ad', '.sponsored_ad', '.google-ad', '.google_ad',
  '[data-ad-slot]', '[data-ad-client]', '[data-ad-unit]', '[data-ad-unit-id]', '[aria-label="Advertisement"]',
  'iframe[src*="doubleclick.net"]', 'iframe[src*="googlesyndication.com"]', 'iframe[src*="googleads.g.doubleclick.net"]',
  'iframe[src*="taboola.com"]', 'iframe[src*="outbrain.com"]',
  '[id^="google_ads_"]', '[id^="div-gpt-ad-"]', '[class^="ad-" i][class*="banner" i]', '[class*=" ad-" i][class*="banner" i]'
]);

const AGGRESSIVE_SELECTORS = Object.freeze([
  '[id^="ad_" i]', '[id^="ad-" i]', '[class~="ad"]', '[class*="advert" i]', '[class*="sponsor" i]',
  '[data-testid*="ad" i][role="complementary"]', '[data-ad]', '[data-ads]'
]);

function buildCosmeticCss({ aggressive = false } = {}) {
  const selectors = aggressive ? [...SAFE_GENERIC_SELECTORS, ...AGGRESSIVE_SELECTORS] : [...SAFE_GENERIC_SELECTORS];
  return `${selectors.join(',\n')} { display: none !important; visibility: hidden !important; pointer-events: none !important; }`;
}

module.exports = { SAFE_GENERIC_SELECTORS, AGGRESSIVE_SELECTORS, buildCosmeticCss };
