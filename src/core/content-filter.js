'use strict';

const GENERIC_COSMETIC_SELECTORS = Object.freeze([
  '.ad', '.ads', '.advert', '.advertisement', '.advertising', '.ad-banner', '.ad_banner', '.ad-container', '.ad_container',
  '.ad-slot', '.ad_slot', '.ad-wrapper', '.ad_wrapper', '.adunit', '.ad-unit', '.adsbygoogle', '.banner-ad', '.display-ad', '.video-ad', '.native-ad', '.sticky-ad', '.interstitial-ad', '.ad-overlay', '.ad-placeholder', '.sponsored-ad', '.sponsored_ad', '.sponsored-content', '.video_ad', '.native_ad',
  '#ad', '#ads', '#advert', '#advertisement', '#ad-container', '#ad_container',
  '[id^="ad_"]', '[id^="ads_"]', '[id^="google_ads_"]', '[id*="-ad-slot"]', '[class~="ad-slot"]', '[class~="ad-container"]', '[class~="ad-wrapper"]',
  '[data-ad]', '[data-ad-slot]', '[data-ad-unit]', '[data-ad-client]', '[data-ad-format]', '[aria-label="Advertisement"]', '[aria-label="Sponsored"]', 'iframe[src*="doubleclick.net"]',
  'iframe[src*="googlesyndication.com"]', 'iframe[src*="googleadservices.com"]', 'iframe[src*="adnxs.com"]',
  'iframe[src*="taboola.com"]', 'iframe[src*="outbrain.com"]', 'iframe[src*="amazon-adsystem.com"]'
]);

const FIRST_PARTY_ANALYTICS_PATHS = Object.freeze([
  /\/(?:matomo|piwik)(?:\.min)?\.js(?:$|\?)/i,
  /\/(?:analytics|tracking|tracker|telemetry|beacon)(?:\.min)?\.js(?:$|\?)/i,
  /\/(?:collect|beacon|pixel|track|tracking)(?:\/|\?|$)/i
]);

const SCRIPT_TRACKER_HOSTS = Object.freeze([
  'imasdk.googleapis.com', 'c.amazon-adsystem.com', 'securepubads.g.doubleclick.net',
  'pagead2.googlesyndication.com', 'googleads.g.doubleclick.net', 'googletagmanager.com', 'google-analytics.com',
  'connect.facebook.net', 'facebook.com', 'static.hotjar.com', 'hotjar.com', 'www.clarity.ms', 'clarity.ms',
  'cdn.taboola.com', 'taboola.com', 'widgets.outbrain.com', 'outbrain.com', 'analytics.tiktok.com', 'ads-twitter.com',
  's.pinimg.com', 'redditstatic.com', 'adnxs.com', 'adsrvr.org', 'criteo.com', 'criteo.net'
]);

function hostMatches(host, ruleHost) { return host === ruleHost || host.endsWith(`.${ruleHost}`); }
function isKnownScriptTrackerUrl(raw) {
  try { const u = new URL(raw); return SCRIPT_TRACKER_HOSTS.some((host) => hostMatches(u.hostname.toLowerCase(), host)); } catch { return false; }
}
function looksFirstPartyAnalytics(raw, resourceType = '') {
  if (!['script','xhr','fetch','ping','image','other'].includes(String(resourceType || ''))) return false;
  try { const u = new URL(raw); return FIRST_PARTY_ANALYTICS_PATHS.some((rx) => rx.test(`${u.pathname}${u.search}`)); } catch { return false; }
}
function safeSelectorList(extra = []) {
  const selectors = [...GENERIC_COSMETIC_SELECTORS, ...(Array.isArray(extra) ? extra : [])]
    .filter((x) => typeof x === 'string').map((x) => x.trim()).filter((x) => x && x.length <= 260 && !/[{}]/.test(x));
  return [...new Set(selectors)].slice(0, 2500);
}
function cosmeticCss(extra = []) {
  const selectors = safeSelectorList(extra);
  if (!selectors.length) return '';
  return `${selectors.join(',\n')}{display:none!important;visibility:hidden!important;min-height:0!important;max-height:0!important;}`;
}

function buildPagePrivacyScript({ maximum = false, privacyApiGuard = true, blockTrackingBeacons = true, globalPrivacyControl = true } = {}) {
  return `(() => {
    'use strict';
    const MAXIMUM = ${maximum ? 'true' : 'false'};
    const API_GUARD = ${privacyApiGuard ? 'true' : 'false'};
    const BEACON_GUARD = ${blockTrackingBeacons ? 'true' : 'false'};
    const GPC = ${globalPrivacyControl ? 'true' : 'false'};
    const undef = (obj, key) => {
      try { Object.defineProperty(obj, key, { configurable:true, enumerable:false, value:undefined, writable:false }); return; } catch {}
      try { obj[key] = undefined; } catch {}
    };
    const trackerUrl = (raw) => {
      try {
        const u = new URL(String(raw || ''), location.href);
        const h = u.hostname.toLowerCase();
        return /(^|\\.)(doubleclick\\.net|googlesyndication\\.com|google-analytics\\.com|googletagmanager\\.com|clarity\\.ms|hotjar\\.com|facebook\\.com|connect\\.facebook\\.net|ads-twitter\\.com|amazon-adsystem\\.com|adnxs\\.com|taboola\\.com|outbrain\\.com)$/.test(h) || /\\/(collect|beacon|pixel|track|tracking)(\\/|\\?|$)/i.test(u.pathname + u.search);
      } catch { return false; }
    };

    try { Object.defineProperty(Navigator.prototype, 'globalPrivacyControl', { configurable:true, get:() => GPC }); } catch {}

    if (API_GUARD) {
      try {
        const n = Navigator.prototype;
        for (const key of ['bluetooth','usb','serial','hid','joinAdInterestGroup','leaveAdInterestGroup','runAdAuction','clearOriginJoinedAdInterestGroups']) undef(n, key);
      } catch {}
      try {
        const d = Document.prototype;
        for (const key of ['browsingTopics','joinAdInterestGroup','leaveAdInterestGroup','runAdAuction','hasPrivateToken','issuePrivateToken']) undef(d, key);
        const nativeRequestStorageAccess = d.requestStorageAccess;
        if (typeof nativeRequestStorageAccess === 'function') Object.defineProperty(d, 'requestStorageAccess', { configurable:true, value:function(...args) {
          try { if (window.top !== window) return Promise.reject(new DOMException('Third-party storage access blocked by Aegis', 'NotAllowedError')); } catch {}
          return nativeRequestStorageAccess.apply(this, args);
        }});
      } catch {}
      try { undef(globalThis, 'queryLocalFonts'); } catch {}
    }

    if (BEACON_GUARD) {
      try {
        if (typeof Navigator.prototype.sendBeacon === 'function') {
          const nativeBeacon = Navigator.prototype.sendBeacon;
          Navigator.prototype.sendBeacon = function(url, data) { if (trackerUrl(url)) return true; return nativeBeacon.call(this, url, data); };
        }
      } catch {}
      try {
        const nativeSet = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function(name, value) {
          if (this instanceof HTMLAnchorElement && String(name).toLowerCase() === 'ping') return nativeSet.call(this, name, '');
          return nativeSet.call(this, name, value);
        };
        Object.defineProperty(HTMLAnchorElement.prototype, 'ping', { configurable:true, get(){return '';}, set(){return '';} });
      } catch {}
    }

    if (MAXIMUM) {
      try { undef(globalThis, 'OfflineAudioContext'); undef(globalThis, 'webkitOfflineAudioContext'); } catch {}
      try {
        const nativeEval = globalThis.eval;
        globalThis.eval = function(code) {
          if (typeof code === 'string') throw new EvalError('Dynamic eval blocked by Aegis Maximum protection');
          return nativeEval(code);
        };
      } catch {}
    }
  })();`;
}

module.exports = {
  GENERIC_COSMETIC_SELECTORS, isKnownScriptTrackerUrl, looksFirstPartyAnalytics,
  safeSelectorList, cosmeticCss, buildPagePrivacyScript
};
