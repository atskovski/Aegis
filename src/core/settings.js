'use strict';

const SEARCH_ENGINES = Object.freeze({
  duckduckgo: { name: 'DuckDuckGo', template: 'https://duckduckgo.com/?q=%s' },
  brave: { name: 'Brave Search', template: 'https://search.brave.com/search?q=%s' },
  startpage: { name: 'Startpage', template: 'https://www.startpage.com/sp/search?query=%s' },
  mojeek: { name: 'Mojeek', template: 'https://www.mojeek.com/search?q=%s' },
  custom: { name: 'Custom', template: '' }
});

const DEFAULT_SETTINGS = Object.freeze({
  schemaVersion: 8,
  privacyLevel: 'strict',
  homePage: 'https://duckduckgo.com/',
  searchEngine: 'duckduckgo',
  customSearchTemplate: '',
  letterbox: true,
  blockTrackers: true,
  blockAds: true,
  blockSocialTrackers: true,
  blockCryptominers: true,
  blockFingerprintingScripts: true,
  cosmeticFiltering: true,
  privacyApiGuard: true,
  blockTrackingBeacons: true,
  bounceTrackingProtection: true,
  bounceTrackingWindowSec: 12,
  heuristicTrackingProtection: true,
  blockThirdPartyCookies: true,
  blockThirdPartyRequests: false,
  blockPrivateNetwork: false,
  blockAllDownloads: false,
  disableWebRtc: false,
  stripTrackingParams: true,
  unwrapTrackingLinks: true,
  stripCrossSiteReferrers: true,
  etagProtection: true,
  publicCdnIsolation: true,
  globalPrivacyControl: true,
  doNotTrack: true,
  disableServiceWorkers: false,
  blockRiskyDownloads: true,
  clearClipboardOnNewIdentity: false,
  javascriptDefault: true,
  compatibilityAssistance: true,
  cookieAutoDelete: true,
  cookieAutoDeleteDelaySec: 10,
  fireproofSites: [],
  customFilterRules: '',
  threatProtection: true,
  siteIntelligence: true,
  sponsorBlock: {
    enabled: false,
    categories: ['sponsor','selfpromo']
  },
  anonymity: {
    torProxy: '127.0.0.1:9050',
    requireTorVerification: true,
    blockPrivateNetwork: true,
    disableDownloads: true,
    disableExtensions: true,
    disableJavaScript: true
  },
  proxy: {
    mode: 'system',
    server: '',
    bypassLocal: true,
    failClosedFixedProxy: true
  },
  permissionDefaults: {
    camera: 'block', microphone: 'block', geolocation: 'block', notifications: 'block', clipboardRead: 'block', displayCapture: 'block', localFonts: 'block', windowManagement: 'block', idleDetection: 'block', usb: 'block', serial: 'block', hid: 'block', midi: 'block'
  },
  sitePermissions: {},
  appearance: {
    theme: 'nebula',
    density: 'comfortable',
    showPrivacyScore: true,
    reduceMotion: false,
    accent: 'cyan',
    textScale: 'large'
  }
});

function cloneDefaults() { return JSON.parse(JSON.stringify(DEFAULT_SETTINGS)); }
function bool(value, fallback) { return typeof value === 'boolean' ? value : fallback; }
function choice(value, allowed, fallback) { return allowed.includes(value) ? value : fallback; }
function clampText(value, max = 240) { return typeof value === 'string' ? value.trim().slice(0, max) : ''; }
function clampNumber(value, min, max, fallback) { const n = Number(value); return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : fallback; }
function listStrings(value, maxItems = 200, maxLen = 220) { return Array.isArray(value) ? [...new Set(value.filter((v) => typeof v === 'string').map((v) => v.trim().slice(0, maxLen)).filter(Boolean))].slice(0, maxItems) : []; }

function sanitizePermissionDefaults(raw) {
  const out = { ...DEFAULT_SETTINGS.permissionDefaults };
  if (!raw || typeof raw !== 'object') return out;
  for (const key of Object.keys(out)) out[key] = choice(raw[key], ['block', 'ask'], out[key]);
  return out;
}
function sanitizeSitePermissionValues(raw) {
  const out = {}; if (!raw || typeof raw !== 'object') return out;
  for (const key of Object.keys(DEFAULT_SETTINGS.permissionDefaults)) if (['allow','block'].includes(raw[key])) out[key] = raw[key];
  return out;
}
function sanitizeSitePermissions(raw) {
  const out = {}; if (!raw || typeof raw !== 'object') return out;
  for (const [origin, values] of Object.entries(raw)) {
    if (typeof origin !== 'string' || origin.length > 300) continue;
    try { const u = new URL(origin); if (!['https:','http:'].includes(u.protocol) || u.origin !== origin) continue; const clean = sanitizeSitePermissionValues(values); if (Object.keys(clean).length) out[origin] = clean; } catch {}
  }
  return out;
}
function sanitizeHomePage(raw) {
  const value = clampText(raw, 500) || DEFAULT_SETTINGS.homePage;
  try { const u = new URL(value); return ['https:','http:','aegis:'].includes(u.protocol) ? u.toString() : DEFAULT_SETTINGS.homePage; } catch { return DEFAULT_SETTINGS.homePage; }
}
function sanitizeSponsor(raw) {
  const allowed = ['sponsor','selfpromo','interaction','intro','outro','preview','music_offtopic'];
  const cats = listStrings(raw?.categories, 8, 40).filter((x) => allowed.includes(x));
  return { enabled: bool(raw?.enabled, DEFAULT_SETTINGS.sponsorBlock.enabled), categories: cats.length ? cats : [...DEFAULT_SETTINGS.sponsorBlock.categories] };
}

function sanitizeAnonymity(raw) {
  const d = DEFAULT_SETTINGS.anonymity;
  const torProxy = clampText(raw?.torProxy, 180) || d.torProxy;
  return {
    torProxy,
    requireTorVerification: bool(raw?.requireTorVerification, d.requireTorVerification),
    blockPrivateNetwork: bool(raw?.blockPrivateNetwork, d.blockPrivateNetwork),
    disableDownloads: bool(raw?.disableDownloads, d.disableDownloads),
    disableExtensions: bool(raw?.disableExtensions, d.disableExtensions),
    disableJavaScript: bool(raw?.disableJavaScript, d.disableJavaScript)
  };
}

function sanitizeSettings(raw = {}) {
  const d = cloneDefaults();
  const migratedLevel = raw.privacyLevel === 'compatible' ? 'standard' : raw.privacyLevel;
  const searchEngine = choice(raw.searchEngine, Object.keys(SEARCH_ENGINES), d.searchEngine);
  const customSearchTemplate = clampText(raw.customSearchTemplate, 500);
  const legacyDefaultDirect = Number(raw.schemaVersion || 0) < 3 && raw.proxy?.mode === 'direct' && !raw.proxy?.server;
  const proxyMode = legacyDefaultDirect ? 'system' : choice(raw.proxy?.mode, ['system','direct','socks5','http','https'], d.proxy.mode);
  const migratedTheme = ['midnight','aurora'].includes(raw.appearance?.theme) ? 'nebula' : raw.appearance?.theme;
  return {
    schemaVersion: 8,
    privacyLevel: choice(migratedLevel, ['standard','strict','maximum'], d.privacyLevel),
    homePage: sanitizeHomePage(raw.homePage),
    searchEngine,
    customSearchTemplate: customSearchTemplate.includes('%s') ? customSearchTemplate : '',
    letterbox: bool(raw.letterbox, d.letterbox),
    blockTrackers: bool(raw.blockTrackers, d.blockTrackers),
    blockAds: bool(raw.blockAds, d.blockAds),
    blockSocialTrackers: bool(raw.blockSocialTrackers, d.blockSocialTrackers),
    blockCryptominers: bool(raw.blockCryptominers, d.blockCryptominers),
    blockFingerprintingScripts: bool(raw.blockFingerprintingScripts, d.blockFingerprintingScripts),
    cosmeticFiltering: bool(raw.cosmeticFiltering, d.cosmeticFiltering),
    privacyApiGuard: bool(raw.privacyApiGuard, d.privacyApiGuard),
    blockTrackingBeacons: bool(raw.blockTrackingBeacons, d.blockTrackingBeacons),
    bounceTrackingProtection: bool(raw.bounceTrackingProtection, d.bounceTrackingProtection),
    bounceTrackingWindowSec: clampNumber(raw.bounceTrackingWindowSec, 3, 60, d.bounceTrackingWindowSec),
    heuristicTrackingProtection: bool(raw.heuristicTrackingProtection, d.heuristicTrackingProtection),
    blockThirdPartyCookies: bool(raw.blockThirdPartyCookies, d.blockThirdPartyCookies),
    blockThirdPartyRequests: bool(raw.blockThirdPartyRequests, d.blockThirdPartyRequests),
    blockPrivateNetwork: bool(raw.blockPrivateNetwork, d.blockPrivateNetwork),
    blockAllDownloads: bool(raw.blockAllDownloads, d.blockAllDownloads),
    disableWebRtc: bool(raw.disableWebRtc, d.disableWebRtc),
    stripTrackingParams: bool(raw.stripTrackingParams, d.stripTrackingParams),
    unwrapTrackingLinks: bool(raw.unwrapTrackingLinks, d.unwrapTrackingLinks),
    stripCrossSiteReferrers: bool(raw.stripCrossSiteReferrers, d.stripCrossSiteReferrers),
    etagProtection: bool(raw.etagProtection, d.etagProtection),
    publicCdnIsolation: bool(raw.publicCdnIsolation, d.publicCdnIsolation),
    globalPrivacyControl: bool(raw.globalPrivacyControl, d.globalPrivacyControl),
    doNotTrack: bool(raw.doNotTrack, d.doNotTrack),
    disableServiceWorkers: bool(raw.disableServiceWorkers, d.disableServiceWorkers),
    blockRiskyDownloads: bool(raw.blockRiskyDownloads, d.blockRiskyDownloads),
    clearClipboardOnNewIdentity: bool(raw.clearClipboardOnNewIdentity, d.clearClipboardOnNewIdentity),
    javascriptDefault: bool(raw.javascriptDefault, d.javascriptDefault),
    compatibilityAssistance: bool(raw.compatibilityAssistance, d.compatibilityAssistance),
    cookieAutoDelete: bool(raw.cookieAutoDelete, d.cookieAutoDelete),
    cookieAutoDeleteDelaySec: clampNumber(raw.cookieAutoDeleteDelaySec, 0, 120, d.cookieAutoDeleteDelaySec),
    fireproofSites: listStrings(raw.fireproofSites, 200, 220),
    customFilterRules: typeof raw.customFilterRules === 'string' ? raw.customFilterRules.slice(0, 100000) : '',
    threatProtection: bool(raw.threatProtection, d.threatProtection),
    siteIntelligence: bool(raw.siteIntelligence, d.siteIntelligence),
    sponsorBlock: sanitizeSponsor(raw.sponsorBlock),
    anonymity: sanitizeAnonymity(raw.anonymity),
    proxy: { mode: proxyMode, server: clampText(raw.proxy?.server, 180), bypassLocal: bool(raw.proxy?.bypassLocal, d.proxy.bypassLocal), failClosedFixedProxy: bool(raw.proxy?.failClosedFixedProxy, d.proxy.failClosedFixedProxy) },
    permissionDefaults: sanitizePermissionDefaults(raw.permissionDefaults),
    sitePermissions: sanitizeSitePermissions(raw.sitePermissions),
    appearance: {
      theme: choice(migratedTheme, ['nebula','graphite','light'], d.appearance.theme),
      density: choice(raw.appearance?.density, ['compact','comfortable'], d.appearance.density),
      showPrivacyScore: bool(raw.appearance?.showPrivacyScore, d.appearance.showPrivacyScore),
      reduceMotion: bool(raw.appearance?.reduceMotion, d.appearance.reduceMotion),
      accent: choice(raw.appearance?.accent, ['cyan','violet','emerald'], d.appearance.accent),
      textScale: choice(raw.appearance?.textScale, ['standard','large','xlarge'], d.appearance.textScale)
    }
  };
}

function searchTemplateFor(settings) { if (settings.searchEngine === 'custom' && settings.customSearchTemplate?.includes('%s')) return settings.customSearchTemplate; return SEARCH_ENGINES[settings.searchEngine]?.template || SEARCH_ENGINES.duckduckgo.template; }
function profileDefaults(level) {
  const base = {
    standard: { privacyLevel:'standard', letterbox:false, blockTrackers:true, blockAds:true, blockSocialTrackers:true, blockThirdPartyCookies:true, stripTrackingParams:true, stripCrossSiteReferrers:true, heuristicTrackingProtection:false, blockFingerprintingScripts:true, cosmeticFiltering:true, privacyApiGuard:false, blockTrackingBeacons:true, disableServiceWorkers:false },
    strict: { privacyLevel:'strict', letterbox:true, blockTrackers:true, blockAds:true, blockSocialTrackers:true, blockThirdPartyCookies:true, stripTrackingParams:true, stripCrossSiteReferrers:true, heuristicTrackingProtection:true, blockFingerprintingScripts:true, cosmeticFiltering:true, privacyApiGuard:true, blockTrackingBeacons:true, disableServiceWorkers:false },
    maximum: { privacyLevel:'maximum', letterbox:true, blockTrackers:true, blockAds:true, blockSocialTrackers:true, blockThirdPartyCookies:true, stripTrackingParams:true, stripCrossSiteReferrers:true, heuristicTrackingProtection:true, blockFingerprintingScripts:true, cosmeticFiltering:true, privacyApiGuard:true, blockTrackingBeacons:true, disableServiceWorkers:true }
  };
  return { ...base[level] };
}
module.exports = { DEFAULT_SETTINGS, SEARCH_ENGINES, sanitizeSettings, searchTemplateFor, profileDefaults, cloneDefaults };
