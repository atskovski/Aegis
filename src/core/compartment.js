'use strict';

const net = require('node:net');

const SENSITIVE_PERMISSION_KEYS = Object.freeze([
  'camera','microphone','geolocation','notifications','clipboardRead','displayCapture',
  'localFonts','windowManagement','idleDetection','usb','serial','hid','midi'
]);

function blockedPermissionDefaults(base = {}) {
  const out = { ...base };
  for (const key of SENSITIVE_PERMISSION_KEYS) out[key] = 'block';
  return out;
}

function privateIpv4(ip) {
  const p = String(ip || '').split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  return p[0] === 10 ||
    p[0] === 127 ||
    (p[0] === 169 && p[1] === 254) ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
    (p[0] === 198 && (p[1] === 18 || p[1] === 19)) ||
    p[0] === 0;
}

function privateIpv6(ip) {
  const value = String(ip || '').toLowerCase();
  if (!value.includes(':')) return false;
  if (value === '::' || value === '::1') return true;
  if (/^f[cd][0-9a-f]:/.test(value)) return true; // fc00::/7
  if (/^fe[89ab][0-9a-f]:/.test(value)) return true; // fe80::/10
  if (/^::ffff:/.test(value)) {
    const v4 = value.slice('::ffff:'.length);
    return net.isIP(v4) === 4 && privateIpv4(v4);
  }
  return false;
}

function isPrivateHost(hostname) {
  const host = String(hostname || '').trim().replace(/^\[|\]$/g, '').toLowerCase();
  if (!host) return false;
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true;
  const version = net.isIP(host);
  if (version === 4) return privateIpv4(host);
  if (version === 6) return privateIpv6(host);
  return false;
}

function isPrivateNetworkUrl(raw) {
  try {
    const u = new URL(String(raw || ''));
    return ['http:','https:','ws:','wss:'].includes(u.protocol) && isPrivateHost(u.hostname);
  } catch { return false; }
}

function hardenedOverrides(globalSettings = {}) {
  return {
    privacyLevel: 'maximum',
    letterbox: true,
    blockTrackers: true,
    blockAds: true,
    blockSocialTrackers: true,
    blockCryptominers: true,
    blockFingerprintingScripts: true,
    cosmeticFiltering: true,
    privacyApiGuard: true,
    blockTrackingBeacons: true,
    heuristicTrackingProtection: true,
    blockThirdPartyCookies: true,
    blockThirdPartyRequests: true,
    stripTrackingParams: true,
    unwrapTrackingLinks: true,
    stripCrossSiteReferrers: true,
    etagProtection: true,
    publicCdnIsolation: true,
    globalPrivacyControl: true,
    doNotTrack: true,
    disableServiceWorkers: true,
    threatProtection: true,
    siteIntelligence: true,
    cookieAutoDelete: true,
    blockRiskyDownloads: true,
    blockAllDownloads: false,
    blockPrivateNetwork: false,
    permissionDefaults: blockedPermissionDefaults(globalSettings.permissionDefaults)
  };
}

function anonymousOverrides(globalSettings = {}, torProxy = '127.0.0.1:9050') {
  return {
    ...hardenedOverrides(globalSettings),
    blockAllDownloads: true,
    blockPrivateNetwork: true,
    blockThirdPartyRequests: true,
    disableExtensions: true,
    disableWebRtc: true,
    anonymousRouteRequired: true,
    proxy: {
      mode: 'socks5',
      server: String(torProxy || '127.0.0.1:9050'),
      bypassLocal: false,
      failClosedFixedProxy: true
    },
    sitePermissions: {},
    fireproofSites: []
  };
}

function effectiveSettings(globalSettings = {}, tab = null) {
  const mode = tab?.securityDomain || 'private';
  if (mode === 'anonymous') {
    const o = anonymousOverrides(globalSettings, tab?.torProxy);
    return {
      ...globalSettings,
      ...o,
      proxy: { ...(globalSettings.proxy || {}), ...o.proxy },
      permissionDefaults: o.permissionDefaults,
      sitePermissions: {},
      sponsorBlock: { ...(globalSettings.sponsorBlock || {}), enabled: false }
    };
  }
  if (mode === 'hardened') {
    const o = hardenedOverrides(globalSettings);
    return {
      ...globalSettings,
      ...o,
      permissionDefaults: o.permissionDefaults,
      sponsorBlock: { ...(globalSettings.sponsorBlock || {}), enabled: false }
    };
  }
  return globalSettings;
}

function domainLabel(tab) {
  if (tab?.securityDomain === 'anonymous') return 'Anonymous compartment';
  if (tab?.securityDomain === 'hardened') return 'Hardened compartment';
  return 'Private compartment';
}

function hardenTabState(tab) {
  if (!tab) return false;
  tab.securityDomain = 'hardened';
  tab.hardenedAt = new Date().toISOString();
  tab.shieldsEnabled = true;
  tab.compatibilityMode = false;
  tab.allowHttp = false;
  tab.disableExtensions = true;
  return true;
}

function anonymousTabState(tab, torProxy) {
  if (!tab) return false;
  tab.securityDomain = 'anonymous';
  tab.anonymousAt = new Date().toISOString();
  tab.torProxy = String(torProxy || '127.0.0.1:9050');
  tab.shieldsEnabled = true;
  tab.compatibilityMode = false;
  tab.allowHttp = false;
  tab.disableExtensions = true;
  return true;
}

module.exports = {
  SENSITIVE_PERMISSION_KEYS,
  blockedPermissionDefaults,
  privateIpv4,
  privateIpv6,
  isPrivateHost,
  isPrivateNetworkUrl,
  hardenedOverrides,
  anonymousOverrides,
  effectiveSettings,
  domainLabel,
  hardenTabState,
  anonymousTabState
};
