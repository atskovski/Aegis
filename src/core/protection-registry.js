'use strict';

const DEFINITIONS = Object.freeze({
  blockTrackers: { id:'tracker-network', label:'Tracker network filtering', layer:'network', setting:'blockTrackers', evidence:'request-firewall' },
  blockAds: { id:'ad-network', label:'Ad network filtering', layer:'network', setting:'blockAds', evidence:'request-firewall' },
  blockSocialTrackers: { id:'social-network', label:'Social tracker filtering', layer:'network', setting:'blockSocialTrackers', evidence:'request-firewall' },
  blockCryptominers: { id:'cryptominer-network', label:'Cryptominer filtering', layer:'network', setting:'blockCryptominers', evidence:'request-firewall' },
  blockFingerprintingScripts: { id:'fingerprint-script-network', label:'Fingerprinting script filtering', layer:'network', setting:'blockFingerprintingScripts', evidence:'request-firewall' },
  cosmeticFiltering: { id:'cosmetic-filtering', label:'Cosmetic ad filtering', layer:'document', setting:'cosmeticFiltering', evidence:'inserted-user-css' },
  privacyApiGuard: { id:'privacy-api-guard', label:'High-entropy API guard', layer:'document', setting:'privacyApiGuard', evidence:'new-document-preload' },
  blockTrackingBeacons: { id:'tracking-beacon-guard', label:'Beacon and ping guard', layer:'document', setting:'blockTrackingBeacons', evidence:'new-document-preload' },
  heuristicTrackingProtection: { id:'heuristic-tracker-learning', label:'Behavioral tracker learning', layer:'network', setting:'heuristicTrackingProtection', evidence:'memory-tracker-learner' },
  blockThirdPartyCookies: { id:'third-party-cookie-defense', label:'Third-party cookie defense', layer:'network', setting:'blockThirdPartyCookies', evidence:'header-firewall' },
  stripTrackingParams: { id:'url-cleaning', label:'Tracking parameter removal', layer:'navigation', setting:'stripTrackingParams', evidence:'navigation-cleaner' },
  unwrapTrackingLinks: { id:'redirect-unwrapper', label:'Tracking redirect unwrapping', layer:'navigation', setting:'unwrapTrackingLinks', evidence:'navigation-cleaner' },
  stripCrossSiteReferrers: { id:'referrer-reduction', label:'Cross-site referrer reduction', layer:'network', setting:'stripCrossSiteReferrers', evidence:'header-firewall' },
  etagProtection: { id:'etag-defense', label:'ETag tracking defense', layer:'network', setting:'etagProtection', evidence:'response-firewall' },
  publicCdnIsolation: { id:'cdn-state-isolation', label:'Public CDN state isolation', layer:'network', setting:'publicCdnIsolation', evidence:'header-firewall' },
  globalPrivacyControl: { id:'gpc', label:'Global Privacy Control', layer:'network+document', setting:'globalPrivacyControl', evidence:'header-and-js' },
  doNotTrack: { id:'dnt', label:'Do Not Track', layer:'network+document', setting:'doNotTrack', evidence:'header-and-js' },
  disableServiceWorkers: { id:'service-worker-control', label:'Service worker control', layer:'document', setting:'disableServiceWorkers', evidence:'new-document-preload' },
  blockRiskyDownloads: { id:'download-guard', label:'Risky download guard', layer:'download', setting:'blockRiskyDownloads', evidence:'download-handler' },
  cookieAutoDelete: { id:'cookie-autodelete', label:'Cookie auto-delete', layer:'storage', setting:'cookieAutoDelete', evidence:'origin-cleanup-timer' },
  threatProtection: { id:'destination-risk', label:'Destination risk analysis', layer:'navigation', setting:'threatProtection', evidence:'url-risk-engine' },
  siteIntelligence: { id:'sentinel', label:'Sentinel site intelligence', layer:'telemetry-local', setting:'siteIntelligence', evidence:'local-audit-plane' }
});

function entryState(def, settings = {}, tab = {}) {
  const enabled = Boolean(settings[def.setting]);
  let enforced = enabled;
  let reason = enabled ? 'Enabled and backed by an enforcement path.' : 'Disabled in settings.';

  if (def.setting === 'cosmeticFiltering') {
    enforced = enabled && Boolean(tab.cosmeticFilteringReady);
    reason = !enabled ? 'Disabled in settings.' : enforced ? 'User-origin CSS is installed in the active document.' : 'Enabled, but CSS enforcement has not reported ready for this document.';
  } else if (['privacyApiGuard','blockTrackingBeacons','globalPrivacyControl','doNotTrack','disableServiceWorkers'].includes(def.setting)) {
    enforced = enabled && Boolean(tab.fingerprintReady);
    reason = !enabled ? 'Disabled in settings.' : enforced ? 'New-document privacy preload reported ready.' : 'Enabled, but the new-document enforcement preload has not reported ready.';
  } else if (def.setting === 'siteIntelligence') {
    enforced = enabled && Boolean(tab.siteIntelligence);
    reason = !enabled ? 'Disabled in settings.' : enforced ? 'Sentinel local audit state is attached to the tab.' : 'Enabled, but Sentinel state is not attached.';
  }
  return { ...def, configured: enabled, enforced, status: !enabled ? 'disabled' : enforced ? 'enforced' : 'degraded', reason };
}

function protectionStatus(settings = {}, tab = {}) {
  const protections = Object.values(DEFINITIONS).map((d) => entryState(d, settings, tab));
  const summary = protections.reduce((acc, item) => {
    acc[item.status] = (acc[item.status] || 0) + 1;
    return acc;
  }, { enforced:0, degraded:0, disabled:0 });
  return { generatedAt:new Date().toISOString(), protections, summary };
}

module.exports = { DEFINITIONS, protectionStatus };
