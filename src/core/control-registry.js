'use strict';

const CONTROL_DEFINITIONS = Object.freeze([
  ['blockTrackers','Tracker network filtering','network-firewall'],
  ['blockAds','Ad network filtering','network-firewall'],
  ['blockSocialTrackers','Social tracker filtering','network-firewall'],
  ['blockCryptominers','Cryptominer filtering','network-firewall'],
  ['blockFingerprintingScripts','Fingerprinting-script filtering','network-firewall'],
  ['cosmeticFiltering','Cosmetic ad filtering','document-css'],
  ['privacyApiGuard','High-entropy API guard','document-preload'],
  ['blockTrackingBeacons','Tracking beacon/ping guard','document-preload'],
  ['heuristicTrackingProtection','Behavioral tracker learning','network-firewall'],
  ['blockThirdPartyCookies','Third-party cookie defense','network-headers'],
  ['stripTrackingParams','Tracking-parameter cleaning','navigation'],
  ['unwrapTrackingLinks','Tracking redirect unwrapping','navigation'],
  ['stripCrossSiteReferrers','Cross-site referrer reduction','network-headers'],
  ['etagProtection','ETag tracking defense','network-headers'],
  ['publicCdnIsolation','Public CDN state isolation','network-headers'],
  ['globalPrivacyControl','Global Privacy Control','network+document'],
  ['doNotTrack','Do Not Track','network+document'],
  ['disableServiceWorkers','Service-worker restriction','document-preload'],
  ['blockRiskyDownloads','Risky download guard','download-policy'],
  ['cookieAutoDelete','Cookie/site-data auto-delete','session-lifecycle'],
  ['threatProtection','Local destination risk analysis','navigation'],
  ['siteIntelligence','Sentinel page intelligence','sentinel'],
  ['blockThirdPartyRequests','All third-party request isolation','network-firewall'],
  ['letterbox','Viewport letterboxing','view-geometry'],
  ['disableWebRtc','WebRTC exposure shutdown','document-preload'],
  ['blockPrivateNetwork','Local/private-network isolation','network-firewall'],
  ['blockAllDownloads','Download shutdown','download-policy']
]);

function controlAssurance(settings, tab) {
  return CONTROL_DEFINITIONS.map(([key,label,layer]) => {
    const enabled = Boolean(settings?.[key]);
    if (!enabled) return { key,label,layer,enabled:false,enforced:false,status:'disabled',evidence:'Disabled by user setting.' };

    const sessionReady = Boolean(tab?.privacySessionReady);
    const documentReady = Boolean(tab?.fingerprintReady);
    const cosmeticReady = Boolean(tab?.cosmeticFilteringReady);
    const sentinelReady = Boolean(tab?.fingerprintStatus?.sentinelPreload);

    let enforced = true;
    let status = 'enforced';
    let evidence = 'Enabled and connected to its enforcement layer.';

    if (key === 'cosmeticFiltering') {
      enforced = cosmeticReady; status = enforced ? 'enforced' : 'degraded';
      evidence = enforced ? 'User-origin cosmetic CSS is active in this document.' : 'Cosmetic filtering is enabled but the current document has not confirmed user-origin CSS.';
    } else if (['privacyApiGuard','blockTrackingBeacons','disableServiceWorkers','disableWebRtc'].includes(key)) {
      enforced = documentReady; status = enforced ? 'enforced' : 'degraded';
      evidence = enforced ? 'The new-document privacy preload is active for this tab.' : 'This control requires the new-document privacy preload, which is not confirmed for this tab.';
    } else if (key === 'globalPrivacyControl' || key === 'doNotTrack') {
      const network = sessionReady;
      const page = documentReady;
      enforced = network && page;
      status = enforced ? 'enforced' : 'degraded';
      evidence = enforced
        ? 'The request header and JavaScript-visible privacy signal are both active.'
        : (network ? 'The request header path is active, but the JavaScript-visible signal is not confirmed in this tab.' : 'Neither the request-header path nor document signal is confirmed.');
    } else if (key === 'siteIntelligence') {
      enforced = sentinelReady; status = enforced ? 'enforced' : 'degraded';
      evidence = enforced ? 'Sentinel audit binding and new-document observer are installed.' : 'Sentinel is enabled, but its page observer is not confirmed in this tab.';
    } else if (['blockTrackers','blockAds','blockSocialTrackers','blockCryptominers','blockFingerprintingScripts','blockThirdPartyCookies','blockThirdPartyRequests','blockPrivateNetwork','stripCrossSiteReferrers','etagProtection','publicCdnIsolation'].includes(key)) {
      enforced = sessionReady; status = enforced ? 'enforced' : 'degraded';
      evidence = enforced ? 'Private-session request/response handlers are installed and read this setting at request time.' : 'The private-session network handlers are not confirmed.';
    } else if (key === 'heuristicTrackingProtection') {
      enforced = sessionReady; status = enforced ? 'enforced' : 'degraded';
      evidence = enforced ? 'The memory-only cross-site tracker learner is connected to the request firewall.' : 'The request firewall is not confirmed.';
    } else if (key === 'cookieAutoDelete') {
      evidence = 'Origin cleanup is scheduled by the tab lifecycle after cross-origin navigation, except for fireproofed sites.';
    } else if (key === 'stripTrackingParams' || key === 'unwrapTrackingLinks' || key === 'threatProtection') {
      evidence = 'The navigation pipeline reads this setting on every navigation.';
    } else if (key === 'blockRiskyDownloads' || key === 'blockAllDownloads') {
      evidence = 'The tab session will-download policy reads this effective compartment setting for every download.';
    } else if (key === 'letterbox') {
      evidence = 'The active WebContentsView is quantized and centered using the effective per-tab privacy policy.';
    }

    return { key,label,layer,enabled:true,enforced,status,evidence };
  });
}

module.exports = { CONTROL_DEFINITIONS, controlAssurance };
