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
  ['siteIntelligence','Sentinel page intelligence','sentinel']
]);

function controlAssurance(settings, tab) {
  return CONTROL_DEFINITIONS.map(([key,label,layer]) => {
    const enabled = Boolean(settings?.[key]);
    let enforced = enabled;
    let evidence = enabled ? 'Enabled and connected to its enforcement layer.' : 'Disabled by user setting.';
    if (key === 'cosmeticFiltering' && enabled) { enforced = Boolean(tab?.cosmeticFilteringReady); evidence = enforced ? 'User-origin cosmetic CSS is active in this document.' : 'Waiting for a remote document to confirm cosmetic CSS.'; }
    if (['privacyApiGuard','globalPrivacyControl','doNotTrack','disableServiceWorkers'].includes(key) && enabled) { enforced = Boolean(tab?.fingerprintReady); evidence = enforced ? 'New-document privacy preload is active.' : 'New-document privacy preload is not confirmed for this tab.'; }
    if (['blockTrackers','blockAds','blockSocialTrackers','blockCryptominers','blockFingerprintingScripts','blockThirdPartyCookies','stripCrossSiteReferrers','etagProtection','publicCdnIsolation'].includes(key) && enabled) { enforced = Boolean(tab?.permissionFirewallReady); evidence = enforced ? 'Private-session request/response handlers are installed.' : 'Session privacy handlers are not confirmed.'; }
    return { key,label,layer,enabled,enforced,status:enabled?(enforced?'enforced':'degraded'):'disabled',evidence };
  });
}

module.exports = { CONTROL_DEFINITIONS, controlAssurance };
