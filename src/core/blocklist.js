'use strict';

// Compact, high-confidence local knowledge. Aegis intentionally avoids fetching
// remote blocklists during browsing. Users can extend blocking with local rules.
const CATEGORY_DOMAINS = Object.freeze({
  ads: [
    'doubleclick.net','googlesyndication.com','googleadservices.com','adservice.google.com',
    'adsrvr.org','adnxs.com','rubiconproject.com','openx.net','pubmatic.com','casalemedia.com',
    'criteo.com','criteo.net','taboola.com','outbrain.com','yieldmo.com','adform.net','zemanta.com'
  ],
  analytics: [
    'google-analytics.com','googletagmanager.com','analytics.google.com','stats.g.doubleclick.net','clarity.ms',
    'scorecardresearch.com','quantserve.com','quantcount.com','hotjar.com','hotjar.io','fullstory.com',
    'mouseflow.com','luckyorange.com','inspectlet.com','mixpanel.com','amplitude.com','heapanalytics.com',
    'heap.io','segment.io','segment.com','chartbeat.com','chartbeat.net','parsely.com','contentsquare.net','contentsquare.com'
  ],
  social: [
    'connect.facebook.net','pixel.facebook.com','ads-twitter.com','analytics.twitter.com','static.ads-twitter.com',
    'ads.linkedin.com','px.ads.linkedin.com','snap.licdn.com','sharethis.com','addthis.com','addthisedge.com'
  ],
  attribution: [
    'branch.io','appsflyer.com','adjust.com','everesttech.net','demdex.net','bluekai.com','mathtag.com','rlcdn.com',
    'agkn.com','permutive.com','skimresources.com','skimlinks.com'
  ],
  marketing: [
    'hubspot.com','hs-analytics.net','hs-scripts.com','hsadspixel.net','marketo.net','marketo.com','pardot.com',
    'omtrdc.net','2o7.net','tealiumiq.com','tiqcdn.com','ensighten.com','optimizely.com','crazyegg.com',
    'kissmetrics.io','kissmetrics.com','bounceexchange.com','yieldify.com'
  ],
  telemetry: ['newrelic.com','nr-data.net','sentry.io','intercom.io','intercomcdn.com'],
  cryptomining: ['coinhive.com','coin-hive.com','authedmine.com','crypto-loot.com','coinimp.com','webminepool.com','minero.cc']
});

const HOST_TO_CATEGORY = new Map();
for (const [category, domains] of Object.entries(CATEGORY_DOMAINS)) for (const domain of domains) HOST_TO_CATEGORY.set(domain, category);

const TRACKER_HOST_HINTS = [/^ad[sx]?\d*\./i,/^analytics\./i,/^metrics\./i,/^telemetry\./i,/^pixel\./i,/^track(?:er|ing)?\./i,/^beacon\./i,/^stats\./i];
const TRACKER_PATH_HINTS = [/\/collect(?:\?|$)/i,/\/beacon(?:\?|$)/i,/\/pixel(?:\.|\/|\?)/i,/\/track(?:ing)?(?:\/|\?|$)/i,/\/analytics(?:\/|\?|$)/i,/\/events?(?:\/|\?|$)/i,/\/telemetry(?:\/|\?|$)/i];
const FINGERPRINT_HINTS = [/fingerprint/i,/fpjs/i,/fingerprintjs/i,/device.?id/i,/browser.?id/i];
const PUBLIC_CDN_DOMAINS = ['cdnjs.cloudflare.com','cdn.jsdelivr.net','unpkg.com','ajax.googleapis.com','code.jquery.com','stackpath.bootstrapcdn.com','maxcdn.bootstrapcdn.com'];

function explicitCategory(hostname) {
  const host = String(hostname || '').toLowerCase();
  if (!host) return '';
  for (const [domain, category] of HOST_TO_CATEGORY) if (host === domain || host.endsWith(`.${domain}`)) return category;
  return '';
}
function explicitDomainMatches(hostname) { return Boolean(explicitCategory(hostname)); }
function domainMatches(hostname) {
  const host = String(hostname || '').toLowerCase();
  return explicitDomainMatches(host) || TRACKER_HOST_HINTS.some((rx) => rx.test(host));
}
function pathLooksTracking(raw) { try { const u = new URL(raw); return TRACKER_PATH_HINTS.some((rx) => rx.test(`${u.pathname}${u.search}`)); } catch { return false; } }
function looksFingerprinting(raw) { try { const u = new URL(raw); return FINGERPRINT_HINTS.some((rx) => rx.test(`${u.hostname}${u.pathname}${u.search}`)); } catch { return false; } }
function isKnownTracker(raw) { try { const u = new URL(raw); return domainMatches(u.hostname) || pathLooksTracking(raw); } catch { return false; } }
function isPublicCdn(raw) { try { const h = new URL(raw).hostname.toLowerCase(); return PUBLIC_CDN_DOMAINS.some((d) => h === d || h.endsWith(`.${d}`)); } catch { return false; } }

module.exports = { CATEGORY_DOMAINS, isKnownTracker, domainMatches, explicitDomainMatches, explicitCategory, pathLooksTracking, looksFingerprinting, isPublicCdn };
