'use strict';

function navigationUrl(eventOrDetails, legacyUrl) {
  if (typeof eventOrDetails === 'string') return eventOrDetails;
  if (eventOrDetails && typeof eventOrDetails.url === 'string') return eventOrDetails.url;
  if (legacyUrl && typeof legacyUrl === 'object' && typeof legacyUrl.url === 'string') return legacyUrl.url;
  if (typeof legacyUrl === 'string') return legacyUrl;
  return '';
}

function navigationIsMainFrame(eventOrDetails, legacyIsMainFrame = true) {
  if (eventOrDetails && typeof eventOrDetails.isMainFrame === 'boolean') return eventOrDetails.isMainFrame;
  if (typeof legacyIsMainFrame === 'boolean') return legacyIsMainFrame;
  return true;
}

function isInternalUrl(raw) {
  try { return new URL(raw).protocol === 'aegis:'; } catch { return false; }
}

function shouldAllowInternalNavigation(currentUrl, targetUrl) {
  if (!isInternalUrl(targetUrl)) return true;
  return isInternalUrl(currentUrl);
}

function failedHttpsCanOfferHttp(raw, errorCode) {
  try {
    const u = new URL(raw);
    if (u.protocol !== 'https:') return false;
    // Common connection / name / TLS failures. The downgrade is never automatic.
    return new Set([-2, -6, -7, -21, -101, -102, -105, -106, -107, -109, -118, -130, -200, -201, -202]).has(Number(errorCode));
  } catch { return false; }
}

module.exports = { navigationUrl, navigationIsMainFrame, isInternalUrl, shouldAllowInternalNavigation, failedHttpsCanOfferHttp };
