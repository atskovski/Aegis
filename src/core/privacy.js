'use strict';

const crypto = require('node:crypto');
const path = require('node:path');
const { isKnownTracker, explicitDomainMatches, explicitCategory, looksFingerprinting, isPublicCdn } = require('./blocklist');
const { isThirdParty, stripTrackingParams } = require('./url');
const { matchFilterRules } = require('./filter-rules');
const { isKnownScriptTrackerUrl, looksFirstPartyAnalytics } = require('./content-filter');
const { isPrivateNetworkUrl } = require('./compartment');

function makeTabStats() {
  return {
    blockedTrackers: 0, adsBlocked: 0, socialBlocked: 0, cryptominersBlocked: 0, fingerprintScriptsBlocked: 0, privateNetworkBlocks: 0,
    learnedTrackersBlocked: 0, blockedPermissions: 0, thirdPartyRequests: 0, thirdPartyCookiesBlocked: 0,
    trackingParamsRemoved: 0, httpsUpgrades: 0, blockedPopups: 0, blockedDownloads: 0, loadFailures: 0,
    etagProtections: 0, cdnIsolations: 0, sponsorSegmentsSkipped: 0, recentBlocked: []
  };
}
function safeHost(raw) { try { return new URL(raw).hostname; } catch { return ''; } }
function safeOrigin(raw) { try { const u = new URL(raw); return ['https:','http:'].includes(u.protocol) ? u.origin : ''; } catch { return ''; } }
function noteBlocked(tab, raw) { const host = safeHost(raw); if (!host) return; tab.stats.recentBlocked = [host, ...tab.stats.recentBlocked.filter((x) => x !== host)].slice(0, 14); }
function buildGenericUA(chromiumVersion) { const major = String(chromiumVersion || '152').split('.')[0]; return `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Safari/537.36`; }
function permissionKeys(permission, details = {}) {
  if (permission === 'media') { const types = Array.isArray(details.mediaTypes) ? [...details.mediaTypes] : []; if (details.mediaType && !types.includes(details.mediaType)) types.push(details.mediaType); const keys = []; if (types.includes('video')) keys.push('camera'); if (types.includes('audio')) keys.push('microphone'); return keys.length ? keys : ['camera','microphone']; }
  if (permission === 'geolocation') return ['geolocation']; if (permission === 'notifications') return ['notifications']; if (permission === 'clipboard-read') return ['clipboardRead']; if (permission === 'display-capture') return ['displayCapture']; if (permission === 'local-fonts') return ['localFonts']; if (permission === 'window-management') return ['windowManagement']; if (permission === 'idle-detection') return ['idleDetection']; if (permission === 'usb') return ['usb']; if (permission === 'serial') return ['serial']; if (permission === 'hid') return ['hid']; if (permission === 'midi' || permission === 'midiSysex') return ['midi']; return [];
}
function permissionDecision(settings, origin, key) { const site = settings.sitePermissions?.[origin]; if (site && ['allow','block'].includes(site[key])) return site[key]; return ['ask','block'].includes(settings.permissionDefaults?.[key]) ? settings.permissionDefaults[key] : 'block'; }
function permissionAllowed(settings, origin, key) { return permissionDecision(settings, origin, key) === 'allow'; }
function requestOrigin(webContents, details = {}) { for (const value of [details.requestingUrl,details.securityOrigin,details.requestingOrigin,details.embeddingOrigin]) { const origin = safeOrigin(value); if (origin) return origin; } try { return safeOrigin(webContents?.getURL?.()); } catch { return ''; } }
function categoryEnabled(settings, category) {
  if (category === 'ads') return settings.blockAds !== false;
  if (category === 'social') return settings.blockSocialTrackers !== false;
  if (category === 'cryptomining') return settings.blockCryptominers !== false;
  return settings.blockTrackers !== false;
}

function configurePrivacySession({ ses, tab, getSettings, chromiumVersion, onStats, onPermissionBlocked, onPermissionPrompt, onSensitiveAccess, onNetworkAccess, trackerLearner, getFilterRules, isTemporarilyAllowed }) {
  const genericUA = buildGenericUA(chromiumVersion);
  ses.setUserAgent(genericUA, 'en-US,en');
  ses.spellCheckerEnabled = false;
  try { ses.setSSLConfig({ minVersion: 'tls1.2', maxVersion: 'tls1.3' }); } catch {}

  ses.setPermissionRequestHandler((webContents, permission, callback, details = {}) => {
    const settings = getSettings(); const keys = permissionKeys(permission, details); const origin = requestOrigin(webContents, details); const decisions = keys.map((key) => (typeof isTemporarilyAllowed === 'function' && isTemporarilyAllowed(origin, key)) ? 'allow' : permissionDecision(settings, origin, key));
    if (typeof onSensitiveAccess === 'function') for (const key of keys) onSensitiveAccess({ category: key, action: 'requested', source: 'permission', detail: permission, frameHost: safeHost(origin) });
    const finish = (allowed) => {
      if (typeof onSensitiveAccess === 'function') for (const key of keys) onSensitiveAccess({ category: key, action: allowed ? 'allowed' : 'blocked', source: 'permission', detail: permission, frameHost: safeHost(origin) });
      if (!allowed) { tab.stats.blockedPermissions += 1; onStats(tab); if (typeof onPermissionBlocked === 'function') onPermissionBlocked({ permission, origin, keys }); } callback(Boolean(allowed));
    };
    if (!keys.length || decisions.includes('block')) return finish(false); if (decisions.every((d) => d === 'allow')) return finish(true); if (decisions.includes('ask') && typeof onPermissionPrompt === 'function') return onPermissionPrompt({ permission, origin, keys, complete: finish }); finish(false);
  });
  ses.setPermissionCheckHandler((webContents, permission, requestingOrigin, details = {}) => { const settings = getSettings(); const merged = { ...details, requestingOrigin }; const keys = permissionKeys(permission, merged); const origin = safeOrigin(requestingOrigin) || requestOrigin(webContents, merged); return keys.length > 0 && keys.every((key) => (typeof isTemporarilyAllowed === 'function' && isTemporarilyAllowed(origin, key)) || permissionDecision(settings, origin, key) === 'allow'); });
  ses.setDevicePermissionHandler(() => false);
  ses.on('select-hid-device', (event, details, callback) => { event.preventDefault(); callback(); });
  ses.on('select-serial-port', (event, portList, webContents, callback) => { event.preventDefault(); callback(''); });
  ses.on('select-usb-device', (event, details, callback) => { event.preventDefault(); callback(); });

  ses.webRequest.onBeforeSendHeaders({ urls: ['*://*/*'] }, (details, callback) => {
    const settings = getSettings();
    const headers = { ...(details.requestHeaders || {}) };
    // Keep the network identity coherent with the JS-visible privacy cohort.
    headers['User-Agent'] = genericUA;
    headers['Accept-Language'] = 'en-US,en;q=0.5';
    if (settings.doNotTrack !== false) headers['DNT'] = '1'; else delete headers['DNT'];
    if (settings.globalPrivacyControl !== false) headers['Sec-GPC'] = '1'; else delete headers['Sec-GPC'];
    // High-entropy UA client hints are unnecessary for normal browsing and create
    // another cross-layer fingerprint. Chromium may regenerate low-entropy hints.
    for (const key of Object.keys(headers)) {
      if (/^sec-ch-ua-(full-version|full-version-list|arch|bitness|model|platform-version|wow64)$/i.test(key)) delete headers[key];
    }
    callback({ requestHeaders: headers });
  });

  ses.webRequest.onBeforeRequest({ urls: ['*://*/*'] }, (details, callback) => {
    const settings = getSettings();
    if (settings.blockPrivateNetwork && isPrivateNetworkUrl(details.url)) {
      tab.stats.privateNetworkBlocks = (tab.stats.privateNetworkBlocks || 0) + 1;
      noteBlocked(tab, details.url);
      if (typeof onNetworkAccess === 'function') onNetworkAccess({ url: details.url, blocked: true, category: 'private-network', resourceType: details.resourceType });
      onStats(tab);
      return callback({ cancel: true });
    }
    if (details.resourceType === 'mainFrame') tab.topUrl = details.url;
    const topUrl = tab.topUrl || tab.url || details.url;
    if (details.resourceType === 'mainFrame' && settings.stripTrackingParams) {
      const cleaned = stripTrackingParams(details.url);
      if (cleaned !== details.url) { tab.stats.trackingParamsRemoved += 1; onStats(tab); return callback({ redirectURL: cleaned }); }
    }
    const thirdParty = isThirdParty(details.url, topUrl);
    if (thirdParty) tab.stats.thirdPartyRequests += 1;

    const rule = matchFilterRules(details.url, typeof getFilterRules === 'function' ? getFilterRules() : null);
    if (rule === 'block' && tab.shieldsEnabled && !tab.compatibilityMode) { tab.stats.blockedTrackers += 1; noteBlocked(tab, details.url); if (thirdParty && typeof onNetworkAccess === 'function') onNetworkAccess({ url: details.url, blocked: true, category: 'custom', resourceType: details.resourceType }); onStats(tab); return callback({ cancel: true }); }
    if (rule === 'allow') { if (thirdParty) { if (typeof onNetworkAccess === 'function') onNetworkAccess({ url: details.url, blocked: false, category: 'allow-rule', resourceType: details.resourceType }); onStats(tab); } return callback({}); }

    let host = ''; try { host = new URL(details.url).hostname; } catch {}
    const category = explicitCategory(host);
    const known = isKnownTracker(details.url);
    const learned = Boolean(settings.heuristicTrackingProtection && thirdParty && trackerLearner?.observe(details.url, topUrl));
    const fpScript = Boolean(settings.blockFingerprintingScripts && thirdParty && looksFingerprinting(details.url));
    const highConfidence = known && (!category || categoryEnabled(settings, category));
    const firstPartyAnalytics = Boolean(settings.heuristicTrackingProtection && !thirdParty && looksFirstPartyAnalytics(details.url, details.resourceType));
    const explicitScriptTracker = Boolean(isKnownScriptTrackerUrl(details.url));
    // Known script hosts are telemetry evidence, but blocking still obeys the category-specific toggles above.
    // Do not let a generic script-host helper silently override Block Ads / Social / Trackers preferences.
    const uncategorizedScriptTracker = explicitScriptTracker && !category && settings.blockTrackers !== false;
    const allThirdParty = Boolean(settings.blockThirdPartyRequests && thirdParty);
    const shouldBlock = tab.shieldsEnabled && !tab.compatibilityMode && (allThirdParty || (thirdParty && (highConfidence || fpScript || learned || uncategorizedScriptTracker)) || firstPartyAnalytics);
    if (shouldBlock) {
      tab.stats.blockedTrackers += 1;
      if (category === 'ads') tab.stats.adsBlocked += 1;
      if (category === 'social') tab.stats.socialBlocked += 1;
      if (category === 'cryptomining') tab.stats.cryptominersBlocked += 1;
      if (fpScript) tab.stats.fingerprintScriptsBlocked += 1;
      if (learned && !known) tab.stats.learnedTrackersBlocked += 1;
      if (firstPartyAnalytics) tab.stats.firstPartyAnalyticsBlocked = (tab.stats.firstPartyAnalyticsBlocked || 0) + 1;
      noteBlocked(tab, details.url); if (typeof onNetworkAccess === 'function') onNetworkAccess({ url: details.url, blocked: true, category: allThirdParty ? 'third-party-block' : (category || (fpScript ? 'fingerprint' : (firstPartyAnalytics ? 'first-party-analytics' : (learned ? 'heuristic' : 'tracker')))), resourceType: details.resourceType }); onStats(tab); return callback({ cancel: true });
    }
    if (thirdParty) { if (typeof onNetworkAccess === 'function') onNetworkAccess({ url: details.url, blocked: false, category: category || (fpScript ? 'fingerprint' : (known ? 'tracker' : 'third-party')), resourceType: details.resourceType }); onStats(tab); }
    callback({});
  });

  ses.webRequest.onBeforeSendHeaders({ urls: ['*://*/*'] }, (details, callback) => {
    const settings = getSettings(); const h = { ...(details.requestHeaders || {}) }; const topUrl = tab.topUrl || tab.url || details.url; const thirdParty = isThirdParty(details.url, topUrl); const cdn = thirdParty && settings.publicCdnIsolation && isPublicCdn(details.url);
    if (settings.doNotTrack) h.DNT = '1'; else delete h.DNT;
    if (settings.globalPrivacyControl) h['Sec-GPC'] = '1'; else delete h['Sec-GPC'];
    h['Accept-Language'] = 'en-US,en;q=0.5'; delete h['X-Client-Data']; delete h['x-client-data'];
    if (settings.privacyLevel !== 'standard') for (const key of ['Sec-CH-UA-Arch','Sec-CH-UA-Bitness','Sec-CH-UA-Full-Version','Sec-CH-UA-Full-Version-List','Sec-CH-UA-Model','Sec-CH-UA-Platform-Version','sec-ch-ua-arch','sec-ch-ua-bitness','sec-ch-ua-full-version','sec-ch-ua-full-version-list','sec-ch-ua-model','sec-ch-ua-platform-version']) delete h[key];
    const refKey = Object.keys(h).find((k) => k.toLowerCase() === 'referer');
    if (refKey && ((settings.stripCrossSiteReferrers && thirdParty) || cdn)) delete h[refKey];
    if (thirdParty && settings.etagProtection && (isKnownTracker(details.url) || trackerLearner?.isLikelyTracker(safeHost(details.url)))) {
      for (const name of Object.keys(h)) if (['if-none-match','if-modified-since'].includes(name.toLowerCase())) delete h[name];
      tab.stats.etagProtections += 1;
    }
    if ((thirdParty && settings.blockThirdPartyCookies && !tab.compatibilityMode) || cdn) {
      const cookieKey = Object.keys(h).find((k) => k.toLowerCase() === 'cookie');
      if (cookieKey) { delete h[cookieKey]; tab.stats.thirdPartyCookiesBlocked += 1; if (cdn) tab.stats.cdnIsolations += 1; onStats(tab); }
    }
    callback({ requestHeaders: h });
  });

  ses.webRequest.onHeadersReceived({ urls: ['*://*/*'] }, (details, callback) => {
    const settings = getSettings(); const headers = { ...(details.responseHeaders || {}) }; const topUrl = tab.topUrl || tab.url || details.url; const thirdParty = isThirdParty(details.url, topUrl); const known = isKnownTracker(details.url); const cdn = thirdParty && settings.publicCdnIsolation && isPublicCdn(details.url);
    for (const k of Object.keys(headers)) {
      const lower = k.toLowerCase();
      if (lower === 'report-to' || lower === 'nel') delete headers[k];
      if (lower === 'accept-ch' && settings.privacyLevel !== 'standard') headers[k] = (headers[k] || []).map((v) => String(v).split(',').map((x) => x.trim()).filter((x) => !/ua-(arch|bitness|full-version|full-version-list|model|platform-version)/i.test(x)).join(', '));
      if ((lower === 'etag' || lower === 'last-modified') && thirdParty && settings.etagProtection && known) { delete headers[k]; tab.stats.etagProtections += 1; }
      if (lower === 'set-cookie' && ((thirdParty && settings.blockThirdPartyCookies && !tab.compatibilityMode) || cdn)) { const values = headers[k] || []; tab.stats.thirdPartyCookiesBlocked += Math.max(1, values.length); if (cdn) tab.stats.cdnIsolations += 1; delete headers[k]; onStats(tab); }
    }
    callback({ responseHeaders: headers });
  });
  return ses;
}

function freshSeed() { return crypto.randomBytes(24).toString('hex'); }
function safeDownloadName(name) { return String(name || 'download').replace(/[\\/:*?"<>|\x00-\x1f]/g, '_').slice(0, 180); }
function isRiskyDownload(filename) { return /\.(?:dmg|pkg|app|exe|msi|scr|bat|cmd|com|ps1|vbs|js|jse|jar|sh|command|desktop|deb|rpm|apk|iso)$/i.test(filename || ''); }
function defaultDownloadPath(app, filename) { return path.join(app.getPath('downloads'), 'Aegis Downloads', safeDownloadName(filename)); }
module.exports = { makeTabStats, configurePrivacySession, buildGenericUA, freshSeed, isRiskyDownload, defaultDownloadPath, safeOrigin, permissionKeys, permissionAllowed, permissionDecision, categoryEnabled };
