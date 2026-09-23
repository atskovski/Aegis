'use strict';

const { app, BrowserWindow, ipcMain, protocol, clipboard, dialog, shell, Menu } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { normalizeInput, stripTrackingParams, cleanNavigationUrl, registrableLike, isAllowedNavigation, shouldUpgradeHttp, upgradeToHttps } = require('./core/url');
const { configurePrivacySession, makeTabStats, freshSeed, isRiskyDownload, defaultDownloadPath, safeOrigin, buildGenericUA } = require('./core/privacy');
const { buildAntiFingerprintScript } = require('./core/fingerprint');
const { policyFor: fingerprintPolicyFor, policyEvidence: fingerprintPolicyEvidence } = require('./core/fingerprint-policy');
const { sanitizeSettings, searchTemplateFor, profileDefaults, cloneDefaults, SEARCH_ENGINES } = require('./core/settings');
const { navigationUrl, navigationIsMainFrame, shouldAllowInternalNavigation, failedHttpsCanOfferHttp } = require('./core/navigation');
const { applyProxyToSession: applyProxyCore, runConnectivityTest, verifyTorRoute } = require('./core/network');
const { parseFilterRules, matchFilterRules, cosmeticSelectorsForHost } = require('./core/filter-rules');
const { CATALOG: FILTER_LIST_CATALOG, readEnabled: readFilterLists, refresh: refreshFilterLists } = require('./core/filter-lists');
const { cosmeticCss, buildPagePrivacyScript } = require('./core/content-filter');
const { TrackerLearner } = require('./core/tracker-learning');
const { analyzeUrl } = require('./core/safety');
const { youtubeVideoId, fetchSponsorSegments, sponsorSkipScript } = require('./core/sponsor');
const { makeSiteIntelligence, resetSiteIntelligence, recordSiteSignal, recordNetworkEvent, publicSiteIntelligence, buildSiteAuditScript } = require('./core/site-intelligence');
const { fetchPublicIp, testSessionIsolation, testWebRtcLeakSurface, inspectPrivacySurfaces, captureFingerprintSnapshot, compareFingerprintSnapshots, compareFingerprintCohort, testNetworkIdentity, testStorageResurrection, testProcessIsolation, routePrivacyStatus, makeCheck, summarizeChecks } = require('./core/security-suite');
const { AegisExtensionRuntime } = require('./core/extensions');
const { controlAssurance } = require('./core/control-registry');
const { effectiveSettings, hardenTabState, anonymousTabState, domainLabel, isPrivateNetworkUrl, SENSITIVE_PERMISSION_KEYS } = require('./core/compartment');
const { makeBounceTracker, noteNavigation, detectBounce } = require('./core/bounce-tracking');
const { createSecurityEventLedger } = require('./core/security-events');
const { evaluateUrl, extensionAllowed } = require('./core/enterprise-policy');
const { createSecurityKernel } = require('./core/security-kernel');
const { createRiskEngine } = require('./core/risk-engine');
const { createKernelAudit } = require('./core/kernel-audit');
const { verifyBundle, applyManagedPolicy, preserveLockedSettings } = require('./core/managed-policy');
const { createElectronChromiumAdapter } = require('./engine/electron-adapter');
const { engineEvidence } = require('./core/engine-contract');
const { createBrowserRuntime } = require('./core/browser-runtime');
const browserEngine = createElectronChromiumAdapter();
const browserRuntime = createBrowserRuntime(browserEngine);

app.setName('Aegis Privacy Browser');

// Aegis never offers a click-through for invalid TLS certificates. Certificate
// errors fail closed in the network process; the page receives the normal local
// error surface rather than a user-bypass path.
app.on('certificate-error', (event, _webContents, url, error, _certificate, callback) => {
  try { event.preventDefault(); } catch {}
  let host = 'unknown-host'; try { host = new URL(String(url || '')).hostname || host; } catch {}
  console.warn('Blocked invalid TLS certificate for host:', host, String(error || 'certificate-error'));
  callback(false);
});
// Keep the wire-level User-Agent generic. Product branding belongs in browser chrome, not in requests sites can fingerprint.
app.userAgentFallback = buildGenericUA(process.versions.chrome);

const gotSingleInstanceLock = app.requestSingleInstanceLock();
if (!gotSingleInstanceLock) {
  app.quit();
}

protocol.registerSchemesAsPrivileged([{
  scheme: 'aegis', privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: false }
},{
  scheme: 'aegis-extension', privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: true }
}]);

// Chromium hardening that must be configured before app readiness.
app.enableSandbox();
app.commandLine.appendSwitch('disable-background-networking');
app.commandLine.appendSwitch('disable-breakpad');
app.commandLine.appendSwitch('disable-sync');
app.commandLine.appendSwitch('disable-quic');
app.commandLine.appendSwitch('force-webrtc-ip-handling-policy', 'disable_non_proxied_udp');
app.commandLine.appendSwitch('site-per-process');
app.commandLine.appendSwitch('no-pings');
app.commandLine.appendSwitch('lang', 'en-US');
app.commandLine.appendSwitch('disable-features', [
  'WebGPU', 'Prerender2', 'BrowsingTopics', 'InterestGroupStorage', 'SharedStorageAPI',
  'AttributionReporting', 'PrivateAggregationApi', 'FencedFrames'
].join(','));

const UI_DIR = path.join(__dirname, 'ui');
const SETTINGS_FILE = () => path.join(app.getPath('userData'), 'settings.json');
const BOOKMARKS_FILE = () => path.join(app.getPath('userData'), 'bookmarks.json');
const FILTER_LIST_DIR = () => path.join(app.getPath('userData'), 'filter-lists');
const TOOLBAR_H = 108;
const LETTERBOX_STEP = 100;
let mainWindow;
let activeId = null;
let nextId = 1;
let identitySeed = freshSeed();
const tabs = new Map();
const pendingPermissions = new Map();
let settings = cloneDefaults();
let bookmarks = [];
let downloads = [];
const activeDownloadItems = new Map();
let lastNetworkTest = null;
let lastSecuritySuite = null;
const temporaryPermissions = new Map();
let uiLayer = { mode: 'none', reserveRight: 0 };
let trackerLearner = new TrackerLearner();
let filterRules = parseFilterRules('');
let extensionRuntime = null;
const securityEvents = createSecurityEventLedger(750);
const kernelAudit = createKernelAudit(1500);
const riskEngine = createRiskEngine();
const securityKernel = createSecurityKernel({getSettings:()=>settings,emit:(e)=>{kernelAudit.append(e);if(!e.allow)securityEvents.add('kernel-deny',e.risk==='critical'?'danger':'warning',{action:e.action,reason:e.reason,layer:e.layer,risk:e.risk,url:e.url},e.tabId);}});
const SECURITY_TEST_TARGETS = Object.freeze({
  eff: 'https://coveryourtracks.eff.org/',
  ip: 'https://browserleaks.com/ip',
  webrtc: 'https://browserleaks.com/webrtc',
  canvas: 'https://browserleaks.com/canvas',
  webgl: 'https://browserleaks.com/webgl',
  tls: 'https://browserleaks.com/tls',
  javascript: 'https://browserleaks.com/javascript'
});
let stateEmitTimer = null;

function tabSettings(tab) { return effectiveSettings(settings, tab); }
function scheduleStateEmit(delay = 35) {
  if (stateEmitTimer) return;
  stateEmitTimer = setTimeout(() => { stateEmitTimer = null; emitState(); }, Math.max(0, delay));
}

function startupLog(message, extra = '') {
  const suffix = extra ? ` ${String(extra)}` : '';
  console.log(`[Aegis startup] ${message}${suffix}`);
}

function internalProtocolHandler(request) {
  const u = new URL(request.url);
  if (u.hostname !== 'app') return new Response('Not found', { status: 404 });
  if (u.pathname === '/search') {
    const q = String(u.searchParams.get('q') || '').trim();
    const target = q ? searchTemplateFor(settings).replace('%s', encodeURIComponent(q)) : 'aegis://app/start.html';
    return Response.redirect(target, 302);
  }

  if (u.pathname === '/open-http') {
    const raw = String(u.searchParams.get('url') || '');
    try {
      const target = new URL(raw);
      if (target.protocol !== 'http:') return new Response('Invalid downgrade target', { status: 400 });
      return Response.redirect(target.toString(), 302);
    } catch { return new Response('Invalid downgrade target', { status: 400 }); }
  }

  const requested = decodeURIComponent(u.pathname.replace(/^\//, '') || 'index.html');
  const target = path.resolve(UI_DIR, requested);
  const relative = path.relative(UI_DIR, target);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative) || !fs.existsSync(target) || !fs.statSync(target).isFile()) {
    if (requested !== 'index.html') return new Response('Not found', { status: 404 });
  }

  const ext = path.extname(target).toLowerCase();
  const mime = ({
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png'
  })[ext] || 'application/octet-stream';
  return new Response(fs.readFileSync(target), {
    status: 200,
    headers: {
      'Content-Type': mime,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    }
  });
}

function extensionProtocolHandler(request) {
  if (!extensionRuntime) return new Response('Extension runtime unavailable', { status: 503 });
  let u; try { u = new URL(request.url); } catch { return new Response('Bad request', { status: 400 }); }
  if (u.hostname !== 'ext') return new Response('Not found', { status: 404 });
  const parts = u.pathname.split('/').filter(Boolean);
  const token = parts.shift() || '';
  let rel = '';
  try { rel = decodeURIComponent(parts.join('/')); } catch { return new Response('Bad resource path', { status: 400 }); }
  const resource = extensionRuntime.resolveResource(token, rel);
  if (!resource) return new Response('Not found', { status: 404 });
  const ext = path.extname(resource.path).toLowerCase();
  const mime = ({
    '.html':'text/html; charset=utf-8','.htm':'text/html; charset=utf-8','.css':'text/css; charset=utf-8',
    '.js':'text/javascript; charset=utf-8','.mjs':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8',
    '.svg':'image/svg+xml','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.gif':'image/gif','.webp':'image/webp',
    '.woff':'font/woff','.woff2':'font/woff2','.ttf':'font/ttf','.wasm':'application/wasm'
  })[ext] || 'application/octet-stream';
  return new Response(fs.readFileSync(resource.path), {
    status:200,
    headers:{
      'Content-Type':mime,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer',
      'Access-Control-Allow-Origin':'*',
      'Content-Security-Policy':"default-src 'self' data: blob:; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src https: http:; object-src 'none'; base-uri 'none'"
    }
  });
}

function registerInternalProtocol(targetProtocol, label = 'session') {
  if (!targetProtocol) throw new Error(`Missing protocol object for ${label}`);
  if (!targetProtocol.isProtocolHandled('aegis')) {
    browserRuntime.protocol(targetProtocol,'aegis',internalProtocolHandler);
    startupLog(`Registered aegis:// protocol for ${label}.`);
  }
  if (extensionRuntime && !targetProtocol.isProtocolHandled('aegis-extension')) {
    browserRuntime.protocol(targetProtocol,'aegis-extension',extensionProtocolHandler);
    startupLog(`Registered aegis-extension:// protocol for ${label}.`);
  }
}


async function withTimeout(promise, ms, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms); })
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function rebuildFilterRules(){
  const subscribed=readFilterLists(FILTER_LIST_DIR(),settings.enabledFilterLists||[]);
  filterRules=parseFilterRules([subscribed,settings.customFilterRules||''].filter(Boolean).join('\n'));
}
async function updateFilterLists(){
  const results=await refreshFilterLists({dir:FILTER_LIST_DIR(),enabled:settings.enabledFilterLists||[],fetchImpl:(url,opts)=>browserRuntime.fetch(url,{...opts,bypassCustomProtocolHandlers:true})});
  rebuildFilterRules();securityEvents.add('filter-lists-refreshed',results.some(x=>!x.ok)?'warning':'success',{results});
  await Promise.allSettled([...tabs.values()].map(tab=>applyCosmeticFiltering(tab)));emitState();return results;
}
function loadSettings() {
  try {
    const raw = JSON.parse(fs.readFileSync(SETTINGS_FILE(), 'utf8'));
    settings = sanitizeSettings(raw);
  } catch {
    settings = sanitizeSettings(settings);
  }
  rebuildFilterRules();
}

function saveSettings() {
  try {
    fs.mkdirSync(path.dirname(SETTINGS_FILE()), { recursive: true, mode: 0o700 });
    fs.writeFileSync(SETTINGS_FILE(), JSON.stringify(settings, null, 2), { mode: 0o600 });
  } catch (err) {
    console.error('Could not save settings:', err.message);
  }
}


function loadBookmarks() {
  try {
    const raw = JSON.parse(fs.readFileSync(BOOKMARKS_FILE(), 'utf8'));
    bookmarks = Array.isArray(raw) ? raw.filter((x) => x && typeof x.url === 'string' && /^https?:\/\//.test(x.url)).slice(0, 500) : [];
  } catch { bookmarks = []; }
}

function saveBookmarks() {
  try {
    fs.mkdirSync(path.dirname(BOOKMARKS_FILE()), { recursive: true, mode: 0o700 });
    fs.writeFileSync(BOOKMARKS_FILE(), JSON.stringify(bookmarks, null, 2), { mode: 0o600 });
  } catch (err) { console.error('Could not save bookmarks:', err.message); }
}

function bookmarkForUrl(url) { return bookmarks.find((x) => x.url === url); }
function toggleBookmark(tab) {
  if (!tab || !/^https?:\/\//.test(tab.url || '')) return false;
  const existing = bookmarks.findIndex((x) => x.url === tab.url);
  if (existing >= 0) bookmarks.splice(existing, 1);
  else bookmarks.unshift({ id: crypto.randomUUID(), url: tab.url, title: tab.title || new URL(tab.url).hostname, createdAt: new Date().toISOString() });
  bookmarks = bookmarks.slice(0, 500);
  saveBookmarks(); emitState();
  return existing < 0;
}

function addDownloadRecord(item, tab) {
  const id = crypto.randomUUID();
  const rec = { id, filename: item.getFilename(), state: 'starting', receivedBytes: 0, totalBytes: item.getTotalBytes() || 0, path: '', startedAt: new Date().toISOString(), source: safeOrigin(tab?.url), mimeType: item.getMimeType?.() || '', sha256: '', sizeVerified: false, contentWarning: '' };
  downloads.unshift(rec); downloads = downloads.slice(0, 50); emitState();
  return rec;
}

function updateDownloadRecord(rec, item, state) {
  rec.state = state || rec.state;
  rec.receivedBytes = item.getReceivedBytes?.() || rec.receivedBytes || 0;
  rec.totalBytes = item.getTotalBytes?.() || rec.totalBytes || 0;
  emitState();
}

async function runNetworkTest() {
  const tab = activeTab();
  const effective = tab ? tabSettings(tab) : settings;
  // Diagnostics deliberately use a disposable Chromium session. This keeps the
  // test working even when the current tab renderer/session is unhealthy and
  // prevents a proxy reset from interrupting a page the user is viewing.
  const ses = browserRuntime.session(`aegis-diagnostic-${crypto.randomUUID()}`, { cache: false });
  try {
    const diagnosticMode = effective.proxy?.mode || 'system';
    const route = await applyProxyCore(ses, effective.proxy || {},  {
      failClosedFixedProxy: !['system','direct'].includes(diagnosticMode),
      freshSession: diagnosticMode === 'system'
    });
    if (!route?.ok) throw new Error((route?.warnings || []).join(' | ') || 'Network route could not be applied.');
    const result = await runConnectivityTest(ses, { target: 'https://duckduckgo.com/', proxyMode: effective.proxy?.mode || 'system' });
    result.routeWarnings = route.warnings || [];
    result.usedDisposableSession = true;
    lastNetworkTest = result;
    emitState();
    return result;
  } catch (err) {
    const result = { ok: false, error: err.message, testedAt: new Date().toISOString(), proxyMode: effective.proxy?.mode || 'system', elapsedMs: 0, usedDisposableSession: true };
    lastNetworkTest = result; emitState(); return result;
  } finally {
    try { await ses.clearData(); } catch {}
    try { await ses.clearCache(); } catch {}
    try { await ses.closeAllConnections(); } catch {}
  }
}

function temporaryPermissionKey(tabId, origin, key) { return `${Number(tabId) || 0}\u0000${String(origin || '')}\u0000${String(key || '')}`; }
function isTemporarilyAllowed(tabId, origin, key) {
  const mapKey = temporaryPermissionKey(tabId, origin, key);
  const expiresAt = Number(temporaryPermissions.get(mapKey) || 0);
  if (!expiresAt) return false;
  if (Date.now() >= expiresAt) { temporaryPermissions.delete(mapKey); return false; }
  return true;
}
function grantTemporaryPermission(tabId, origin, key, durationMs = 10 * 60 * 1000) {
  if (!origin || !Object.prototype.hasOwnProperty.call(settings.permissionDefaults || {}, key)) return false;
  temporaryPermissions.set(temporaryPermissionKey(tabId, origin, key), Date.now() + Math.max(1000, Number(durationMs) || 0));
  return true;
}
function clearTemporaryPermission(tabId, origin, key) { temporaryPermissions.delete(temporaryPermissionKey(tabId, origin, key)); }
function clearTemporaryPermissionsForOrigin(origin, tabId = null) {
  const originToken = `\u0000${String(origin || '')}\u0000`;
  const tabPrefix = tabId == null ? '' : `${Number(tabId) || 0}\u0000`;
  for (const mapKey of temporaryPermissions.keys()) {
    if ((tabId == null || mapKey.startsWith(tabPrefix)) && mapKey.includes(originToken)) temporaryPermissions.delete(mapKey);
  }
}

async function runSecuritySuite() {
  const tab = activeTab();
  const effective = tab ? tabSettings(tab) : settings;
  const checks = [];
  const testedAt = new Date().toISOString();

  if (tab) {
    const policy = tab.rendererPolicy || {};
    const rendererOk = policy.sandbox === true && policy.contextIsolation === true && policy.nodeIntegration === false && policy.webSecurity === true && policy.devTools === false;
    checks.push(makeCheck('renderer-isolation', 'Renderer isolation', rendererOk ? 'pass' : 'fail',
      rendererOk
        ? 'Active web renderer is sandboxed with context isolation, Node disabled, webSecurity enabled, and DevTools disabled.'
        : 'One or more required renderer-isolation controls are not active.', 'runtime-policy'));
    const processIsolation = await testProcessIsolation((source)=>browserRuntime.evaluate(tab.view,source,true), policy);
    checks.push(makeCheck('process-isolation-behavior', 'Process / Node isolation behavior', processIsolation.status, processIsolation.evidence, 'behavioral-test'));
    checks.push(makeCheck('permission-firewall', 'Permission firewall', tab.permissionFirewallReady ? 'pass' : 'fail',
      tab.permissionFirewallReady ? 'Permission request and permission check handlers are installed for this private tab session.' : 'Permission handlers are not confirmed for the active tab.', 'runtime-policy'));
    const fpNeeded = effective.privacyLevel !== 'standard';
    checks.push(makeCheck('fingerprint-defense', 'Fingerprint normalization', (!fpNeeded || tab.fingerprintReady) ? 'pass' : 'fail',
      fpNeeded ? (tab.fingerprintReady ? 'Anti-fingerprint preload and CDP locale/timezone normalization initialized.' : 'Strict/Maximum fingerprint defenses did not report ready.') : 'Standard mode intentionally uses reduced fingerprint normalization.', 'runtime'));
    checks.push(makeCheck('cosmetic-filtering', 'Cosmetic ad filtering', effective.cosmeticFiltering === false ? 'warning' : (tab.cosmeticFilteringReady || String(tab.url || '').startsWith('aegis://') ? 'pass' : 'not-tested'),
      effective.cosmeticFiltering === false ? 'Cosmetic filtering is disabled in Settings.' : (tab.cosmeticFilteringReady ? 'User-origin CSS filtering is active in the current document.' : 'No remote document is ready for cosmetic-filter verification.'), 'runtime'));
    checks.push(makeCheck('https-first', 'HTTPS-first navigation', (!tab.allowHttp && !String(tab.url || '').startsWith('http://')) ? 'pass' : 'fail',
      (!tab.allowHttp && !String(tab.url || '').startsWith('http://')) ? 'HTTP downgrade is not enabled for this tab.' : 'This tab currently allows or is using insecure HTTP.', 'runtime'));

    const surface = await inspectPrivacySurfaces((source) => browserRuntime.evaluate(tab.view,source, true));
    if (surface.status === 'pass') {
      const v = surface.values || {};
      const guardedSurfacesHidden = !v.bluetooth && !v.usb && !v.serial && !v.hid && !v.localFonts && !v.joinAdInterestGroup && !v.runAdAuction && !v.privateToken;
      checks.push(makeCheck('privacy-api-guard', 'High-entropy & ad API guard', effective.privacyApiGuard === false ? 'warning' : (guardedSurfacesHidden ? 'pass' : 'fail'),
        effective.privacyApiGuard === false
          ? 'Privacy API Guard is disabled in Settings; exposed surfaces are not treated as a verification pass.'
          : (guardedSurfacesHidden
            ? 'Local font access, hardware-device APIs, Protected Audience and Private State Token surfaces are not exposed in the active renderer.'
            : `One or more guarded APIs remain exposed (fonts=${Boolean(v.localFonts)}, bluetooth=${Boolean(v.bluetooth)}, protectedAudience=${Boolean(v.joinAdInterestGroup || v.runAdAuction)}, privateToken=${Boolean(v.privateToken)}).`), 'behavioral-test'));
      checks.push(makeCheck('gpc-signal', 'Global Privacy Control', effective.globalPrivacyControl === false ? 'warning' : (v.gpc ? 'pass' : 'fail'), effective.globalPrivacyControl === false ? 'Global Privacy Control is disabled in Settings.' : (v.gpc ? 'navigator.globalPrivacyControl reports true and Sec-GPC is sent by the network layer.' : 'The JavaScript GPC signal was not observed as true.'), 'behavioral-test'));
      const screenOk = effective.privacyLevel === 'standard' || (Array.isArray(v.screen) && v.screen[0] === 1440 && v.screen[1] === 900 && v.screen[2] === 24 && v.screen[3] === 1);
      checks.push(makeCheck('screen-normalization', 'Screen metric normalization', screenOk ? 'pass' : 'warning',
        screenOk ? `Observed standardized screen metrics: ${(v.screen || []).join(' × ')}.` : `Observed screen metrics differ from the Strict/Maximum standard: ${(v.screen || []).join(' × ')}.`, 'behavioral-test'));
      checks.push(makeCheck('webgl-debug-info', 'WebGL debug renderer exposure', v.debugRendererInfo === false ? 'pass' : 'warning',
        v.debugRendererInfo === false ? 'WEBGL_debug_renderer_info is unavailable to the page.' : 'WebGL debug renderer information may remain queryable.', 'behavioral-test'));
      checks.push(makeCheck('ua-product-leak', 'Browser product identifier', /Aegis/i.test(String(v.userAgent || '')) ? 'warning' : 'pass',
        /Aegis/i.test(String(v.userAgent || '')) ? 'The page-visible JavaScript user agent contains an Aegis product token.' : 'The page-visible JavaScript user agent does not contain an Aegis product token.', 'behavioral-test'));
      const fontExpected = effective.privacyLevel !== 'standard';
      checks.push(makeCheck('font-metric-protection', 'CSS font enumeration resistance', !fontExpected ? 'info' : (v.fontMetricProtected ? 'pass' : 'fail'),
        !fontExpected ? 'Standard mode does not normalize off-screen CSS font metric probes.' : (v.fontMetricProtected ? 'Common off-screen font metric probes returned standardized geometry.' : 'Installed-font metric differences remain observable to the active page.'), 'behavioral-test'));
    } else {
      for (const [id,label] of [['privacy-api-guard','High-entropy & ad API guard'],['gpc-signal','Global Privacy Control'],['screen-normalization','Screen metric normalization'],['webgl-debug-info','WebGL debug renderer exposure'],['ua-product-leak','Browser product identifier'],['font-metric-protection','CSS font enumeration resistance']]) checks.push(makeCheck(id,label,'not-tested',surface.evidence,'behavioral-test'));
    }

    if (effective.privacyLevel !== 'standard' && tab.javascriptEnabled !== false) {
      const fpOne = await captureFingerprintSnapshot((source) => browserRuntime.evaluate(tab.view,source, true));
      const fpTwo = await captureFingerprintSnapshot((source) => browserRuntime.evaluate(tab.view,source, true));
      if (fpOne.status === 'pass' && fpTwo.status === 'pass') {
        const stability = compareFingerprintSnapshots(fpOne, fpTwo);
        checks.push(makeCheck('fingerprint-stability', 'Fingerprint surface stability', stability.status, stability.evidence, 'behavioral-test'));
        const v = fpOne.values || {};
        const coherent = /Chrome\//.test(String(v.ua || '')) && !/Aegis|Electron/i.test(String(v.ua || '')) && v.timezone === 'UTC' && v.hardwareConcurrency === 4 && v.deviceMemory === 8;
        checks.push(makeCheck('fingerprint-coherence', 'Fingerprint cohort coherence', coherent ? 'pass' : 'fail',
          coherent
            ? 'UA branding, timezone, CPU concurrency and memory report the standardized Aegis cohort values without Aegis/Electron product tokens.'
            : `Fingerprint cohort is internally inconsistent (timezone=${v.timezone || 'unknown'}, cores=${v.hardwareConcurrency}, memory=${v.deviceMemory}, ua=${String(v.ua || '').slice(0,120)}).`, 'behavioral-test'));
      } else {
        checks.push(makeCheck('fingerprint-stability', 'Fingerprint surface stability', 'not-tested', fpOne.evidence || fpTwo.evidence, 'behavioral-test'));
        checks.push(makeCheck('fingerprint-coherence', 'Fingerprint cohort coherence', 'not-tested', fpOne.evidence || fpTwo.evidence, 'behavioral-test'));
      }
    } else if (tab.javascriptEnabled === false) {
      checks.push(makeCheck('fingerprint-stability', 'Fingerprint surface stability', 'info', 'JavaScript is disabled in this renderer, so script-based fingerprint sampling is intentionally unavailable.', 'behavioral-test'));
      checks.push(makeCheck('fingerprint-coherence', 'Fingerprint cohort coherence', 'info', 'JavaScript is disabled; network-visible identity is evaluated separately from script-visible surfaces.', 'behavioral-test'));
    }

    const webrtc = await testWebRtcLeakSurface((source) => browserRuntime.evaluate(tab.view,source, true));
    const webrtcStatus = effective.disableWebRtc && webrtc.status === 'not-tested' ? 'pass' : webrtc.status;
    const webrtcEvidence = effective.disableWebRtc && webrtc.status === 'not-tested'
      ? 'WebRTC is removed from the anonymous compartment, so no peer-connection candidate surface is available.'
      : webrtc.evidence;
    checks.push(makeCheck('webrtc-behavior', 'WebRTC local-IP behavioral test', webrtcStatus, webrtcEvidence, 'behavioral-test'));

    if (tab.securityDomain === 'hardened' || tab.securityDomain === 'anonymous') {
      checks.push(makeCheck('compartment-policy', 'Compartment hardening', (tab.disableExtensions && !tab.allowHttp && !tab.compatibilityMode && effective.blockThirdPartyRequests) ? 'pass' : 'fail',
        tab.disableExtensions && !tab.allowHttp && !tab.compatibilityMode && effective.blockThirdPartyRequests
          ? 'Extensions are disabled, HTTP downgrade is off, compatibility mode is off, and all third-party requests are blocked.'
          : 'One or more compartment hardening controls are not active.', 'runtime-policy'));
      checks.push(makeCheck('compartment-service-workers', 'Service worker isolation', effective.disableServiceWorkers ? 'pass' : 'fail',
        effective.disableServiceWorkers ? 'Service-worker registration is blocked by the compartment privacy preload.' : 'Service workers remain enabled.', 'runtime-policy'));
    }
    if (tab.securityDomain === 'anonymous') {
      checks.push(makeCheck('anonymous-tor-route', 'Tor route verification', tab.torVerified ? 'pass' : 'fail',
        tab.torVerified ? 'The Tor Project verification endpoint confirmed the active anonymous tab route.' : 'The anonymous tab has not verified its route as Tor and remains fail-closed.', 'external-proof'));
      checks.push(makeCheck('anonymous-lan-block', 'Local-network isolation', effective.blockPrivateNetwork ? 'pass' : 'fail',
        effective.blockPrivateNetwork ? 'localhost, .local, loopback, link-local and private IPv4/IPv6 literals are blocked in this compartment.' : 'Local/private-network blocking is disabled.', 'runtime-policy'));
      checks.push(makeCheck('anonymous-downloads', 'Anonymous download isolation', effective.blockAllDownloads ? 'pass' : 'warning',
        effective.blockAllDownloads ? 'Downloads are blocked so files cannot be casually opened outside the anonymous route.' : 'Downloads are allowed in the anonymous compartment.', 'runtime-policy'));
      const anonymousJsOff = tab.javascriptEnabled === false;
      checks.push(makeCheck('anonymous-javascript', 'Anonymous active-content isolation', effective.javascriptDefault === false ? (anonymousJsOff ? 'pass' : 'fail') : 'warning',
        effective.javascriptDefault === false
          ? (anonymousJsOff ? 'JavaScript is disabled in this anonymous renderer, sharply reducing active fingerprinting and script attack surface.' : 'Anonymous policy requests JavaScript shutdown, but the active renderer still reports JavaScript enabled.')
          : 'JavaScript is intentionally enabled for anonymous browsing compatibility; this increases fingerprinting and active-content exposure.', 'runtime-policy'));
    }
  } else {
    for (const [id,label] of [
      ['renderer-isolation','Renderer isolation'],['permission-firewall','Permission firewall'],['fingerprint-defense','Fingerprint normalization'],
      ['cosmetic-filtering','Cosmetic ad filtering'],['https-first','HTTPS-first navigation'],['privacy-api-guard','High-entropy & ad API guard'],
      ['gpc-signal','Global Privacy Control'],['screen-normalization','Screen metric normalization'],['webgl-debug-info','WebGL debug renderer exposure'],
      ['ua-product-leak','Browser product identifier'],['font-metric-protection','CSS font enumeration resistance'],['webrtc-behavior','WebRTC local-IP behavioral test']
    ]) checks.push(makeCheck(id, label, 'not-tested', 'No active web tab.', 'runtime'));
  }

  checks.push(makeCheck('webrtc-startup-policy', 'WebRTC non-proxied UDP policy', 'pass',
    'Chromium is launched with force-webrtc-ip-handling-policy=disable_non_proxied_udp.', 'startup-policy'));
  checks.push(makeCheck('site-isolation', 'Site-per-process isolation', 'pass',
    'Chromium is launched with site-per-process and every normal tab uses its own non-persistent session partition.', 'startup-policy'));
  const assurance = new Map((tab ? controlAssurance(effective, tab) : []).map((item) => [item.key, item]));
  const addControlCheck = (key, id, label) => {
    const item = assurance.get(key);
    if (!effective[key]) return checks.push(makeCheck(id, label, 'warning', 'Disabled in Settings.', 'runtime-policy'));
    if (!tab || !item) return checks.push(makeCheck(id, label, 'not-tested', 'No active web tab is available to confirm enforcement.', 'runtime-policy'));
    return checks.push(makeCheck(id, label, item.status === 'enforced' ? 'pass' : 'fail', item.evidence, 'runtime-policy'));
  };
  addControlCheck('blockThirdPartyCookies', 'third-party-cookies', 'Third-party cookie defense');
  addControlCheck('blockTrackers', 'tracker-blocking', 'Generic tracker network filtering');
  addControlCheck('blockAds', 'ad-blocking', 'Ad network filtering');
  addControlCheck('blockSocialTrackers', 'social-blocking', 'Social tracker filtering');
  addControlCheck('blockCryptominers', 'cryptominer-blocking', 'Cryptominer filtering');
  addControlCheck('blockFingerprintingScripts', 'fingerprinting-script-blocking', 'Fingerprinting-script filtering');
  addControlCheck('blockTrackingBeacons', 'tracking-beacons', 'Tracking beacon guard');
  if (tab?.securityDomain === 'hardened' || tab?.securityDomain === 'anonymous') {
    addControlCheck('blockThirdPartyRequests', 'third-party-request-isolation', 'All third-party request isolation');
    addControlCheck('letterbox', 'viewport-letterbox', 'Viewport letterboxing');
  }
  if (tab?.securityDomain === 'anonymous') {
    addControlCheck('disableWebRtc', 'webrtc-shutdown', 'WebRTC exposure shutdown');
    addControlCheck('blockPrivateNetwork', 'private-network-firewall', 'Private-network firewall');
    addControlCheck('blockAllDownloads', 'download-shutdown', 'Anonymous download shutdown');
  }
  checks.push(makeCheck('tls-fingerprint', 'TLS fingerprint visibility', 'info',
    'Sites can still observe Chromium TLS characteristics (for example JA3/JA4-style fingerprints). Aegis does not claim to rewrite the Chromium TLS stack.', 'known-limit'));

  if (tab && effective.privacyLevel !== 'standard' && tab.javascriptEnabled !== false) {
    const liveTabs = tabs.filter((candidate) =>
      candidate?.id !== tab.id &&
      candidate?.securityDomain === tab.securityDomain &&
      candidate?.javascriptEnabled !== false &&
      candidate?.fingerprintReady &&
      candidate?.view?.webContents &&
      !browserRuntime.destroyed(candidate.view)
    ).slice(0, 2);
    if (liveTabs.length) {
      const samples = [await captureFingerprintSnapshot((source) => browserRuntime.evaluate(tab.view,source, true))];
      for (const candidate of liveTabs) {
        samples.push(await captureFingerprintSnapshot((source) => browserRuntime.evaluate(candidate.view,source, true)));
      }
      const cohort = compareFingerprintCohort(samples);
      checks.push(makeCheck('cross-tab-cohort', 'Cross-tab fingerprint cohort', cohort.status, cohort.evidence, 'behavioral-test'));
    } else {
      checks.push(makeCheck('cross-tab-cohort', 'Cross-tab fingerprint cohort', 'not-tested', 'Open a second tab in the same security compartment to compare the exposed fingerprint cohort across isolated renderer sessions.', 'behavioral-test'));
    }
  }

  const isolation = await testSessionIsolation((suffix) => browserRuntime.session(`aegis-suite-${suffix}-${crypto.randomUUID()}`, { cache: false }));
  checks.push(makeCheck('session-isolation', 'Ephemeral session isolation', isolation.status, isolation.evidence, 'behavioral-test'));

  const ses = browserRuntime.session(`aegis-security-suite-${crypto.randomUUID()}`, { cache: false });
  let route = null;
  let connectivity = null;
  let publicIp = { ok: false, status: 'not-tested', ip: '', provider: '', error: 'Not tested.' };
  try {
    const diagnosticMode = effective.proxy?.mode || 'system';
    route = await applyProxyCore(ses, effective.proxy || {},  {
      failClosedFixedProxy: !['system','direct'].includes(diagnosticMode),
      freshSession: diagnosticMode === 'system'
    });
    if (!route?.ok) throw new Error((route?.warnings || []).join(' | ') || 'Network route could not be applied.');
    const routeStatus = routePrivacyStatus(effective.proxy?.mode || 'system', route);
    checks.push(makeCheck('network-route', 'IP routing posture', routeStatus.status, routeStatus.evidence, 'runtime-policy'));

    const expectedNetworkUa = buildGenericUA(process.versions.chrome);
    configurePrivacySession({
      ses, tab: { url:'https://example.com/', topUrl:'https://example.com/', stats:createStats() },
      getSettings:()=>effective, chromiumVersion:process.versions.chrome, onStats:()=>{},
      onPermissionBlocked:()=>{}, onPermissionPrompt:({ complete })=>complete(false),
      onSensitiveAccess:()=>{}, onNetworkAccess:()=>{}, trackerLearner:null, getFilterRules:()=>null, isTemporarilyAllowed:()=>false
    });
    const storageProbe = await testStorageResurrection(ses);
    checks.push(makeCheck('storage-resurrection', 'Storage resurrection cleanup', storageProbe.status, storageProbe.evidence, 'behavioral-test'));

    const networkIdentity = await testNetworkIdentity(ses, {
      ua: expectedNetworkUa, doNotTrack: effective.doNotTrack, globalPrivacyControl: effective.globalPrivacyControl
    });
    checks.push(makeCheck('network-identity-coherence', 'Network / JavaScript identity coherence', networkIdentity.status, networkIdentity.evidence, 'behavioral-test'));

    connectivity = await runConnectivityTest(ses, { target: 'https://duckduckgo.com/', proxyMode: effective.proxy?.mode || 'system' });
    checks.push(makeCheck('dns-https', 'DNS + HTTPS reachability', connectivity.ok ? 'pass' : 'fail',
      `Proxy ${connectivity.proxy || 'unknown'}; DNS ${connectivity.dns || 'unknown'}; HTTPS ${connectivity.https || 'unknown'}.`, 'behavioral-test'));

    publicIp = await fetchPublicIp(ses);
    checks.push(makeCheck('public-ip', 'Observed public IP', publicIp.status,
      publicIp.ok ? `Destination sites can observe ${publicIp.ip} through the configured Chromium route (${publicIp.provider}). This is evidence of the route, not proof of anonymity.` : `Public IP lookup failed: ${publicIp.error}`, 'external-proof'));
  } catch (err) {
    checks.push(makeCheck('network-route', 'IP routing posture', 'fail', `Routing configuration failed: ${err.message}`, 'runtime-policy'));
    checks.push(makeCheck('dns-https', 'DNS + HTTPS reachability', 'fail', `Routing/connectivity test failed: ${err.message}`, 'behavioral-test'));
    checks.push(makeCheck('public-ip', 'Observed public IP', 'not-tested', 'Public IP could not be checked because the disposable routed session failed.', 'external-proof'));
  } finally {
    try { await ses.clearData(); } catch {}
    try { await ses.clearCache(); } catch {}
    try { await ses.closeAllConnections(); } catch {}
  }

  lastSecuritySuite = {
    testedAt,
    publicIp,
    route: route ? { ok: route.ok, mode: route.mode, warnings: route.warnings || [], fallback: Boolean(route.fallback), inheritedSystemRoute: Boolean(route.inheritedSystemRoute) } : null,
    connectivity,
    checks,
    summary: summarizeChecks(checks)
  };
  emitState();
  return lastSecuritySuite;
}

function errorPageUrl(raw, code, description, offerHttp = false) {
  const q = new URLSearchParams({ url: String(raw || ''), code: String(code || ''), description: String(description || 'Page could not be loaded'), offerHttp: offerHttp ? '1' : '0' });
  return `aegis://app/error.html?${q.toString()}`;
}

async function showLoadError(tab, raw, code, description) {
  if (!tab || !raw || String(raw).startsWith('aegis://')) return;
  const errorKey = `${raw}|${code}`;
  const now = Date.now();
  if (tab._lastErrorKey === errorKey && now - (tab._lastErrorAt || 0) < 1200) return;
  tab._lastErrorKey = errorKey; tab._lastErrorAt = now;
  tab.loading = false;
  tab.lastError = { url: raw, code: Number(code || 0), description: String(description || 'Page could not be loaded') };
  tab.stats.loadFailures += 1;
  emitState();
  const effective = tabSettings(tab);
  const offerHttp = effective.compatibilityAssistance && !effective.anonymousRouteRequired && tab.securityDomain !== 'hardened' && failedHttpsCanOfferHttp(raw, code);
  try { await browserRuntime.load(tab.view,errorPageUrl(raw, code, description, offerHttp)); } catch {}
}

function assertUiSender(event) {
  try { return event.senderFrame.url.startsWith('aegis://app/'); } catch { return false; }
}

function activeTab() { return tabs.get(activeId); }

function serializeTab(tab) {
  const nav = browserRuntime.history(tab.view);
  return {
    id: tab.id,
    title: tab.title,
    url: tab.url,
    origin: safeOrigin(tab.url),
    loading: tab.loading,
    canGoBack: nav.canGoBack(),
    canGoForward: nav.canGoForward(),
    shieldsEnabled: tab.shieldsEnabled,
    allowHttp: tab.allowHttp,
    javascriptEnabled: tab.javascriptEnabled,
    compatibilityMode: tab.compatibilityMode,
    bookmarked: Boolean(bookmarkForUrl(tab.url)),
    lastError: tab.lastError,
    safety: tab.safety || { risk: 0, warnings: [] },
    fingerprintReady: Boolean(tab.fingerprintReady),
    fingerprintStatus: tab.fingerprintStatus || null,
    extensionIds: Array.isArray(tab.extensionIds) ? tab.extensionIds : [],
    privacySessionReady: Boolean(tab.privacySessionReady),
    networkRoute: tab.networkRoute || null,
    securityDomain: tab.securityDomain || 'private',
    securityDomainLabel: domainLabel(tab),
    hardenedAt: tab.hardenedAt || null,
    anonymousAt: tab.anonymousAt || null,
    disableExtensions: Boolean(tab.disableExtensions),
    torVerified: Boolean(tab.torVerified),
    sponsorSegments: tab.sponsorSegments || 0,
    siteIntelligence: publicSiteIntelligence(tab),
    stats: tab.stats
  };
}

function statePayload() {
  const currentTab = activeTab();
  const currentSettings = tabSettings(currentTab);
  return {
    activeId,
    tabs: [...tabs.values()].map(serializeTab),
    settings,
    searchEngines: SEARCH_ENGINES,
    bookmarks,
    downloads: downloads.map(({ path: _path, ...item }) => item),
    network: { lastTest: lastNetworkTest, proxyMode: currentSettings.proxy?.mode || 'system', securityDomain: currentTab?.securityDomain || 'private', torVerified: Boolean(currentTab?.torVerified) },
    securitySuite: lastSecuritySuite,
    securityEvents: securityEvents.list(activeId).slice(0,100),
    securityKernel: { ...securityKernel.evidence(), audit: kernelAudit.verify(), risk: riskEngine.score({tabId:activeId}) },
    extensions: extensionRuntime ? extensionRuntime.list() : [],
    privacyControls: controlAssurance(currentSettings, currentTab),
    engine: {
      appVersion: app.getVersion(),
      electron: process.versions.electron,
      chromium: process.versions.chrome,
      node: process.versions.node,
      platform: process.platform,
      arch: process.arch
    },
    privacySummary: {
      ephemeralTabs: true,
      fingerprinting: currentSettings.privacyLevel,
      webrtc: currentSettings.disableWebRtc ? 'disabled in this compartment' : 'non-proxied UDP disabled',
      tlsMinimum: 'TLS 1.2',
      telemetry: 'off',
      history: 'not stored'
    }
  };
}

function emitState() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.webContents.send('state', statePayload());
}

function toast(message, tone = 'default') {
  if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('toast', { message: String(message), tone });
}
function queuePermissionPrompt({ tabId, origin, keys, complete }) {
  if (!origin || !keys?.length || !mainWindow || mainWindow.isDestroyed()) return complete(false);
  const id = crypto.randomUUID();
  const timer = setTimeout(() => {
    const pending = pendingPermissions.get(id);
    if (!pending) return;
    pendingPermissions.delete(id);
    try { pending.complete(false); } catch {}
    try { mainWindow.webContents.send('permission:closed', { id }); } catch {}
  }, 20000);
  pendingPermissions.set(id, { tabId: Number(tabId) || 0, origin, keys, complete, timer });
  mainWindow.webContents.send('permission:prompt', { id, origin, keys });
}

function resolvePermissionPrompt(id, action) {
  const pending = pendingPermissions.get(String(id || ''));
  if (!pending) return;
  pendingPermissions.delete(String(id));
  clearTimeout(pending.timer);
  let allow = action === 'allow-once' || action === 'allow-10m' || action === 'allow-always';
  if (action === 'allow-10m') {
    for (const key of pending.keys) grantTemporaryPermission(pending.tabId, pending.origin, key);
  } else if (action === 'allow-always') {
    for (const key of pending.keys) { clearTemporaryPermissionsForOrigin(pending.origin); applySitePermission(pending.origin, key, 'allow'); }
  } else if (action === 'block-always') {
    for (const key of pending.keys) { clearTemporaryPermissionsForOrigin(pending.origin); applySitePermission(pending.origin, key, 'block'); }
  }
  try { pending.complete(allow); } catch {}
  try { mainWindow.webContents.send('permission:closed', { id: String(id) }); } catch {}
}

function normalizeUiLayer(payload) {
  const mode = ['none', 'hidden', 'reserve-right'].includes(payload?.mode) ? payload.mode : 'none';
  const reserveRight = mode === 'reserve-right' ? Math.max(0, Math.min(1000, Math.round(Number(payload?.reserveRight) || 0))) : 0;
  return { mode, reserveRight };
}

function applyUiLayer(payload) {
  uiLayer = normalizeUiLayer(payload);
  const active = activeTab();
  for (const tab of tabs.values()) {
    const shouldShow = Boolean(active && tab.id === active.id && uiLayer.mode !== 'hidden');
    try { tab.view.setVisible(shouldShow); } catch {}
  }
  relayout();
}

function relayout() {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  const b = mainWindow.getContentBounds();
  const tab = activeTab();
  if (!tab) return;

  if (uiLayer.mode === 'hidden') {
    try { tab.view.setVisible(false); } catch {}
    return;
  }

  const reserved = uiLayer.mode === 'reserve-right' ? Math.min(uiLayer.reserveRight, Math.max(0, b.width - 420)) : 0;
  const availableW = Math.max(320, b.width - reserved);
  const availableH = Math.max(240, b.height - TOOLBAR_H);
  let w = availableW;
  let h = availableH;
  let x = 0;
  let y = TOOLBAR_H;

  const effective = tabSettings(tab);
  if (effective.letterbox && effective.privacyLevel !== 'standard') {
    w = Math.max(300, Math.floor(availableW / LETTERBOX_STEP) * LETTERBOX_STEP);
    h = Math.max(200, Math.floor(availableH / LETTERBOX_STEP) * LETTERBOX_STEP);
    x = Math.floor((availableW - w) / 2);
    y = TOOLBAR_H + Math.floor((availableH - h) / 2);
  }
  tab.view.setBounds({ x, y, width: w, height: h });
  try { tab.view.setVisible(true); } catch {}
}

function chromiumMajor() { return String(browserEngine.version() || '152').split('.')[0]; }

async function installFingerprintDefenses(tab) {
  
  const dbg = tab?.view?.webContents?.debugger;
  const effective = tabSettings(tab);
  tab.fingerprintStatus = { debugger:false, page:false, timezone:false, locale:false, fingerprintPreload:false, privacyPreload:false, sentinelPreload:false, errors:[], policy:fingerprintPolicyEvidence(fingerprintPolicyFor({profile:effective.privacyLevel,anonymousMode:effective.anonymousRouteRequired===true,disableWebRtc:effective.disableWebRtc===true,chromiumMajor:chromiumMajor()})) };
  if (!dbg) { tab.fingerprintStatus.errors.push('Debugger interface unavailable.'); return false; }
  const step = async (name, fn, required = false) => {
    try { await fn(); tab.fingerprintStatus[name] = true; return true; }
    catch (err) { tab.fingerprintStatus.errors.push(name + ': ' + err.message); if (required) console.error('Required privacy preload step failed:', name, err.message); else console.warn('Optional privacy preload step failed:', name, err.message); return false; }
  };
  try {
    if (!browserRuntime.inspectorAttached(tab.view)) browserRuntime.attachInspector(tab.view,'1.3');
    tab.fingerprintStatus.debugger = true;
  } catch (err) {
    tab.fingerprintStatus.errors.push('debugger: ' + err.message);
    return false;
  }

  await step('page', () => withTimeout(browserRuntime.command(tab.view,'Page.enable'), 1800, 'Fingerprint Page.enable'), true);
  await step('runtime', () => withTimeout(browserRuntime.command(tab.view,'Runtime.enable'), 1800, 'Privacy Runtime.enable'));

  if (effective.privacyLevel !== 'standard') {
    await step('timezone', () => withTimeout(browserRuntime.command(tab.view,'Emulation.setTimezoneOverride', { timezoneId: 'UTC' }), 1400, 'Timezone defense'));
    await step('locale', () => withTimeout(browserRuntime.command(tab.view,'Emulation.setLocaleOverride', { locale: 'en-US' }), 1400, 'Locale defense'));
  }

  const fpSource = buildAntiFingerprintScript({ seed: identitySeed + ':' + tab.seed, chromiumMajor: chromiumMajor(), profile: effective.privacyLevel, disableServiceWorkers: effective.disableServiceWorkers, globalPrivacyControl: effective.globalPrivacyControl, doNotTrack: effective.doNotTrack, anonymousMode: effective.anonymousRouteRequired === true, disableWebRtc: effective.disableWebRtc === true });
  await step('fingerprintPreload', () => withTimeout(browserRuntime.command(tab.view,'Page.addScriptToEvaluateOnNewDocument', { source: fpSource }), 1800, 'Fingerprint preload'), true);

  const privacySource = buildPagePrivacyScript({
    maximum: effective.privacyLevel === 'maximum',
    privacyApiGuard: effective.privacyApiGuard !== false,
    blockTrackingBeacons: effective.blockTrackingBeacons !== false,
    globalPrivacyControl: effective.globalPrivacyControl !== false
  });
  await step('privacyPreload', () => withTimeout(browserRuntime.command(tab.view,'Page.addScriptToEvaluateOnNewDocument', { source: privacySource }), 1800, 'Page privacy preload'), true);

  if (effective.siteIntelligence !== false) {
    const bindingName = '__aegisAudit_' + tab.seed.slice(0, 12);
    tab.auditBinding = bindingName;
    const bindingReady = await step('sentinelBinding', () => withTimeout(browserRuntime.command(tab.view,'Runtime.addBinding', { name: bindingName }), 1400, 'Sentinel binding'));
    if (bindingReady) {
      if (!tab.auditMessageHandler && typeof dbg.on === 'function') {
        tab.auditMessageHandler = (_event, method, params) => {
          if (tabSettings(tab).siteIntelligence === false || method !== 'Runtime.bindingCalled' || params?.name !== tab.auditBinding) return;
          try { const payload = JSON.parse(String(params.payload || '{}')); if (recordSiteSignal(tab, payload)) emitState(); } catch {}
        };
        browserRuntime.onInspectorMessage(tab.view, tab.auditMessageHandler);
      }
      await step('sentinelPreload', () => withTimeout(browserRuntime.command(tab.view,'Page.addScriptToEvaluateOnNewDocument', { source: buildSiteAuditScript({ bindingName }) }), 1800, 'Sentinel preload'));
    }
  }

  tab.fingerprintReady = Boolean(tab.fingerprintStatus.page && tab.fingerprintStatus.fingerprintPreload && tab.fingerprintStatus.privacyPreload);
  return tab.fingerprintReady;
}


function applySessionDownloadPolicy(tab) {
  browserRuntime.downloads(browserRuntime.sessionOf(tab.view), (event, item) => {
    const effective = tabSettings(tab);
    const filename = item.getFilename();
    if (effective.blockAllDownloads) {
      event.preventDefault();
      tab.stats.blockedDownloads += 1;
      scheduleStateEmit();
      toast('Downloads are blocked in the anonymous compartment. Open the page in a normal private tab if you intentionally need a file.', 'warning');
      return;
    }
    if (effective.blockRiskyDownloads && isRiskyDownload(filename)) {
      event.preventDefault();
      tab.stats.blockedDownloads += 1;
      emitState();
      toast(`Blocked high-risk download: ${filename}`, 'danger');
      return;
    }
    const rec = addDownloadRecord(item, tab);
    activeDownloadItems.set(rec.id, item);
    const target = defaultDownloadPath(app, filename);
    rec.path = target;
    try { fs.mkdirSync(path.dirname(target), { recursive: true }); } catch {}
    item.setSavePath(target);
    item.on('updated', (_e, state) => updateDownloadRecord(rec, item, state));
    item.once('done', (_e, state) => {
      updateDownloadRecord(rec, item, state);
      activeDownloadItems.delete(rec.id);
      if (state === 'completed') {
        try {
          const stat=fs.statSync(target);
          const hash=crypto.createHash('sha256');
          const stream=fs.createReadStream(target);
          stream.on('data',(chunk)=>hash.update(chunk));
          stream.on('end',()=>{
            rec.sha256=hash.digest('hex');
            rec.sizeVerified=stat.size === rec.receivedBytes || rec.receivedBytes === 0;
            const ext=path.extname(filename).toLowerCase();
            const mime=String(rec.mimeType||'').toLowerCase();
            const suspicious=(mime.includes('html') && !['.html','.htm'].includes(ext)) || (mime.includes('javascript') && !['.js','.mjs'].includes(ext)) || (mime.includes('executable') && !isRiskyDownload(filename));
            rec.contentWarning=suspicious ? 'Server MIME type does not match the apparent file extension.' : '';
            emitState();
          });
          stream.on('error',()=>{ rec.contentWarning='Could not hash downloaded file.'; emitState(); });
        } catch { rec.contentWarning='Could not verify downloaded file on disk.'; emitState(); }
      }
      toast(state === 'completed' ? `Download saved: ${filename}` : `Download ${state}: ${filename}`, state === 'completed' ? 'success' : 'warning');
    });
  });
}

async function applyProxyToSession(ses, options = {}, tab = null) {
  const effective = tabSettings(tab);
  const proxy = effective.proxy || settings.proxy || {};
  const result = await applyProxyCore(ses, proxy, {
    failClosedFixedProxy: Boolean(proxy?.failClosedFixedProxy),
    freshSession: Boolean(options.freshSession)
  });
  if (result.warnings?.length) console.warn('Aegis network routing warning:', result.warnings.join(' | '));
  return result;
}

const REMOTE_RENDERER_POLICY = Object.freeze({
  sandbox: true,
  contextIsolation: true,
  nodeIntegration: false,
  nodeIntegrationInSubFrames: false,
  webSecurity: true,
  allowRunningInsecureContent: false,
  webviewTag: false,
  plugins: false,
  spellcheck: false,
  safeDialogs: true,
  devTools: false,
  autoplayPolicy: 'document-user-activation-required',
  v8CacheOptions: 'none',
  navigateOnDragDrop: false,
  enableWebSQL: false,
  transparent: false
});

function createTabView(tab) {
  tab.rendererPolicy = { ...REMOTE_RENDERER_POLICY };
  const view = browserRuntime.view({
      ...REMOTE_RENDERER_POLICY,
      preload: path.join(__dirname, 'extension-bridge-preload.js'),
      additionalArguments: extensionRuntime ? extensionRuntime.bridgeArguments() : [],
      session: tab.privateSession,
      javascript: Boolean(tab.javascriptEnabled)
  });
  browserRuntime.zoomMode(view,'isolated');
  return view;
}

function isFireproofOrigin(origin) {
  if (!origin) return false;
  try {
    const host = new URL(origin).hostname.toLowerCase();
    return (settings.fireproofSites || []).some((entry) => {
      try { const h = new URL(entry.includes('://') ? entry : `https://${entry}`).hostname.toLowerCase(); return host === h || host.endsWith(`.${h}`); } catch { return false; }
    });
  } catch { return false; }
}

function scheduleOriginCleanup(tab, oldOrigin, newOrigin) {
  if (!settings.cookieAutoDelete || !oldOrigin || oldOrigin === newOrigin || isFireproofOrigin(oldOrigin)) return;
  const oldHost = (() => { try { return registrableLike(new URL(oldOrigin).hostname); } catch { return ''; } })();
  const newHost = (() => { try { return registrableLike(new URL(newOrigin).hostname); } catch { return ''; } })();
  if (!oldHost || oldHost === newHost) return;
  clearTimeout(tab.cookieCleanupTimer);
  tab.cookieCleanupTimer = setTimeout(async () => {
    try {
      await tab.privateSession.clearData({ dataTypes: ['cookies','localStorage','indexedDB','serviceWorkers','cache'], origins: [oldOrigin], originMatchingMode: 'origin-in-all-contexts' });
      tab.stats.siteDataCleanups = (tab.stats.siteDataCleanups || 0) + 1;
      emitState();
    } catch (err) { console.warn('Site data auto-clean failed:', err.message); }
  }, Math.max(0, Number(settings.cookieAutoDeleteDelaySec || 0)) * 1000);
}

async function applyCosmeticFiltering(tab) {
  if (!tab?.view?.webContents || browserRuntime.destroyed(tab.view)) return false;
  if (tab.cosmeticCssKey) {
    try { await browserRuntime.removeCSS(tab.view,tab.cosmeticCssKey); } catch {}
    tab.cosmeticCssKey = '';
  }
  const effective = tabSettings(tab);
  const enabled = effective.cosmeticFiltering !== false && tab.shieldsEnabled && !tab.compatibilityMode;
  if (!enabled) { tab.cosmeticFilteringReady = false; return false; }
  try {
    let cosmeticHost='';try{cosmeticHost=new URL(tab.url||'').hostname;}catch{}
    const customSelectors=cosmeticSelectorsForHost(cosmeticHost,filterRules);
    tab.cosmeticCssKey = await browserRuntime.css(tab.view,cosmeticCss(customSelectors), { cssOrigin: 'user' });
    tab.cosmeticFilteringReady = true;
    return true;
  } catch (err) {
    tab.cosmeticFilteringReady = false;
    console.warn('Cosmetic filtering could not be applied:', err.message);
    return false;
  }
}

async function applySponsorProtection(tab) {
  const effective = tabSettings(tab);
  if (!effective.sponsorBlock?.enabled || !tab?.url) return;
  const videoId = youtubeVideoId(tab.url); if (!videoId) return;
  try {
    const segments = await fetchSponsorSegments(tab.privateSession, videoId, effective.sponsorBlock.categories);
    if (!segments.length || browserRuntime.destroyed(tab.view)) return;
    await browserRuntime.evaluate(tab.view,sponsorSkipScript(segments), true);
    tab.sponsorSegments = segments.length;
    emitState();
  } catch (err) { console.warn('Sponsor protection unavailable:', err.message); }
}

function wireTabView(tab, view) {
  browserRuntime.windows(view,({ url }) => {
    const effective=tabSettings(tab);const rule=matchFilterRules(url,filterRules,{topUrl:tab.url||url,resourceType:'popup'});
    if(rule==='block'||!isAllowedNavigation(url)){tab.stats.blockedPopups+=1;scheduleStateEmit();return {action:'deny'};}
    createTab(url,true);return {action:'deny'};
  });

  browserRuntime.on(view,'context-menu', (_event, params) => showTabContextMenu(tab, params));

  browserRuntime.on(view,'will-navigate', (event, legacyDetails) => {
    const original = navigationUrl(event, legacyDetails);
    const effective = tabSettings(tab);
    const url = cleanNavigationUrl(original, { strip: effective.stripTrackingParams, unwrap: effective.unwrapTrackingLinks });
    const managed=securityKernel.navigate({url,tab});
    if (!url || !isAllowedNavigation(url) || !managed.allow || !shouldAllowInternalNavigation(browserRuntime.url(view), url)) {
      event.preventDefault(); toast(`Blocked unsafe navigation${url ? `: ${String(url).split(':')[0]}:` : '.'}`, 'danger'); return;
    }
    if (url !== original) {
      event.preventDefault(); tab.stats.trackingParamsRemoved += 1; emitState();
      browserRuntime.load(view,url).catch((err) => showLoadError(tab, url, err?.errno, err?.message)); return;
    }
    tab.safety = effective.threatProtection ? analyzeUrl(url) : { risk: 0, warnings: [] };
    if (tab.safety.risk >= 50) toast(`Caution: ${tab.safety.warnings[0]}`, 'warning');
    if (shouldUpgradeHttp(url, tab.allowHttp)) {
      event.preventDefault(); tab.stats.httpsUpgrades += 1; emitState();
      browserRuntime.load(view,upgradeToHttps(url)).catch((err) => showLoadError(tab, upgradeToHttps(url), err?.errno, err?.message));
    }
  });

  browserRuntime.on(view,'will-frame-navigate', (event, legacyDetails, _isInPlace, legacyIsMainFrame) => {
    const url = navigationUrl(event, legacyDetails);
    const isMainFrame = navigationIsMainFrame(event, legacyIsMainFrame);
    if (!url || !isAllowedNavigation(url) || (isMainFrame && !shouldAllowInternalNavigation(browserRuntime.url(view), url))) event.preventDefault();
  });
  browserRuntime.on(view,'will-redirect', (event, legacyDetails) => {
    const original = navigationUrl(event, legacyDetails);
    const effective = tabSettings(tab);
    const url = cleanNavigationUrl(original, { strip: effective.stripTrackingParams, unwrap: effective.unwrapTrackingLinks });
    const managed=securityKernel.redirect({url,tab});
    if (!url || !isAllowedNavigation(url) || !managed.allow || !shouldAllowInternalNavigation(browserRuntime.url(view), url)) { event.preventDefault(); toast('Blocked unsafe or enterprise-restricted redirect.', 'danger'); return; }
    if (url !== original) { event.preventDefault(); tab.stats.trackingParamsRemoved += 1; emitState(); browserRuntime.load(view,url).catch(() => {}); }
  });
  browserRuntime.on(view,'did-start-navigation', (event, legacyDetails, _isInPlace, legacyIsMainFrame) => {
    const url = navigationUrl(event, legacyDetails);
    const isMainFrame = navigationIsMainFrame(event, legacyIsMainFrame);
    if (!isMainFrame || !url || String(url).startsWith('aegis://')) return;
    tab.extensionInjectionKeys = new Set();
    tab.extensionIds = [];
    const nextOrigin = safeOrigin(url);
    if (tab.siteIntelligence?.url !== url) { resetSiteIntelligence(tab, url, nextOrigin); emitState(); }
  });
  browserRuntime.on(view,'did-start-loading', () => { tab.loading = true; emitState(); });
  browserRuntime.on(view,'dom-ready', () => {
    extensionRuntime?.inject(tab, 'end').then((ids) => {
      tab.extensionIds = [...new Set([...(tab.extensionIds || []), ...ids])];
      emitState();
    }).catch((err) => console.warn('Extension document-end injection failed:', err.message));
  });
  browserRuntime.on(view,'did-stop-loading', () => { tab.loading = false; emitState(); });
  browserRuntime.on(view,'page-title-updated', (event, title) => {
    event.preventDefault();
    tab.title = String(title || 'Tab').replace(/\s+/g, ' ').slice(0, 90);
    emitState();
  });
  browserRuntime.on(view,'did-navigate', (_event, url, httpResponseCode = -1, httpStatusText = '') => {
    const oldOrigin = safeOrigin(tab.url); const newOrigin = safeOrigin(url);
    tab.url = url; tab.topUrl = url; tab.safety = tabSettings(tab).threatProtection ? analyzeUrl(url) : { risk: 0, warnings: [] };
    if (!String(url).startsWith('aegis://app/error')) tab.lastError = null;
    tab.httpStatus = { code: httpResponseCode, text: httpStatusText };
    const effective = tabSettings(tab);
    if (effective.bounceTrackingProtection && oldOrigin && newOrigin && oldOrigin !== newOrigin) {
      noteNavigation(tab.bounceTracker, tab.url || oldOrigin, url);
      const bounce = detectBounce(tab.bounceTracker, effective.bounceTrackingWindowSec);
      if (bounce?.intermediaryOrigin && bounce.intermediaryOrigin !== newOrigin) {
        securityEvents.add('bounce-tracker-purge','warning',{intermediary:bounce.intermediaryHost,destination:bounce.destinationHost,elapsedMs:bounce.elapsedMs},tab.id);
        tab.privateSession.clearData({
          dataTypes:['cookies','localStorage','indexedDB','serviceWorkers','cacheStorage'],
          origins:[bounce.intermediaryOrigin], originMatchingMode:'origin-in-all-contexts'
        }).then(()=>{ tab.bouncePurges=(tab.bouncePurges||0)+1; scheduleStateEmit(); }).catch(()=>{});
      }
    } else if (newOrigin) {
      noteNavigation(tab.bounceTracker, oldOrigin || newOrigin, url);
    }
    scheduleOriginCleanup(tab, oldOrigin, newOrigin); emitState();
  });
  browserRuntime.on(view,'did-finish-load', () => {
    applyCosmeticFiltering(tab);
    applySponsorProtection(tab);
    extensionRuntime?.inject(tab, 'idle').then((ids) => {
      tab.extensionIds = [...new Set([...(tab.extensionIds || []), ...ids])];
      emitState();
    }).catch((err) => console.warn('Extension document-idle injection failed:', err.message));
  });
  browserRuntime.on(view,'did-navigate-in-page', (_event, url) => { tab.url = url; emitState(); });
  browserRuntime.on(view,'did-fail-load', (_event, code, desc, url, isMainFrame) => {
    if (isMainFrame && code !== -3 && !String(url || '').startsWith('aegis://')) {
      console.error(`Page load failed ${url}: ${desc} (${code})`);
      setTimeout(() => showLoadError(tab, url, code, desc), 0);
    }
  });
  browserRuntime.certificates(view, (_event, url, error, certificate) => {
    tab.tls={valid:false,error:String(error||'certificate-error'),host:(()=>{try{return new URL(url).hostname}catch{return''}})(),issuer:certificate?.issuerName||'',subject:certificate?.subjectName||'',validStart:certificate?.validStart||0,validExpiry:certificate?.validExpiry||0,serialNumber:certificate?.serialNumber||'',fingerprint:certificate?.fingerprint||'',at:new Date().toISOString()};
    securityEvents.add('tls-certificate-error','danger',tab.tls,tab.id); emitState();
  });
  browserRuntime.on(view,'did-finish-load', async () => {
    if (!/^https:/i.test(tab.url||'')) return;
    try {
      const cert=await browserRuntime.evaluate(view,`({protocol:location.protocol,secure:location.protocol==='https:'})`,true);
      tab.tls={...(tab.tls||{}),valid:true,protocol:cert?.protocol||'https:',observedAt:new Date().toISOString()};
    } catch {}
  });

  browserRuntime.on(view,'render-process-gone', (_e, details) => {
    tab.rendererCrashes=(tab.rendererCrashes||0)+1;
    tab.lastRendererExit={ reason:String(details?.reason||'unknown'), exitCode:Number(details?.exitCode||0), at:new Date().toISOString() };
    emitState();
    toast(`Tab renderer stopped: ${details.reason}`, 'danger');
  });
  browserRuntime.on(view,'unresponsive', () => toast('This tab is not responding.', 'warning'));
}

async function replaceTabView(tab, javascriptEnabled) {
  if (!tab || !tab.privateSession) return;

  const previousView = tab.view;
  const previousUrl = tab.url || previousView ? browserRuntime.url(previousView) : '' || 'aegis://app/start.html';
  const wasActive = activeId === tab.id;
  const previousBounds = previousView?.getBounds?.();

  tab.javascriptEnabled = Boolean(javascriptEnabled);
  const nextView = createTabView(tab);
  tab.view = nextView;
  browserRuntime.mount(mainWindow,nextView);
  nextView.setVisible(false);
  wireTabView(tab, nextView);
  await installFingerprintDefenses(tab);

  if (previousBounds) nextView.setBounds(previousBounds);
  if (wasActive) nextView.setVisible(uiLayer.mode !== 'hidden');

  browserRuntime.unmount(mainWindow,previousView);
  try {
    if (previousView && !browserRuntime.destroyed(previousView)) browserRuntime.close(previousView);
  } catch {}

  try { await browserRuntime.load(nextView,previousUrl); } catch {}
  if (wasActive) {
    relayout();
    browserRuntime.focus(nextView);
  }
  emitState();
}

async function createTab(raw = null, activate = true, waitForNavigation = false, options = {}) {
  const id = nextId++;
  const partition = `aegis-tab-${crypto.randomUUID()}`; // no persist: prefix = memory-only session
  const privateSession = browserRuntime.session(partition, { cache: false });
  // Custom protocols are session-scoped in Electron. Every in-memory tab session
  // must explicitly register Aegis's internal protocol before loading start/settings pages.
  registerInternalProtocol(privateSession.protocol, `private tab ${id}`);

  const tab = {
    id,
    view: null,
    privateSession,
    partition,
    seed: freshSeed(),
    title: 'New Private Tab',
    url: '',
    loading: false,
    stats: makeTabStats(),
    shieldsEnabled: true,
    allowHttp: false,
    javascriptEnabled: options.securityDomain === 'anonymous' && settings.anonymity?.disableJavaScript !== false ? false : settings.javascriptDefault,
    compatibilityMode: false,
    lastError: null,
    httpStatus: null,
    topUrl: '',
    safety: { risk: 0, warnings: [] },
    fingerprintReady: false,
    networkRoute: null,
    sponsorSegments: 0,
    siteIntelligence: makeSiteIntelligence(),
    auditBinding: '',
    auditMessageHandler: null,
    cookieCleanupTimer: null,
    cosmeticCssKey: '',
    cosmeticFilteringReady: false,
    bounceTracker: makeBounceTracker(),
    bouncePurges: 0,
    rendererCrashes: 0,
    lastRendererExit: null,
    tls: null,
    securityDomain: options.securityDomain === 'anonymous' ? 'anonymous' : (options.securityDomain === 'hardened' ? 'hardened' : 'private'),
    hardenedAt: null,
    anonymousAt: null,
    torProxy: options.torProxy || '',
    torVerified: false,
    disableExtensions: Boolean(options.disableExtensions)
  };
  if (tab.securityDomain === 'hardened') hardenTabState(tab);
  if (tab.securityDomain === 'anonymous') {
    anonymousTabState(tab, options.torProxy || '127.0.0.1:9050');
    tab.javascriptEnabled = settings.anonymity?.disableJavaScript === false ? Boolean(settings.javascriptDefault) : false;
  }

  const view = createTabView(tab);
  tab.view = view;
  tabs.set(id, tab);
  browserRuntime.mount(mainWindow,view);
  view.setVisible(false);

  configurePrivacySession({
    ses: privateSession,
    tab,
    getSettings: () => tabSettings(tab),
    chromiumVersion: process.versions.chrome,
    onStats: () => scheduleStateEmit(),
    onSensitiveAccess: (event) => { if (recordSiteSignal(tab, event)) scheduleStateEmit(); },
    onNetworkAccess: (event) => { if (recordNetworkEvent(tab, event)) scheduleStateEmit(); },
    onPermissionBlocked: ({ keys }) => {
      const label = (keys && keys[0]) ? keys[0].replace(/([A-Z])/g, ' $1').toLowerCase() : 'permission';
      toast(`Blocked ${label} access. Change it in Site controls if you trust this site.`, 'warning');
    },
    onPermissionPrompt: (payload) => queuePermissionPrompt({ ...payload, tabId: tab.id }),
    trackerLearner,
    getFilterRules: () => filterRules,
    isTemporarilyAllowed: (origin, key) => isTemporarilyAllowed(tab.id, origin, key)
  });
  tab.permissionFirewallReady = true;
  tab.privacySessionReady = true;
  applySessionDownloadPolicy(tab);
  wireTabView(tab, view);
  if (activate) activateTab(id);

  // Install new-document privacy defenses before the first remote navigation.
  // The work remains bounded and fail-soft so browser chrome stays usable if CDP is unavailable.
  tab.privacyReadyPromise = installFingerprintDefenses(tab).then((ready) => { emitState(); return ready; }).catch(() => false);

  const effective = tabSettings(tab);
  const target = raw || settings.homePage || 'https://duckduckgo.com/';
  const routeMustSet = (effective.proxy?.mode || 'system') !== 'system';
  const fixedProxy = !['system','direct'].includes(effective.proxy?.mode || 'system');
  let routePromise = applyProxyToSession(privateSession, { freshSession: true }, tab).then((r) => { tab.networkRoute = r; emitState(); return r; }).catch((err) => {
    tab.networkRoute = { ok: false, warnings: [err.message] }; emitState();
    if (fixedProxy && effective.proxy?.failClosedFixedProxy) throw err;
    return tab.networkRoute;
  });

  const startNavigation = async () => {
    if (options.deferNavigation) return null;
    try {
      if (routeMustSet) await withTimeout(routePromise, 6000, 'Private network route');
      try { await withTimeout(tab.privacyReadyPromise, 5000, 'Privacy preload'); } catch (err) { console.warn('Privacy preload did not complete before navigation (fail-soft):', err.message); }
      tab.lastNavigationOk = await navigateTab(tab, target);
    } catch (err) {
      tab.lastNavigationOk = false; console.error('Initial tab navigation failed:', err);
      await showLoadError(tab, target, 'AEGIS_NETWORK', err.message);
      toast(`Could not open ${target}: ${err.message}`, 'danger');
    }
    return tab.lastNavigationOk;
  };
  tab.navigationPromise = startNavigation();
  if (waitForNavigation) await tab.navigationPromise;
  return tab;
}

async function navigateTab(tab, raw) {
  if (!tab) return;
  const effective = tabSettings(tab);
  let url = normalizeInput(raw, searchTemplateFor(settings));
  url = cleanNavigationUrl(url, { strip: effective.stripTrackingParams, unwrap: effective.unwrapTrackingLinks });
  if (effective.blockPrivateNetwork && isPrivateNetworkUrl(url)) {
    tab.stats.privateNetworkBlocks = (tab.stats.privateNetworkBlocks || 0) + 1;
    scheduleStateEmit();
    toast('Blocked local/private-network navigation in the anonymous compartment.', 'danger');
    return false;
  }
  tab.safety = effective.threatProtection ? analyzeUrl(url) : { risk: 0, warnings: [] };
  if (!isAllowedNavigation(url)) {
    toast('That address uses a blocked protocol.', 'danger');
    return false;
  }
  if (shouldUpgradeHttp(url, tab.allowHttp)) {
    tab.stats.httpsUpgrades += 1;
    url = upgradeToHttps(url);
  }
  try {
    await browserRuntime.load(tab.view,url);
    tab.lastNavigationOk = true;
    return true;
  } catch (err) {
    if (err && err.code !== 'ERR_ABORTED' && err.errno !== -3) await showLoadError(tab, url, err.errno || err.code, err.message);
    tab.lastNavigationOk = false;
    return false;
  }
}

function activateTab(id) {
  const target = tabs.get(Number(id));
  if (!target) return;
  for (const tab of tabs.values()) tab.view.setVisible(tab.id === target.id && uiLayer.mode !== 'hidden');
  activeId = target.id;
  relayout();
  emitState();
  browserRuntime.focus(target.view);
}

async function destroyTab(tab) {
  if (!tab) return;
  clearTimeout(tab.cookieCleanupTimer);
  try {
    await browserRuntime.clearData(browserRuntime.sessionOf(tab.view));
    await browserRuntime.clearCache(browserRuntime.sessionOf(tab.view));
    await browserRuntime.closeConnections(browserRuntime.sessionOf(tab.view));
  } catch {}
  browserRuntime.unmount(mainWindow,tab.view);
  if (!browserRuntime.destroyed(tab.view)) browserRuntime.close(tab.view);
  tabs.delete(tab.id);
  if (tab.securityDomain === 'anonymous' && ![...tabs.values()].some((t) => t.securityDomain === 'anonymous')) {
    try { await extensionRuntime?.resumeAll('anonymous-tabs'); } catch (err) { console.warn('Could not resume extension backgrounds:', err.message); }
  }
}

async function closeTab(id) {
  const tab = tabs.get(Number(id));
  if (!tab) return;
  const ids = [...tabs.keys()];
  const idx = ids.indexOf(tab.id);
  await destroyTab(tab);
  if (activeId === tab.id) {
    const fallback = ids[idx + 1] ?? ids[idx - 1] ?? null;
    activeId = null;
    if (fallback && tabs.has(fallback)) activateTab(fallback);
    else await createTab();
  }
  emitState();
}

async function newIdentity() {
  const oldTabs = [...tabs.values()];
  activeId = null;
  for (const tab of oldTabs) await destroyTab(tab);
  identitySeed = freshSeed();
  trackerLearner.reset();
  temporaryPermissions.clear();
  nextId = 1;
  if (settings.clearClipboardOnNewIdentity) {
    try { clipboard.clear(); } catch {}
  }
  await createTab(settings.homePage || 'https://duckduckgo.com/');
  toast('New identity created. All tab sessions, storage, cache, and connections were destroyed.', 'success');
}

async function clearTabData(tab, reload = true) {
  if (!tab) return;
  try {
    await browserRuntime.clearData(browserRuntime.sessionOf(tab.view));
    await browserRuntime.clearCache(browserRuntime.sessionOf(tab.view));
    await browserRuntime.closeConnections(browserRuntime.sessionOf(tab.view));
    clearTemporaryPermissionsForOrigin(safeOrigin(tab.url), tab.id);
    tab.stats = makeTabStats();
    if (reload && tab.url) browserRuntime.reload(tab.view);
    emitState();
    toast('Current tab data cleared.', 'success');
  } catch (err) {
    toast(`Could not clear tab data: ${err.message}`, 'danger');
  }
}

async function clearAllData() {
  for (const tab of tabs.values()) await clearTabData(tab, false);
  const tab = activeTab();
  if (tab?.url) browserRuntime.reload(tab.view);
  toast('All active tab storage and caches cleared.', 'success');
}

function applySitePermission(origin, key, value) {
  if (!origin || !['allow', 'block'].includes(value)) return false;
  try {
    const u = new URL(origin);
    if (!['http:', 'https:'].includes(u.protocol) || u.origin !== origin) return false;
  } catch { return false; }
  const allowedKeys = Object.keys(settings.permissionDefaults);
  if (!allowedKeys.includes(key)) return false;
  settings.sitePermissions[origin] = { ...(settings.sitePermissions[origin] || {}), [key]: value };
  saveSettings();
  emitState();
  return true;
}

async function hardenTab(tab) {
  if (!tab) return false;
  const origin = safeOrigin(tab.url);
  hardenTabState(tab);
  if (origin) {
    // Remove temporary grants. Persistent site exceptions remain untouched because
    // hardened enforcement comes from the tab's effective policy, not global prefs.
    for (const key of SENSITIVE_PERMISSION_KEYS) clearTemporaryPermission(tab.id, origin, key);
  }

  // Remove state accumulated before hardening so the reloaded page starts from a
  // genuinely clean compartment instead of inheriting old cookies/cache/storage.
  try {
    await tab.privateSession.clearData({ dataTypes:['cookies','localStorage','indexedDB','serviceWorkers','cache','cacheStorage'] });
    await tab.privateSession.clearCache();
    await tab.privateSession.closeAllConnections();
  } catch (err) { console.warn('Harden cleanup warning:', err.message); }

  tab.javascriptEnabled = true;
  await replaceTabView(tab, true);
  await applyCosmeticFiltering(tab);
  emitState();
  toast(origin
    ? `Hardened ${new URL(origin).hostname}: Maximum fingerprint defense, all third-party requests blocked, extensions disabled, service workers disabled, permissions blocked, HTTPS-only, and prior site state cleared.`
    : 'Current tab moved into a hardened compartment.', 'success');
  return true;
}

async function createAnonymousTab(raw = null) {
  const torProxy = settings.anonymity?.torProxy || '127.0.0.1:9050';
  const tab = await createTab(raw || 'https://check.torproject.org/', true, false, {
    securityDomain:'anonymous',
    torProxy,
    disableExtensions:true,
    deferNavigation:true
  });
  if (!tab) return null;
  // Extensions are excluded per-tab by the compartment policy. Do not globally
  // suspend them just because an anonymous tab exists; ordinary tabs remain usable.
  try {
    const route = await applyProxyToSession(tab.privateSession, { freshSession:false }, tab);
    tab.networkRoute = route;
    if (!route?.ok) throw new Error(route?.warnings?.join(' | ') || 'Tor proxy route failed.');

    const proof = await verifyTorRoute(tab.privateSession);
    tab.torVerification = proof;
    tab.torVerified = Boolean(proof.verified);
    if (settings.anonymity?.requireTorVerification !== false && !proof.verified) {
      tab.networkRoute = { ...route, ok:false, warnings:[...(route.warnings || []), proof.error || 'Tor verification failed.'] };
      await showLoadError(tab, 'https://check.torproject.org/', 'AEGIS_TOR_REQUIRED', 'Anonymous compartment refused to browse because the configured route could not be verified as Tor.');
      emitState();
      toast('Anonymous tab is fail-closed: Aegis could not verify the Tor route. Start Tor locally or update the Tor SOCKS address in Settings → Network.', 'danger');
      return tab;
    }

    const target = raw || settings.homePage || 'https://duckduckgo.com/';
    tab.lastNavigationOk = await navigateTab(tab, target);
    emitState();
    toast('Anonymous compartment active. Tor route verified, local-network access blocked, extensions disabled, downloads blocked, and maximum fingerprint defenses enabled.', 'success');
    return tab;
  } catch (err) {
    tab.torVerified = false;
    tab.networkRoute = { ok:false, mode:'socks5', warnings:[err.message] };
    try { await showLoadError(tab, 'https://check.torproject.org/', 'AEGIS_TOR_REQUIRED', err.message); } catch {}
    emitState();
    toast('Anonymous compartment is fail-closed: ' + err.message, 'danger');
    return tab;
  }
}


function openBrowserUi(payload) {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  mainWindow.webContents.send('ui:open', payload || {});
}

function normalizedContextLink(raw) {
  const value = String(raw || '');
  if (!/^https?:\/\//i.test(value)) return '';
  const cleaned = cleanNavigationUrl(value, { strip: settings.stripTrackingParams, unwrap: settings.unwrapTrackingLinks });
  return /^https?:\/\//i.test(cleaned || '') ? cleaned : '';
}

function showTabContextMenu(tab, params = {}) {
  if (!tab || !mainWindow || mainWindow.isDestroyed()) return;
  const link = normalizedContextLink(params.linkURL);
  const selectedText = String(params.selectionText || '').trim().slice(0, 4000);
  const template = [];
  if (link) {
    template.push(
      { label: 'Open Link in New Isolated Tab', click: () => createTab(link, true) },
      { label: 'Open Link in Anonymous Compartment', click: () => createAnonymousTab(link) },
      { label: 'Copy Clean Link', click: () => clipboard.writeText(link) }
    );
  } else if (selectedText) {
    template.push({ label: 'Copy', role: 'copy' });
  }
  if (template.length) template.push({ type: 'separator' });
  template.push(
    { label: 'Site Privacy Inspector', click: () => openBrowserUi({ panel: 'privacyPanel' }) },
    { label: tab.securityDomain === 'hardened' ? 'Site Hardened' : 'Harden This Site', enabled: Boolean(safeOrigin(tab.url)) && tab.securityDomain === 'private', click: () => hardenTab(tab) },
    { label: 'Open Anonymous Compartment', click: () => createAnonymousTab(tab.url || null) },
    { label: 'Clear This Tab Data', click: () => clearTabData(tab) },
    { type: 'separator' },
    { label: 'Security Suite & Verification', click: () => openBrowserUi({ settingsPage: 'diagnostics' }) }
  );
  Menu.buildFromTemplate(template).popup({ window: mainWindow });
}

async function awaitCosmeticRefresh() {
  await Promise.allSettled([...tabs.values()].map((tab) => applyCosmeticFiltering(tab)));
}

function wireIpc() {
  ipcMain.handle('state:get', (event) => assertUiSender(event) ? statePayload() : null);
  ipcMain.handle('settings:get', (event) => assertUiSender(event) ? settings : null);
  ipcMain.on('ui:layer', (event, payload) => { if (assertUiSender(event)) applyUiLayer(payload); });
  ipcMain.handle('network:test', (event) => assertUiSender(event) ? runNetworkTest() : { ok: false, error: 'IPC sender denied' });
  ipcMain.handle('network:test-tor', async (event, payload = {}) => {
    if (!assertUiSender(event)) return { ok:false, verified:false, error:'IPC sender denied' };
    const partition = 'aegis-tor-proof-' + crypto.randomUUID();
    const ses = browserRuntime.session(partition, { cache:false });
    const server = String(payload?.torProxy || settings.anonymity?.torProxy || '127.0.0.1:9050').trim().slice(0,180);
    try {
      const route = await applyProxyCore(ses, { mode:'socks5', server, bypassLocal:false, failClosedFixedProxy:true }, { failClosedFixedProxy:true, freshSession:true });
      if (!route?.ok) return { ok:false, verified:false, error:(route?.warnings || []).join(' | ') || 'Tor proxy setup failed.' };
      return await verifyTorRoute(ses);
    } catch (err) {
      return { ok:false, verified:false, error:err.message };
    } finally {
      try { await ses.clearData(); } catch {}
      try { await ses.clearCache(); } catch {}
      try { await ses.closeAllConnections(); } catch {}
    }
  });
  ipcMain.handle('security-suite:run', (event) => assertUiSender(event) ? runSecuritySuite() : { testedAt: new Date().toISOString(), checks: [], summary: { pass: 0, warning: 0, info: 0, fail: 0, 'not-tested': 0, total: 0 }, error: 'IPC sender denied' });
  ipcMain.handle('security-test:open', async (event, key) => {
    if (!assertUiSender(event)) return { ok:false, error:'IPC sender denied' };
    const url=SECURITY_TEST_TARGETS[String(key||'')];
    if (!url) return { ok:false, error:'Unknown security test.' };
    try {
      const tab=await createTab(url,true,false,{securityDomain:'hardened',disableExtensions:true});
      return {ok:true,tabId:tab.id,url};
    } catch (err) { return {ok:false,error:err.message}; }
  });
  ipcMain.handle('adblock:lists', async (event)=>{if(!assertUiSender(event))return [];return FILTER_LIST_CATALOG.map(x=>({...x,enabled:(settings.enabledFilterLists||[]).includes(x.id)}));});
  ipcMain.handle('adblock:refresh-lists', async (event)=>{if(!assertUiSender(event))return {ok:false,error:'IPC sender denied'};const results=await updateFilterLists();return {ok:results.every(x=>x.ok),results};});
  ipcMain.handle('adblock:pick-element', async (event) => {
    if(!assertUiSender(event))return {ok:false,error:'IPC sender denied'};
    const tab=activeTab();if(!tab?.view?.webContents||browserRuntime.destroyed(tab.view))return {ok:false,error:'No active web page.'};
    let host='';try{host=new URL(tab.url).hostname;}catch{return {ok:false,error:'Element picker requires an HTTP(S) page.'};}
    try{
      const selector=await browserRuntime.evaluate(tab.view,`new Promise((resolve)=>{
        const old=document.getElementById('__aegis_picker_style');if(old)old.remove();
        const st=document.createElement('style');st.id='__aegis_picker_style';st.textContent='.__aegis_pick{outline:3px solid #58c7ff!important;outline-offset:2px!important;cursor:crosshair!important}';document.documentElement.appendChild(st);
        let last=null,done=false;
        const css=(el)=>{if(el.id&&/^[A-Za-z][\\w-]{0,80}$/.test(el.id))return '#'+CSS.escape(el.id);let p=el.tagName.toLowerCase();const cls=[...el.classList].filter(x=>!x.startsWith('__aegis_')&&x.length<50).slice(0,3);if(cls.length)p+='.'+cls.map(CSS.escape).join('.');if(el.parentElement){const same=[...el.parentElement.children].filter(x=>x.tagName===el.tagName);if(same.length>1)p+=':nth-of-type('+(same.indexOf(el)+1)+')';}return p;};
        const clean=()=>{done=true;if(last)last.classList.remove('__aegis_pick');st.remove();document.removeEventListener('mousemove',move,true);document.removeEventListener('click',click,true);document.removeEventListener('keydown',key,true);};
        const move=e=>{if(done)return;if(last)last.classList.remove('__aegis_pick');last=e.target;last.classList.add('__aegis_pick');};
        const click=e=>{e.preventDefault();e.stopPropagation();const s=css(e.target);clean();resolve(s);};
        const key=e=>{if(e.key==='Escape'){e.preventDefault();clean();resolve('');}};
        document.addEventListener('mousemove',move,true);document.addEventListener('click',click,true);document.addEventListener('keydown',key,true);
      })`,true);
      if(!selector)return {ok:false,canceled:true};
      const rule=host+'##'+String(selector).slice(0,500);
      settings.customFilterRules=(settings.customFilterRules?settings.customFilterRules.trimEnd()+'\n':'')+rule;
      settings=sanitizeSettings(settings);filterRules=parseFilterRules(settings.customFilterRules||'');saveSettings();await applyCosmeticFiltering(tab);emitState();
      return {ok:true,rule};
    }catch(err){return {ok:false,error:'Element picker failed: '+err.message};}
  });
  ipcMain.handle('enterprise:export-events', async (event) => {
    if(!assertUiSender(event))return {ok:false,error:'IPC sender denied'};
    const pick=await dialog.showSaveDialog(mainWindow,{title:'Export Aegis security evidence',defaultPath:'aegis-security-events.json',filters:[{name:'JSON',extensions:['json']}]});
    if(pick.canceled||!pick.filePath)return {ok:false,canceled:true};
    const payload={schema:'aegis.security-events.v1',exportedAt:new Date().toISOString(),events:securityEvents.list()};
    fs.writeFileSync(pick.filePath,JSON.stringify(payload,null,2),{mode:0o600});
    return {ok:true,count:payload.events.length};
  });
  ipcMain.handle('enterprise:import-policy', async (event) => {
    if(!assertUiSender(event)) return {ok:false,error:'IPC sender denied'};
    const key=process.env.AEGIS_POLICY_PUBLIC_KEY||'';
    const pick=await dialog.showOpenDialog(mainWindow,{title:'Import signed Aegis policy',properties:['openFile'],filters:[{name:'Aegis Policy',extensions:['json','aegispolicy']}]});
    if(pick.canceled||!pick.filePaths[0])return {ok:false,canceled:true};
    try{
      const bundle=JSON.parse(fs.readFileSync(pick.filePaths[0],'utf8'));
      const verified=verifyBundle(bundle,key);
      if(!verified.ok){securityEvents.add('managed-policy-rejected','danger',{reason:verified.error});return verified;}
      settings=sanitizeSettings(applyManagedPolicy(settings,verified.policy)); saveSettings();
      securityEvents.add('managed-policy-applied','success',{id:verified.policy.id||'',version:verified.policy.version||'',digest:verified.digest});
      await Promise.allSettled([...tabs.values()].map(tab=>replaceTabView(tab,tab.javascriptEnabled)));
      emitState();return {ok:true,digest:verified.digest,policy:settings.managedPolicy||null};
    }catch(err){return {ok:false,error:'Could not import policy: '+err.message};}
  });
  ipcMain.handle('extensions:list', (event) => assertUiSender(event) && extensionRuntime ? extensionRuntime.list() : []);
  ipcMain.handle('extensions:install', async (event) => {
    if (!assertUiSender(event) || !extensionRuntime) return { ok:false, error:'IPC sender denied' };
    const pick = await dialog.showOpenDialog(mainWindow, { title:'Install Firefox WebExtension (.xpi)', properties:['openFile'], filters:[{name:'Firefox WebExtension',extensions:['xpi']}] });
    if (pick.canceled || !pick.filePaths?.[0]) return { ok:false, canceled:true };
    try {
      const summary = await extensionRuntime.inspect(pick.filePaths[0]);
      const unsupported = summary.compatibility.unsupported.map((x) => x.api).join(', ') || 'None';
      const risky = summary.risk.filter((x) => x.level === 'high').map((x) => x.permission).join(', ') || 'None';
      const signatureNote = summary.signature?.metadataPresent ? 'Mozilla signature metadata: present (not cryptographically verified by this beta).' : 'Mozilla signature metadata: not detected.';
      const answer = await dialog.showMessageBox(mainWindow, { type:'warning', buttons:['Cancel','Install'], defaultId:0, cancelId:0, title:'Review extension permissions', message:summary.name + ' ' + summary.version, detail:'Aegis compatibility: ' + summary.compatibility.score + '%\nHigh-risk permissions: ' + risky + '\nUnsupported APIs: ' + unsupported + '\n' + signatureNote + '\n\nAegis runs content scripts in an extension-specific isolated world and does not grant Node.js access.' });
      if (answer.response !== 1) return { ok:false, canceled:true, summary };
      if(!extensionAllowed(summary.id, settings)) return {ok:false,error:'Extension blocked by enterprise allowlist policy.',summary};
      const installed = await extensionRuntime.install(pick.filePaths[0]);
      await Promise.allSettled([...tabs.values()].map((tab) => replaceTabView(tab, tab.javascriptEnabled)));
      emitState(); return { ok:true, extension:installed };
    } catch (err) { return { ok:false, error:err.message }; }
  });
  ipcMain.handle('extensions:set-enabled', async (event, payload) => {
    if (!assertUiSender(event) || !extensionRuntime) return { ok:false, error:'IPC sender denied' };
    try { const extension=await extensionRuntime.setEnabled(String(payload?.id||''), Boolean(payload?.enabled)); await Promise.allSettled([...tabs.values()].map((tab) => replaceTabView(tab, tab.javascriptEnabled))); emitState(); return { ok:true, extension }; } catch (err) { return { ok:false, error:err.message }; }
  });
  ipcMain.handle('extensions:remove', (event, id) => {
    if (!assertUiSender(event) || !extensionRuntime) return { ok:false, error:'IPC sender denied' };
    const ok=extensionRuntime.remove(String(id||'')); Promise.allSettled([...tabs.values()].map((tab) => replaceTabView(tab, tab.javascriptEnabled))).then(emitState); return { ok };
  });
  ipcMain.handle('extension:call', (event, payload) => extensionRuntime ? extensionRuntime.call(event.sender, payload) : Promise.reject(new Error('Extension runtime unavailable.')));
  ipcMain.on('extension:message-response', (event, payload) => { if (extensionRuntime) extensionRuntime.handleBackgroundResponse(event.sender, payload); });

  ipcMain.on('nav', (event, value) => { if (assertUiSender(event)) navigateTab(activeTab(), value); });
  ipcMain.on('tab:new', (event, value) => { if (assertUiSender(event)) createTab(value || settings.homePage || 'https://duckduckgo.com/'); });
  ipcMain.on('tab:close', (event, id) => { if (assertUiSender(event)) closeTab(id); });
  ipcMain.on('tab:activate', (event, id) => { if (assertUiSender(event)) activateTab(id); });
  ipcMain.on('tab:duplicate', (event) => {
    if (!assertUiSender(event)) return;
    const tab = activeTab();
    createTab(tab?.url || 'aegis://app/start.html');
  });
  ipcMain.on('tab:command', (event, command) => {
    if (!assertUiSender(event)) return;
    const tab = activeTab();
    if (!tab) return;
    const nav = browserRuntime.history(tab.view);
    if (command === 'back' && nav.canGoBack()) nav.goBack();
    else if (command === 'forward' && nav.canGoForward()) nav.goForward();
    else if (command === 'reload') tab.loading ? browserRuntime.stop(tab.view) : browserRuntime.reload(tab.view);
    else if (command === 'home') navigateTab(tab, settings.homePage || 'https://duckduckgo.com/');
  });

  ipcMain.on('identity:new', (event) => { if (assertUiSender(event)) newIdentity(); });
  ipcMain.on('data:clear-tab', (event) => { if (assertUiSender(event)) clearTabData(activeTab()); });
  ipcMain.on('data:clear-all', (event) => { if (assertUiSender(event)) clearAllData(); });
  ipcMain.on('bookmark:toggle', (event) => {
    if (!assertUiSender(event)) return;
    const added = toggleBookmark(activeTab());
    toast(added ? 'Bookmark saved locally.' : 'Bookmark removed.', 'success');
  });
  ipcMain.on('bookmark:open', (event, url) => { if (assertUiSender(event) && /^https?:\/\//.test(String(url || ''))) createTab(url); });
  ipcMain.on('bookmark:remove', (event, id) => {
    if (!assertUiSender(event)) return;
    bookmarks = bookmarks.filter((x) => x.id !== String(id || ''));
    saveBookmarks(); emitState();
  });
  ipcMain.on('downloads:clear', (event) => {
    if (!assertUiSender(event)) return;
    downloads = downloads.filter((x) => activeDownloadItems.has(x.id));
    emitState();
  });
  ipcMain.on('download:cancel', (event, id) => {
    if (!assertUiSender(event)) return;
    const item = activeDownloadItems.get(String(id || ''));
    if (item) item.cancel();
  });
  ipcMain.on('download:reveal', (event, id) => {
    if (!assertUiSender(event)) return;
    const rec = downloads.find((x) => x.id === id);
    if (rec?.path && fs.existsSync(rec.path)) shell.showItemInFolder(rec.path);
  });


  ipcMain.on('shields:set', (event, enabled) => {
    if (!assertUiSender(event)) return;
    const tab = activeTab();
    if (!tab) return;
    if (tab.securityDomain !== 'private' && !Boolean(enabled)) {
      tab.shieldsEnabled = true;
      emitState();
      toast('Privacy shields are locked on in this security compartment.', 'warning');
      return;
    }
    tab.shieldsEnabled = Boolean(enabled);
    applyCosmeticFiltering(tab).finally(emitState);
  });
  ipcMain.on('javascript:set', (event, enabled) => {
    if (!assertUiSender(event)) return;
    const tab = activeTab();
    if (!tab) return;
    if (tab.securityDomain === 'anonymous' && tabSettings(tab).anonymity?.disableJavaScript !== false && Boolean(enabled)) {
      tab.javascriptEnabled = false;
      emitState();
      toast('JavaScript is locked off by the anonymous compartment policy.', 'warning');
      return;
    }
    replaceTabView(tab, Boolean(enabled)).catch((err) => {
      console.error('Could not change JavaScript policy:', err);
      toast(`Could not change JavaScript policy: ${err.message}`, 'danger');
    });
  });
  ipcMain.on('http:set', (event, enabled) => {
    if (!assertUiSender(event)) return;
    const tab = activeTab();
    if (!tab) return;
    if (tab.securityDomain !== 'private' && Boolean(enabled)) {
      tab.allowHttp = false;
      emitState();
      toast('HTTP downgrade is locked off in this security compartment.', 'warning');
      return;
    }
    tab.allowHttp = Boolean(enabled);
    emitState();
  });
  ipcMain.on('compatibility:set', (event, enabled) => {
    if (!assertUiSender(event)) return;
    const tab = activeTab();
    if (!tab) return;
    if (tab.securityDomain !== 'private' && Boolean(enabled)) {
      tab.compatibilityMode = false;
      emitState();
      toast('Compatibility mode cannot weaken a hardened or anonymous compartment.', 'warning');
      return;
    }
    tab.compatibilityMode = Boolean(enabled);
    emitState();
    browserRuntime.reload(tab.view);
    toast(tab.compatibilityMode ? 'Compatibility mode enabled for this tab. Core sandbox and permission protections remain active.' : 'Full privacy filtering restored for this tab.', 'success');
  });

  ipcMain.on('site:harden', (event) => {
    if (!assertUiSender(event)) return;
    hardenTab(activeTab()).catch((err) => toast('Could not harden this site: ' + err.message, 'danger'));
  });
  ipcMain.on('tab:new-anonymous', (event, raw) => {
    if (!assertUiSender(event)) return;
    createAnonymousTab(typeof raw === 'string' ? raw : null).catch((err) => toast('Could not create anonymous tab: ' + err.message, 'danger'));
  });

  ipcMain.on('permission:respond', (event, response) => {
    if (!assertUiSender(event) || !response || typeof response !== 'object') return;
    if (!['allow-once', 'allow-10m', 'allow-always', 'block-once', 'block-always'].includes(response.action)) return;
    resolvePermissionPrompt(response.id, response.action);
  });

  ipcMain.on('site-permission:set', (event, patch) => {
    if (!assertUiSender(event) || !patch || typeof patch !== 'object') return;
    const tab = activeTab();
    const origin = safeOrigin(tab?.url);
    const key = String(patch.key || '');
    if (!origin || !Object.keys(settings.permissionDefaults).includes(key)) return;
    if (tab?.securityDomain !== 'private') {
      toast('Site permission exceptions are locked in this security compartment.', 'warning');
      emitState();
      return;
    }
    clearTemporaryPermissionsForOrigin(origin);
    if (patch.value === 'default') {
      if (settings.sitePermissions[origin]) {
        delete settings.sitePermissions[origin][key];
        if (!Object.keys(settings.sitePermissions[origin]).length) delete settings.sitePermissions[origin];
      }
      saveSettings(); emitState();
      toast(`Site permission reset to the global default for ${new URL(origin).hostname}.`, 'success');
      return;
    }
    if (applySitePermission(origin, key, patch.value)) {
      toast(`Site permission updated for ${new URL(origin).hostname}.`, 'success');
    }
  });
  ipcMain.on('site-permission:reset', (event) => {
    if (!assertUiSender(event)) return;
    const origin = safeOrigin(activeTab()?.url);
    if (origin) clearTemporaryPermissionsForOrigin(origin);
    if (origin && settings.sitePermissions[origin]) {
      delete settings.sitePermissions[origin];
      saveSettings();
      emitState();
      toast('Site permission exceptions reset.', 'success');
    }
  });

  ipcMain.on('settings:profile', async (event, level) => {
    if (!assertUiSender(event) || !['standard', 'strict', 'maximum'].includes(level)) return;
    settings = sanitizeSettings({ ...settings, ...profileDefaults(level) });
    saveSettings();
    relayout();
    await Promise.allSettled([...tabs.values()].map((tab) => replaceTabView(tab, tab.javascriptEnabled)));
    await awaitCosmeticRefresh();
    emitState();
    toast(`${level[0].toUpperCase() + level.slice(1)} privacy profile applied to every active tab.`, 'success');
  });

  ipcMain.on('settings:reset', async (event) => {
    if (!assertUiSender(event)) return;
    settings = sanitizeSettings(cloneDefaults());
    rebuildFilterRules();
    saveSettings();
    relayout();
    await Promise.allSettled([...tabs.values()].map((tab) => applyProxyToSession(browserRuntime.sessionOf(tab.view), {}, tab)));
    await awaitCosmeticRefresh();
    emitState();
    toast('Aegis settings restored to hardened defaults.', 'success');
  });

  ipcMain.on('settings:update', async (event, patch) => {
    if (!assertUiSender(event) || !patch || typeof patch !== 'object') return;
    const previousSettings = settings;
    patch = preserveLockedSettings(settings, patch);
    const siteIntelligenceWasEnabled = settings.siteIntelligence !== false;
    settings = sanitizeSettings({
      ...settings,
      ...patch,
      proxy: { ...settings.proxy, ...(patch.proxy || {}) },
      anonymity: { ...settings.anonymity, ...(patch.anonymity || {}) },
      permissionDefaults: { ...settings.permissionDefaults, ...(patch.permissionDefaults || {}) },
      appearance: { ...settings.appearance, ...(patch.appearance || {}) },
      sitePermissions: settings.sitePermissions
    });
    filterRules = parseFilterRules(settings.customFilterRules || '');
    saveSettings();
    relayout();
    const proxyResults = await Promise.allSettled([...tabs.values()].map((tab) => applyProxyToSession(browserRuntime.sessionOf(tab.view), {}, tab)));
    const proxyFailures = proxyResults.filter((result) => result.status === 'rejected').length;
    await awaitCosmeticRefresh();
    const preloadKeys = ['privacyLevel','privacyApiGuard','blockTrackingBeacons','globalPrivacyControl','doNotTrack','disableServiceWorkers','siteIntelligence'];
    const anonymityChanged = JSON.stringify(previousSettings.anonymity || {}) !== JSON.stringify(settings.anonymity || {});
    const preloadChanged = preloadKeys.some((key) => previousSettings[key] !== settings[key]) || anonymityChanged;
    if (preloadChanged) {
      await Promise.allSettled([...tabs.values()].map((tab) => replaceTabView(tab, tab.javascriptEnabled)));
    }
    if (!preloadChanged && !siteIntelligenceWasEnabled && settings.siteIntelligence !== false) {
      await Promise.allSettled([...tabs.values()].map(async (tab) => {
        await installFingerprintDefenses(tab);
        if (tab.auditBinding && tab.url && !String(tab.url).startsWith('aegis://')) {
          try { await browserRuntime.evaluate(tab.view,buildSiteAuditScript({ bindingName: tab.auditBinding }), false); } catch {}
        }
      }));
    } else if (!preloadChanged && siteIntelligenceWasEnabled && settings.siteIntelligence === false) {
      for (const tab of tabs.values()) resetSiteIntelligence(tab, tab.url, safeOrigin(tab.url));
    }
    emitState();
    toast(proxyFailures
      ? `Settings saved, but ${proxyFailures} tab network session${proxyFailures === 1 ? '' : 's'} could not apply the new routing. Run Diagnostics.`
      : (preloadChanged ? 'Settings saved. Privacy preload controls were rebuilt in every active tab.' : 'Settings saved. Privacy and network controls are live.'), proxyFailures ? 'warning' : 'success');
  });
}

async function createMainWindow() {
  startupLog('Creating browser window.');
  mainWindow = new BrowserWindow({
    width: 1500,
    height: 940,
    minWidth: 1040,
    minHeight: 700,
    center: true,
    title: 'Aegis Privacy Browser',
    backgroundColor: '#0a0d14',
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
      devTools: false
    }
  });

  mainWindow.setMenuBarVisibility(false);
  mainWindow.on('resize', relayout);
  mainWindow.on('maximize', relayout);
  mainWindow.on('unmaximize', relayout);
  mainWindow.on('closed', () => { mainWindow = null; });
  mainWindow.on('unresponsive', () => toast('Aegis UI is not responding.', 'warning'));
  mainWindow.webContents.on('render-process-gone', (_event, details) => {
    console.error('Aegis browser chrome renderer stopped:', details);
  });
  mainWindow.webContents.on('did-fail-load', (_event, code, description, url, isMainFrame) => {
    if (isMainFrame && code !== -3) console.error(`Browser chrome failed to load ${url}: ${description} (${code})`);
  });

  await withTimeout(mainWindow.loadURL('aegis://app/index.html'), 10000, 'Browser chrome load');
  startupLog('Browser chrome loaded.');
  uiLayer = { mode: 'none', reserveRight: 0 };

  // Make the shell visible before creating the first isolated tab. If a tab/session
  // initialization ever fails, Aegis still opens and can display diagnostics.
  mainWindow.show();
  mainWindow.focus();
  if (process.platform === 'darwin') {
    app.show();
    app.focus({ steal: true });
  }
  startupLog('Browser window opened successfully.');

  try {
    const smokeUrl = process.env.AEGIS_SMOKE_TEST_URL || settings.homePage || 'https://duckduckgo.com/';
    const firstTab = await withTimeout(createTab(smokeUrl, true, Boolean(process.env.AEGIS_SMOKE_TEST_URL)), process.env.AEGIS_SMOKE_TEST_URL ? 25000 : 7000, 'First private tab initialization');
    if (process.env.AEGIS_SMOKE_TEST_URL && firstTab.lastNavigationOk !== true) throw new Error(`External website smoke test failed: ${process.env.AEGIS_SMOKE_TEST_URL}`);
    startupLog('First private tab initialized.');
    if (process.env.AEGIS_SMOKE_TEST_URL) startupLog(`External website smoke test passed: ${process.env.AEGIS_SMOKE_TEST_URL}`);
    if (process.env.AEGIS_SMOKE_TEST === '1') {
      startupLog('Smoke test passed; exiting cleanly.');
      setTimeout(() => app.quit(), 700);
    }
  } catch (err) {
    console.error('First private tab initialization failed:', err);
    toast(`Private tab startup failed: ${err.message}`, 'danger');
    if (process.env.AEGIS_SMOKE_TEST === '1') setTimeout(() => app.exit(2), 300);
  }
}

app.whenReady().then(async () => {
  startupLog(`Electron ${process.versions.electron}; Chromium ${process.versions.chrome}; ${process.platform}/${process.arch}.`);
  loadSettings();
  if(settings.filterListAutoUpdate) updateFilterLists().catch(err=>securityEvents.add('filter-list-update-failed','warning',{error:err.message}));
  saveSettings(); // persist schema migrations and sanitized network defaults
  loadBookmarks();
  extensionRuntime = new AegisExtensionRuntime({
    rootDir: app.getPath('userData'),
    getTabs: () => [...tabs.values()],
    getActiveId: () => activeId,
    BrowserWindow,
    electronSession: { fromPartition:(partition,options)=>browserRuntime.session(partition,options) },
    registerProtocols: registerInternalProtocol,
    createTab,
    updateTab: async (id, props = {}) => { const tab=tabs.get(Number(id)); if(!tab) throw new Error('Tab not found'); if(props.url) await navigateTab(tab, props.url); if(props.active) activateTab(tab.id); return serializeTab(tab); },
    removeTab: (id) => closeTab(id)
  });

  registerInternalProtocol(protocol, 'default UI session');

  wireIpc();
  await extensionRuntime.startAll();
  await createMainWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow().catch((err) => console.error('Aegis window creation failed:', err));
    }
  });
}).catch((err) => {
  console.error('Aegis fatal startup error:', err);
  try {
    dialog.showErrorBox(
      'Aegis could not start',
      `${err?.message || err}

Run Diagnose-Aegis.command for local startup details.`
    );
  } catch {}
  app.exit(1);
});

app.on('second-instance', () => {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.show();
  mainWindow.focus();
  if (process.platform === 'darwin') app.focus({ steal: true });
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('before-quit', () => {
  try { extensionRuntime?.stopAll(); } catch {}
  for (const [id, pending] of pendingPermissions) {
    clearTimeout(pending.timer);
    try { pending.complete(false); } catch {}
    pendingPermissions.delete(id);
  }
  for (const tab of tabs.values()) {
    try {
      browserRuntime.clearData(browserRuntime.sessionOf(tab.view));
      browserRuntime.clearCache(browserRuntime.sessionOf(tab.view));
      browserRuntime.closeConnections(browserRuntime.sessionOf(tab.view));
    } catch {}
  }
});

process.on('uncaughtException', (err) => console.error('Aegis error:', err));
process.on('unhandledRejection', (err) => console.error('Aegis rejected promise:', err));
