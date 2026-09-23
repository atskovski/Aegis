'use strict';
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const required = [
  'src/main.js','src/preload.js','src/core/privacy.js','src/core/compartment.js','src/core/control-registry.js','src/core/url.js','src/core/blocklist.js',
  'src/core/fingerprint.js','src/core/browser-runtime.js','src/core/engine-contract.js','src/core/security-kernel.js','src/engine/electron-adapter.js','src/core/security-events.js','src/core/bounce-tracking.js','src/core/settings.js','src/core/site-intelligence.js','src/core/security-suite.js','src/core/navigation.js','src/core/network.js','src/core/filter-rules.js','src/core/tracker-learning.js','src/core/safety.js','src/core/sponsor.js','src/ui/index.html','src/ui/start.html','src/ui/start.css','src/ui/start.js','src/ui/error.html','src/ui/error.js','src/ui/error.css','src/ui/styles.css','src/ui/app.js',
  'Run-Aegis.command','Repair-Aegis.command','Verify-Aegis.command','Diagnose-Aegis.command','Smoke-Test-Aegis.command'
];
let bad = false;
for (const rel of required) {
  const p = path.join(root, rel);
  if (!fs.existsSync(p) || fs.statSync(p).size === 0) { console.error('Missing:', rel); bad = true; }
}
const corpus = ['src/main.js','src/core/privacy.js','src/core/network.js','src/core/settings.js','src/preload.js'].map((rel) => fs.readFileSync(path.join(root, rel),'utf8')).join('\n');
for (const token of [
  'sandbox: true','contextIsolation: true','nodeIntegration: false','setPermissionRequestHandler','setPermissionCheckHandler',
  'disable-background-networking','force-webrtc-ip-handling-policy','site-per-process',
  "minVersion: 'tls1.2'",'blockThirdPartyCookies','clearData','closeAllConnections',
  'cache: false',"v8CacheOptions: 'none'",'javascript: Boolean(tab.javascriptEnabled)','permission:prompt','permission:respond',
  "registerInternalProtocol(privateSession.protocol","registerInternalProtocol(protocol, 'default UI session')","navigationUrl(event, legacyDetails)","mode: 'system'","runConnectivityTest","heuristicTrackingProtection","cookieAutoDelete","https://duckduckgo.com/","freshSession: true","aegis-diagnostic-","blockThirdPartyRequests","blockPrivateNetwork","blockAllDownloads","anonymousRouteRequired","onBeforeSendHeaders","Sec-GPC","testStorageResurrection","testProcessIsolation","createSecurityEventLedger","bounceTrackingProtection","sha256","enterpriseMode","evaluateUrl","extensionAllowed","mediaClickToPlay","verifyBundle","preserveLockedSettings","enterprise:export-events"
]) {
  if (!corpus.includes(token)) { console.error('Hardening token missing:', token); bad = true; }
}
const mainSource = fs.readFileSync(path.join(root, 'src/main.js'), 'utf8');
const privacySource = fs.readFileSync(path.join(root, 'src/core/privacy.js'), 'utf8');
const runtimeSource = fs.readFileSync(path.join(root, 'src/core/browser-runtime.js'), 'utf8');
const adapterSource = fs.readFileSync(path.join(root, 'src/engine/electron-adapter.js'), 'utf8');

const architectureChecks = [
  ['privacy sessions receive the active engine adapter', mainSource.includes('engine: browserEngine')],
  ['permission handlers route through the engine adapter', privacySource.includes('engine?.installPermissionHandlers') && adapterSource.includes('setPermissionRequestHandler') && adapterSource.includes('setPermissionCheckHandler')],
  ['device permissions fail closed through the engine adapter', privacySource.includes('engine?.installDevicePermissionHandlers') && adapterSource.includes('setDevicePermissionHandler(()=>false)')],
  ['zoom isolation routes through BrowserRuntime', mainSource.includes("browserRuntime.zoomMode(view,'isolated')") && runtimeSource.includes('engine.setZoomMode(view,mode)') && adapterSource.includes('setZoomMode:(view,mode)')]
];
for (const [label, ok] of architectureChecks) {
  if (!ok) { console.error('Architecture hardening check failed:', label); bad = true; }
}

const uiSource = fs.readFileSync(path.join(root, 'src/ui/app.js'), 'utf8');
const preloadSource = fs.readFileSync(path.join(root, 'src/preload.js'), 'utf8');
const uiHtml = fs.readFileSync(path.join(root, 'src/ui/index.html'), 'utf8');

function unique(values) { return [...new Set(values)].sort(); }
function channelMatches(source, rx) { return unique([...source.matchAll(rx)].map((m) => m[1])); }
function setValues(source, name) {
  const match = source.match(new RegExp(name + ' = new Set\\(\\[([\\s\\S]*?)\\]\\)'));
  return match ? unique([...match[1].matchAll(/'([^']+)'/g)].map((m) => m[1])) : [];
}

const uiSends = channelMatches(uiSource, /window\.aegis\.send\('([^']+)'/g);
const uiInvokes = channelMatches(uiSource, /window\.aegis\.invoke\('([^']+)'/g);
const allowedSends = setValues(preloadSource, 'allowedSend');
const allowedInvokes = setValues(preloadSource, 'allowedInvoke');
const mainOns = channelMatches(mainSource, /ipcMain\.on\('([^']+)'/g);
const mainHandles = channelMatches(mainSource, /ipcMain\.handle\('([^']+)'/g);

for (const channel of uiSends) {
  if (!allowedSends.includes(channel) || !mainOns.includes(channel)) {
    console.error('UI send channel is not fully wired:', channel);
    bad = true;
  }
}
for (const channel of uiInvokes) {
  if (!allowedInvokes.includes(channel) || !mainHandles.includes(channel)) {
    console.error('UI invoke channel is not fully wired:', channel);
    bad = true;
  }
}

const draftBlock = uiSource.match(/const draftControlIds = \[([\s\S]*?)\];/);
if (!draftBlock) {
  console.error('Settings draft control registry missing.');
  bad = true;
} else {
  const ids = [...draftBlock[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
  for (const id of ids) {
    if (!uiHtml.includes('id="' + id + '"') && !uiHtml.includes("id='" + id + "'")) {
      console.error('Settings control missing from UI:', id);
      bad = true;
    }
  }
}

const invalidSelectorIterations = uiSource.split('\n').filter((line) => /(^|[^$])\$\((['"])[^)\n]+\2\)\.forEach\(/.test(line));
if (invalidSelectorIterations.length) {
  console.error('Single-node selector iterated as a collection:', invalidSelectorIterations.join(' | '));
  bad = true;
}

const mapNames = [...mainSource.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new Map\s*\(/g)].map((m) => m[1]);
for (const name of mapNames) {
  for (const method of ['filter','map','some','find','slice','reduce','includes','at','flatMap','sort']) {
    if (new RegExp('\\b' + name + '\\.' + method + '\\s*\\(').test(mainSource)) {
      console.error('Map collection uses Array-only method:', name + '.' + method);
      bad = true;
    }
  }
}
if (/\bcreateStats\s*\(/.test(mainSource)) {
  console.error('Stale Security Suite stats factory present: createStats().');
  bad = true;
}
if (/candidate\?\.view\?\.webContents/.test(mainSource)) {
  console.error('Security Suite bypasses BrowserRuntime with a direct candidate view webContents check.');
  bad = true;
}

const browserRuntimeSource = fs.readFileSync(path.join(root, 'src/core/browser-runtime.js'), 'utf8');
const usedRuntimeOps = unique([...mainSource.matchAll(/\bbrowserRuntime\.([A-Za-z0-9_]+)\b/g)].map((m) => m[1]));
const exposedRuntimeOps = unique([...browserRuntimeSource.matchAll(/\b([A-Za-z0-9_]+)\s*:\s*\(/g)].map((m) => m[1]));
for (const op of usedRuntimeOps) {
  if (!exposedRuntimeOps.includes(op)) {
    console.error('BrowserRuntime operation used but not exposed:', op);
    bad = true;
  }
}

const privacyHeaderHandlers = [...privacySource.matchAll(/ses\.webRequest\.onBeforeSendHeaders\(/g)].length;
if (privacyHeaderHandlers !== 1) {
  console.error('Privacy session must register exactly one onBeforeSendHeaders pipeline; found:', privacyHeaderHandlers);
  bad = true;
}

const launcher = fs.readFileSync(path.join(root, 'Run-Aegis.command'), 'utf8');
const packageVersion = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
const launcherVersion = launcher.match(/VERSION="([^"]+)"/)?.[1] || '';
if (!packageVersion || launcherVersion !== packageVersion) {
  console.error('Release version mismatch:', { packageVersion, launcherVersion });
  bad = true;
}

for (const token of ['Library/Application Support','rsync','runtime-v$VERSION','44.4.3','codesign --verify --deep --strict','shasum -a 256','ELECTRON_RUN_AS_NODE=1','darwin-$ELECTRON_ARCH.zip']) {
  if (!launcher.includes(token)) { console.error('Launcher hardening token missing:', token); bad = true; }
}
if (corpus.includes('setJavaScriptEnabled')) { console.error('Unsupported Electron API present: setJavaScriptEnabled'); bad = true; }
if (bad) process.exit(1);
console.log('Aegis self-check passed.');
