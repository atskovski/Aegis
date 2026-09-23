'use strict';
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const required = [
  'src/main.js','src/preload.js','src/core/privacy.js','src/core/compartment.js','src/core/control-registry.js','src/core/url.js','src/core/blocklist.js',
  'src/core/fingerprint.js','src/core/security-events.js','src/core/bounce-tracking.js','src/core/settings.js','src/core/site-intelligence.js','src/core/security-suite.js','src/core/navigation.js','src/core/network.js','src/core/filter-rules.js','src/core/tracker-learning.js','src/core/safety.js','src/core/sponsor.js','src/ui/index.html','src/ui/start.html','src/ui/start.css','src/ui/start.js','src/ui/error.html','src/ui/error.js','src/ui/error.css','src/ui/styles.css','src/ui/app.js',
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
  'setDevicePermissionHandler','disable-background-networking','force-webrtc-ip-handling-policy','site-per-process',
  "minVersion: 'tls1.2'",'blockThirdPartyCookies','clearData','closeAllConnections',
  'cache: false',"v8CacheOptions: 'none'",'javascript: Boolean(tab.javascriptEnabled)','permission:prompt','permission:respond',
  "registerInternalProtocol(privateSession.protocol","registerInternalProtocol(protocol, 'default UI session')","setZoomMode('isolated')","navigationUrl(event, legacyDetails)","mode: 'system'","runConnectivityTest","heuristicTrackingProtection","cookieAutoDelete","https://duckduckgo.com/","freshSession: true","aegis-diagnostic-","blockThirdPartyRequests","blockPrivateNetwork","blockAllDownloads","anonymousRouteRequired","onBeforeSendHeaders","Sec-GPC","testStorageResurrection","testProcessIsolation","createSecurityEventLedger","bounceTrackingProtection","sha256","enterpriseMode","evaluateUrl","extensionAllowed","mediaClickToPlay"
]) {
  if (!corpus.includes(token)) { console.error('Hardening token missing:', token); bad = true; }
}
const launcher = fs.readFileSync(path.join(root, 'Run-Aegis.command'), 'utf8');
for (const token of ['Library/Application Support','rsync','runtime-v$VERSION','44.4.3','codesign --verify --deep --strict','shasum -a 256','ELECTRON_RUN_AS_NODE=1','darwin-$ELECTRON_ARCH.zip']) {
  if (!launcher.includes(token)) { console.error('Launcher hardening token missing:', token); bad = true; }
}
if (corpus.includes('setJavaScriptEnabled')) { console.error('Unsupported Electron API present: setJavaScriptEnabled'); bad = true; }
if (bad) process.exit(1);
console.log('Aegis self-check passed.');
