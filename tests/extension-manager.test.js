'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');

const root=path.resolve(__dirname,'..');
const read=(rel)=>fs.readFileSync(path.join(root,rel),'utf8');
const html=read('src/ui/index.html');
const ui=read('src/ui/app.js');
const preload=read('src/preload.js');
const main=read('src/main.js');
const runtime=read('src/core/extensions.js');
const shim=read('src/core/extension-shim.js');
const pagePreload=read('src/extension-page-preload.js');
const bridgePreload=read('src/extension-bridge-preload.js');

test('Extensions manager exposes staged review and installed-extension controls',()=>{
  for(const id of [
    'extensionActions','installReferenceExtension','installExtensionPackage','loadUnpackedExtension','addonUrlInput','installAddonUrl','addonRuntimeSummary','addonHealthyCount','addonDegradedCount',
    'addonReview','addonReviewName','addonReviewScore','addonReviewPermissions','addonReviewHosts','addonReviewUnsupported','addonReviewFeatures',
    'addonReviewId','addonReviewDigest','confirmAddonInstall','cancelAddonInstall','addonSearch','addonFilter','refreshAddons','addonList','addonManagerStatus','storeInstall'
  ]) assert.match(html,new RegExp('id="'+id+'"'));
  assert.match(ui,/extensions:pick-package/);
  assert.match(ui,/PRIVACY_BADGER_CHROME_ID/);
  assert.match(ui,/installReferenceExtension/);
  assert.match(ui,/extensions:pick-unpacked/);
  assert.match(ui,/extensions:install-url/);
  assert.match(ui,/extensionStoreSource/);
  assert.match(ui,/storeInstall/);
  assert.match(ui,/renderStoreInstallButton\(\);/);
  assert.doesNotMatch(ui,/renderStoreInstallButton\(tab\);/);
  assert.match(ui,/extensions:install-staged/);
  assert.match(ui,/extensions:diagnose/);
  assert.match(ui,/extensions:cancel-install/);
  assert.match(ui,/extensions:open-action/);
  assert.match(ui,/extensions:open-options/);
  assert.match(ui,/extensions:reload/);
  assert.match(ui,/Check update/);
  assert.match(ui,/updateFor:addon\.id/);
  assert.match(ui,/Update rejected because the downloaded package identity does not match/);
  assert.match(ui,/Already current at version/);
  assert.match(ui,/Extension updated/);
  assert.match(ui,/let refreshError = '';/);
  assert.match(ui,/The Extensions view could not refresh automatically/);
  assert.match(ui,/100% package installed/);
  assert.match(ui,/Package installation is complete\. API\/runtime compatibility is reported separately\./);
  assert.doesNotMatch(ui,/confirm\('Remove '/);
});

test('extension manager IPC is allowlisted and implemented',()=>{
  for(const channel of [
    'extensions:list','extensions:pick-package','extensions:pick-unpacked','extensions:install-url','extensions:cancel-install','extensions:install-staged',
    'extensions:set-enabled','extensions:diagnose','extensions:reload','extensions:open-action','extensions:open-options','extensions:remove'
  ]){
    assert.ok(preload.includes("'"+channel+"'"),channel+' missing from preload allowlist');
    assert.ok(main.includes("ipcMain.handle('"+channel+"'"),channel+' missing main handler');
  }
});

test('extension runtime hosts the major WebExtension execution surfaces',()=>{
  for(const api of ['action','browserAction','pageAction','alarms','commands','scripting','webNavigation','windows','cookies']) assert.ok(runtime.includes("'"+api+"'"));
  assert.match(runtime,/async openAction\(/);
  assert.match(runtime,/async openOptions\(/);
  assert.match(runtime,/async openExtensionPage\(/);
  assert.match(runtime,/notifyTabCreated/);
  assert.match(runtime,/notifyTabUpdated/);
  assert.match(runtime,/notifyNavigation/);
  assert.match(runtime,/clearActiveGrantForTab/);
  assert.match(runtime,/requiresSubFramePreload/);
  assert.match(runtime,/injectAllSubframes/);
  assert.match(runtime,/sendTabMessage/);
  assert.match(runtime,/blockingWebRequestDecision/);
  assert.match(runtime,/handleBlockingWebRequestResponse/);
  assert.match(main,/extension:blocking-webrequest-response/);
  assert.match(bridgePreload,/extension:frame-message/);
  assert.match(pagePreload,/extension:blocking-webrequest/);
  assert.match(pagePreload,/webRequestMeta/);
  assert.match(pagePreload,/webRequestFilterMatches/);
  assert.match(main,/nodeIntegrationInSubFrames: subframeBridge/);
  assert.match(main,/frame-created/);
  assert.match(main,/extension:frame-inject-result/);
  assert.match(main,/extension:frame-message-result/);
  assert.match(bridgePreload,/extension:frame-inject/);
  assert.match(bridgePreload,/extension:frame-message/);
  assert.match(runtime,/Aegis isolated-world bridge was not ready for this document/);
  assert.match(runtime,/content-script:'\+rel/);
  assert.match(runtime,/sourceURL='\+extensionResourceUrl/);
  assert.match(runtime,/bg\.page/);
});

test('shared shim and extension page preload expose matching WebExtension namespaces',()=>{
  for(const api of ['runtime','storage','tabs','windows','cookies','permissions','i18n','alarms','commands','scripting','webNavigation','webRequest','declarativeNetRequest','privacy','notifications','menus','contextMenus','action','browserAction','pageAction']){
    assert.ok(shim.includes(api),api+' missing from shared shim');
    assert.ok(pagePreload.includes(api),api+' missing from extension page preload');
  }
});

test('protected browser capabilities remain unavailable to extensions',()=>{
  assert.match(runtime,/proxy:'Extensions cannot replace Aegis network routing/);
  assert.match(runtime,/nativeMessaging:'Native messaging is disabled/);
  assert.match(runtime,/management:'Extensions cannot manage other extensions/);
  assert.match(runtime,/debugger:'The Chrome debugger API is not exposed/);
  assert.match(runtime,/securityDomain!=='anonymous'/);
  assert.match(runtime,/securityDomain!=='hardened'/);
});


test('extension menus and notifications integrate through Aegis-owned chrome',()=>{
  assert.match(runtime,/contextMenuTemplate\(/);
  assert.match(runtime,/notifications\.create/);
  assert.match(main,/extensionRuntime\?\.contextMenuTemplate\(tab, params\)/);
  assert.match(main,/notifyExtension:/);
});


test('Runtime 6 manager and bridge expose Chrome package health repair and persistent Port messaging',()=>{
  assert.match(html,/AEGIS CHROME EXTENSION RUNTIME 6/);
  assert.match(html,/Chrome Web Store, extension ID, or direct package URL/);
  assert.match(html,/What Runtime 6 implements/);
  assert.doesNotMatch(html,/Firefox Add-ons|XPI/);
  assert.match(ui,/function addonHealth/);
  assert.match(ui,/Health check/);
  assert.match(ui,/Repair runtime/);
  assert.match(runtime,/async diagnose\(/);
  assert.match(runtime,/runtime\.portOpen/);
  assert.match(runtime,/runtime\.portPost/);
  assert.match(runtime,/tabs\.connect/);
  assert.match(shim,/runtimeConnect/);
  assert.match(shim,/managed:area\('managed'\)/);
  assert.match(pagePreload,/runtimeConnect/);
  assert.match(pagePreload,/managed:area\('managed'\)/);
  assert.match(pagePreload,/extension:runtime-error/);
  assert.match(main,/extension:runtime-error/);
  assert.match(runtime,/recordRendererError/);
  assert.match(pagePreload,/@@ui_locale/);
  assert.match(shim,/@@ui_locale/);
});


test('Chrome package manager exposes CRX Web Store and unpacked flows',()=>{
  assert.match(html,/Choose CRX \/ ZIP/);
  assert.match(html,/Load unpacked/);
  assert.match(html,/CRX2\/CRX3, ZIP and unpacked/);
  assert.match(main,/chromewebstore\.google\.com/);
  assert.match(main,/clients2\.google\.com\/service\/update2\/crx/);
  assert.doesNotMatch(main,/addons\.mozilla\.org/);
  assert.match(main,/acceptformat=crx2,crx3/);
  assert.match(runtime,/parseCrxBuffer/);
  assert.match(runtime,/format:'crx3'/);
  assert.match(runtime,/stageDirectory/);
  assert.match(runtime,/installDirectory/);
});
