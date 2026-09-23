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

test('Add-ons manager exposes staged review and installed-extension controls',()=>{
  for(const id of [
    'extensionActions','installXpi','addonRuntimeSummary','addonReview','addonReviewName','addonReviewScore',
    'addonReviewPermissions','addonReviewHosts','addonReviewUnsupported','addonReviewFeatures',
    'addonReviewId','addonReviewDigest','confirmAddonInstall','cancelAddonInstall','addonList','addonManagerStatus'
  ]) assert.match(html,new RegExp('id="'+id+'"'));
  assert.match(ui,/extensions:pick-package/);
  assert.match(ui,/extensions:install-staged/);
  assert.match(ui,/extensions:cancel-install/);
  assert.match(ui,/extensions:open-action/);
  assert.match(ui,/extensions:open-options/);
  assert.match(ui,/extensions:reload/);
  assert.doesNotMatch(ui,/confirm\('Remove '/);
});

test('extension manager IPC is allowlisted and implemented',()=>{
  for(const channel of [
    'extensions:list','extensions:pick-package','extensions:cancel-install','extensions:install-staged',
    'extensions:set-enabled','extensions:reload','extensions:open-action','extensions:open-options','extensions:remove'
  ]){
    assert.ok(preload.includes("'"+channel+"'"),channel+' missing from preload allowlist');
    assert.ok(main.includes("ipcMain.handle('"+channel+"'"),channel+' missing main handler');
  }
});

test('extension runtime hosts the major WebExtension execution surfaces',()=>{
  for(const api of ['action','browserAction','pageAction','alarms','commands','scripting','webNavigation']) assert.ok(runtime.includes("'"+api+"'"));
  assert.match(runtime,/async openAction\(/);
  assert.match(runtime,/async openOptions\(/);
  assert.match(runtime,/async openExtensionPage\(/);
  assert.match(runtime,/notifyTabCreated/);
  assert.match(runtime,/notifyTabUpdated/);
  assert.match(runtime,/notifyNavigation/);
  assert.match(runtime,/clearActiveGrantForTab/);
  assert.match(runtime,/bg\.page/);
});

test('shared shim and extension page preload expose matching WebExtension namespaces',()=>{
  for(const api of ['runtime','storage','tabs','permissions','i18n','alarms','commands','scripting','webNavigation','action','browserAction','pageAction']){
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
