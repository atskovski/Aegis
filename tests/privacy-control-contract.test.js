'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root=path.join(__dirname,'..');
const { CONTROL_DEFINITIONS } = require('../src/core/control-registry');
const { DEFAULT_SETTINGS, sanitizeSettings } = require('../src/core/settings');

const implementation=[
  fs.readFileSync(path.join(root,'src/main.js'),'utf8'),
  fs.readFileSync(path.join(root,'src/core/privacy.js'),'utf8'),
  fs.readFileSync(path.join(root,'src/core/fingerprint.js'),'utf8'),
  fs.readFileSync(path.join(root,'src/core/url.js'),'utf8'),
  fs.readFileSync(path.join(root,'src/core/settings.js'),'utf8'),
  fs.readFileSync(path.join(root,'src/core/control-registry.js'),'utf8')
].join('\n');

test('every advertised privacy control is backed by the settings schema', () => {
  for (const [key] of CONTROL_DEFINITIONS) {
    assert.ok(Object.prototype.hasOwnProperty.call(DEFAULT_SETTINGS,key), key+' is missing from DEFAULT_SETTINGS');
    assert.equal(typeof sanitizeSettings({[key]:true})[key], 'boolean', key+' is not sanitized as a boolean');
  }
});

test('every advertised privacy control has an implementation consumer outside the UI', () => {
  for (const [key] of CONTROL_DEFINITIONS) {
    const direct=new RegExp('settings\\.'+key+'\\b').test(implementation);
    const effective=new RegExp('effective\\.'+key+'\\b').test(implementation);
    const bracket=new RegExp("(?:settings|effective)\\[['\"]"+key+"['\"]\\]").test(implementation);
    assert.ok(direct||effective||bracket, key+' has no code-level settings consumer');
  }
});

test('the enforcement registry never reports an enabled unconfirmed document control as enforced', () => {
  const { controlAssurance } = require('../src/core/control-registry');
  const settings=sanitizeSettings({
    privacyApiGuard:true,
    blockTrackingBeacons:true,
    globalPrivacyControl:true,
    doNotTrack:true,
    cosmeticFiltering:true,
    siteIntelligence:true
  });
  const rows=controlAssurance(settings,{
    privacySessionReady:true,
    fingerprintReady:false,
    cosmeticFilteringReady:false,
    fingerprintStatus:{sentinelPreload:false}
  });
  for(const key of ['privacyApiGuard','blockTrackingBeacons','globalPrivacyControl','doNotTrack','cosmeticFiltering','siteIntelligence']){
    assert.notEqual(rows.find((x)=>x.key===key)?.status,'enforced',key+' falsely reported enforcement');
  }
});
