'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const { protectionStatus, DEFINITIONS }=require('../src/core/protection-registry');

test('every registered protection exposes a backend evidence source',()=>{
  for(const def of Object.values(DEFINITIONS)){
    assert.ok(def.setting);
    assert.ok(def.evidence);
    assert.ok(def.layer);
  }
});

test('document protections report degraded when configured but runtime preload is not ready',()=>{
  const out=protectionStatus({privacyApiGuard:true,cosmeticFiltering:true,siteIntelligence:true},{fingerprintReady:false,cosmeticFilteringReady:false});
  const api=out.protections.find(x=>x.setting==='privacyApiGuard');
  const css=out.protections.find(x=>x.setting==='cosmeticFiltering');
  assert.equal(api.status,'degraded');
  assert.equal(css.status,'degraded');
  assert.ok(out.summary.degraded>=2);
});

test('document protections report enforced when their runtime evidence is ready',()=>{
  const out=protectionStatus({privacyApiGuard:true,cosmeticFiltering:true,siteIntelligence:true},{fingerprintReady:true,cosmeticFilteringReady:true,siteIntelligence:{}});
  assert.equal(out.protections.find(x=>x.setting==='privacyApiGuard').status,'enforced');
  assert.equal(out.protections.find(x=>x.setting==='cosmeticFiltering').status,'enforced');
  assert.equal(out.protections.find(x=>x.setting==='siteIntelligence').status,'enforced');
});
