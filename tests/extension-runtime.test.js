'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const { analyzeManifest, installDecision, isSafeRelativeFile }=require('../src/core/extension-runtime');

test('valid static WebExtension manifests can enter compatibility runtime',()=>{
  const manifest={manifest_version:2,name:'Static Helper',version:'1.0.0',content_scripts:[{matches:['https://*/*'],js:['content.js']}]};
  const out=installDecision(manifest);
  assert.equal(out.allowed,true);
  assert.equal(out.mode,'compat-runtime');
});

test('Firefox capabilities that Aegis Chromium cannot fulfill require Gecko',()=>{
  const manifest={manifest_version:2,name:'Proxy Add-on',version:'1.0.0',permissions:['proxy'],background:{scripts:['bg.js']}};
  const out=installDecision(manifest);
  assert.equal(out.allowed,false);
  assert.equal(out.mode,'requires-gecko');
  assert.ok(out.report.unsupported.includes('proxy'));
  assert.ok(out.report.unsupported.includes('background'));
});

test('manifest validation rejects unsafe content-script paths',()=>{
  assert.equal(isSafeRelativeFile('../escape.js'),false);
  assert.equal(isSafeRelativeFile('/absolute.js'),false);
  assert.equal(isSafeRelativeFile('scripts/ok.js'),true);
});

test('malformed manifests are rejected before install',()=>{
  const out=analyzeManifest({manifest_version:7,name:'',version:'banana'});
  assert.equal(out.valid,false);
  assert.ok(out.errors.length>=2);
});
