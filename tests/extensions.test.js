'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { safeRel, normalizeManifest, compatibility, matchPattern, matchingContentScripts, installRisk } = require('../src/core/extensions');

test('XPI runtime rejects unsafe relative paths', () => {
  assert.equal(safeRel('../secret'), '');
  assert.equal(safeRel('/absolute'), '');
  assert.equal(safeRel('content/main.js'), 'content/main.js');
});

test('WebExtension manifest validation accepts v2/v3 and requires identity fields', () => {
  assert.equal(normalizeManifest({manifest_version:2,name:'Test',version:'1.0'}).name, 'Test');
  assert.equal(normalizeManifest({manifest_version:3,name:'Test',version:'1.0'}).manifest_version, 3);
  assert.throws(() => normalizeManifest({manifest_version:1,name:'Old',version:'1'}));
});

test('Firefox match patterns are applied conservatively', () => {
  assert.equal(matchPattern('https://news.example.com/a?b=1','*://*.example.com/*'), true);
  assert.equal(matchPattern('https://example.net/a','*://*.example.com/*'), false);
  assert.equal(matchPattern('https://example.com/a','<all_urls>'), true);
});

test('matching content scripts honor include and exclude patterns', () => {
  const manifest={manifest_version:2,name:'T',version:'1',content_scripts:[{matches:['*://*.example.com/*'],exclude_matches:['*://private.example.com/*'],js:['x.js']}]};
  assert.equal(matchingContentScripts(manifest,'https://www.example.com/page').length,1);
  assert.equal(matchingContentScripts(manifest,'https://private.example.com/page').length,0);
});

test('compatibility report never claims unsupported privileged APIs work', () => {
  const manifest={manifest_version:2,name:'T',version:'1',permissions:['storage','tabs','webRequest','proxy'],background:{scripts:['bg.js']}};
  const report=compatibility(manifest);
  assert.ok(report.supported.includes('storage'));
  assert.ok(report.unsupported.some((x)=>x.api==='webRequest'));
  assert.ok(report.unsupported.some((x)=>x.api==='proxy'));
  assert.ok(report.unsupported.some((x)=>x.api==='background'));
  assert.equal(report.background,'not-implemented');
  assert.ok(report.score < 100);
});

test('high-power extension permissions are marked high risk', () => {
  const manifest={manifest_version:2,name:'T',version:'1',permissions:['<all_urls>','storage']};
  const risk=installRisk(manifest);
  assert.equal(risk.find((x)=>x.permission==='<all_urls>').level,'high');
});
