'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const zlib=require('node:zlib');
const { safeEntryName, patternMatches }=require('../src/core/xpi-package');

test('XPI path validation blocks traversal and absolute paths',()=>{
  assert.equal(safeEntryName('../evil.js'),'');
  assert.equal(safeEntryName('/evil.js'),'');
  assert.equal(safeEntryName('scripts/content.js'),'scripts/content.js');
});

test('WebExtension match patterns support exact and wildcard hosts',()=>{
  assert.equal(patternMatches('https://example.com/a','https://example.com/*'),true);
  assert.equal(patternMatches('https://sub.example.com/a','https://*.example.com/*'),true);
  assert.equal(patternMatches('http://sub.example.com/a','https://*.example.com/*'),false);
  assert.equal(patternMatches('https://anything.test/a','<all_urls>'),true);
});
