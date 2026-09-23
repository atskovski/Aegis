'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {makeBounceTracker,noteNavigation,detectBounce,sameSite}=require('../src/core/bounce-tracking');

test('sameSite approximates ordinary registrable domains',()=>{
  assert.equal(sameSite('https://www.example.com/a','https://cdn.example.com/b'),true);
  assert.equal(sameSite('https://example.com','https://tracker.test'),false);
});
test('detects a short-lived cross-site redirect intermediary',()=>{
  const s=makeBounceTracker(), t=Date.now();
  noteNavigation(s,'https://shop.example','https://tracker.invalid/click',t);
  noteNavigation(s,'https://tracker.invalid/click','https://merchant.example/landing',t+900);
  const hit=detectBounce(s,12,t+1000);
  assert.equal(hit.intermediaryHost,'tracker.invalid');
});
test('does not flag slow or same-site navigation',()=>{
  const s=makeBounceTracker(), t=Date.now();
  noteNavigation(s,'https://a.example.com','https://b.example.com',t);
  noteNavigation(s,'https://b.example.com','https://c.example.com',t+500);
  assert.equal(detectBounce(s,12,t+600),null);
  const s2=makeBounceTracker();
  noteNavigation(s2,'https://one.example','https://tracker.invalid',t);
  noteNavigation(s2,'https://tracker.invalid','https://two.example',t+20000);
  assert.equal(detectBounce(s2,12,t+20001),null);
});
