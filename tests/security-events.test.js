'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {createSecurityEventLedger}=require('../src/core/security-events');
test('ledger is bounded and supports per-tab evidence',()=>{
 const l=createSecurityEventLedger(50);for(let i=0;i<70;i++)l.add('x','info',{i},i%2);
 assert.equal(l.list().length,50);assert.equal(l.list(0).every(x=>x.tabId===0),true);
});
test('ledger copies event detail and clears',()=>{
 const l=createSecurityEventLedger();const e=l.add('tls','danger',{host:'example.test'},3);
 assert.equal(e.type,'tls');const out=l.list(3);out[0].detail.host='changed';assert.equal(l.list(3)[0].detail.host,'example.test');l.clear();assert.equal(l.list().length,0);
});

test('ledger redacts secrets before retention',()=>{
 const l=createSecurityEventLedger();l.add('diagnostic','warning',{token:'topsecret',authorization:'Bearer abc.def',url:'https://x.test/?token=hidden'},1);
 const d=l.list(1)[0].detail;assert.equal(d.token,'[REDACTED]');assert.equal(d.authorization,'[REDACTED]');assert.doesNotMatch(d.url,/hidden/);
});
