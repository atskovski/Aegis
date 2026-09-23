'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const {policyFor}=require('../src/core/fingerprint-policy');
test('strict cohort is deterministic and coherent',()=>{const a=policyFor({profile:'strict',chromiumMajor:'152'}),b=policyFor({profile:'strict',chromiumMajor:'152'});assert.deepEqual(a,b);assert.equal(a.timezone,'UTC');assert.equal(a.cores,4);assert.equal(a.webgl,'normalized');});
test('anonymous always elevates to maximum cohort',()=>{const p=policyFor({profile:'standard',anonymousMode:true});assert.equal(p.name,'maximum');assert.equal(p.webrtc,'blocked');assert.equal(p.webgl,'blocked');});
