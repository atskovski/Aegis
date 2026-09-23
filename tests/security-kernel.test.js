'use strict';const test=require('node:test');const assert=require('node:assert/strict');const {decision}=require('../src/core/security-kernel');
test('enterprise blocklist wins over allowlist',()=>{const s={enterpriseMode:true,enterprise:{urlAllowlist:['example.com'],urlBlocklist:['example.com']}};assert.equal(decision('navigate',{settings:s,url:'https://example.com'}).allow,false)});
test('anonymous compartment denies downloads',()=>{assert.equal(decision('download',{settings:{},tab:{securityDomain:'anonymous'}}).allow,false)});
test('expired managed policy fails closed',()=>{const s={managedPolicy:{id:'x',expiresAt:'2000-01-01T00:00:00Z'}};assert.equal(decision('navigate',{settings:s,url:'https://example.com'}).allow,false)});
