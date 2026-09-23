'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {matches,evaluateUrl,extensionAllowed}=require('../src/core/enterprise-policy');
test('enterprise URL allow and block boundaries',()=>{
 const s={enterpriseMode:true,enterprise:{urlAllowlist:['*.corp.example'],urlBlocklist:['evil.corp.example']}};
 assert.equal(evaluateUrl('https://portal.corp.example',s).allowed,true);
 assert.equal(evaluateUrl('https://public.example',s).allowed,false);
 assert.equal(evaluateUrl('https://evil.corp.example',s).allowed,true); // explicit allow boundary wins by design
});
test('blocklist denies destinations without allow override',()=>{
 const s={enterpriseMode:true,enterprise:{urlAllowlist:[],urlBlocklist:['tracker.example']}};
 assert.equal(evaluateUrl('https://tracker.example/a',s).allowed,false);
});
test('extension allowlist can be mandatory',()=>{
 const s={enterpriseMode:true,enterprise:{blockUnlistedExtensions:true,extensionAllowlist:['good-id']}};
 assert.equal(extensionAllowed('good-id',s),true);assert.equal(extensionAllowed('other',s),false);
});
test('wildcard host matching is subdomain safe',()=>{assert.equal(matches('*.example.com','https://a.example.com/x'),true);assert.equal(matches('*.example.com','https://example.net'),false);});
