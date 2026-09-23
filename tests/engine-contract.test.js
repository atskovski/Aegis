'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {assertEngineAdapter,engineEvidence,REQUIRED}=require('../src/core/engine-contract');
function fake(){const x={name:()=> 'fake',version:()=> '1',capabilities:()=>({views:true,sessions:true,protocols:true,networkInterception:true,permissions:true,devicePermissions:true,proxy:true,downloads:true,devtoolsProtocol:true,isolatedWorlds:true,certificatePolicy:true,navigationPolicy:true,rendererLifecycle:true}),getRuntimeVersions:()=>({chromium:'x'})};for(const k of REQUIRED)if(!x[k])x[k]=()=>true;return x;}
test('engine contract accepts complete adapter',()=>{assert.equal(assertEngineAdapter(fake()).name(),'fake');assert.equal(engineEvidence(fake()).capabilities.views,true);});
test('engine contract rejects incomplete adapters',()=>{const x=fake();delete x.executeIsolatedWorld;assert.throws(()=>assertEngineAdapter(x),/executeIsolatedWorld/);});
test('engine contract requires explicit privileged capabilities',()=>{const x=fake();const caps=x.capabilities();delete caps.certificatePolicy;x.capabilities=()=>caps;assert.throws(()=>assertEngineAdapter(x),/certificatePolicy/);});
