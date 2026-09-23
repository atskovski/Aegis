'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {assertEngineAdapter,engineEvidence}=require('../src/core/engine-contract');
function fake(){return {name:()=> 'fake',version:()=> '1',capabilities:()=>({views:true,sessions:true,protocols:true,networkInterception:true,permissions:true,proxy:true,downloads:true,devtoolsProtocol:true,isolatedWorlds:true,certificatePolicy:true}),createSession(){},createView(){},attachView(){},detachView(){},destroyView(){},registerProtocol(){},fetch(){},getRuntimeVersions:()=>({chromium:'x'})};}
test('engine contract accepts complete adapter',()=>{assert.equal(assertEngineAdapter(fake()).name(),'fake');assert.equal(engineEvidence(fake()).capabilities.views,true);});
test('engine contract rejects incomplete adapters',()=>{const x=fake();delete x.createView;assert.throws(()=>assertEngineAdapter(x),/createView/);});
