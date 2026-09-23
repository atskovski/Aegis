'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const crypto=require('node:crypto');
const {canonical,verifyBundle,applyManagedPolicy,preserveLockedSettings}=require('../src/core/managed-policy');
test('Ed25519 managed policy verifies and tampering fails',()=>{
 const {publicKey,privateKey}=crypto.generateKeyPairSync('ed25519');
 const policy={id:'corp',version:'1',settings:{enterpriseMode:true,privacyLevel:'maximum'}};
 const signature=crypto.sign(null,Buffer.from(canonical(policy)),privateKey).toString('base64');
 assert.equal(verifyBundle({policy,signature},publicKey).ok,true);
 policy.settings.privacyLevel='standard';
 assert.equal(verifyBundle({policy,signature},publicKey).ok,false);
});
test('managed keys cannot be overridden by UI patch',()=>{
 const s=applyManagedPolicy({privacyLevel:'strict'},{id:'x',settings:{privacyLevel:'maximum',enterpriseMode:true}});
 const p=preserveLockedSettings(s,{privacyLevel:'standard',theme:'x'});
 assert.equal(p.privacyLevel,undefined);assert.equal(p.theme,'x');assert.equal(s.privacyLevel,'maximum');
});
