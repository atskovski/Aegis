'use strict';
const crypto=require('node:crypto');
function canonical(value){
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
 return JSON.stringify(value);
}
function verifyBundle(bundle,publicKeyPem){
 if(!bundle||typeof bundle!=='object'||!bundle.policy||typeof bundle.signature!=='string')return {ok:false,error:'Invalid policy bundle.'};
 if(!publicKeyPem)return {ok:false,error:'No administrator policy public key is configured.'};
 try{
  const data=Buffer.from(canonical(bundle.policy));
  const sig=Buffer.from(bundle.signature,'base64');
  const ok=crypto.verify(null,data,publicKeyPem,sig);
  if(!ok)return {ok:false,error:'Managed policy signature verification failed.'};
  const p=bundle.policy;
  if(p.expiresAt&&Date.parse(p.expiresAt)<=Date.now())return {ok:false,error:'Managed policy has expired.'};
  return {ok:true,policy:p,digest:crypto.createHash('sha256').update(data).digest('hex')};
 }catch(err){return {ok:false,error:'Managed policy verification failed: '+err.message};}
}
function applyManagedPolicy(current,policy){
 const locked=policy?.settings&&typeof policy.settings==='object'?policy.settings:{};
 return {...current,...locked,
  enterprise:{...(current.enterprise||{}),...(locked.enterprise||{})},
  proxy:{...(current.proxy||{}),...(locked.proxy||{})},
  anonymity:{...(current.anonymity||{}),...(locked.anonymity||{})},
  permissionDefaults:{...(current.permissionDefaults||{}),...(locked.permissionDefaults||{})},
  managedPolicy:{id:String(policy?.id||''),version:String(policy?.version||''),issuedAt:policy?.issuedAt||null,expiresAt:policy?.expiresAt||null,lockedKeys:Object.keys(locked)}
 };
}
function preserveLockedSettings(current,patch){
 const keys=new Set(current?.managedPolicy?.lockedKeys||[]);
 const out={...patch}; for(const key of keys)delete out[key]; return out;
}
module.exports={canonical,verifyBundle,applyManagedPolicy,preserveLockedSettings};
