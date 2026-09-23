'use strict';
const crypto=require('node:crypto');
function canonical(value){
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 if(value&&typeof value==='object')return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
 return JSON.stringify(value);
}
function versionParts(v){return String(v??'0').split(/[.-]/).map(x=>/^\d+$/.test(x)?Number(x):x)}
function compareVersions(a,b){const x=versionParts(a),y=versionParts(b),n=Math.max(x.length,y.length);for(let i=0;i<n;i++){const A=x[i]??0,B=y[i]??0;if(A===B)continue;if(typeof A==='number'&&typeof B==='number')return A>B?1:-1;return String(A)>String(B)?1:-1}return 0}
function verifyBundle(bundle,publicKeyPem,{minimumVersion=null,expectedKeyId=null,now=Date.now()}={}){
 if(!bundle||typeof bundle!=='object'||!bundle.policy||typeof bundle.signature!=='string')return {ok:false,error:'Invalid policy bundle.'};
 if(!publicKeyPem)return {ok:false,error:'No administrator policy public key is configured.'};
 try{
  const p=bundle.policy;
  if(expectedKeyId&&String(p.keyId||'')!==String(expectedKeyId))return {ok:false,error:'Managed policy signing key ID is not trusted.'};
  if(p.issuedAt&&Date.parse(p.issuedAt)>now+300000)return {ok:false,error:'Managed policy issue time is in the future.'};
  if(p.expiresAt&&Date.parse(p.expiresAt)<=now)return {ok:false,error:'Managed policy has expired.'};
  if(minimumVersion!=null&&compareVersions(p.version,minimumVersion)<0)return {ok:false,error:'Managed policy rollback rejected.'};
  const data=Buffer.from(canonical(p)),sig=Buffer.from(bundle.signature,'base64');
  if(!crypto.verify(null,data,publicKeyPem,sig))return {ok:false,error:'Managed policy signature verification failed.'};
  return {ok:true,policy:p,digest:crypto.createHash('sha256').update(data).digest('hex')};
 }catch(err){return {ok:false,error:'Managed policy verification failed: '+err.message};}
}
function applyManagedPolicy(current,policy){
 const locked=policy?.settings&&typeof policy.settings==='object'?policy.settings:{};
 return {...current,...locked,enterprise:{...(current.enterprise||{}),...(locked.enterprise||{})},proxy:{...(current.proxy||{}),...(locked.proxy||{})},anonymity:{...(current.anonymity||{}),...(locked.anonymity||{})},permissionDefaults:{...(current.permissionDefaults||{}),...(locked.permissionDefaults||{})},managedPolicy:{id:String(policy?.id||''),version:String(policy?.version||''),keyId:String(policy?.keyId||''),issuedAt:policy?.issuedAt||null,expiresAt:policy?.expiresAt||null,lockedKeys:Object.keys(locked)}};
}
function preserveLockedSettings(current,patch){
 const keys=new Set(current?.managedPolicy?.lockedKeys||[]),out={...patch};for(const key of keys)delete out[key];return out;
}
function policyRuntimeStatus(settings,now=Date.now()){const p=settings?.managedPolicy;if(!p?.id)return {valid:true,managed:false,reason:'unmanaged'};if(p.expiresAt&&Date.parse(p.expiresAt)<=now)return {valid:false,managed:true,reason:'expired'};return {valid:true,managed:true,reason:'active',id:p.id,version:p.version,keyId:p.keyId||''}}
module.exports={canonical,compareVersions,verifyBundle,applyManagedPolicy,preserveLockedSettings,policyRuntimeStatus};
