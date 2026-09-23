'use strict';
const {evaluateUrl,extensionAllowed}=require('./enterprise-policy');
const {isPrivateNetworkUrl,effectiveSettings}=require('./compartment');
const {policyRuntimeStatus}=require('./managed-policy');
const ACTIONS=Object.freeze(['navigate','redirect','popup','request','permission','download','extension','clipboard-read','screen-capture','print','devtools']);
const HIGH_RISK_SCHEMES=/^(?:file|javascript|data|vbscript|filesystem):/i;
function verdict(allow,action,reason,layer,risk='low',extra={}){return Object.freeze({allow:Boolean(allow),action,reason,layer,risk,...extra})}
function sitePermission(effective,origin,key){
 const site=effective.sitePermissions?.[origin]?.[key];if(site==='allow'||site==='block')return site;
 const d=effective.permissionDefaults?.[key];return d==='allow'||d==='ask'||d==='block'?d:'block';
}
function decision(action,ctx={}){
 const {settings={},tab=null,url='',extensionId='',permission='',origin='',userGesture=false,resourceType='',thirdParty=false}=ctx;
 if(!ACTIONS.includes(action))return verdict(false,action,'unknown-security-action','kernel','high');
 const effective=effectiveSettings(settings,tab),managed=policyRuntimeStatus(settings);
 if(!managed.valid)return verdict(false,action,'managed-policy-'+managed.reason,'managed-policy','critical');
 if(['navigate','redirect','popup','request'].includes(action)){
  if(HIGH_RISK_SCHEMES.test(String(url)))return verdict(false,action,'dangerous-scheme','transport','critical');
  if(['navigate','redirect','popup'].includes(action)){
   const enterprise=evaluateUrl(url,effective);if(!enterprise.allowed)return verdict(false,action,enterprise.reason,'enterprise','high');
   if(effective.httpsOnly&&/^http:/i.test(url)&&!tab?.allowHttp)return verdict(false,action,'https-only','transport','high');
  }
  if(effective.blockPrivateNetwork&&isPrivateNetworkUrl(url))return verdict(false,action,'private-network','compartment','critical');
  if(action==='request'&&effective.blockThirdPartyRequests&&thirdParty)return verdict(false,action,'third-party-request','privacy','medium',{resourceType});
  return verdict(true,action,'allowed','kernel','low');
 }
 if(action==='extension')return extensionAllowed(extensionId,effective)&&!effective.disableExtensions?verdict(true,action,'allowed','kernel'):verdict(false,action,'extension-policy','extension','high');
 if(action==='download'){
  if(effective.blockAllDownloads||effective.anonymousRouteRequired)return verdict(false,action,'download-policy','compartment','high');
  return verdict(true,action,'allowed','kernel');
 }
 if(action==='permission'){
  const v=sitePermission(effective,origin,permission);
  if(v==='allow')return verdict(true,action,'permission-allow','permission','medium');
  if(v==='ask'&&userGesture)return verdict(false,action,'permission-requires-user-confirmation','permission','medium',{prompt:true});
  return verdict(false,action,v==='ask'?'permission-no-user-gesture':'permission-blocked','permission','high');
 }
 if(action==='clipboard-read'&&effective.enterpriseMode&&effective.enterprise?.disableClipboardRead!==false)return verdict(false,action,'enterprise-clipboard-policy','enterprise','high');
 if(action==='screen-capture'&&effective.enterpriseMode&&effective.enterprise?.disableScreenCapture!==false)return verdict(false,action,'enterprise-screen-capture-policy','enterprise','high');
 if(action==='print'&&effective.enterpriseMode&&effective.enterprise?.disablePrinting===true)return verdict(false,action,'enterprise-print-policy','enterprise','medium');
 if(action==='devtools'&&effective.enterpriseMode&&effective.enterprise?.disableDeveloperTools!==false)return verdict(false,action,'enterprise-devtools-policy','enterprise','high');
 return verdict(true,action,'allowed','kernel','low');
}
function createSecurityKernel({getSettings=()=>({}),emit=()=>{}}={}){
 let seq=0;
 const decide=(action,ctx={})=>{const out=decision(action,{...ctx,settings:ctx.settings||getSettings()});const evidence={sequence:++seq,at:new Date().toISOString(),...out,url:ctx.url||'',origin:ctx.origin||'',tabId:ctx.tab?.id??null};try{emit(evidence)}catch{}return out};
 return Object.freeze({decide,navigate:(ctx)=>decide('navigate',ctx),redirect:(ctx)=>decide('redirect',ctx),popup:(ctx)=>decide('popup',ctx),request:(ctx)=>decide('request',ctx),permission:(ctx)=>decide('permission',ctx),download:(ctx)=>decide('download',ctx),extension:(ctx)=>decide('extension',ctx),evidence:()=>({actions:[...ACTIONS],sequence:seq,failClosed:true})});
}
module.exports={ACTIONS,HIGH_RISK_SCHEMES,decision,createSecurityKernel,sitePermission};
