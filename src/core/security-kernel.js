'use strict';
const {evaluateUrl,extensionAllowed}=require('./enterprise-policy');
const {isPrivateNetworkUrl,effectiveSettings}=require('./compartment');
const {policyRuntimeStatus}=require('./managed-policy');
function decision(action,{settings={},tab=null,url='',extensionId='',permission=''}={}){
 const effective=effectiveSettings(settings,tab),managed=policyRuntimeStatus(settings);
 if(!managed.valid)return {allow:false,action,reason:'managed-policy-'+managed.reason,layer:'managed-policy'};
 if(action==='navigate'){
  const enterprise=evaluateUrl(url,effective);if(!enterprise.allowed)return {allow:false,action,reason:enterprise.reason,layer:'enterprise'};
  if(effective.blockPrivateNetwork&&isPrivateNetworkUrl(url))return {allow:false,action,reason:'private-network',layer:'compartment'};
  if(effective.httpsOnly&&/^http:/i.test(url)&&!tab?.allowHttp)return {allow:false,action,reason:'https-only',layer:'transport'};
  return {allow:true,action,reason:'allowed',layer:'kernel'};
 }
 if(action==='extension')return extensionAllowed(extensionId,effective)&&!effective.disableExtensions?{allow:true,action,reason:'allowed',layer:'kernel'}:{allow:false,action,reason:'extension-policy',layer:'extension'};
 if(action==='download'&&(effective.blockAllDownloads||effective.anonymousRouteRequired))return {allow:false,action,reason:'download-policy',layer:'compartment'};
 if(action==='permission'){const v=effective.permissionDefaults?.[permission];return v==='allow'?{allow:true,action,reason:'permission-default',layer:'permission'}:{allow:false,action,reason:v||'permission-not-granted',layer:'permission'};}
 return {allow:true,action,reason:'no-restriction',layer:'kernel'};
}
module.exports={decision};
