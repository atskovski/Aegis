'use strict';
function host(url){try{return new URL(String(url)).hostname.toLowerCase()}catch{return''}}
function matches(pattern,url){
 const p=String(pattern||'').trim().toLowerCase(); if(!p)return false;
 const h=host(url); if(!h)return false;
 if(p==='*')return true;
 if(p.startsWith('*.'))return h===p.slice(2)||h.endsWith('.'+p.slice(2));
 if(p.includes('://'))return String(url).toLowerCase().startsWith(p);
 return h===p||h.endsWith('.'+p);
}
function evaluateUrl(url,settings={}){
 if(!settings.enterpriseMode)return {allowed:true,reason:'enterprise-disabled'};
 const e=settings.enterprise||{}, allow=e.urlAllowlist||[], block=e.urlBlocklist||[];
 if(allow.length&&!allow.some(p=>matches(p,url)))return {allowed:false,reason:'not-on-enterprise-allowlist'};
 if(block.some(p=>matches(p,url))&&!allow.some(p=>matches(p,url)))return {allowed:false,reason:'enterprise-blocklist'};
 return {allowed:true,reason:'enterprise-policy'};
}
function extensionAllowed(id,settings={}){
 if(!settings.enterpriseMode)return true;
 const e=settings.enterprise||{}, list=(e.extensionAllowlist||[]).map(String);
 return e.blockUnlistedExtensions!==true||list.includes(String(id));
}
module.exports={matches,evaluateUrl,extensionAllowed};
