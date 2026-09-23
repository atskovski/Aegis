'use strict';

const fs = require('node:fs');
const path = require('node:path');

function safeRel(value) {
  const v = String(value || '').replace(/\\/g, '/').replace(/^\.\//, '');
  if (!v || v.startsWith('/') || v.includes('\0') || v.split('/').some((x) => !x || x === '.' || x === '..')) return '';
  return v;
}

function localeMessages(ext) {
  const locale = safeRel(ext?.manifest?.default_locale || '');
  if (!locale) return {};
  const file = path.join(ext.path, '_locales', locale, 'messages.json');
  try {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
    const out = {};
    for (const [key, value] of Object.entries(raw || {})) {
      if (value && typeof value.message === 'string') out[key] = value.message;
    }
    return out;
  } catch {
    return {};
  }
}

function commandList(manifest) {
  return Object.entries(manifest?.commands || {}).map(([name, value]) => ({
    name,
    description: String(value?.description || ''),
    shortcut: String(value?.suggested_key?.mac || value?.suggested_key?.default || '')
  }));
}

function webExtensionBootstrap(ext, bridgeGlobal = '__aegisExtensionBridge') {
  const id = JSON.stringify(ext.id);
  const token = JSON.stringify(ext.resourceToken);
  const manifest = JSON.stringify(ext.manifest);
  const messages = JSON.stringify(localeMessages(ext));
  const bridge = JSON.stringify(bridgeGlobal);
  const messageHook = bridgeGlobal === '__aegisBackgroundBridge'
    ? "B.onMessage?.(async(p)=>{const response=await globalThis.__aegisReceiveMessage(p.message,p.sender||{});B.respond?.(p.messageId,response)});"
    : "B.onMessage?.((p)=>globalThis.__aegisReceiveMessage(p.message,p.sender||{}));";

  return `(()=>{'use strict';
const ID=${id},TOKEN=${token},M=Object.freeze(${manifest}),MSG=Object.freeze(${messages}),B=globalThis[${bridge}];if(!B)return;
if(globalThis.__aegisWebExtensionBootstrapId===ID)return;
const events=new Map();
const listeners=(name)=>{if(!events.has(name))events.set(name,[]);return events.get(name)};
const event=(name)=>({addListener:(f)=>{if(typeof f==='function'&&!listeners(name).includes(f))listeners(name).push(f)},removeListener:(f)=>{const a=listeners(name),i=a.indexOf(f);if(i>=0)a.splice(i,1)},hasListener:(f)=>listeners(name).includes(f),hasListeners:()=>listeners(name).length>0});
let runtimeLastError=null;
const call=(m,...a)=>{const cb=typeof a[a.length-1]==='function'?a.pop():null,p=Promise.resolve().then(()=>B.call(m,a));if(!cb)return p;p.then((value)=>{runtimeLastError=null;try{cb(value)}finally{runtimeLastError=null}}).catch((err)=>{runtimeLastError={message:String(err?.message||err||'Extension API call failed')};try{cb()}finally{runtimeLastError=null}});return undefined};
const area=(n)=>({get:(k,...r)=>call('storage.'+n+'.get',k,...r),getKeys:(...r)=>call('storage.'+n+'.getKeys',...r),getBytesInUse:(k,...r)=>call('storage.'+n+'.getBytesInUse',k,...r),set:(v,...r)=>call('storage.'+n+'.set',v,...r),remove:(k,...r)=>call('storage.'+n+'.remove',k,...r),clear:(...r)=>call('storage.'+n+'.clear',...r)});
const ports=new Map();
const portEvent=()=>{const a=[];return {addListener:(f)=>{if(typeof f==='function'&&!a.includes(f))a.push(f)},removeListener:(f)=>{const i=a.indexOf(f);if(i>=0)a.splice(i,1)},hasListener:(f)=>a.includes(f),hasListeners:()=>a.length>0,_emit:(...v)=>{for(const f of [...a])try{f(...v)}catch{}}}};
const makePort=(portId,name='',sender={})=>{if(ports.has(portId))return ports.get(portId);const onMessage=portEvent(),onDisconnect=portEvent();const p={name:String(name||''),sender:sender||{},error:undefined,onMessage,onDisconnect,postMessage:(msg)=>call('runtime.portPost',portId,msg),disconnect:()=>{ports.delete(portId);call('runtime.portDisconnect',portId).catch(()=>{});onDisconnect._emit(p)}};ports.set(portId,p);return p};
const portId=()=>('aegis-port-'+Date.now().toString(36)+'-'+Math.random().toString(36).slice(2));
const runtimeConnect=(...a)=>{let target=ID,info={};if(typeof a[0]==='string'){target=a[0];info=a[1]||{}}else info=a[0]||{};if(target!==ID)throw new Error('Cross-extension runtime.connect is not supported.');const id=portId(),p=makePort(id,info.name||'',{id:ID});call('runtime.portOpen',{portId:id,name:p.name}).catch((err)=>{p.error=err;ports.delete(id);p.onDisconnect._emit(p)});return p};
const runtime={id:ID,get lastError(){return runtimeLastError},getManifest:()=>M,getURL:(p='')=>'aegis-extension://'+TOKEN+'/'+String(p).replace(/^\\/+/,''),getPlatformInfo:(...a)=>call('runtime.getPlatformInfo',...a),getBrowserInfo:(...a)=>call('runtime.getBrowserInfo',...a),getContexts:(...a)=>call('runtime.getContexts',...a),openOptionsPage:(...a)=>call('runtime.openOptionsPage',...a),reload:(...a)=>call('runtime.reload',...a),sendMessage:(...a)=>call('runtime.sendMessage',...a),connect:runtimeConnect,onConnect:event('runtime.onConnect'),onMessage:event('runtime.onMessage'),onInstalled:event('runtime.onInstalled'),onStartup:event('runtime.onStartup')};
globalThis.__aegisReceiveMessage=async(msg,sender={})=>{for(const fn of [...listeners('runtime.onMessage')]){try{let settled=false,resolveResponse;const responsePromise=new Promise((resolve)=>{resolveResponse=resolve});const sendResponse=(value)=>{if(!settled){settled=true;resolveResponse(value)}return true};let r=fn(msg,sender,sendResponse);if(r&&typeof r.then==='function')r=await r;if(r===true){if(settled)return await responsePromise;return await Promise.race([responsePromise,new Promise((resolve)=>setTimeout(()=>resolve(undefined),30000))])}if(settled)return await responsePromise;if(r!==undefined)return r}catch{}}};
const tabs={query:(q={},...r)=>call('tabs.query',q||{},...r),get:(id,...r)=>call('tabs.get',id,...r),getCurrent:(...a)=>call('tabs.getCurrent',...a),create:(p={},...r)=>call('tabs.create',p||{},...r),update:(...a)=>call('tabs.update',...a),remove:(...a)=>call('tabs.remove',...a),reload:(...a)=>call('tabs.reload',...a),sendMessage:(...a)=>call('tabs.sendMessage',...a),connect:(id,info={})=>{const pid=portId(),p=makePort(pid,info.name||'',{id:ID});Promise.resolve(call('tabs.connect',id,{...info,portId:pid})).catch((err)=>{p.error=err;ports.delete(pid);p.onDisconnect._emit(p)});return p},executeScript:(...a)=>call('tabs.executeScript',...a),insertCSS:(...a)=>call('tabs.insertCSS',...a),removeCSS:(...a)=>call('tabs.removeCSS',...a),getZoom:(...a)=>call('tabs.getZoom',...a),setZoom:(...a)=>call('tabs.setZoom',...a),captureVisibleTab:(...a)=>call('tabs.captureVisibleTab',...a),onCreated:event('tabs.onCreated'),onUpdated:event('tabs.onUpdated'),onRemoved:event('tabs.onRemoved'),onActivated:event('tabs.onActivated'),onReplaced:event('tabs.onReplaced')};
const actionApi=(root)=>({setTitle:(d={},...r)=>call(root+'.setTitle',d||{},...r),getTitle:(d={},...r)=>call(root+'.getTitle',d||{},...r),setBadgeText:(d={},...r)=>call(root+'.setBadgeText',d||{},...r),getBadgeText:(d={},...r)=>call(root+'.getBadgeText',d||{},...r),setBadgeBackgroundColor:(d={},...r)=>call(root+'.setBadgeBackgroundColor',d||{},...r),setBadgeTextColor:(d={},...r)=>call(root+'.setBadgeTextColor',d||{},...r),setPopup:(d={},...r)=>call(root+'.setPopup',d||{},...r),getPopup:(d={},...r)=>call(root+'.getPopup',d||{},...r),setIcon:(d={},...r)=>call(root+'.setIcon',d||{},...r),enable:(...a)=>call(root+'.enable',...a),disable:(...a)=>call(root+'.disable',...a),isEnabled:(...a)=>call(root+'.isEnabled',...a),openPopup:(...a)=>call(root+'.openPopup',...a),getUserSettings:(...a)=>call(root+'.getUserSettings',...a),onClicked:event(root+'.onClicked')});
const permissionsApi={contains:(p={},...r)=>call('permissions.contains',p||{},...r),getAll:(...a)=>call('permissions.getAll',...a),request:(p={},...r)=>call('permissions.request',p||{},...r),remove:(p={},...r)=>call('permissions.remove',p||{},...r),onAdded:event('permissions.onAdded'),onRemoved:event('permissions.onRemoved')};
const windows={get:(...a)=>call('windows.get',...a),getCurrent:(...a)=>call('windows.getCurrent',...a),getLastFocused:(...a)=>call('windows.getLastFocused',...a),getAll:(...a)=>call('windows.getAll',...a),update:(...a)=>call('windows.update',...a),onFocusChanged:event('windows.onFocusChanged'),onCreated:event('windows.onCreated'),onRemoved:event('windows.onRemoved')};
const cookies={get:(...a)=>call('cookies.get',...a),getAll:(...a)=>call('cookies.getAll',...a),set:(...a)=>call('cookies.set',...a),remove:(...a)=>call('cookies.remove',...a),getAllCookieStores:(...a)=>call('cookies.getAllCookieStores',...a),onChanged:event('cookies.onChanged')};
const privacySetting=(section,key)=>({get:(...a)=>call('privacy.'+section+'.'+key+'.get',...a),set:(...a)=>call('privacy.'+section+'.'+key+'.set',...a),clear:(...a)=>call('privacy.'+section+'.'+key+'.clear',...a),onChange:event('privacy.'+section+'.'+key+'.onChange')});
const dnr={getDynamicRules:(...a)=>call('declarativeNetRequest.getDynamicRules',...a),updateDynamicRules:(...a)=>call('declarativeNetRequest.updateDynamicRules',...a),getSessionRules:(...a)=>call('declarativeNetRequest.getSessionRules',...a),updateSessionRules:(...a)=>call('declarativeNetRequest.updateSessionRules',...a),getEnabledRulesets:(...a)=>call('declarativeNetRequest.getEnabledRulesets',...a),updateEnabledRulesets:(...a)=>call('declarativeNetRequest.updateEnabledRulesets',...a),getMatchedRules:(...a)=>call('declarativeNetRequest.getMatchedRules',...a),isRegexSupported:(...a)=>call('declarativeNetRequest.isRegexSupported',...a),setExtensionActionOptions:(...a)=>call('declarativeNetRequest.setExtensionActionOptions',...a),onRuleMatchedDebug:event('declarativeNetRequest.onRuleMatchedDebug')};
const webRequest={OnBeforeRequestOptions:Object.freeze({BLOCKING:'blocking',REQUEST_BODY:'requestBody'}),OnBeforeSendHeadersOptions:Object.freeze({REQUEST_HEADERS:'requestHeaders',BLOCKING:'blocking',EXTRA_HEADERS:'extraHeaders'}),OnHeadersReceivedOptions:Object.freeze({RESPONSE_HEADERS:'responseHeaders',BLOCKING:'blocking',EXTRA_HEADERS:'extraHeaders'}),OnResponseStartedOptions:Object.freeze({RESPONSE_HEADERS:'responseHeaders',EXTRA_HEADERS:'extraHeaders'}),onBeforeRequest:event('webRequest.onBeforeRequest'),onBeforeSendHeaders:event('webRequest.onBeforeSendHeaders'),onSendHeaders:event('webRequest.onSendHeaders'),onHeadersReceived:event('webRequest.onHeadersReceived'),onResponseStarted:event('webRequest.onResponseStarted'),onCompleted:event('webRequest.onCompleted'),onErrorOccurred:event('webRequest.onErrorOccurred'),handlerBehaviorChanged:(...a)=>call('webRequest.handlerBehaviorChanged',...a)};
const api={runtime,extension:{getURL:runtime.getURL},storage:{local:area('local'),sync:area('sync'),session:area('session'),managed:area('managed'),onChanged:event('storage.onChanged')},tabs,windows,cookies,permissions:permissionsApi,
i18n:{getUILanguage:()=> 'en-US',getMessage:(key,subs)=>{const n=String(key||''),reserved={'@@ui_locale':'en-US','@@bidi_dir':'ltr','@@bidi_reversed_dir':'rtl','@@bidi_start_edge':'left','@@bidi_end_edge':'right','@@extension_id':ID};let t=Object.prototype.hasOwnProperty.call(reserved,n)?reserved[n]:String(MSG[n]||'');const a=Array.isArray(subs)?subs:[subs];a.filter(x=>x!==undefined).forEach((v,i)=>{t=t.split('$'+(i+1)).join(String(v))});return t}},
alarms:{create:(...a)=>call('alarms.create',...a),get:(...a)=>call('alarms.get',...a),getAll:(...a)=>call('alarms.getAll',...a),clear:(...a)=>call('alarms.clear',...a),clearAll:(...a)=>call('alarms.clearAll',...a),onAlarm:event('alarms.onAlarm')},
commands:{getAll:(...a)=>call('commands.getAll',...a),onCommand:event('commands.onCommand')},
scripting:{ExecutionWorld:Object.freeze({ISOLATED:'ISOLATED',MAIN:'MAIN'}),executeScript:(...a)=>call('scripting.executeScript',...a),insertCSS:(...a)=>call('scripting.insertCSS',...a),removeCSS:(...a)=>call('scripting.removeCSS',...a),registerContentScripts:(...a)=>call('scripting.registerContentScripts',...a),updateContentScripts:(...a)=>call('scripting.updateContentScripts',...a),unregisterContentScripts:(...a)=>call('scripting.unregisterContentScripts',...a),getRegisteredContentScripts:(...a)=>call('scripting.getRegisteredContentScripts',...a)},
webNavigation:{onBeforeNavigate:event('webNavigation.onBeforeNavigate'),onCommitted:event('webNavigation.onCommitted'),onCompleted:event('webNavigation.onCompleted'),onErrorOccurred:event('webNavigation.onErrorOccurred')},
webRequest,declarativeNetRequest:dnr,
privacy:{network:{webRTCIPHandlingPolicy:privacySetting('network','webRTCIPHandlingPolicy'),networkPredictionEnabled:privacySetting('network','networkPredictionEnabled')},services:{passwordSavingEnabled:privacySetting('services','passwordSavingEnabled'),autofillAddressEnabled:privacySetting('services','autofillAddressEnabled'),autofillCreditCardEnabled:privacySetting('services','autofillCreditCardEnabled'),alternateErrorPagesEnabled:privacySetting('services','alternateErrorPagesEnabled')},websites:{thirdPartyCookiesAllowed:privacySetting('websites','thirdPartyCookiesAllowed'),hyperlinkAuditingEnabled:privacySetting('websites','hyperlinkAuditingEnabled'),referrersEnabled:privacySetting('websites','referrersEnabled'),protectedContentEnabled:privacySetting('websites','protectedContentEnabled'),topicsEnabled:privacySetting('websites','topicsEnabled'),adMeasurementEnabled:privacySetting('websites','adMeasurementEnabled'),fledgeEnabled:privacySetting('websites','fledgeEnabled')}},
notifications:{create:(...a)=>call('notifications.create',...a),clear:(...a)=>call('notifications.clear',...a),getAll:(...a)=>call('notifications.getAll',...a),onClicked:event('notifications.onClicked'),onClosed:event('notifications.onClosed')},
menus:{create:(d={},cb)=>{const details={...(d||{})},id=details.id!==undefined?String(details.id):('aegis-menu-'+Math.random().toString(36).slice(2));details.id=id;call('menus.create',details,cb);return id},update:(...a)=>call('menus.update',...a),remove:(...a)=>call('menus.remove',...a),removeAll:(...a)=>call('menus.removeAll',...a),onClicked:event('menus.onClicked')},
contextMenus:{create:(d={},cb)=>{const details={...(d||{})},id=details.id!==undefined?String(details.id):('aegis-menu-'+Math.random().toString(36).slice(2));details.id=id;call('contextMenus.create',details,cb);return id},update:(...a)=>call('contextMenus.update',...a),remove:(...a)=>call('contextMenus.remove',...a),removeAll:(...a)=>call('contextMenus.removeAll',...a),onClicked:event('contextMenus.onClicked')},
action:actionApi('action'),browserAction:actionApi('browserAction'),pageAction:actionApi('pageAction')};
try{Object.defineProperty(globalThis,'__aegisWebExtensionBootstrapId',{value:ID,writable:false,configurable:false})}catch{globalThis.__aegisWebExtensionBootstrapId=ID}
const expose=(name)=>{try{const existing=globalThis[name];if(existing&&typeof existing==='object'){for(const [key,value] of Object.entries(api))try{existing[key]=value}catch{};return existing}Object.defineProperty(globalThis,name,{value:api,writable:false,configurable:false});return api}catch{try{globalThis[name]=api;return globalThis[name]}catch{return api}}};
expose('browser');expose('chrome');
${messageHook}
B.onEvent?.((p)=>{const type=String(p?.type||''),args=Array.isArray(p?.args)?p.args:[];if(type==='runtime.portMessage'){const port=ports.get(String(args[0]||''));if(port)port.onMessage._emit(args[1],port);return}if(type==='runtime.portDisconnect'){const id=String(args[0]||''),port=ports.get(id);if(port){ports.delete(id);port.onDisconnect._emit(port)}return}if(type==='runtime.onConnect'&&args[0]?.__aegisPort){const d=args[0],port=makePort(String(d.portId||''),d.name||'',d.sender||{});for(const fn of [...listeners('runtime.onConnect')])try{fn(port)}catch{}return}const a=listeners(type);for(const fn of [...a]){try{fn(...args)}catch{}}});
})();`;
}

module.exports = { safeRel, localeMessages, commandList, webExtensionBootstrap };
