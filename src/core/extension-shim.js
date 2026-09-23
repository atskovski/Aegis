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
const events=new Map();
const listeners=(name)=>{if(!events.has(name))events.set(name,[]);return events.get(name)};
const event=(name)=>({addListener:(f)=>{if(typeof f==='function'&&!listeners(name).includes(f))listeners(name).push(f)},removeListener:(f)=>{const a=listeners(name),i=a.indexOf(f);if(i>=0)a.splice(i,1)},hasListener:(f)=>listeners(name).includes(f),hasListeners:()=>listeners(name).length>0});
const call=(m,...a)=>B.call(m,a);
const area=(n)=>({get:(k)=>call('storage.'+n+'.get',k),set:(v)=>call('storage.'+n+'.set',v),remove:(k)=>call('storage.'+n+'.remove',k),clear:()=>call('storage.'+n+'.clear')});
const runtime={id:ID,getManifest:()=>M,getURL:(p='')=>'aegis-extension://'+TOKEN+'/'+String(p).replace(/^\\/+/,''),getPlatformInfo:()=>call('runtime.getPlatformInfo'),getBrowserInfo:()=>call('runtime.getBrowserInfo'),getContexts:(f={})=>call('runtime.getContexts',f),openOptionsPage:()=>call('runtime.openOptionsPage'),reload:()=>call('runtime.reload'),sendMessage:(...a)=>call('runtime.sendMessage',...a),onMessage:event('runtime.onMessage'),onInstalled:event('runtime.onInstalled'),onStartup:event('runtime.onStartup')};
globalThis.__aegisReceiveMessage=async(msg,sender={})=>{for(const fn of [...listeners('runtime.onMessage')]){try{const r=await fn(msg,sender,()=>{});if(r!==undefined)return r}catch{}}};
const tabs={query:(q)=>call('tabs.query',q||{}),get:(id)=>call('tabs.get',id),getCurrent:()=>call('tabs.getCurrent'),create:(p)=>call('tabs.create',p||{}),update:(...a)=>call('tabs.update',...a),remove:(ids)=>call('tabs.remove',ids),reload:(...a)=>call('tabs.reload',...a),sendMessage:(id,msg)=>call('tabs.sendMessage',id,msg),executeScript:(...a)=>call('tabs.executeScript',...a),insertCSS:(...a)=>call('tabs.insertCSS',...a),removeCSS:(...a)=>call('tabs.removeCSS',...a),getZoom:(id)=>call('tabs.getZoom',id),setZoom:(...a)=>call('tabs.setZoom',...a),captureVisibleTab:(...a)=>call('tabs.captureVisibleTab',...a),onCreated:event('tabs.onCreated'),onUpdated:event('tabs.onUpdated'),onRemoved:event('tabs.onRemoved'),onActivated:event('tabs.onActivated')};
const actionApi=(root)=>({setTitle:(d)=>call(root+'.setTitle',d||{}),getTitle:(d)=>call(root+'.getTitle',d||{}),setBadgeText:(d)=>call(root+'.setBadgeText',d||{}),getBadgeText:(d)=>call(root+'.getBadgeText',d||{}),setBadgeBackgroundColor:(d)=>call(root+'.setBadgeBackgroundColor',d||{}),setPopup:(d)=>call(root+'.setPopup',d||{}),getPopup:(d)=>call(root+'.getPopup',d||{}),setIcon:(d)=>call(root+'.setIcon',d||{}),enable:(id)=>call(root+'.enable',id),disable:(id)=>call(root+'.disable',id),isEnabled:(id)=>call(root+'.isEnabled',id),openPopup:()=>call(root+'.openPopup'),onClicked:event(root+'.onClicked')});
const permissionsApi={contains:(p)=>call('permissions.contains',p||{}),getAll:()=>call('permissions.getAll'),request:(p)=>call('permissions.request',p||{}),remove:(p)=>call('permissions.remove',p||{}),onAdded:event('permissions.onAdded'),onRemoved:event('permissions.onRemoved')};
const windows={get:(id,o)=>call('windows.get',id,o||{}),getCurrent:(o)=>call('windows.getCurrent',o||{}),getLastFocused:(o)=>call('windows.getLastFocused',o||{}),getAll:(o)=>call('windows.getAll',o||{}),update:(id,o)=>call('windows.update',id,o||{}),onFocusChanged:event('windows.onFocusChanged'),onCreated:event('windows.onCreated'),onRemoved:event('windows.onRemoved')};
const cookies={get:(d)=>call('cookies.get',d||{}),getAll:(d)=>call('cookies.getAll',d||{}),set:(d)=>call('cookies.set',d||{}),remove:(d)=>call('cookies.remove',d||{}),getAllCookieStores:()=>call('cookies.getAllCookieStores'),onChanged:event('cookies.onChanged')};
const api={runtime,extension:{getURL:runtime.getURL},storage:{local:area('local'),sync:area('sync'),session:area('session'),onChanged:event('storage.onChanged')},tabs,windows,cookies,permissions:permissionsApi,
i18n:{getUILanguage:()=> 'en-US',getMessage:(key,subs)=>{let t=String(MSG[String(key||'')]||'');const a=Array.isArray(subs)?subs:[subs];a.filter(x=>x!==undefined).forEach((v,i)=>{t=t.split('$'+(i+1)).join(String(v))});return t}},
alarms:{create:(...a)=>call('alarms.create',...a),get:(n)=>call('alarms.get',n),getAll:()=>call('alarms.getAll'),clear:(n)=>call('alarms.clear',n),clearAll:()=>call('alarms.clearAll'),onAlarm:event('alarms.onAlarm')},
commands:{getAll:()=>call('commands.getAll'),onCommand:event('commands.onCommand')},
scripting:{executeScript:(d)=>call('scripting.executeScript',d||{}),insertCSS:(d)=>call('scripting.insertCSS',d||{}),removeCSS:(d)=>call('scripting.removeCSS',d||{})},
webNavigation:{onBeforeNavigate:event('webNavigation.onBeforeNavigate'),onCommitted:event('webNavigation.onCommitted'),onCompleted:event('webNavigation.onCompleted'),onErrorOccurred:event('webNavigation.onErrorOccurred')},
notifications:{create:(...a)=>call('notifications.create',...a),clear:(id)=>call('notifications.clear',id),getAll:()=>call('notifications.getAll'),onClicked:event('notifications.onClicked'),onClosed:event('notifications.onClosed')},
menus:{create:(d)=>call('menus.create',d||{}),update:(id,d)=>call('menus.update',id,d||{}),remove:(id)=>call('menus.remove',id),removeAll:()=>call('menus.removeAll'),onClicked:event('menus.onClicked')},
contextMenus:{create:(d)=>call('contextMenus.create',d||{}),update:(id,d)=>call('contextMenus.update',id,d||{}),remove:(id)=>call('contextMenus.remove',id),removeAll:()=>call('contextMenus.removeAll'),onClicked:event('contextMenus.onClicked')},
action:actionApi('action'),browserAction:actionApi('browserAction'),pageAction:actionApi('pageAction')};
Object.defineProperty(globalThis,'browser',{value:api,configurable:false});if(!globalThis.chrome)Object.defineProperty(globalThis,'chrome',{value:api,configurable:false});
${messageHook}
B.onEvent?.((p)=>{const a=listeners(String(p?.type||''));for(const fn of [...a]){try{fn(...(Array.isArray(p?.args)?p.args:[]))}catch{}}});
})();`;
}

module.exports = { safeRel, localeMessages, commandList, webExtensionBootstrap };
