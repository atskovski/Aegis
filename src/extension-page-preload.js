'use strict';
const { contextBridge, ipcRenderer } = require('electron');

function arg(name) {
  const prefix = '--' + name + '=';
  const value = process.argv.find((x) => x.startsWith(prefix));
  return value ? value.slice(prefix.length) : '';
}
function decodeJson(value, fallback = {}) {
  if (!value) return fallback;
  try { return JSON.parse(Buffer.from(value, 'base64url').toString('utf8')); } catch { return fallback; }
}

let extensionId = '';
let resourceToken = '';
try { extensionId = decodeURIComponent(arg('aegis-extension-id')); } catch {}
try { resourceToken = decodeURIComponent(arg('aegis-extension-token')); } catch {}
const manifest = Object.freeze(decodeJson(arg('aegis-extension-manifest'), {}));
const messages = Object.freeze(decodeJson(arg('aegis-extension-messages'), {}));
const context = String(arg('aegis-extension-context') || 'page');

const events = new Map();
const eventList = (name) => {
  if (!events.has(name)) events.set(name, new Set());
  return events.get(name);
};
const event = (name) => ({
  addListener(fn) { if (typeof fn === 'function') eventList(name).add(fn); },
  removeListener(fn) { eventList(name).delete(fn); },
  hasListener(fn) { return eventList(name).has(fn); },
  hasListeners() { return eventList(name).size > 0; }
});
const validMethod = (name) => Boolean(name && name.length <= 96 && /^[a-zA-Z0-9_.-]+$/.test(name));
const call = (method, ...args) => {
  const name = String(method || '');
  if (!validMethod(name)) return Promise.reject(new Error('Invalid extension API.'));
  return ipcRenderer.invoke('extension:call', { extensionId, method:name, args });
};
const area = (name) => ({
  get: (keys) => call('storage.' + name + '.get', keys),
  getKeys: () => call('storage.' + name + '.getKeys'),
  getBytesInUse: (keys) => call('storage.' + name + '.getBytesInUse', keys),
  set: (items) => call('storage.' + name + '.set', items),
  remove: (keys) => call('storage.' + name + '.remove', keys),
  clear: () => call('storage.' + name + '.clear')
});
const actionApi = (root) => ({
  setTitle: (details={}) => call(root + '.setTitle', details),
  getTitle: (details={}) => call(root + '.getTitle', details),
  setBadgeText: (details={}) => call(root + '.setBadgeText', details),
  getBadgeText: (details={}) => call(root + '.getBadgeText', details),
  setBadgeBackgroundColor: (details={}) => call(root + '.setBadgeBackgroundColor', details),
  setPopup: (details={}) => call(root + '.setPopup', details),
  getPopup: (details={}) => call(root + '.getPopup', details),
  setIcon: (details={}) => call(root + '.setIcon', details),
  enable: (tabId) => call(root + '.enable', tabId),
  disable: (tabId) => call(root + '.disable', tabId),
  isEnabled: (tabId) => call(root + '.isEnabled', tabId),
  openPopup: () => call(root + '.openPopup'),
  onClicked: event(root + '.onClicked')
});
function localMessage(key, substitutions) {
  let text = String(messages[String(key || '')] || '');
  const values = Array.isArray(substitutions) ? substitutions : [substitutions];
  values.filter((x) => x !== undefined).forEach((value, index) => {
    text = text.replace(new RegExp('\\$' + (index + 1), 'g'), String(value));
  });
  return text;
}

const ports = new Map();
const makePortEvent = () => {
  const set = new Set();
  return {
    addListener(fn) { if (typeof fn === 'function') set.add(fn); },
    removeListener(fn) { set.delete(fn); },
    hasListener(fn) { return set.has(fn); },
    hasListeners() { return set.size > 0; },
    _emit(...args) { for (const fn of [...set]) { try { fn(...args); } catch {} } }
  };
};
const makePort = (portId, name = '', sender = {}) => {
  if (ports.has(portId)) return ports.get(portId);
  const onMessage = makePortEvent(), onDisconnect = makePortEvent();
  const port = {
    name:String(name || ''), sender:sender || {}, error:undefined, onMessage, onDisconnect,
    postMessage(message) { return call('runtime.portPost', portId, message); },
    disconnect() { ports.delete(portId); call('runtime.portDisconnect', portId).catch(()=>{}); onDisconnect._emit(port); }
  };
  ports.set(portId, port);
  return port;
};
const newPortId = () => 'aegis-port-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2);
const runtimeConnect = (...args) => {
  let target = extensionId, info = {};
  if (typeof args[0] === 'string') { target = args[0]; info = args[1] || {}; } else info = args[0] || {};
  if (target !== extensionId) throw new Error('Cross-extension runtime.connect is not supported.');
  const portId = newPortId(), port = makePort(portId, info.name || '', { id:extensionId });
  call('runtime.portOpen', { portId, name:port.name }).catch((err) => { port.error = err; ports.delete(portId); port.onDisconnect._emit(port); });
  return port;
};

const runtime = {
  id: extensionId,
  getManifest: () => manifest,
  getURL: (p='') => 'aegis-extension://' + resourceToken + '/' + String(p).replace(/^\/+/, ''),
  getPlatformInfo: () => call('runtime.getPlatformInfo'),
  getBrowserInfo: () => call('runtime.getBrowserInfo'),
  getContexts: (filter={}) => call('runtime.getContexts', filter),
  openOptionsPage: () => call('runtime.openOptionsPage'),
  reload: () => call('runtime.reload'),
  sendMessage: (...args) => call('runtime.sendMessage', ...args),
  connect: runtimeConnect,
  onConnect: event('runtime.onConnect'),
  onMessage: event('runtime.onMessage'),
  onInstalled: event('runtime.onInstalled'),
  onStartup: event('runtime.onStartup')
};
const tabs = {
  query: (q={}) => call('tabs.query', q),
  get: (id) => call('tabs.get', id),
  getCurrent: () => call('tabs.getCurrent'),
  create: (props={}) => call('tabs.create', props),
  update: (...args) => call('tabs.update', ...args),
  remove: (ids) => call('tabs.remove', ids),
  reload: (...args) => call('tabs.reload', ...args),
  sendMessage: (id,msg) => call('tabs.sendMessage', id, msg),
  connect: (id,info={}) => { const portId=newPortId(),port=makePort(portId,info.name||'',{id:extensionId}); call('tabs.connect',id,{...info,portId}).catch((err)=>{port.error=err;ports.delete(portId);port.onDisconnect._emit(port);}); return port; },
  executeScript: (...args) => call('tabs.executeScript', ...args),
  insertCSS: (...args) => call('tabs.insertCSS', ...args),
  removeCSS: (...args) => call('tabs.removeCSS', ...args),
  getZoom: (id) => call('tabs.getZoom', id),
  setZoom: (...args) => call('tabs.setZoom', ...args),
  captureVisibleTab: (...args) => call('tabs.captureVisibleTab', ...args),
  onCreated: event('tabs.onCreated'),
  onUpdated: event('tabs.onUpdated'),
  onRemoved: event('tabs.onRemoved'),
  onActivated: event('tabs.onActivated')
};
const api = {
  runtime,
  extension: { getURL: runtime.getURL },
  storage: { local:area('local'), sync:area('sync'), session:area('session'), managed:area('managed'), onChanged:event('storage.onChanged') },
  tabs,
  windows: {
    get:(id,info={})=>call('windows.get',id,info),
    getCurrent:(info={})=>call('windows.getCurrent',info),
    getLastFocused:(info={})=>call('windows.getLastFocused',info),
    getAll:(info={})=>call('windows.getAll',info),
    update:(id,info={})=>call('windows.update',id,info),
    onFocusChanged:event('windows.onFocusChanged'),
    onCreated:event('windows.onCreated'),
    onRemoved:event('windows.onRemoved')
  },
  cookies: {
    get:(details={})=>call('cookies.get',details),
    getAll:(details={})=>call('cookies.getAll',details),
    set:(details={})=>call('cookies.set',details),
    remove:(details={})=>call('cookies.remove',details),
    getAllCookieStores:()=>call('cookies.getAllCookieStores'),
    onChanged:event('cookies.onChanged')
  },
  permissions: {
    contains: (p={}) => call('permissions.contains', p),
    getAll: () => call('permissions.getAll'),
    request: (p={}) => call('permissions.request', p),
    remove: (p={}) => call('permissions.remove', p),
    onAdded: event('permissions.onAdded'),
    onRemoved: event('permissions.onRemoved')
  },
  i18n: { getUILanguage:()=>'en-US', getMessage:localMessage },
  alarms: {
    create: (...args) => call('alarms.create', ...args),
    get: (name) => call('alarms.get', name),
    getAll: () => call('alarms.getAll'),
    clear: (name) => call('alarms.clear', name),
    clearAll: () => call('alarms.clearAll'),
    onAlarm: event('alarms.onAlarm')
  },
  commands: { getAll:()=>call('commands.getAll'), onCommand:event('commands.onCommand') },
  scripting: {
    executeScript:(details={})=>call('scripting.executeScript',details),
    insertCSS:(details={})=>call('scripting.insertCSS',details),
    removeCSS:(details={})=>call('scripting.removeCSS',details)
  },
  webNavigation: {
    onBeforeNavigate:event('webNavigation.onBeforeNavigate'),
    onCommitted:event('webNavigation.onCommitted'),
    onCompleted:event('webNavigation.onCompleted'),
    onErrorOccurred:event('webNavigation.onErrorOccurred')
  },
  notifications: {
    create:(...args)=>call('notifications.create',...args),
    clear:(id)=>call('notifications.clear',id),
    getAll:()=>call('notifications.getAll'),
    onClicked:event('notifications.onClicked'),
    onClosed:event('notifications.onClosed')
  },
  menus: {
    create:(details={})=>call('menus.create',details),
    update:(id,details={})=>call('menus.update',id,details),
    remove:(id)=>call('menus.remove',id),
    removeAll:()=>call('menus.removeAll'),
    onClicked:event('menus.onClicked')
  },
  contextMenus: {
    create:(details={})=>call('contextMenus.create',details),
    update:(id,details={})=>call('contextMenus.update',id,details),
    remove:(id)=>call('contextMenus.remove',id),
    removeAll:()=>call('contextMenus.removeAll'),
    onClicked:event('contextMenus.onClicked')
  },
  action:actionApi('action'),
  browserAction:actionApi('browserAction'),
  pageAction:actionApi('pageAction')
};

contextBridge.exposeInMainWorld('browser', api);
contextBridge.exposeInMainWorld('chrome', api);
contextBridge.exposeInMainWorld('__aegisExtensionContext', Object.freeze({ id:extensionId, context }));

ipcRenderer.on('extension:event', (_event, payload) => {
  if (String(payload?.extensionId || '') !== extensionId) return;
  const type = String(payload?.type || '');
  const args = Array.isArray(payload?.args) ? payload.args : [];
  if (type === 'runtime.portMessage') {
    const port = ports.get(String(args[0] || ''));
    if (port) port.onMessage._emit(args[1], port);
    return;
  }
  if (type === 'runtime.portDisconnect') {
    const id = String(args[0] || ''), port = ports.get(id);
    if (port) { ports.delete(id); port.onDisconnect._emit(port); }
    return;
  }
  if (type === 'runtime.onConnect' && args[0]?.__aegisPort) {
    const descriptor = args[0], port = makePort(String(descriptor.portId || ''), descriptor.name || '', descriptor.sender || {});
    for (const fn of [...eventList('runtime.onConnect')]) { try { fn(port); } catch {} }
    return;
  }
  const set = eventList(type);
  for (const fn of [...set]) { try { fn(...args); } catch {} }
});

ipcRenderer.on('extension:runtime-message', async (_event, payload) => {
  if (String(payload?.extensionId || '') !== extensionId) return;
  let response;
  for (const fn of [...eventList('runtime.onMessage')]) {
    try {
      const value = await fn(payload?.message, payload?.sender || {}, () => {});
      if (value !== undefined) { response = value; break; }
    } catch {}
  }
  ipcRenderer.send('extension:message-response', {
    extensionId,
    messageId:String(payload?.messageId || ''),
    response
  });
});
