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
let runtimeLastError = null;
const call = (method, ...args) => {
  const name = String(method || ''), callback = typeof args[args.length - 1] === 'function' ? args.pop() : null;
  const promise = validMethod(name)
    ? ipcRenderer.invoke('extension:call', { extensionId, method:name, args })
    : Promise.reject(new Error('Invalid extension API.'));
  if (!callback) return promise;
  promise.then((value) => {
    runtimeLastError = null;
    try { callback(value); } finally { runtimeLastError = null; }
  }).catch((err) => {
    runtimeLastError = { message:String(err?.message || err || 'Extension API call failed') };
    try { callback(); } finally { runtimeLastError = null; }
  });
  return undefined;
};
const area = (name) => ({
  get: (keys, ...rest) => call('storage.' + name + '.get', keys, ...rest),
  getKeys: (...args) => call('storage.' + name + '.getKeys', ...args),
  getBytesInUse: (keys, ...rest) => call('storage.' + name + '.getBytesInUse', keys, ...rest),
  set: (items, ...rest) => call('storage.' + name + '.set', items, ...rest),
  remove: (keys, ...rest) => call('storage.' + name + '.remove', keys, ...rest),
  clear: (...args) => call('storage.' + name + '.clear', ...args)
});
const actionApi = (root) => ({
  setTitle: (details={}, ...rest) => call(root + '.setTitle', details, ...rest),
  getTitle: (details={}, ...rest) => call(root + '.getTitle', details, ...rest),
  setBadgeText: (details={}, ...rest) => call(root + '.setBadgeText', details, ...rest),
  getBadgeText: (details={}, ...rest) => call(root + '.getBadgeText', details, ...rest),
  setBadgeBackgroundColor: (details={}, ...rest) => call(root + '.setBadgeBackgroundColor', details, ...rest),
  setPopup: (details={}, ...rest) => call(root + '.setPopup', details, ...rest),
  getPopup: (details={}, ...rest) => call(root + '.getPopup', details, ...rest),
  setIcon: (details={}, ...rest) => call(root + '.setIcon', details, ...rest),
  enable: (...args) => call(root + '.enable', ...args),
  disable: (...args) => call(root + '.disable', ...args),
  isEnabled: (...args) => call(root + '.isEnabled', ...args),
  openPopup: (...args) => call(root + '.openPopup', ...args),
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
  get lastError() { return runtimeLastError; },
  getManifest: () => manifest,
  getURL: (p='') => 'aegis-extension://' + resourceToken + '/' + String(p).replace(/^\/+/, ''),
  getPlatformInfo: (...args) => call('runtime.getPlatformInfo', ...args),
  getBrowserInfo: (...args) => call('runtime.getBrowserInfo', ...args),
  getContexts: (...args) => call('runtime.getContexts', ...args),
  openOptionsPage: (...args) => call('runtime.openOptionsPage', ...args),
  reload: (...args) => call('runtime.reload', ...args),
  sendMessage: (...args) => call('runtime.sendMessage', ...args),
  connect: runtimeConnect,
  onConnect: event('runtime.onConnect'),
  onMessage: event('runtime.onMessage'),
  onInstalled: event('runtime.onInstalled'),
  onStartup: event('runtime.onStartup')
};
const tabs = {
  query: (q={}, ...rest) => call('tabs.query', q, ...rest),
  get: (id, ...rest) => call('tabs.get', id, ...rest),
  getCurrent: (...args) => call('tabs.getCurrent', ...args),
  create: (props={}, ...rest) => call('tabs.create', props, ...rest),
  update: (...args) => call('tabs.update', ...args),
  remove: (...args) => call('tabs.remove', ...args),
  reload: (...args) => call('tabs.reload', ...args),
  sendMessage: (...args) => call('tabs.sendMessage', ...args),
  connect: (id,info={}) => { const portId=newPortId(),port=makePort(portId,info.name||'',{id:extensionId}); call('tabs.connect',id,{...info,portId}).catch((err)=>{port.error=err;ports.delete(portId);port.onDisconnect._emit(port);}); return port; },
  executeScript: (...args) => call('tabs.executeScript', ...args),
  insertCSS: (...args) => call('tabs.insertCSS', ...args),
  removeCSS: (...args) => call('tabs.removeCSS', ...args),
  getZoom: (...args) => call('tabs.getZoom', ...args),
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
    get:(...args)=>call('windows.get',...args),
    getCurrent:(...args)=>call('windows.getCurrent',...args),
    getLastFocused:(...args)=>call('windows.getLastFocused',...args),
    getAll:(...args)=>call('windows.getAll',...args),
    update:(...args)=>call('windows.update',...args),
    onFocusChanged:event('windows.onFocusChanged'),
    onCreated:event('windows.onCreated'),
    onRemoved:event('windows.onRemoved')
  },
  cookies: {
    get:(...args)=>call('cookies.get',...args),
    getAll:(...args)=>call('cookies.getAll',...args),
    set:(...args)=>call('cookies.set',...args),
    remove:(...args)=>call('cookies.remove',...args),
    getAllCookieStores:(...args)=>call('cookies.getAllCookieStores',...args),
    onChanged:event('cookies.onChanged')
  },
  permissions: {
    contains: (p={}, ...rest) => call('permissions.contains', p, ...rest),
    getAll: (...args) => call('permissions.getAll', ...args),
    request: (p={}, ...rest) => call('permissions.request', p, ...rest),
    remove: (p={}, ...rest) => call('permissions.remove', p, ...rest),
    onAdded: event('permissions.onAdded'),
    onRemoved: event('permissions.onRemoved')
  },
  i18n: { getUILanguage:()=>'en-US', getMessage:localMessage },
  alarms: {
    create: (...args) => call('alarms.create', ...args),
    get: (...args) => call('alarms.get', ...args),
    getAll: (...args) => call('alarms.getAll', ...args),
    clear: (...args) => call('alarms.clear', ...args),
    clearAll: (...args) => call('alarms.clearAll', ...args),
    onAlarm: event('alarms.onAlarm')
  },
  commands: { getAll:(...args)=>call('commands.getAll',...args), onCommand:event('commands.onCommand') },
  scripting: {
    executeScript:(...args)=>call('scripting.executeScript',...args),
    insertCSS:(...args)=>call('scripting.insertCSS',...args),
    removeCSS:(...args)=>call('scripting.removeCSS',...args)
  },
  webNavigation: {
    onBeforeNavigate:event('webNavigation.onBeforeNavigate'),
    onCommitted:event('webNavigation.onCommitted'),
    onCompleted:event('webNavigation.onCompleted'),
    onErrorOccurred:event('webNavigation.onErrorOccurred')
  },
  notifications: {
    create:(...args)=>call('notifications.create',...args),
    clear:(...args)=>call('notifications.clear',...args),
    getAll:(...args)=>call('notifications.getAll',...args),
    onClicked:event('notifications.onClicked'),
    onClosed:event('notifications.onClosed')
  },
  menus: {
    create:(details={},callback)=>{ const d={...(details||{})},id=d.id!==undefined?String(d.id):('aegis-menu-'+Math.random().toString(36).slice(2));d.id=id;call('menus.create',d,callback);return id; },
    update:(...args)=>call('menus.update',...args),
    remove:(...args)=>call('menus.remove',...args),
    removeAll:(...args)=>call('menus.removeAll',...args),
    onClicked:event('menus.onClicked')
  },
  contextMenus: {
    create:(details={},callback)=>{ const d={...(details||{})},id=d.id!==undefined?String(d.id):('aegis-menu-'+Math.random().toString(36).slice(2));d.id=id;call('contextMenus.create',d,callback);return id; },
    update:(...args)=>call('contextMenus.update',...args),
    remove:(...args)=>call('contextMenus.remove',...args),
    removeAll:(...args)=>call('contextMenus.removeAll',...args),
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
