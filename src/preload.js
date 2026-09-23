'use strict';
const { contextBridge, ipcRenderer } = require('electron');

const allowedSend = new Set([
  'nav','tab:new','tab:close','tab:activate','tab:duplicate','tab:command','identity:new',
  'settings:update','settings:profile','settings:reset','shields:set','http:set','javascript:set',
  'site-permission:set','site-permission:reset','data:clear-tab','data:clear-all','permission:respond',
  'compatibility:set','ui:layer','bookmark:toggle','bookmark:open','bookmark:remove','downloads:clear','download:cancel','download:reveal'
]);
const allowedInvoke = new Set(['state:get','settings:get','network:test','security-suite:run']);
const allowedReceive = new Set(['state','toast','permission:prompt','permission:closed','ui:open']);

contextBridge.exposeInMainWorld('aegis', {
  send(channel, payload) {
    if (!allowedSend.has(channel)) throw new Error('IPC channel denied');
    ipcRenderer.send(channel, payload);
  },
  invoke(channel, payload) {
    if (!allowedInvoke.has(channel)) return Promise.reject(new Error('IPC channel denied'));
    return ipcRenderer.invoke(channel, payload);
  },
  on(channel, callback) {
    if (!allowedReceive.has(channel)) throw new Error('IPC channel denied');
    const fn = (_event, data) => callback(data);
    ipcRenderer.on(channel, fn);
    return () => ipcRenderer.removeListener(channel, fn);
  }
});
