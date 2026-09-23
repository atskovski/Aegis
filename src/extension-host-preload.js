'use strict';
const { contextBridge, ipcRenderer } = require('electron');

const arg = process.argv.find((x) => x.startsWith('--aegis-extension-id='));
let extensionId = '';
try { extensionId = decodeURIComponent(String(arg || '').slice('--aegis-extension-id='.length)); } catch {}

const listeners = new Set();
const eventListeners = new Set();
const validMethod = (name) => Boolean(name && name.length <= 80 && /^[a-zA-Z0-9_.-]+$/.test(name));
const bridge = {
  call(method, args) {
    const name = String(method || '');
    if (!validMethod(name)) return Promise.reject(new Error('Invalid extension API.'));
    return ipcRenderer.invoke('extension:call', { extensionId, method: name, args: Array.isArray(args) ? args : [] });
  },
  onMessage(callback) {
    if (typeof callback === 'function') listeners.add(callback);
  },
  onEvent(callback) {
    if (typeof callback === 'function') eventListeners.add(callback);
  },
  respond(messageId, response) {
    ipcRenderer.send('extension:message-response', { extensionId, messageId: String(messageId || ''), response });
  }
};

ipcRenderer.on('extension:runtime-message', (_event, payload) => {
  if (String(payload?.extensionId || '') !== extensionId) return;
  const safe = { messageId: String(payload?.messageId || ''), message: payload?.message, sender: payload?.sender || {} };
  for (const callback of [...listeners]) { try { callback(safe); } catch {} }
});

contextBridge.exposeInMainWorld('__aegisBackgroundBridge', bridge);

ipcRenderer.on('extension:event', (_event, payload) => {
  if (String(payload?.extensionId || '') !== extensionId) return;
  const safe = { type:String(payload?.type || ''), args:Array.isArray(payload?.args) ? payload.args : [] };
  for (const callback of [...eventListeners]) { try { callback(safe); } catch {} }
});
