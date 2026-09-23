'use strict';
const { contextBridge, ipcRenderer } = require('electron');
const WORLD_ID = 1004;
const listeners = new Map();

function call(extensionId, method, args) {
  const id = String(extensionId || '');
  const name = String(method || '');
  if (!id || id.length > 120 || !/^[a-z0-9@._-]+$/i.test(id)) return Promise.reject(new Error('Invalid extension id.'));
  if (!name || name.length > 80 || !/^[a-zA-Z0-9_.-]+$/.test(name)) return Promise.reject(new Error('Invalid extension API.'));
  return ipcRenderer.invoke('extension:call', { extensionId: id, method: name, args: Array.isArray(args) ? args : [] });
}
function onMessage(extensionId, callback) {
  if (typeof callback !== 'function') return;
  const id = String(extensionId || '');
  if (!listeners.has(id)) listeners.set(id, new Set());
  listeners.get(id).add(callback);
}
ipcRenderer.on('extension:event', (_event, payload) => {
  const id = String(payload?.extensionId || '');
  const set = listeners.get(id);
  if (!set) return;
  const safe = { message: payload?.message, sender: payload?.sender || {} };
  for (const fn of [...set]) { try { fn(safe); } catch {} }
});
contextBridge.exposeInIsolatedWorld(WORLD_ID, '__aegisExtensionBridge', { call, onMessage });
