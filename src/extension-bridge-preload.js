'use strict';
const { contextBridge, ipcRenderer } = require('electron');

const listeners = new Map();

function validId(id) { return Boolean(id && id.length <= 120 && /^[a-z0-9@._-]+$/i.test(id)); }
function validMethod(name) { return Boolean(name && name.length <= 80 && /^[a-zA-Z0-9_.-]+$/.test(name)); }

function registerWorld(extensionId, worldId) {
  if (!validId(extensionId) || !Number.isInteger(worldId) || worldId < 1000) return;
  const callbacks = new Set();
  listeners.set(extensionId, callbacks);
  const api = {
    call(method, args) {
      const name = String(method || '');
      if (!validMethod(name)) return Promise.reject(new Error('Invalid extension API.'));
      return ipcRenderer.invoke('extension:call', { extensionId, method: name, args: Array.isArray(args) ? args : [] });
    },
    onMessage(callback) {
      if (typeof callback === 'function') callbacks.add(callback);
    }
  };
  contextBridge.exposeInIsolatedWorld(worldId, '__aegisExtensionBridge', api);
}

for (const arg of process.argv.filter((x) => x.startsWith('--aegis-extension-world='))) {
  const raw = arg.slice('--aegis-extension-world='.length);
  const split = raw.lastIndexOf(':');
  if (split <= 0) continue;
  let extensionId = '';
  try { extensionId = decodeURIComponent(raw.slice(0, split)); } catch { continue; }
  const worldId = Number(raw.slice(split + 1));
  try { registerWorld(extensionId, worldId); } catch {}
}

ipcRenderer.on('extension:event', (_event, payload) => {
  const id = String(payload?.extensionId || '');
  const set = listeners.get(id);
  if (!set) return;
  const safe = { message: payload?.message, sender: payload?.sender || {} };
  for (const fn of [...set]) { try { fn(safe); } catch {} }
});
