'use strict';
const { contextBridge, ipcRenderer, webFrame } = require('electron');

const listeners = new Map();
const eventListeners = new Map();

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
    },
    onEvent(callback) {
      if (typeof callback !== 'function') return;
      if (!eventListeners.has(extensionId)) eventListeners.set(extensionId, new Set());
      eventListeners.get(extensionId).add(callback);
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
  const set = eventListeners.get(id);
  if (!set) return;
  const safe = { type:String(payload?.type || ''), args:Array.isArray(payload?.args) ? payload.args : [] };
  for (const fn of [...set]) { try { fn(safe); } catch {} }
});

ipcRenderer.on('extension:frame-inject', async (_event, payload) => {
  const extensionId = String(payload?.extensionId || '');
  const requestId = String(payload?.requestId || '');
  const worldId = Number(payload?.worldId);
  const requestedRoutingId = Number(payload?.frameRoutingId);
  const failures = [];
  let scriptCount = 0, cssCount = 0;

  const respond = (extra = {}) => ipcRenderer.send('extension:frame-inject-result', {
    requestId,
    extensionId,
    frameRoutingId:Number(webFrame.routingId),
    frameProcessId:Number(process.pid),
    scriptCount,
    cssCount,
    failures,
    ...extra
  });

  if (!requestId || !validId(extensionId) || !listeners.has(extensionId)) {
    respond({ ok:false, error:'Extension frame bridge is unavailable.' });
    return;
  }
  if (!Number.isInteger(worldId) || worldId < 1000) {
    respond({ ok:false, error:'Invalid extension isolated-world id.' });
    return;
  }
  if (Number.isFinite(requestedRoutingId) && requestedRoutingId !== Number(webFrame.routingId)) {
    respond({ ok:false, error:'Extension frame routing mismatch.' });
    return;
  }

  const scripts = Array.isArray(payload?.scripts) ? payload.scripts.slice(0, 128) : [];
  const css = Array.isArray(payload?.css) ? payload.css.slice(0, 128) : [];
  const world = String(payload?.world || 'ISOLATED').toUpperCase();

  for (const item of scripts) {
    const label = String(item?.label || 'script').slice(0, 240);
    const code = String(item?.code || '');
    if (!code || code.length > 8 * 1024 * 1024) {
      failures.push({ kind:'script', label, message:'Script payload is empty or exceeds the per-file limit.' });
      continue;
    }
    try {
      if (world === 'MAIN') await webFrame.executeJavaScript(code, false);
      else await webFrame.executeJavaScriptInIsolatedWorld(worldId, [{ code, url:String(item?.url || '') }], false);
      scriptCount += 1;
    } catch (err) {
      failures.push({ kind:'script', label, message:String(err?.message || err || 'Script execution failed.').slice(0,500) });
    }
  }

  for (const item of css) {
    const label = String(item?.label || 'style').slice(0,240);
    const code = String(item?.code || '');
    if (!code || code.length > 4 * 1024 * 1024) {
      failures.push({ kind:'css', label, message:'CSS payload is empty or exceeds the per-file limit.' });
      continue;
    }
    try {
      await webFrame.insertCSS(code, { cssOrigin:'author' });
      cssCount += 1;
    } catch (err) {
      failures.push({ kind:'css', label, message:String(err?.message || err || 'CSS insertion failed.').slice(0,500) });
    }
  }

  respond({ ok:true });
});


ipcRenderer.on('extension:frame-message', async (_event, payload) => {
  const extensionId = String(payload?.extensionId || '');
  const requestId = String(payload?.requestId || '');
  const worldId = Number(payload?.worldId);
  const requestedRoutingId = Number(payload?.frameRoutingId);
  const respond = (extra = {}) => ipcRenderer.send('extension:frame-message-result', {
    requestId,
    extensionId,
    frameRoutingId:Number(webFrame.routingId),
    ...extra
  });

  if (!requestId || !validId(extensionId) || !listeners.has(extensionId)) {
    respond({ ok:false, error:'Extension frame message bridge is unavailable.' });
    return;
  }
  if (!Number.isInteger(worldId) || worldId < 1000) {
    respond({ ok:false, error:'Invalid extension isolated-world id.' });
    return;
  }
  if (Number.isFinite(requestedRoutingId) && requestedRoutingId !== Number(webFrame.routingId)) {
    respond({ ok:false, error:'Extension frame routing mismatch.' });
    return;
  }

  try {
    const code = 'globalThis.__aegisReceiveMessage?globalThis.__aegisReceiveMessage(' +
      JSON.stringify(payload?.message) + ',' + JSON.stringify(payload?.sender || {id:extensionId}) + '):undefined';
    const response = await webFrame.executeJavaScriptInIsolatedWorld(worldId, [{ code }], false);
    respond({ ok:true, response });
  } catch (err) {
    respond({ ok:false, error:String(err?.message || err || 'Frame message failed.').slice(0,500) });
  }
});
