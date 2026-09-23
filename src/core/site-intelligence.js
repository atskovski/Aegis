'use strict';

const SIGNAL_DEFS = Object.freeze({
  camera: { label: 'Camera', group: 'sensitive', risk: 5 },
  microphone: { label: 'Microphone', group: 'sensitive', risk: 5 },
  geolocation: { label: 'Location', group: 'sensitive', risk: 5 },
  displayCapture: { label: 'Screen capture', group: 'sensitive', risk: 6 },
  clipboardRead: { label: 'Clipboard', group: 'sensitive', risk: 4 },
  notifications: { label: 'Notifications', group: 'sensitive', risk: 2 },
  credentials: { label: 'Credentials / passkeys', group: 'sensitive', risk: 5 },
  bluetooth: { label: 'Bluetooth devices', group: 'device', risk: 4 },
  usb: { label: 'USB devices', group: 'device', risk: 4 },
  serial: { label: 'Serial devices', group: 'device', risk: 4 },
  hid: { label: 'HID devices', group: 'device', risk: 4 },
  midi: { label: 'MIDI devices', group: 'device', risk: 3 },
  mediaDevices: { label: 'Media-device inventory', group: 'fingerprint', risk: 3 },
  cookies: { label: 'Cookies', group: 'storage', risk: 2 },
  localStorage: { label: 'Local storage', group: 'storage', risk: 1 },
  indexedDB: { label: 'IndexedDB', group: 'storage', risk: 1 },
  hardware: { label: 'Hardware profile', group: 'fingerprint', risk: 3 },
  screen: { label: 'Screen geometry', group: 'fingerprint', risk: 2 },
  canvas: { label: 'Canvas fingerprint surface', group: 'fingerprint', risk: 4 },
  webgl: { label: 'GPU / WebGL fingerprint', group: 'fingerprint', risk: 4 },
  audio: { label: 'Audio fingerprint surface', group: 'fingerprint', risk: 4 },
  fonts: { label: 'Installed-font probing', group: 'fingerprint', risk: 3 },
  highEntropyUA: { label: 'High-entropy browser details', group: 'fingerprint', risk: 3 },
  speechVoices: { label: 'Speech voice inventory', group: 'fingerprint', risk: 2 },
  webrtc: { label: 'WebRTC / peer connection', group: 'fingerprint', risk: 4 },
  battery: { label: 'Battery information', group: 'fingerprint', risk: 3 },
  networkInfo: { label: 'Network connection details', group: 'fingerprint', risk: 2 },
  timezone: { label: 'Timezone / locale profile', group: 'fingerprint', risk: 2 },
  languages: { label: 'Language profile', group: 'fingerprint', risk: 2 },
  gamepad: { label: 'Gamepad inventory', group: 'device', risk: 2 },
  formEmail: { label: 'Email address field', group: 'form', risk: 2 },
  formPassword: { label: 'Password field', group: 'form', risk: 4 },
  formPayment: { label: 'Payment-card field', group: 'form', risk: 5 },
  formAddress: { label: 'Address / postal field', group: 'form', risk: 3 },
  formPhone: { label: 'Phone-number field', group: 'form', risk: 3 },
  fileUpload: { label: 'File upload field', group: 'form', risk: 4 }
});

const VALID_ACTIONS = new Set(['observed', 'requested', 'blocked', 'allowed', 'read', 'write']);

function makeSiteIntelligence(url = '', origin = '') {
  return {
    url: String(url || '').slice(0, 1000),
    origin: String(origin || '').slice(0, 500),
    startedAt: new Date().toISOString(),
    signals: {},
    recent: [],
    network: { thirdPartyHosts: {}, totalThirdParty: 0, blockedThirdParty: 0, allowedThirdParty: 0 }
  };
}

function resetSiteIntelligence(tab, url = '', origin = '') {
  if (!tab) return null;
  tab.siteIntelligence = makeSiteIntelligence(url, origin);
  return tab.siteIntelligence;
}

function normalizeSignal(input = {}) {
  const category = Object.prototype.hasOwnProperty.call(SIGNAL_DEFS, input.category) ? input.category : '';
  if (!category) return null;
  const action = VALID_ACTIONS.has(input.action) ? input.action : 'observed';
  const count = Math.max(1, Math.min(10000, Math.floor(Number(input.count) || 1)));
  return {
    category,
    action,
    count,
    detail: String(input.detail || '').replace(/\s+/g, ' ').trim().slice(0, 160),
    source: String(input.source || 'page').replace(/[^a-z0-9_-]/gi, '').slice(0, 30) || 'page',
    frameHost: String(input.frameHost || '').toLowerCase().replace(/[^a-z0-9.-]/g, '').slice(0, 255)
  };
}

function recordSiteSignal(tab, input = {}) {
  if (!tab) return false;
  if (!tab.siteIntelligence) tab.siteIntelligence = makeSiteIntelligence(tab.url, '');
  const event = normalizeSignal(input);
  if (!event) return false;

  const now = new Date().toISOString();
  const entry = tab.siteIntelligence.signals[event.category] || {
    category: event.category,
    label: SIGNAL_DEFS[event.category].label,
    group: SIGNAL_DEFS[event.category].group,
    risk: SIGNAL_DEFS[event.category].risk,
    attempts: 0,
    blocked: 0,
    allowed: 0,
    reads: 0,
    writes: 0,
    lastAction: 'observed',
    lastDetail: '',
    firstSeenAt: now,
    lastSeenAt: now
  };

  // Browser-side instrumentation reports a monotonic count for a document. Use
  // it as a lower bound rather than blindly adding it, which keeps the ledger
  // robust against duplicate delivery from the DevTools binding.
  if (event.source === 'audit') entry.attempts = Math.max(entry.attempts, event.count);
  else entry.attempts += event.count;
  if (event.action === 'blocked') entry.blocked += event.count;
  if (event.action === 'allowed') entry.allowed += event.count;
  if (event.action === 'read') entry.reads += event.count;
  if (event.action === 'write') entry.writes += event.count;
  entry.lastAction = event.action;
  entry.lastDetail = event.detail;
  entry.lastSeenAt = now;
  tab.siteIntelligence.signals[event.category] = entry;

  tab.siteIntelligence.recent.unshift({
    kind: 'signal',
    category: event.category,
    label: entry.label,
    group: entry.group,
    action: event.action,
    detail: event.detail,
    source: event.source,
    frameHost: event.frameHost,
    at: now
  });
  tab.siteIntelligence.recent = tab.siteIntelligence.recent.slice(0, 60);
  return true;
}

function recordNetworkEvent(tab, input = {}) {
  if (!tab) return false;
  if (!tab.siteIntelligence) tab.siteIntelligence = makeSiteIntelligence(tab.url, '');
  if (!tab.siteIntelligence.network) tab.siteIntelligence.network = { thirdPartyHosts: {}, totalThirdParty: 0, blockedThirdParty: 0, allowedThirdParty: 0 };
  let host = '';
  try { host = new URL(String(input.url || '')).hostname.toLowerCase(); } catch { return false; }
  if (!host) return false;
  const blocked = Boolean(input.blocked);
  const category = String(input.category || 'third-party').replace(/[^a-z0-9_-]/gi, '').slice(0, 32) || 'third-party';
  const resourceType = String(input.resourceType || 'other').replace(/[^a-z0-9_-]/gi, '').slice(0, 32) || 'other';
  const now = new Date().toISOString();
  const net = tab.siteIntelligence.network;
  net.totalThirdParty += 1;
  if (blocked) net.blockedThirdParty += 1; else net.allowedThirdParty += 1;
  const entry = net.thirdPartyHosts[host] || { host, requests: 0, blocked: 0, allowed: 0, categories: {}, resources: {}, firstSeenAt: now, lastSeenAt: now };
  entry.requests += 1;
  if (blocked) entry.blocked += 1; else entry.allowed += 1;
  entry.categories[category] = (entry.categories[category] || 0) + 1;
  entry.resources[resourceType] = (entry.resources[resourceType] || 0) + 1;
  entry.lastSeenAt = now;
  net.thirdPartyHosts[host] = entry;

  // The timeline stores only host/category metadata, never a full request URL.
  if (blocked || entry.requests === 1) {
    tab.siteIntelligence.recent.unshift({
      kind: 'network', label: host, group: 'network', action: blocked ? 'blocked' : 'observed',
      detail: `${category} · ${resourceType}`, source: 'network', frameHost: host, at: now
    });
    tab.siteIntelligence.recent = tab.siteIntelligence.recent.slice(0, 60);
  }
  return true;
}

function publicSiteIntelligence(tab) {
  const raw = tab?.siteIntelligence || makeSiteIntelligence(tab?.url || '', '');
  const signals = Object.values(raw.signals || {}).map((entry) => ({ ...entry })).sort((a, b) => {
    const groupOrder = { sensitive: 0, device: 1, form: 2, fingerprint: 3, storage: 4 };
    return (groupOrder[a.group] ?? 9) - (groupOrder[b.group] ?? 9) || b.risk - a.risk || b.attempts - a.attempts;
  });
  const rawHosts = Object.values(raw.network?.thirdPartyHosts || {});
  const hosts = rawHosts.map((entry) => ({
    host: entry.host,
    requests: entry.requests || 0,
    blocked: entry.blocked || 0,
    allowed: entry.allowed || 0,
    category: Object.entries(entry.categories || {}).sort((a,b) => b[1]-a[1])[0]?.[0] || 'third-party',
    resourceType: Object.entries(entry.resources || {}).sort((a,b) => b[1]-a[1])[0]?.[0] || 'other'
  })).sort((a,b) => b.blocked - a.blocked || b.requests - a.requests || a.host.localeCompare(b.host)).slice(0, 24);
  const allowedSensitive = signals.filter((x) => (x.group === 'sensitive' || x.group === 'device') && (x.allowed || 0) > 0).length;
  const requestedSensitive = signals.filter((x) => (x.group === 'sensitive' || x.group === 'device') && (x.attempts || 0) > 0).length;
  return {
    url: raw.url || '',
    origin: raw.origin || '',
    startedAt: raw.startedAt || '',
    signals,
    recent: (raw.recent || []).slice(0, 30),
    network: {
      uniqueThirdParties: rawHosts.length,
      blockedUnique: rawHosts.filter((x) => (x.blocked || 0) > 0).length,
      allowedUnique: rawHosts.filter((x) => (x.allowed || 0) > 0).length,
      totalThirdParty: raw.network?.totalThirdParty || 0,
      blockedThirdParty: raw.network?.blockedThirdParty || 0,
      allowedThirdParty: raw.network?.allowedThirdParty || 0,
      hosts
    },
    totals: {
      categories: signals.length,
      attempts: signals.reduce((sum, x) => sum + (x.attempts || 0), 0),
      blocked: signals.reduce((sum, x) => sum + (x.blocked || 0), 0),
      allowed: signals.reduce((sum, x) => sum + (x.allowed || 0), 0),
      sensitiveCategories: requestedSensitive,
      allowedSensitiveCategories: allowedSensitive,
      formCategories: signals.filter((x) => x.group === 'form').length,
      fingerprintCategories: signals.filter((x) => x.group === 'fingerprint').length
    }
  };
}

function buildSiteAuditScript({ bindingName }) {
  const binding = JSON.stringify(String(bindingName || ''));
  return `(() => {
    'use strict';
    const BINDING = ${binding};
    if (!BINDING || globalThis.__aegisSiteAuditInstalled) return;
    try { Object.defineProperty(globalThis, '__aegisSiteAuditInstalled', { value: true, configurable: false }); } catch { return; }
    const counts = Object.create(null);
    const reportPoints = new Set([1,2,5,10,25,50,100,250,500]);
    const emit = (category, detail = '', action = 'observed') => {
      try {
        const count = (counts[category] = (counts[category] || 0) + 1);
        if (!reportPoints.has(count)) return;
        const fn = globalThis[BINDING];
        if (typeof fn !== 'function') return;
        fn(JSON.stringify({ category, detail: String(detail || '').slice(0,120), action, count, source:'audit', frameHost: location.hostname || '' }));
      } catch {}
    };
    const wrapMethod = (obj, key, category, detailFn) => {
      try {
        if (!obj || typeof obj[key] !== 'function') return;
        const native = obj[key];
        const desc = Object.getOwnPropertyDescriptor(obj, key) || { configurable:true, writable:true, enumerable:false };
        const wrapped = new Proxy(native, { apply(target, thisArg, args) {
          let detail = ''; try { detail = typeof detailFn === 'function' ? detailFn(args) : (detailFn || ''); } catch {}
          emit(category, detail); return Reflect.apply(target, thisArg, args);
        }});
        Object.defineProperty(obj, key, { ...desc, value: wrapped });
      } catch {}
    };
    const wrapGetter = (proto, key, category, detail = '') => {
      try {
        const desc = Object.getOwnPropertyDescriptor(proto, key); if (!desc || typeof desc.get !== 'function') return;
        const nativeGet = desc.get;
        Object.defineProperty(proto, key, { ...desc, get: function(){ emit(category, detail || key); return nativeGet.call(this); } });
      } catch {}
    };

    try {
      const md = globalThis.MediaDevices && MediaDevices.prototype;
      wrapMethod(md, 'getUserMedia', 'mediaDevices', (args) => { const c=args[0]||{}; if (c.audio && c.video) return 'camera + microphone'; if (c.audio) return 'microphone'; return 'camera'; });
      wrapMethod(md, 'getDisplayMedia', 'displayCapture', 'screen/window/tab');
      wrapMethod(md, 'enumerateDevices', 'mediaDevices', 'enumerate');
    } catch {}
    try {
      const geo = globalThis.Geolocation && Geolocation.prototype;
      wrapMethod(geo, 'getCurrentPosition', 'geolocation', 'current position');
      wrapMethod(geo, 'watchPosition', 'geolocation', 'continuous position');
    } catch {}
    try { if (globalThis.Notification) wrapMethod(Notification, 'requestPermission', 'notifications', 'request'); } catch {}
    try { const cp = globalThis.Clipboard && Clipboard.prototype; wrapMethod(cp, 'read', 'clipboardRead', 'read'); wrapMethod(cp, 'readText', 'clipboardRead', 'read text'); } catch {}
    try { const cp = globalThis.CredentialsContainer && CredentialsContainer.prototype; wrapMethod(cp, 'get', 'credentials', 'get'); wrapMethod(cp, 'create', 'credentials', 'create'); } catch {}
    try { if (navigator.usb) wrapMethod(Object.getPrototypeOf(navigator.usb), 'requestDevice', 'usb', 'request device'); } catch {}
    try { if (navigator.serial) wrapMethod(Object.getPrototypeOf(navigator.serial), 'requestPort', 'serial', 'request port'); } catch {}
    try { if (navigator.hid) wrapMethod(Object.getPrototypeOf(navigator.hid), 'requestDevice', 'hid', 'request device'); } catch {}
    try { if (navigator.bluetooth) wrapMethod(Object.getPrototypeOf(navigator.bluetooth), 'requestDevice', 'bluetooth', 'request device'); } catch {}
    try { wrapMethod(Navigator.prototype, 'requestMIDIAccess', 'midi', 'request MIDI'); } catch {}
    try { wrapMethod(Navigator.prototype, 'getGamepads', 'gamepad', 'enumerate'); } catch {}
    try { wrapMethod(Navigator.prototype, 'getBattery', 'battery', 'battery status'); } catch {}

    try {
      for (const key of ['hardwareConcurrency','deviceMemory','platform','maxTouchPoints']) wrapGetter(Navigator.prototype, key, 'hardware', key);
      wrapGetter(Navigator.prototype, 'language', 'languages', 'primary language');
      wrapGetter(Navigator.prototype, 'languages', 'languages', 'language list');
      try { wrapGetter(Navigator.prototype, 'connection', 'networkInfo', 'connection API'); } catch {}
      wrapGetter(Screen.prototype, 'width', 'screen', 'geometry');
      wrapGetter(Screen.prototype, 'height', 'screen', 'geometry');
      wrapGetter(Screen.prototype, 'colorDepth', 'screen', 'color depth');
      const uaData = navigator.userAgentData && Object.getPrototypeOf(navigator.userAgentData);
      wrapMethod(uaData, 'getHighEntropyValues', 'highEntropyUA', 'high entropy client hints');
    } catch {}
    try { wrapMethod(Intl.DateTimeFormat.prototype, 'resolvedOptions', 'timezone', 'resolved locale/timezone'); } catch {}
    try { const sp = globalThis.SpeechSynthesis && SpeechSynthesis.prototype; wrapMethod(sp, 'getVoices', 'speechVoices', 'voice list'); } catch {}
    try { const ff = globalThis.FontFaceSet && FontFaceSet.prototype; wrapMethod(ff, 'check', 'fonts', 'font check'); } catch {}

    try {
      const c2d = globalThis.CanvasRenderingContext2D && CanvasRenderingContext2D.prototype;
      wrapMethod(c2d, 'getImageData', 'canvas', 'pixel read');
      wrapMethod(c2d, 'measureText', 'fonts', 'text metrics');
      const canvas = globalThis.HTMLCanvasElement && HTMLCanvasElement.prototype;
      wrapMethod(canvas, 'toDataURL', 'canvas', 'toDataURL');
      wrapMethod(canvas, 'toBlob', 'canvas', 'toBlob');
    } catch {}
    try {
      for (const proto of [globalThis.WebGLRenderingContext?.prototype, globalThis.WebGL2RenderingContext?.prototype]) {
        wrapMethod(proto, 'getParameter', 'webgl', 'GPU parameter');
        wrapMethod(proto, 'getExtension', 'webgl', 'extension query');
        wrapMethod(proto, 'getSupportedExtensions', 'webgl', 'extension inventory');
      }
    } catch {}
    try {
      for (const Ctx of [globalThis.AudioContext, globalThis.OfflineAudioContext]) {
        if (Ctx?.prototype) { wrapMethod(Ctx.prototype, 'createOscillator', 'audio', 'oscillator'); wrapMethod(Ctx.prototype, 'createAnalyser', 'audio', 'analyser'); }
      }
    } catch {}
    try {
      const rtc = globalThis.RTCPeerConnection && RTCPeerConnection.prototype;
      wrapMethod(rtc, 'createOffer', 'webrtc', 'create offer');
      wrapMethod(rtc, 'createDataChannel', 'webrtc', 'data channel');
      wrapMethod(rtc, 'addIceCandidate', 'webrtc', 'ICE candidate');
    } catch {}

    try {
      const docProto = globalThis.Document && Document.prototype;
      wrapGetter(docProto, 'cookie', 'cookies', 'cookie read');
      const storageProto = globalThis.Storage && Storage.prototype;
      wrapMethod(storageProto, 'getItem', 'localStorage', 'read'); wrapMethod(storageProto, 'setItem', 'localStorage', 'write');
      if (globalThis.IDBFactory) { wrapMethod(IDBFactory.prototype, 'open', 'indexedDB', 'open database'); wrapMethod(IDBFactory.prototype, 'databases', 'indexedDB', 'database inventory'); }
    } catch {}

    // Form-intent scanner records only the presence/type of sensitive fields.
    // It never reads field values, labels, user input, names, or submitted data.
    try {
      const seen = new Set();
      const flag = (category, detail) => { if (seen.has(category)) return; seen.add(category); emit(category, detail); };
      const scan = () => {
        const fields = document.querySelectorAll('input, select, textarea');
        for (const el of fields) {
          const type = String(el.getAttribute('type') || '').toLowerCase();
          const ac = String(el.getAttribute('autocomplete') || '').toLowerCase();
          if (type === 'email' || ac === 'email') flag('formEmail', 'page contains an email field');
          if (type === 'password' || /current-password|new-password/.test(ac)) flag('formPassword', 'page contains a password field');
          if (type === 'tel' || ac === 'tel' || ac.startsWith('tel-')) flag('formPhone', 'page contains a phone field');
          if (type === 'file') flag('fileUpload', 'page contains a file upload');
          if (ac.startsWith('cc-')) flag('formPayment', 'page contains a payment-card field');
          if (/street-address|address-line|postal-code|country/.test(ac)) flag('formAddress', 'page contains an address field');
        }
      };
      if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', scan, { once:true }); else scan();
      let queued = false;
      new MutationObserver(() => { if (queued) return; queued = true; queueMicrotask(() => { queued = false; scan(); }); }).observe(document.documentElement || document, { childList:true, subtree:true });
    } catch {}
  })();`;
}

module.exports = { SIGNAL_DEFS, makeSiteIntelligence, resetSiteIntelligence, recordSiteSignal, recordNetworkEvent, publicSiteIntelligence, buildSiteAuditScript };
