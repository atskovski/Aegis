'use strict';
const { policyFor } = require('./fingerprint-policy');

function buildAntiFingerprintScript({ seed, chromiumMajor = '152', profile = 'strict', disableServiceWorkers = true, globalPrivacyControl = true, doNotTrack = true, anonymousMode = false, disableWebRtc = false }) {
  const ua = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromiumMajor}.0.0.0 Safari/537.36`;
  const policy=policyFor({profile,anonymousMode,disableWebRtc,chromiumMajor});
  const strict = policy.name === 'strict' || policy.name === 'maximum';
  const maximum = policy.name === 'maximum';

  return `(() => {
    'use strict';
    const BASE = ${JSON.stringify(String(seed))};
    const UA = ${JSON.stringify(ua)};
    const STRICT = ${strict ? 'true' : 'false'};
    const MAXIMUM = ${maximum ? 'true' : 'false'};
    const DISABLE_SW = ${disableServiceWorkers ? 'true' : 'false'};
    const GPC = ${globalPrivacyControl ? 'true' : 'false'};
    const DNT = ${doNotTrack ? 'true' : 'false'};
    const ANONYMOUS = ${anonymousMode ? 'true' : 'false'};
    const DISABLE_WEBRTC = ${disableWebRtc ? 'true' : 'false'};
    const host = (() => { try { return location.hostname || 'opaque'; } catch { return 'opaque'; } })();
    let h = 2166136261 >>> 0;
    // Strict/Maximum/anonymous profiles use a cohort seed, not a per-user seed. This makes
    // perturbation deterministic across Aegis users at the same first party instead
    // of creating a stable, user-specific randomized fingerprint.
    const COHORT = "aegis-cohort-v2";
    const input = (STRICT || ANONYMOUS ? COHORT : BASE) + '|' + host;
    for (let i = 0; i < input.length; i++) { h ^= input.charCodeAt(i); h = Math.imul(h, 16777619); }
    const randByte = (index) => {
      let x = (h ^ Math.imul(index + 1, 0x45d9f3b)) >>> 0;
      x ^= x >>> 16; x = Math.imul(x, 0x45d9f3b); x ^= x >>> 16;
      return x & 0xff;
    };
    const def = (obj, key, getter) => { try { Object.defineProperty(obj, key, { configurable: true, get: getter }); } catch {} };
    const undef = (obj, key) => {
      try { Object.defineProperty(obj, key, { configurable: true, enumerable: false, value: undefined, writable: false }); return; } catch {}
      try { obj[key] = undefined; } catch {}
    };
    try {
      const navProto = Navigator.prototype;
      def(navProto, 'hardwareConcurrency', () => 4);
      def(navProto, 'deviceMemory', () => 8);
      def(navProto, 'maxTouchPoints', () => 0);
      def(navProto, 'language', () => 'en-US');
      def(navProto, 'languages', () => Object.freeze(['en-US', 'en']));
      def(navProto, 'platform', () => 'MacIntel');
      def(navProto, 'vendor', () => 'Google Inc.');
      def(navProto, 'userAgent', () => UA);
      def(navProto, 'appVersion', () => UA.replace(/^Mozilla\\//, ''));
      def(navProto, 'doNotTrack', () => DNT ? '1' : null);
      def(navProto, 'globalPrivacyControl', () => GPC);
      def(navProto, 'webdriver', () => false);
      def(navProto, 'pdfViewerEnabled', () => true);
      if (STRICT) {
        def(navProto, 'plugins', () => Object.freeze([]));
        def(navProto, 'mimeTypes', () => Object.freeze([]));
      }
      try { Object.defineProperty(navigator, 'connection', { configurable: true, value: undefined }); } catch {}
      try { Object.defineProperty(navigator, 'getBattery', { configurable: true, value: undefined }); } catch {}
      if (ANONYMOUS) {
        try { undef(navProto, 'bluetooth'); } catch {}
        try { undef(navProto, 'usb'); } catch {}
        try { undef(navProto, 'serial'); } catch {}
        try { undef(navProto, 'hid'); } catch {}
        try { undef(navProto, 'presentation'); } catch {}
        try { undef(navProto, 'wakeLock'); } catch {}
        try { undef(navProto, 'xr'); } catch {}
      }
      if (STRICT) { try { undef(globalThis, 'queryLocalFonts'); } catch {} }

      const uaData = Object.freeze({
        brands: Object.freeze([{brand:'Chromium', version:'${chromiumMajor}'},{brand:'Not=A?Brand', version:'99'}]),
        mobile: false,
        platform: 'macOS',
        getHighEntropyValues: async (hints) => {
          const out = { brands: [{brand:'Chromium', version:'${chromiumMajor}'},{brand:'Not=A?Brand', version:'99'}], mobile:false, platform:'macOS' };
          for (const key of (hints || [])) {
            if (key === 'architecture') out.architecture = 'x86';
            else if (key === 'bitness') out.bitness = '64';
            else if (key === 'model') out.model = '';
            else if (key === 'platformVersion') out.platformVersion = '10.15.7';
            else if (key === 'uaFullVersion') out.uaFullVersion = '${chromiumMajor}.0.0.0';
            else if (key === 'fullVersionList') out.fullVersionList = [{brand:'Chromium',version:'${chromiumMajor}.0.0.0'},{brand:'Not=A?Brand',version:'99.0.0.0'}];
            else if (key === 'wow64') out.wow64 = false;
          }
          return out;
        },
        toJSON() { return { brands:this.brands, mobile:false, platform:'macOS' }; }
      });
      def(navProto, 'userAgentData', () => uaData);

    } catch {}

    if (STRICT) {
      try {
        const scr = Screen.prototype;
        def(scr, 'width', () => 1440); def(scr, 'height', () => 900);
        def(scr, 'availWidth', () => 1440); def(scr, 'availHeight', () => 860);
        def(scr, 'colorDepth', () => 24); def(scr, 'pixelDepth', () => 24);
        def(window, 'devicePixelRatio', () => 1);
      } catch {}
    }

    try {
      const nativeResolved = Intl.DateTimeFormat.prototype.resolvedOptions;
      Object.defineProperty(Intl.DateTimeFormat.prototype, 'resolvedOptions', {
        configurable: true,
        value: function() {
          const out = nativeResolved.call(this);
          try { return { ...out, locale: 'en-US', timeZone: 'UTC' }; } catch { return out; }
        }
      });
    } catch {}

    try {
      const pnow = performance.now.bind(performance);
      performance.now = () => { const q=MAXIMUM?10:2; return Math.round(pnow()/q)*q; };
    } catch {}

    if (DISABLE_SW && STRICT) {
      try {
        if (navigator.serviceWorker && navigator.serviceWorker.register) {
          Object.defineProperty(navigator.serviceWorker, 'register', {
            configurable: true,
            value: async () => { throw new DOMException('Service workers disabled by Aegis', 'SecurityError'); }
          });
        }
      } catch {}
    }

    if (DISABLE_WEBRTC) {
      try { undef(globalThis, 'RTCPeerConnection'); } catch {}
      try { undef(globalThis, 'webkitRTCPeerConnection'); } catch {}
      try { undef(globalThis, 'RTCDataChannel'); } catch {}
    }

    if (STRICT) {
      try { if (globalThis.speechSynthesis) speechSynthesis.getVoices = () => []; } catch {}
      try { undef(navProto,'getInstalledRelatedApps'); } catch {}
      try { undef(navProto,'getGamepads'); } catch {}
      try { undef(navProto,'keyboard'); } catch {}
      try { undef(navProto,'mediaCapabilities'); } catch {}
      try { undef(navProto,'storageBuckets'); } catch {}
      try { undef(globalThis,'IdleDetector'); } catch {}
      try { undef(globalThis,'EyeDropper'); } catch {}
      try { undef(globalThis,'LaunchQueue'); } catch {}
      try { undef(globalThis,'PressureObserver'); } catch {}
      try { undef(globalThis,'ComputePressureObserver'); } catch {}
      try { undef(globalThis,'getScreenDetails'); } catch {}
      try { undef(globalThis,'showOpenFilePicker'); undef(globalThis,'showSaveFilePicker'); undef(globalThis,'showDirectoryPicker'); } catch {}
      try {
        if (globalThis.matchMedia) {
          const nativeMM=globalThis.matchMedia.bind(globalThis);
          globalThis.matchMedia=(q)=>{const s=String(q||'');if(/prefers-color-scheme|prefers-contrast|forced-colors|dynamic-range|video-dynamic-range|inverted-colors/i.test(s)){const r=nativeMM('(width: 0px)');try{Object.defineProperty(r,'matches',{configurable:true,value:false});Object.defineProperty(r,'media',{configurable:true,value:s});}catch{}return r;}return nativeMM(s);};
        }
      } catch {}
      if (ANONYMOUS || DISABLE_WEBRTC) {
        for (const key of ['RTCPeerConnection','webkitRTCPeerConnection','mozRTCPeerConnection','RTCDataChannel']) {
          try { Object.defineProperty(globalThis, key, { configurable:true, enumerable:false, value:undefined, writable:false }); } catch {}
        }
        try { if (navigator.mediaDevices) Object.defineProperty(navigator.mediaDevices, 'getUserMedia', { configurable:true, value:async()=>{ throw new DOMException('Media capture disabled by Aegis anonymous compartment','NotAllowedError'); } }); } catch {}
      }
      if (ANONYMOUS) {
        try { Object.defineProperty(navigator, 'share', { configurable:true, value:undefined }); } catch {}
        try { Object.defineProperty(navigator, 'contacts', { configurable:true, value:undefined }); } catch {}
        try { Object.defineProperty(navigator, 'bluetooth', { configurable:true, value:undefined }); } catch {}
        try { Object.defineProperty(navigator, 'usb', { configurable:true, value:undefined }); } catch {}
        try { Object.defineProperty(navigator, 'serial', { configurable:true, value:undefined }); } catch {}
        try { Object.defineProperty(navigator, 'hid', { configurable:true, value:undefined }); } catch {}
        try { Object.defineProperty(navigator, 'credentials', { configurable:true, value:undefined }); } catch {}
      }

      // Common font fingerprinting libraries compare off-screen span metrics across
      // hundreds of candidate fonts. Normalize only that probe-shaped pattern so
      // ordinary visible layout remains untouched.
      try {
        const widthDesc = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth');
        const heightDesc = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetHeight');
        const looksLikeFontProbe = (el) => {
          try {
            if (!el || !['SPAN','DIV'].includes(el.tagName)) return false;
            const style = el.style || {};
            const family = String(style.fontFamily || '');
            const left = Number.parseFloat(style.left || '0');
            const top = Number.parseFloat(style.top || '0');
            const offscreen = left < -500 || top < -500 || style.visibility === 'hidden';
            const fallbackPair = family.includes(',') && /(monospace|sans-serif|serif)/i.test(family);
            return offscreen && fallbackPair && String(el.textContent || '').length >= 4;
          } catch { return false; }
        };
        if (widthDesc?.get) Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
          configurable: true,
          get() {
            if (looksLikeFontProbe(this)) {
              const size = Number.parseFloat(getComputedStyle(this).fontSize || '16') || 16;
              return Math.max(1, Math.round(String(this.textContent || '').length * size * 0.59));
            }
            return widthDesc.get.call(this);
          }
        });
        if (heightDesc?.get) Object.defineProperty(HTMLElement.prototype, 'offsetHeight', {
          configurable: true,
          get() {
            if (looksLikeFontProbe(this)) {
              const size = Number.parseFloat(getComputedStyle(this).fontSize || '16') || 16;
              return Math.max(1, Math.round(size * 1.22));
            }
            return heightDesc.get.call(this);
          }
        });
      } catch {}

      try {
        const nativeGet = CanvasRenderingContext2D.prototype.getImageData;
        const nativePut = CanvasRenderingContext2D.prototype.putImageData;
        const nativeToDataURL = HTMLCanvasElement.prototype.toDataURL;
        const nativeToBlob = HTMLCanvasElement.prototype.toBlob;
        const nativeMeasureText = CanvasRenderingContext2D.prototype.measureText;
        const perturb = (image) => {
          if (!image || !image.data || image.data.length < 4) return image;
          const px = image.data.length / 4;
          const stride = Math.max(1, Math.floor(px / 128));
          for (let p = 0; p < px; p += stride) {
            const i = p * 4;
            image.data[i] = Math.max(0, Math.min(255, image.data[i] + ((randByte(i) & 1) ? 1 : -1)));
          }
          return image;
        };
        CanvasRenderingContext2D.prototype.getImageData = function(...args) { return perturb(nativeGet.apply(this, args)); };
        CanvasRenderingContext2D.prototype.measureText = function(text) {
          const result = nativeMeasureText.call(this, text);
          if (!MAXIMUM) return result;
          try { return new Proxy(result, { get(target, prop) { if (prop === 'width') return Math.round(target.width * 64) / 64; return Reflect.get(target, prop); } }); } catch { return result; }
        };
        const noisyClone = (canvas) => {
          const clone = document.createElement('canvas');
          clone.width = canvas.width; clone.height = canvas.height;
          const c = clone.getContext('2d');
          if (!c || !canvas.width || !canvas.height) return clone;
          c.drawImage(canvas, 0, 0);
          try {
            const image = perturb(nativeGet.call(c, 0, 0, canvas.width, canvas.height));
            nativePut.call(c, image, 0, 0);
          } catch {}
          return clone;
        };
        HTMLCanvasElement.prototype.toDataURL = function(...args) {
          if (MAXIMUM && this.width * this.height > 0) {
            const placeholder = document.createElement('canvas'); placeholder.width = Math.max(1, this.width); placeholder.height = Math.max(1, this.height);
            return nativeToDataURL.apply(placeholder, args);
          }
          return nativeToDataURL.apply(noisyClone(this), args);
        };
        HTMLCanvasElement.prototype.toBlob = function(...args) {
          if (MAXIMUM && this.width * this.height > 0) {
            const placeholder = document.createElement('canvas'); placeholder.width = Math.max(1, this.width); placeholder.height = Math.max(1, this.height);
            return nativeToBlob.apply(placeholder, args);
          }
          return nativeToBlob.apply(noisyClone(this), args);
        };
        if (globalThis.OffscreenCanvas && OffscreenCanvas.prototype.convertToBlob) {
          const nativeConvert = OffscreenCanvas.prototype.convertToBlob;
          OffscreenCanvas.prototype.convertToBlob = function(...args) {
            if (!MAXIMUM) return nativeConvert.apply(this, args);
            const placeholder = new OffscreenCanvas(Math.max(1, this.width), Math.max(1, this.height));
            return nativeConvert.apply(placeholder, args);
          };
        }
      } catch {}

      try {
        const patchGL = (proto) => {
          if (!proto) return;
          const gp = proto.getParameter;
          const ge = proto.getExtension;
          const read = proto.readPixels;
          proto.getParameter = function(p) {
            if (p === 37445) return 'Apple Inc.';
            if (p === 37446) return 'Apple GPU';
            return gp.call(this, p);
          };
          proto.getExtension = function(name) {
            if (String(name) === 'WEBGL_debug_renderer_info' || String(name).toUpperCase() === 'WEBGL_DEBUG_RENDERER_INFO') return null;
            return ge.call(this, name);
          };
          if (typeof read === 'function') proto.readPixels = function(...args) {
            const out = read.apply(this, args);
            const pixels = args[6];
            if (pixels && pixels.length) {
              const step = Math.max(4, Math.floor(pixels.length / 128));
              for (let i = 0; i < pixels.length; i += step) pixels[i] = (pixels[i] ^ (randByte(i) & 1));
            }
            return out;
          };
        };
        patchGL(globalThis.WebGLRenderingContext && WebGLRenderingContext.prototype);
        patchGL(globalThis.WebGL2RenderingContext && WebGL2RenderingContext.prototype);
        if (MAXIMUM && HTMLCanvasElement.prototype.getContext) {
          const nativeContext = HTMLCanvasElement.prototype.getContext;
          HTMLCanvasElement.prototype.getContext = function(type, ...args) {
            if (/^webgl2?$/i.test(String(type || ''))) return null;
            return nativeContext.call(this, type, ...args);
          };
        }
      } catch {}

      try {
        const enumDevices = MediaDevices.prototype.enumerateDevices;
        MediaDevices.prototype.enumerateDevices = async function() {
          const devices = await enumDevices.call(this);
          return devices.map((d, i) => ({ deviceId: d.kind + '-' + i, kind: d.kind, label: '', groupId: '', toJSON(){ return this; } }));
        };
      } catch {}

      try {
        if (MAXIMUM || ANONYMOUS) {
          const nativeCreate = globalThis.AudioContext && AudioContext.prototype.createAnalyser;
          if (nativeCreate) AudioContext.prototype.createAnalyser = function(...args) { const a = nativeCreate.apply(this,args); try { Object.defineProperty(a,'frequencyBinCount',{configurable:true,get:()=>1024}); } catch {} return a; };
        }
        const nativeChannel = AudioBuffer.prototype.getChannelData;
        AudioBuffer.prototype.getChannelData = function(channel) {
          const original = nativeChannel.call(this, channel);
          const copy = new Float32Array(original);
          const magnitude = MAXIMUM ? 1e-7 : 1e-8;
          for (let i = 0; i < copy.length; i += 256) copy[i] += ((randByte(i + channel) & 1) ? 1 : -1) * magnitude;
          return copy;
        };
      } catch {}
    }

    if (STRICT) {
      try {
        if (document.fonts && document.fonts.check) {
          const nativeCheck = document.fonts.check.bind(document.fonts);
          document.fonts.check = (font, text) => {
            const value = String(font || '').toLowerCase();
            if (/system-ui|sans-serif|serif|monospace|arial|times|courier|helvetica/.test(value)) return nativeCheck(font, text);
            return false;
          };
        }
      } catch {}
    }
  })();`;
}

module.exports = { buildAntiFingerprintScript };
