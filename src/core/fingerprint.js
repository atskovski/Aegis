'use strict';

function buildAntiFingerprintScript({ seed, chromiumMajor = '152', profile = 'strict', disableServiceWorkers = true }) {
  const ua = `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${chromiumMajor}.0.0.0 Safari/537.36`;
  const strict = profile === 'strict' || profile === 'maximum';
  const maximum = profile === 'maximum';

  return `(() => {
    'use strict';
    const BASE = ${JSON.stringify(String(seed))};
    const COHORT = 'aegis-v09-standardized';
    const UA = ${JSON.stringify(ua)};
    const STRICT = ${strict ? 'true' : 'false'};
    const MAXIMUM = ${maximum ? 'true' : 'false'};
    const DISABLE_SW = ${disableServiceWorkers ? 'true' : 'false'};
    const host = (() => { try { return location.hostname || 'opaque'; } catch { return 'opaque'; } })();
    let h = 2166136261 >>> 0;
    const input = (MAXIMUM ? COHORT : BASE) + '|' + host;
    for (let i = 0; i < input.length; i++) { h ^= input.charCodeAt(i); h = Math.imul(h, 16777619); }
    const randByte = (index) => {
      let x = (h ^ Math.imul(index + 1, 0x45d9f3b)) >>> 0;
      x ^= x >>> 16; x = Math.imul(x, 0x45d9f3b); x ^= x >>> 16;
      return x & 0xff;
    };
    const def = (obj, key, getter) => {
      try { Object.defineProperty(obj, key, { configurable: true, get: getter }); } catch {}
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
      def(navProto, 'doNotTrack', () => '1');
      def(navProto, 'webdriver', () => false);
      def(navProto, 'pdfViewerEnabled', () => true);
      if (STRICT) {
        def(navProto, 'plugins', () => Object.freeze([]));
        def(navProto, 'mimeTypes', () => Object.freeze([]));
      }
      try { Object.defineProperty(navigator, 'connection', { configurable: true, value: undefined }); } catch {}
      try { Object.defineProperty(navigator, 'getBattery', { configurable: true, value: undefined }); } catch {}

      const uaData = Object.freeze({
        brands: Object.freeze([{brand:'Chromium', version:'${chromiumMajor}'},{brand:'Not=A?Brand', version:'99'}]),
        mobile: false,
        platform: 'macOS',
        getHighEntropyValues: async (hints) => {
          const out = { brands: [{brand:'Chromium', version:'${chromiumMajor}'},{brand:'Not=A?Brand',version:'99'}], mobile:false, platform:'macOS' };
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
      performance.now = () => Math.round(pnow() * (MAXIMUM ? 1 : 2)) / (MAXIMUM ? 1 : 2);
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

    if (STRICT) {
      try { if (globalThis.speechSynthesis) speechSynthesis.getVoices = () => []; } catch {}

      try {
        const nativeGet = CanvasRenderingContext2D.prototype.getImageData;
        const nativePut = CanvasRenderingContext2D.prototype.putImageData;
        const nativeToDataURL = HTMLCanvasElement.prototype.toDataURL;
        const nativeToBlob = HTMLCanvasElement.prototype.toBlob;
        const perturb = (image) => {
          if (!image || !image.data || image.data.length < 4) return image;
          const step = Math.max(4, Math.floor(image.data.length / 64 / 4) * 4);
          for (let i = 0; i < image.data.length; i += step) image.data[i] ^= (randByte(i) & 1);
          return image;
        };
        CanvasRenderingContext2D.prototype.getImageData = function(...args) { return perturb(nativeGet.apply(this, args)); };
        const noisyClone = (canvas) => {
          const clone = document.createElement('canvas');
          clone.width = canvas.width; clone.height = canvas.height;
          const c = clone.getContext('2d');
          if (!c || !canvas.width || !canvas.height) return clone;
          c.drawImage(canvas, 0, 0);
          try {
            const w = Math.min(canvas.width, 16), hh = Math.min(canvas.height, 16);
            const image = perturb(nativeGet.call(c, 0, 0, w, hh));
            nativePut.call(c, image, 0, 0);
          } catch {}
          return clone;
        };
        HTMLCanvasElement.prototype.toDataURL = function(...args) { return nativeToDataURL.apply(noisyClone(this), args); };
        HTMLCanvasElement.prototype.toBlob = function(...args) { return nativeToBlob.apply(noisyClone(this), args); };
      } catch {}

      try {
        const patchGL = (proto) => {
          if (!proto) return;
          const gp = proto.getParameter;
          const ge = proto.getExtension;
          proto.getParameter = function(p) {
            if (p === 37445) return 'Apple Inc.';
            if (p === 37446) return 'Apple GPU';
            return gp.call(this, p);
          };
          proto.getExtension = function(name) {
            if (String(name).toLowerCase() === 'webgl_debug_renderer_info') return null;
            return ge.call(this, name);
          };
        };
        patchGL(globalThis.WebGLRenderingContext && WebGLRenderingContext.prototype);
        patchGL(globalThis.WebGL2RenderingContext && WebGL2RenderingContext.prototype);
      } catch {}

      try {
        const enumDevices = MediaDevices.prototype.enumerateDevices;
        MediaDevices.prototype.enumerateDevices = async function() {
          const devices = await enumDevices.call(this);
          return devices.map((d, i) => ({ deviceId: d.kind + '-' + i, kind: d.kind, label: '', groupId: '', toJSON(){ return this; } }));
        };
      } catch {}
    }

    if (MAXIMUM) {
      try { Object.defineProperty(window, 'queryLocalFonts', { configurable: true, value: undefined }); } catch {}
      try { Object.defineProperty(Navigator.prototype, 'bluetooth', { configurable: true, get: () => undefined }); } catch {}
      try { Object.defineProperty(Navigator.prototype, 'usb', { configurable: true, get: () => undefined }); } catch {}
      try { Object.defineProperty(Navigator.prototype, 'serial', { configurable: true, get: () => undefined }); } catch {}
      try { Object.defineProperty(Navigator.prototype, 'hid', { configurable: true, get: () => undefined }); } catch {}
      try { Object.defineProperty(window, 'SharedWorker', { configurable: true, value: undefined }); } catch {}
      try { Object.defineProperty(window, 'BroadcastChannel', { configurable: true, value: undefined }); } catch {}
      try {
        const nativeMeasureText = CanvasRenderingContext2D.prototype.measureText;
        CanvasRenderingContext2D.prototype.measureText = function(text) {
          const metrics = nativeMeasureText.call(this, text);
          try { Object.defineProperty(metrics, 'width', { configurable: true, value: Math.round(metrics.width * 2) / 2 }); } catch {}
          return metrics;
        };
      } catch {}
      try {
        const patchReadPixels = (proto) => {
          if (!proto || !proto.readPixels) return;
          const nativeReadPixels = proto.readPixels;
          proto.readPixels = function(...args) {
            const result = nativeReadPixels.apply(this, args);
            const pixels = args[6];
            if (pixels && pixels.length) {
              const limit = Math.min(pixels.length, 512);
              for (let i = 0; i < limit; i += 16) pixels[i] = (pixels[i] & 0xfe) | (randByte(i) & 1);
            }
            return result;
          };
        };
        patchReadPixels(globalThis.WebGLRenderingContext && WebGLRenderingContext.prototype);
        patchReadPixels(globalThis.WebGL2RenderingContext && WebGL2RenderingContext.prototype);
      } catch {}
      try {
        const nativeChannel = AudioBuffer.prototype.getChannelData;
        AudioBuffer.prototype.getChannelData = function(channel) {
          const original = nativeChannel.call(this, channel);
          const copy = new Float32Array(original);
          for (let i = 0; i < copy.length; i += 256) copy[i] += ((randByte(i + channel) & 1) ? 1 : -1) * 1e-8;
          return copy;
        };
      } catch {}
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
