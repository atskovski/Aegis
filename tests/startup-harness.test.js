'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
const { EventEmitter } = require('node:events');
const Module = require('node:module');

function makeProtocol() {
  const handlers = new Map();
  return {
    handlers,
    isProtocolHandled(scheme) { return handlers.has(scheme); },
    handle(scheme, handler) { handlers.set(scheme, handler); },
    unhandle(scheme) { handlers.delete(scheme); }
  };
}

function makeSession() {
  const ses = new EventEmitter();
  ses.protocol = makeProtocol();
  ses.webRequest = {
    onBeforeRequest() {},
    onBeforeSendHeaders() {},
    onHeadersReceived() {}
  };
  ses.setUserAgent = () => {};
  ses.setSSLConfig = () => {};
  ses.setPermissionRequestHandler = () => {};
  ses.setPermissionCheckHandler = () => {};
  ses.setDevicePermissionHandler = () => {};
  ses.setProxy = async () => {};
  ses.closeAllConnections = async () => {};
  ses.clearData = async () => {};
  ses.clearCache = async () => {};
  ses.spellCheckerEnabled = false;
  return ses;
}

test('main-process startup shows chrome and initializes an aegis:// page inside a private session', async () => {
  const events = [];
  const defaultProtocol = makeProtocol();
  const sessions = [];
  const windows = [];
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-startup-harness-'));

  class FakeWebContents extends EventEmitter {
    constructor(session, label) {
      super();
      this.session = session;
      this.label = label;
      this.destroyed = false;
      this.currentUrl = '';
      this.navigationHistory = {
        canGoBack: () => false,
        canGoForward: () => false,
        goBack() {},
        goForward() {}
      };
      this.debugger = {
        attached: false,
        isAttached: () => this.debugger.attached,
        attach: () => { this.debugger.attached = true; },
        sendCommand: async () => ({})
      };
    }
    setWindowOpenHandler() {}
    setZoomMode(mode) { this.zoomMode = mode; }
    async loadURL(url) {
      this.currentUrl = url;
      events.push(`${this.label}:load:${url}`);
      if (url.startsWith('aegis://')) {
        const handler = this.session.protocol.handlers.get('aegis');
        if (!handler) throw new Error(`No aegis:// handler in ${this.label}`);
        const response = await handler({ url });
        if (!response || response.status >= 400) throw new Error(`Internal protocol returned ${response?.status}`);
      }
      this.emit('did-start-loading');
      this.emit('did-navigate', {}, url);
      this.emit('did-stop-loading');
      return undefined;
    }
    getURL() { return this.currentUrl; }
    focus() { events.push(`${this.label}:focus`); }
    send() {}
    stop() {}
    reload() {}
    isDestroyed() { return this.destroyed; }
    close() { this.destroyed = true; }
  }

  class FakeWebContentsView {
    constructor(options = {}) {
      this.webContents = new FakeWebContents(options.webPreferences?.session || makeSession(), `tab${sessions.length}`);
      this.visible = true;
      this.bounds = { x: 0, y: 0, width: 0, height: 0 };
    }
    setVisible(v) { this.visible = Boolean(v); events.push(`tab:visible:${this.visible}`); }
    setBounds(b) { this.bounds = b; }
    getBounds() { return this.bounds; }
  }

  class FakeBrowserWindow extends EventEmitter {
    static getAllWindows() { return windows.filter((w) => !w.destroyed); }
    constructor() {
      super();
      this.destroyed = false;
      this.visible = false;
      this.minimized = false;
      this.children = [];
      const defaultSession = makeSession();
      defaultSession.protocol = defaultProtocol;
      this.webContents = new FakeWebContents(defaultSession, 'chrome');
      this.contentView = {
        addChildView: (v) => this.children.push(v),
        removeChildView: (v) => { this.children = this.children.filter((x) => x !== v); }
      };
      windows.push(this);
    }
    setMenuBarVisibility() {}
    getContentBounds() { return { width: 1500, height: 940 }; }
    isDestroyed() { return this.destroyed; }
    isMinimized() { return this.minimized; }
    restore() { this.minimized = false; }
    async loadURL(url) { return this.webContents.loadURL(url); }
    show() { this.visible = true; events.push('window:show'); }
    focus() { events.push('window:focus'); }
  }

  const app = new EventEmitter();
  app.setName = () => {};
  app.requestSingleInstanceLock = () => true;
  app.quit = () => {};
  app.exit = (code) => { throw new Error(`app.exit(${code})`); };
  app.enableSandbox = () => {};
  app.commandLine = { appendSwitch() {} };
  app.whenReady = () => Promise.resolve();
  app.getPath = (name) => name === 'userData' ? tmp : tmp;
  app.getVersion = () => '0.8.0';
  app.show = () => {};
  app.focus = () => {};

  const ipcMain = { handle() {}, on() {} };
  const electronSession = {
    fromPartition(partition, options) {
      const ses = makeSession();
      ses.partition = partition;
      ses.options = options;
      sessions.push(ses);
      return ses;
    }
  };

  const fakeElectron = {
    app,
    BrowserWindow: FakeBrowserWindow,
    WebContentsView: FakeWebContentsView,
    ipcMain,
    protocol: {
      ...defaultProtocol,
      registerSchemesAsPrivileged() {}
    },
    clipboard: { clear() {} },
    dialog: { showErrorBox(_title, message) { throw new Error(message); } },
    session: electronSession
  };
  // Preserve method receiver state after object spread above.
  fakeElectron.protocol.handlers = defaultProtocol.handlers;
  fakeElectron.protocol.isProtocolHandled = defaultProtocol.isProtocolHandled.bind(defaultProtocol);
  fakeElectron.protocol.handle = defaultProtocol.handle.bind(defaultProtocol);

  const originalLoad = Module._load;
  Module._load = function patchedLoad(request, parent, isMain) {
    if (request === 'electron') return fakeElectron;
    return originalLoad.call(this, request, parent, isMain);
  };

  const mainPath = path.join(__dirname, '..', 'src', 'main.js');
  delete require.cache[require.resolve(mainPath)];
  try {
    require(mainPath);
    await new Promise((resolve) => setTimeout(resolve, 80));
  } finally {
    Module._load = originalLoad;
  }

  assert.equal(windows.length, 1, 'one browser window should be created');
  assert.equal(windows[0].visible, true, 'browser window should be visible');
  assert.equal(defaultProtocol.isProtocolHandled('aegis'), true, 'default UI session must handle aegis://');
  assert.equal(sessions.length, 1, 'one private tab session should be created');
  assert.equal(sessions[0].protocol.isProtocolHandled('aegis'), true, 'private tab session must handle aegis://');
  assert.equal(windows[0].children.length, 1, 'first WebContentsView should be attached');
  assert.equal(windows[0].children[0].visible, true, 'first private tab view should be visible');
  assert.equal(windows[0].children[0].webContents.zoomMode, 'isolated');

  const showIndex = events.indexOf('window:show');
  const tabLoadIndex = events.findIndex((e) => e.includes(':load:https://duckduckgo.com/'));
  assert.ok(showIndex >= 0, 'window show event should occur');
  assert.ok(tabLoadIndex > showIndex, 'browser chrome must be shown before initial private-tab navigation');
});
