'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildGenericUA, isRiskyDownload, makeTabStats, permissionKeys, permissionAllowed, permissionDecision, categoryEnabled, applyExtensionHeaderRemovals, configurePrivacySession } = require('../src/core/privacy');

test('generic UA hides Electron token and uses reduced Chromium version', () => {
  const ua = buildGenericUA('152.0.7977.130');
  assert.match(ua, /Chrome\/152\.0\.0\.0/);
  assert.match(ua, /Macintosh/);
  assert.doesNotMatch(ua, /Electron/);
});

test('flags executable downloads', () => {
  assert.equal(isRiskyDownload('installer.dmg'), true);
  assert.equal(isRiskyDownload('payload.command'), true);
  assert.equal(isRiskyDownload('report.pdf'), false);
});

test('stats start at zero', () => {
  const stats = makeTabStats();
  assert.equal(stats.blockedTrackers, 0);
  assert.equal(stats.thirdPartyCookiesBlocked, 0);
});

test('maps media permissions to camera and microphone', () => {
  assert.deepEqual(permissionKeys('media', { mediaTypes: ['video', 'audio'] }), ['camera', 'microphone']);
  assert.deepEqual(permissionKeys('geolocation'), ['geolocation']);
  assert.deepEqual(permissionKeys('media', { mediaType: 'audio' }), ['microphone']);
});

test('site permission overrides global permission default', () => {
  const settings = {
    permissionDefaults: { camera: 'block' },
    sitePermissions: { 'https://example.com': { camera: 'allow' } }
  };
  assert.equal(permissionAllowed(settings, 'https://example.com', 'camera'), true);
  assert.equal(permissionAllowed(settings, 'https://other.example', 'camera'), false);
});


test('permission decision asks globally and explicit site rules win', () => {
  const settings = {
    permissionDefaults: { camera: 'ask' },
    sitePermissions: { 'https://example.com': { camera: 'allow' } }
  };
  assert.equal(permissionDecision(settings, 'https://elsewhere.test', 'camera'), 'ask');
  assert.equal(permissionDecision(settings, 'https://example.com', 'camera'), 'allow');
});

test('maps high-entropy permissions to explicit guarded categories', () => {
  assert.deepEqual(permissionKeys('local-fonts'), ['localFonts']);
  assert.deepEqual(permissionKeys('window-management'), ['windowManagement']);
  assert.deepEqual(permissionKeys('idle-detection'), ['idleDetection']);
});


test('tracker categories obey their own settings independently', () => {
  const s={blockTrackers:false,blockAds:true,blockSocialTrackers:false,blockCryptominers:true};
  assert.equal(categoryEnabled(s,'ads'),true);
  assert.equal(categoryEnabled(s,'social'),false);
  assert.equal(categoryEnabled(s,'cryptomining'),true);
  assert.equal(categoryEnabled(s,'analytics'),false);
});


test('extension header removals are case-insensitive and removal-only', () => {
  const headers={Cookie:'a=1',Referer:'https://example.com/',ETag:'abc','User-Agent':'Aegis'};
  const out=applyExtensionHeaderRemovals(headers,[
    {header:'cookie',operation:'remove'},
    {header:'REFERER',operation:'remove'},
    {header:'user-agent',operation:'set'}
  ]);
  assert.equal(out.Cookie,undefined);
  assert.equal(out.Referer,undefined);
  assert.equal(out.ETag,'abc');
  assert.equal(out['User-Agent'],'Aegis');
});


test('privacy session forwards onResponseStarted into the extension event pipeline', () => {
  const handlers={};
  const filters={};
  const webRequest={
    onBeforeRequest:(filter,fn)=>{filters.beforeRequest=filter;handlers.beforeRequest=fn;},
    onBeforeSendHeaders:(filter,fn)=>{filters.beforeSendHeaders=filter;handlers.beforeSendHeaders=fn;},
    onHeadersReceived:(filter,fn)=>{filters.headersReceived=filter;handlers.headersReceived=fn;},
    onResponseStarted:(filter,fn)=>{filters.responseStarted=filter;handlers.responseStarted=fn;},
    onCompleted:(filter,fn)=>{filters.completed=filter;handlers.completed=fn;},
    onErrorOccurred:(filter,fn)=>{filters.errorOccurred=filter;handlers.errorOccurred=fn;}
  };
  const ses={
    webRequest,
    setUserAgent(){},
    setSSLConfig(){},
    setPermissionRequestHandler(){},
    setPermissionCheckHandler(){},
    spellCheckerEnabled:true
  };
  const events=[];
  const tab={id:1,url:'https://example.test/',topUrl:'https://example.test/',stats:makeTabStats(),shieldsEnabled:true,compatibilityMode:false};
  configurePrivacySession({
    ses,tab,chromiumVersion:'152.0.0.0',
    getSettings:()=>({blockTrackers:false,blockAds:false,blockSocialTrackers:false,blockCryptominers:false,blockThirdPartyCookies:false,stripTrackingParams:false,globalPrivacyControl:true,doNotTrack:true}),
    onStats(){},
    onExtensionRequest:(type,details)=>events.push({type,details}),
    trackerLearner:null,
    getFilterRules:()=>[],
    isTemporarilyAllowed:()=>false
  });
  assert.equal(typeof handlers.responseStarted,'function');
  assert.ok(filters.beforeRequest.urls.includes('ws://*/*'));
  assert.ok(filters.beforeRequest.urls.includes('wss://*/*'));
  assert.ok(filters.completed.urls.includes('wss://*/*'));
  assert.deepEqual(filters.responseStarted.urls,['http://*/*','https://*/*']);
  const details={url:'https://cdn.example.test/pixel.gif',resourceType:'image',responseHeaders:{'set-cookie':['x=1']}};
  handlers.responseStarted(details);
  assert.equal(events.at(-1).type,'webRequest.onResponseStarted');
  assert.equal(events.at(-1).details,details);
});
