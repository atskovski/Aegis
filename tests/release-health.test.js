'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');
const main = read('src/main.js');
const ui = read('src/ui/app.js');
const preload = read('src/preload.js');
const privacy = read('src/core/privacy.js');
const suiteCore = read('src/core/security-suite.js');
const browserRuntime = read('src/core/browser-runtime.js');
const html = read('src/ui/index.html');
const launcher = read('Run-Aegis.command');
const pkg = JSON.parse(read('package.json'));

function unique(values) { return [...new Set(values)].sort(); }
function channels(source, rx) { return unique([...source.matchAll(rx)].map((m) => m[1])); }
function setValues(source, name) {
  const match = source.match(new RegExp(name + ' = new Set\\(\\[([\\s\\S]*?)\\]\\)'));
  return match ? unique([...match[1].matchAll(/'([^']+)'/g)].map((m) => m[1])) : [];
}

test('UI IPC commands are permitted by preload and implemented by main', () => {
  const sends = channels(ui, /window\.aegis\.send\('([^']+)'/g);
  const invokes = channels(ui, /window\.aegis\.invoke\('([^']+)'/g);
  const allowedSend = setValues(preload, 'allowedSend');
  const allowedInvoke = setValues(preload, 'allowedInvoke');
  const mainOn = channels(main, /ipcMain\.on\('([^']+)'/g);
  const mainHandle = channels(main, /ipcMain\.handle\('([^']+)'/g);

  assert.deepEqual(sends.filter((x) => !allowedSend.includes(x)), [], 'UI send channel missing from preload allowlist');
  assert.deepEqual(invokes.filter((x) => !allowedInvoke.includes(x)), [], 'UI invoke channel missing from preload allowlist');
  assert.deepEqual(sends.filter((x) => !mainOn.includes(x)), [], 'UI send channel missing main handler');
  assert.deepEqual(invokes.filter((x) => !mainHandle.includes(x)), [], 'UI invoke channel missing main handler');
});

test('Settings dynamic controls all exist in the settings document', () => {
  const block = ui.match(/const draftControlIds = \[([\s\S]*?)\];/);
  assert.ok(block, 'draftControlIds declaration missing');
  const ids = [...block[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
  const missing = ids.filter((id) => !new RegExp('id=["\\\']' + id + '["\\\']').test(html));
  assert.deepEqual(missing, []);
});

test('Settings render and collect paths cover every dynamic control', () => {
  const block = ui.match(/const draftControlIds = \[([\s\S]*?)\];/);
  assert.ok(block, 'draftControlIds declaration missing');
  const ids = [...block[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
  const renderStart = ui.indexOf('function renderSettingsDraft()');
  const renderEnd = ui.indexOf('function collectDraftFromControls()', renderStart);
  const collectEnd = ui.indexOf('function switchSettingsPage(', renderEnd);
  const renderSource = ui.slice(renderStart, renderEnd);
  const collectSource = ui.slice(renderEnd, collectEnd);
  const rendered = new Set([...renderSource.matchAll(/\$\('#([^']+)'\)/g)].map((m) => m[1]));
  const collected = new Set([...collectSource.matchAll(/\$\('#([^']+)'\)/g)].map((m) => m[1]));
  assert.deepEqual(ids.filter((id) => !rendered.has(id)), [], 'dynamic setting missing from render path');
  assert.deepEqual(ids.filter((id) => !collected.has(id)), [], 'dynamic setting missing from collect path');
});

test('Map-backed runtime collections are not used with Array-only methods', () => {
  const mapNames = [...main.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*new Map\s*\(/g)].map((m) => m[1]);
  const arrayOnly = ['filter','map','some','find','slice','reduce','includes','at','flatMap','sort'];
  const violations = [];
  for (const name of mapNames) {
    for (const method of arrayOnly) {
      if (new RegExp('\\b' + name + '\\.' + method + '\\s*\\(').test(main)) violations.push(name + '.' + method);
    }
  }
  assert.deepEqual(violations, []);
});

test('Security Suite uses current runtime factories and engine-neutral view checks', () => {
  assert.doesNotMatch(main, /\btabs\.filter\s*\(/);
  assert.doesNotMatch(main, /\bcreateStats\s*\(/);
  assert.match(main, /\[\.\.\.tabs\.values\(\)\]\.filter/);
  assert.match(main, /stats:makeTabStats\(\)/);
  assert.doesNotMatch(main, /candidate\?\.view\?\.webContents/);
  assert.match(main, /suite-runtime-integrity/);
});

test('every BrowserRuntime operation used by main is exposed by the runtime contract', () => {
  const used = unique([...main.matchAll(/\bbrowserRuntime\.([A-Za-z0-9_]+)\b/g)].map((m) => m[1]));
  const exposed = unique([...browserRuntime.matchAll(/\b([A-Za-z0-9_]+)\s*:\s*\(/g)].map((m) => m[1]));
  assert.deepEqual(used.filter((name) => !exposed.includes(name)), []);
});

test('profile and reset actions preserve managed locks and rebuild runtime state', () => {
  const profileAt = main.indexOf("ipcMain.on('settings:profile'");
  const resetAt = main.indexOf("ipcMain.on('settings:reset'");
  const updateAt = main.indexOf("ipcMain.on('settings:update'");
  assert.ok(profileAt >= 0 && resetAt > profileAt && updateAt > resetAt);
  const profileSource = main.slice(profileAt, resetAt);
  const resetSource = main.slice(resetAt, updateAt);
  assert.match(profileSource, /preserveLockedSettings\(settings, profileDefaults\(level\)\)/);
  assert.match(profileSource, /managedPolicy: settings\.managedPolicy/);
  assert.match(resetSource, /preserveLockedSettings\(settings, cloneDefaults\(\)\)/);
  assert.match(resetSource, /managedPolicy: settings\.managedPolicy/);
  assert.match(resetSource, /replaceTabView\(tab, tab\.javascriptEnabled\)/);
});

test('privacy session uses one deterministic request-header pipeline', () => {
  const registrations = [...privacy.matchAll(/ses\.webRequest\.onBeforeSendHeaders\(/g)];
  assert.equal(registrations.length, 1, 'privacy session must install exactly one onBeforeSendHeaders handler');
  assert.match(privacy, /h\['User-Agent'\] = genericUA/);
  assert.match(privacy, /onRequestHeaders/);
  assert.match(suiteCore, /installObserver/);
  assert.match(main, /onRequestHeaders:observeHeaders/);
});

test('UI receive channels are permitted and emitted by main', () => {
  const receives = channels(ui, /window\.aegis\.on\('([^']+)'/g);
  const allowedReceive = setValues(preload, 'allowedReceive');
  const mainSends = channels(main, /webContents\.send\('([^']+)'/g);
  assert.deepEqual(receives.filter((x) => !allowedReceive.includes(x)), []);
  assert.deepEqual(receives.filter((x) => !mainSends.includes(x)), []);
});

test('launcher and package release versions stay synchronized', () => {
  const match = launcher.match(/VERSION="([^"]+)"/);
  assert.ok(match, 'launcher VERSION missing');
  assert.equal(match[1], pkg.version);
});

test('single-node DOM selectors are never iterated as collections', () => {
  const invalid = ui.split('\n').filter((line) => /(^|[^$])\$\((['"])[^)\n]+\2\)\.forEach\(/.test(line));
  assert.deepEqual(invalid, []);
});
