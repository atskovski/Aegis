'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { sanitizeSettings, searchTemplateFor, profileDefaults } = require('../src/core/settings');

test('sanitizes unknown privacy profile to strict', () => {
  assert.equal(sanitizeSettings({ privacyLevel: 'mystery' }).privacyLevel, 'strict');
});

test('migrates compatible profile to standard', () => {
  assert.equal(sanitizeSettings({ privacyLevel: 'compatible' }).privacyLevel, 'standard');
});

test('rejects invalid custom search template', () => {
  const s = sanitizeSettings({ searchEngine: 'custom', customSearchTemplate: 'https://example.com/search' });
  assert.equal(s.customSearchTemplate, '');
  assert.equal(searchTemplateFor(s), 'https://duckduckgo.com/?q=%s');
});

test('accepts valid custom search template', () => {
  const s = sanitizeSettings({ searchEngine: 'custom', customSearchTemplate: 'https://example.com/?q=%s' });
  assert.equal(searchTemplateFor(s), 'https://example.com/?q=%s');
});

test('maximum profile enables key hardening defaults', () => {
  const p = profileDefaults('maximum');
  assert.equal(p.letterbox, true);
  assert.equal(p.blockThirdPartyCookies, true);
  assert.equal(p.disableServiceWorkers, true);
});


test('permission sanitizer accepts ask but rejects persistent global allow', () => {
  const s = sanitizeSettings({ permissionDefaults: { camera: 'ask', microphone: 'allow', geolocation: 'ask' } });
  assert.equal(s.permissionDefaults.camera, 'ask');
  assert.equal(s.permissionDefaults.microphone, 'block');
  assert.equal(s.permissionDefaults.geolocation, 'ask');
});


test('new installs use macOS system proxy routing by default', () => {
  assert.equal(sanitizeSettings({}).proxy.mode, 'system');
});

test('migrates untouched v0.3 direct proxy default to system routing', () => {
  assert.equal(sanitizeSettings({ schemaVersion: 2, proxy: { mode: 'direct', server: '', bypassLocal: true } }).proxy.mode, 'system');
});

test('preserves an explicit direct proxy choice in schema v3', () => {
  assert.equal(sanitizeSettings({ schemaVersion: 3, proxy: { mode: 'direct', server: '', bypassLocal: true } }).proxy.mode, 'direct');
});

test('strict profile keeps service workers available for site compatibility', () => {
  assert.equal(profileDefaults('strict').disableServiceWorkers, false);
});


test('anonymous compartment settings are sanitized and default fail-closed', () => {
  const d=sanitizeSettings({});
  assert.equal(d.anonymity.torProxy,'127.0.0.1:9050');
  assert.equal(d.anonymity.requireTorVerification,true);
  assert.equal(d.anonymity.blockPrivateNetwork,true);
  assert.equal(d.anonymity.disableDownloads,true);
  assert.equal(d.anonymity.disableExtensions,true);
  assert.equal(d.anonymity.disableJavaScript,true);
  const s=sanitizeSettings({anonymity:{torProxy:'127.0.0.1:9150',requireTorVerification:false,blockPrivateNetwork:false,disableDownloads:false,disableExtensions:false}});
  assert.equal(s.anonymity.torProxy,'127.0.0.1:9150');
  assert.equal(s.anonymity.requireTorVerification,false);
});


test('migrates legacy internal start page default to DuckDuckGo', () => {
  assert.equal(sanitizeSettings({ homePage: 'aegis://app/start.html' }).homePage, 'https://duckduckgo.com/');
});

test('preserves explicit custom home pages', () => {
  assert.equal(sanitizeSettings({ homePage: 'https://example.com/' }).homePage, 'https://example.com/');
});
