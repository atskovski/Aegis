'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { isPublicIp, makeCheck, summarizeChecks } = require('../src/core/security-suite');

const root = path.resolve(__dirname, '..');
const main = fs.readFileSync(path.join(root, 'src/main.js'), 'utf8');
const html = fs.readFileSync(path.join(root, 'src/ui/index.html'), 'utf8');
const js = fs.readFileSync(path.join(root, 'src/ui/app.js'), 'utf8');
const preload = fs.readFileSync(path.join(root, 'src/preload.js'), 'utf8');

test('public IP parser accepts IPv4 and IPv6 and rejects malformed values', () => {
  assert.equal(isPublicIp('203.0.113.5'), true);
  assert.equal(isPublicIp('2001:db8::1'), true);
  assert.equal(isPublicIp('999.10.2.3'), false);
  assert.equal(isPublicIp('example.com'), false);
});

test('security suite summaries preserve pass fail and not-tested states', () => {
  const checks = [
    makeCheck('a','A','pass','ok'),
    makeCheck('b','B','fail','bad'),
    makeCheck('c','C','not-tested','n/a')
  ];
  assert.deepEqual(summarizeChecks(checks), { pass: 1, warning: 0, info: 0, fail: 1, 'not-tested': 1, total: 3 });
});

test('full verification is wired through narrow IPC and visible UI', () => {
  assert.match(main, /ipcMain\.handle\('security-suite:run'/);
  assert.match(preload, /'security-suite:run'/);
  for (const id of ['runSecuritySuite','securitySuiteResults','publicIpValue','suiteSummary','suiteTestedAt']) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  assert.match(js, /function renderSecuritySuite/);
  assert.match(js, /function runSecuritySuite/);
});

test('native context menu exposes security and privacy actions', () => {
  assert.match(main, /on\('context-menu'/);
  assert.match(main, /Site Privacy Inspector/);
  assert.match(main, /Harden This Site/);
  assert.match(main, /Security Suite & Verification/);
  assert.match(main, /Open Link in New Isolated Tab/);
});

test('permission UX includes risk explanations and tab-scoped memory-only 10 minute grants', () => {
  assert.match(html, /id="permissionRiskList"/);
  assert.match(html, /id="permissionAllow10m"/);
  assert.match(js, /PERMISSION_RISKS/);
  assert.match(main, /function temporaryPermissionKey\(tabId, origin, key\)/);
  assert.match(main, /isTemporarilyAllowed: \(origin, key\) => isTemporarilyAllowed\(tab\.id, origin, key\)/);
  assert.match(main, /grantTemporaryPermission\(pending\.tabId, pending\.origin, key\)/);
  assert.match(main, /allow-10m/);
});
