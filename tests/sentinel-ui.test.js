'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'src/ui/index.html'), 'utf8');
const js = fs.readFileSync(path.join(root, 'src/ui/app.js'), 'utf8');
const css = fs.readFileSync(path.join(root, 'src/ui/styles.css'), 'utf8');
const main = fs.readFileSync(path.join(root, 'src/main.js'), 'utf8');

test('toolbar has a live Sentinel beacon beside Settings', () => {
  const beacon = html.indexOf('id="privacyBeacon"');
  const settings = html.indexOf('id="settingsBtn"');
  assert.ok(beacon > 0 && settings > beacon);
  for (const id of ['beaconScore','beaconCount','securityScore','privacyPosture','protectionCount','dataAccessList','protectionLayers']) assert.match(html, new RegExp(`id="${id}"`));
  assert.match(css, /\.privacy-beacon/);
  assert.match(js, /combinedPosture\(tab\)/);
});

test('site inspector renders locally observed page-seeking signals', () => {
  assert.match(js, /function renderSiteIntelligence/);
  assert.match(js, /signalStatus/);
  assert.match(main, /Runtime\.addBinding/);
  assert.match(main, /Runtime\.bindingCalled/);
  assert.match(main, /buildSiteAuditScript/);
});

test('settings expose an explicit local-only Site Privacy Intelligence control', () => {
  assert.match(html, /id="siteIntelligence"/);
  assert.match(html, /No telemetry is uploaded/);
  assert.match(js, /draftSettings\.siteIntelligence/);
});

test('one-click Harden this site restores shields and blocks sensitive site permissions', () => {
  assert.match(html, /id="hardenSite"/);
  assert.match(js, /window\.aegis\.send\('site:harden'\)/);
  assert.match(main, /ipcMain\.on\('site:harden'/);
  assert.match(main, /hardenTabState\(tab\)/);
  assert.match(main, /SENSITIVE_PERMISSION_KEYS/);
  assert.match(main, /browserRuntime\.clearData\(tab\.privateSession, \{ dataTypes:/);
  assert.match(main, /replaceTabView\(tab, true\)/);
});


test('Sentinel includes network, identity exposure, and local activity views', () => {
  for (const id of ['thirdPartyUnique','thirdPartyBlockedUnique','thirdPartyAllowedUnique','thirdPartyList','identitySurfaceList','exposureScore','privacyTimeline','timelineCount']) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  for (const fn of ['renderNetworkIntelligence','renderIdentitySurfaces','renderPrivacyTimeline','exposureScore']) assert.match(js, new RegExp(`function ${fn}`));
  assert.match(css, /\.third-party-list/);
  assert.match(css, /\.identity-surface-list/);
  assert.match(css, /\.privacy-timeline/);
});

test('network privacy ledger is fed by the request interception engine', () => {
  assert.match(main, /recordNetworkEvent/);
  assert.match(main, /onNetworkAccess/);
});
