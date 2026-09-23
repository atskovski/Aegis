'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { controlAssurance, CONTROL_DEFINITIONS } = require('../src/core/control-registry');

test('control registry maps every advertised privacy control to an enforcement layer', () => {
  assert.ok(CONTROL_DEFINITIONS.length >= 20);
  for (const row of CONTROL_DEFINITIONS) {
    assert.equal(row.length,3);
    assert.ok(row[0] && row[1] && row[2]);
  }
});

test('document controls report degraded until preload is confirmed', () => {
  const settings={privacyApiGuard:true,globalPrivacyControl:true,cosmeticFiltering:true};
  const tab={fingerprintReady:false,cosmeticFilteringReady:false,permissionFirewallReady:true};
  const rows=controlAssurance(settings,tab);
  assert.equal(rows.find((x)=>x.key==='privacyApiGuard').status,'degraded');
  assert.equal(rows.find((x)=>x.key==='cosmeticFiltering').status,'degraded');
});

test('session firewall controls report enforced when handlers are installed', () => {
  const settings={blockTrackers:true,blockThirdPartyCookies:true};
  const tab={privacySessionReady:true};
  const rows=controlAssurance(settings,tab);
  assert.equal(rows.find((x)=>x.key==='blockTrackers').status,'enforced');
  assert.equal(rows.find((x)=>x.key==='blockThirdPartyCookies').status,'enforced');
});
