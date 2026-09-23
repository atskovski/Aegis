'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root=path.join(__dirname,'..');
const html=fs.readFileSync(path.join(root,'src/ui/index.html'),'utf8');
const js=fs.readFileSync(path.join(root,'src/ui/app.js'),'utf8');
const main=fs.readFileSync(path.join(root,'src/main.js'),'utf8');

test('Sentinel exposes simple and advanced modes with routed IP evidence',()=>{
  for(const id of ['sentinelSimple','sentinelAdvanced','sentinelIp','sentinelRoute','sentinelHeadline']) assert.match(html,new RegExp('id="'+id+'"'));
  assert.match(js,/applySentinelMode/);
  assert.match(js,/renderSentinelSummary/);
});

test('Aegis has an XPI add-on manager backed by main-process IPC',()=>{
  assert.match(html,/data-settings-page="addons"/);
  assert.match(html,/id="installXpi"/);
  assert.match(js,/extensions:install/);
  assert.match(main,/extensions:install/);
  assert.match(main,/extension-bridge-preload\.js/);
});

test('Diagnostics exposes per-control enforcement evidence',()=>{
  assert.match(html,/id="privacyControlResults"/);
  assert.match(js,/renderControlAssurance/);
  assert.match(main,/controlAssurance/);
});
