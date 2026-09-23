'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.join(__dirname,'..');
const html=fs.readFileSync(path.join(root,'src/ui/index.html'),'utf8');
const app=fs.readFileSync(path.join(root,'src/ui/app.js'),'utf8');
const main=fs.readFileSync(path.join(root,'src/main.js'),'utf8');
const ext=fs.readFileSync(path.join(root,'src/core/extensions.js'),'utf8');
const fp=fs.readFileSync(path.join(root,'src/core/fingerprint.js'),'utf8');

test('anonymous compartment controls are present and wired',()=>{
  for(const id of ['anonymousTab','anonymousTorProxy','anonymousRequireTor','anonymousBlockLan','anonymousDisableDownloads','anonymousDisableExtensions','anonymousDisableJavaScript','testTorRoute','newAnonymousTabFromNetwork']) assert.match(html,new RegExp('id="'+id+'"'));
  assert.match(app,/tab:new-anonymous/);
  assert.match(app,/network:test-tor/);
  assert.match(main,/createAnonymousTab/);
  assert.match(main,/verifyTorRoute/);
});

test('Harden This Site is backed by destructive compartment enforcement',()=>{
  assert.match(main,/hardenTabState\(tab\)/);
  assert.match(main,/clearData\(\{ dataTypes:\['cookies','localStorage','indexedDB','serviceWorkers','cache','cacheStorage'\]/);
  assert.match(main,/replaceTabView\(tab, true\)/);
  assert.match(main,/SENSITIVE_PERMISSION_KEYS/);
});

test('hardened and anonymous tabs exclude extension content scripts',()=>{
  assert.match(ext,/tab\?\.disableExtensions/);
  assert.match(ext,/securityDomain === 'anonymous'/);
  assert.match(ext,/securityDomain === 'hardened'/);
});

test('maximum fingerprinting uses a cohort rather than a per-user perturbation seed',()=>{
  assert.match(fp,/const COHORT = 'aegis-cohort-v1'/);
  assert.match(fp,/STRICT \|\| ANONYMOUS \? COHORT : BASE/);
  assert.match(fp,/undef\(globalThis, 'RTCPeerConnection'\)/);
});


test('network hardening disables QUIC to avoid UDP route bypass',()=>{
  assert.match(main,/appendSwitch\('disable-quic'\)/);
});

test('anonymous tabs default to JavaScript disabled',()=>{
  assert.match(main,/securityDomain === 'anonymous'.*disableJavaScript/s);
});


test('protected compartments cannot be weakened by per-tab UI controls',()=>{
  assert.match(main,/Privacy shields are locked on in this security compartment/);
  assert.match(main,/HTTP downgrade is locked off in this security compartment/);
  assert.match(main,/Compatibility mode cannot weaken a hardened or anonymous compartment/);
  assert.match(main,/JavaScript is locked off by the anonymous compartment policy/);
  assert.match(app,/protectedCompartment/);
  assert.match(app,/compartmentLocked/);
});


test('independent security test lab is allowlisted and opens hardened tabs',()=>{
  for(const key of ['eff','ip','webrtc','canvas','webgl','tls','javascript']) assert.match(main,new RegExp(key+": 'https://"));
  assert.match(main,/security-test:open/);
  assert.match(main,/securityDomain:'hardened'/);
  assert.match(app,/data-security-test/);
  assert.match(html,/data-security-test="eff"/);
  assert.match(html,/data-security-test="webrtc"/);
});
