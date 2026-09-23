'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const { privateIpv4, privateIpv6, isPrivateHost, isPrivateNetworkUrl, effectiveSettings, hardenTabState, anonymousTabState }=require('../src/core/compartment');

test('private-network detector covers localhost, RFC1918, CGNAT and link-local',()=>{
  for(const ip of ['10.1.2.3','127.0.0.1','169.254.9.2','172.16.0.1','172.31.255.254','192.168.1.5','100.64.0.1']) assert.equal(privateIpv4(ip),true,ip);
  assert.equal(privateIpv4('8.8.8.8'),false);
  assert.equal(privateIpv6('::1'),true);
  assert.equal(privateIpv6('fe80::1'),true);
  assert.equal(privateIpv6('fc00::1234'),true);
  assert.equal(isPrivateHost('printer.local'),true);
  assert.equal(isPrivateNetworkUrl('https://192.168.1.1/admin'),true);
  assert.equal(isPrivateNetworkUrl('https://example.com/'),false);
});

test('hardened compartment forces maximum browser privacy controls',()=>{
  const global={privacyLevel:'standard',blockTrackers:false,blockAds:false,disableServiceWorkers:false,permissionDefaults:{camera:'ask'},proxy:{mode:'system'},sponsorBlock:{enabled:true}};
  const tab={securityDomain:'hardened'};
  const s=effectiveSettings(global,tab);
  assert.equal(s.privacyLevel,'maximum');
  assert.equal(s.blockTrackers,true);
  assert.equal(s.blockAds,true);
  assert.equal(s.blockThirdPartyRequests,true);
  assert.equal(s.disableServiceWorkers,true);
  assert.equal(s.permissionDefaults.camera,'block');
  assert.equal(s.sponsorBlock.enabled,false);
});

test('anonymous compartment is fail-closed and amnesic-oriented',()=>{
  const global={permissionDefaults:{camera:'ask'},anonymity:{torProxy:'127.0.0.1:9150',blockPrivateNetwork:true,disableDownloads:true,disableExtensions:true},proxy:{mode:'system'},sponsorBlock:{enabled:true}};
  const tab={securityDomain:'anonymous',torProxy:'127.0.0.1:9150'};
  const s=effectiveSettings(global,tab);
  assert.equal(s.proxy.mode,'socks5');
  assert.equal(s.proxy.server,'127.0.0.1:9150');
  assert.equal(s.proxy.failClosedFixedProxy,true);
  assert.equal(s.blockPrivateNetwork,true);
  assert.equal(s.blockAllDownloads,true);
  assert.equal(s.disableExtensions,true);
  assert.equal(s.disableWebRtc,true);
  assert.equal(s.sitePermissions && Object.keys(s.sitePermissions).length,0);
});

test('tab state transitions are explicit and disable compatibility/HTTP/extensions',()=>{
  const a={};
  hardenTabState(a);
  assert.equal(a.securityDomain,'hardened');
  assert.equal(a.shieldsEnabled,true);
  assert.equal(a.allowHttp,false);
  assert.equal(a.compatibilityMode,false);
  assert.equal(a.disableExtensions,true);
  const b={};
  anonymousTabState(b,'127.0.0.1:9050');
  assert.equal(b.securityDomain,'anonymous');
  assert.equal(b.torProxy,'127.0.0.1:9050');
  assert.equal(b.disableExtensions,true);
});
