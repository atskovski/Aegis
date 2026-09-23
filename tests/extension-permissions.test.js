'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../src/core/extensions.js'),'utf8');
test('tab mutation APIs require declared tab capability and protected compartments stay excluded',()=>{
  assert.match(source,/requireTabs=\(\)=>\{if\(!hasTabs\)throw new Error/);
  assert.match(source,/if\(m==='tabs\.create'\)\{requireTabs\(\)/);
  assert.match(source,/if\(m==='tabs\.update'\)\{/);
  assert.match(source,/if\(m==='tabs\.remove'\)\{requireTabs\(\)/);
  assert.match(source,/extensionVisibleTab\(target\)/);
});
test('tab metadata and script injection are gated by tabs, host permission, or activeTab grant',()=>{
  assert.match(source,/canAccessTab\(e,tab/);
  assert.match(source,/networkAllowedByManifest\(e\.manifest,tab\.url\|\|''\)/);
  assert.match(source,/this\.activeGrants\.get\(e\.id\)\?\.has\(tab\.id\)/);
  assert.match(source,/if\(!this\.canAccessTab\(e,tab,\{inject:true\}\)\)throw new Error/);
});


test('unsafe browser takeover APIs stay outside the extension compatibility boundary',()=>{
  assert.match(source,/proxy:'Extensions cannot replace Aegis network routing/);
  assert.match(source,/nativeMessaging:'Native messaging is disabled/);
  assert.match(source,/debugger:'The Chrome debugger API is not exposed/);
});
