'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../src/core/extensions.js'),'utf8');
test('tab mutation APIs require declared tab capability',()=>{
  assert.match(source,/const requireTabs=/);
  assert.match(source,/if\(m==='tabs\.create'\)\{requireTabs\(\)/);
  assert.match(source,/if\(m==='tabs\.update'\)\{\s*requireTabs\(\)/);
  assert.match(source,/if\(m==='tabs\.remove'\)\{\s*requireTabs\(\)/);
  assert.match(source,/if\(m==='tabs\.sendMessage'\)\{requireTabs\(\)/);
});
test('tab metadata is gated by tabs or host permission',()=>{
  assert.match(source,/networkAllowedByManifest\(e\.manifest,t\.url\|\|''\)/);
  assert.match(source,/url:mayRead\(t\)/);
});
