'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');
test('portable core has no Electron dependency',()=>{const dir=path.join(__dirname,'..','src','core');const offenders=[];for(const name of fs.readdirSync(dir).filter(x=>x.endsWith('.js'))){const src=fs.readFileSync(path.join(dir,name),'utf8');if(/require\(['"]electron['"]\)|from\s+['"]electron['"]/.test(src))offenders.push(name);}assert.deepEqual(offenders,[],'Electron imports found in portable core: '+offenders.join(', '));});
