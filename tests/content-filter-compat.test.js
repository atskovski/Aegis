'use strict';
const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const path=require('node:path');
test('Maximum filtering does not monkey-patch JavaScript eval',()=>{
 const s=fs.readFileSync(path.join(__dirname,'../src/core/content-filter.js'),'utf8');
 assert.doesNotMatch(s,/globalThis\.eval\s*=/);
 assert.doesNotMatch(s,/Dynamic eval blocked by Aegis/);
});
