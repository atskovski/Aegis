'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const os=require('node:os');
const {execFileSync}=require('node:child_process');
const {AegisExtensionRuntime}=require('../src/core/extensions');

function makeXpi(root,version='1.0.0'){
  const pkg=path.join(root,'pkg-'+version);fs.mkdirSync(pkg,{recursive:true});
  const manifest={
    manifest_version:2,name:'Aegis Test Extension',version,description:'Integration test package',
    browser_specific_settings:{gecko:{id:'aegis-test@example'}},
    permissions:['storage','tabs','https://example.com/*'],
    browser_action:{default_title:'Aegis Test',default_popup:'popup.html',default_icon:{32:'icon.svg'}},
    options_ui:{page:'options.html',open_in_tab:false},
    content_scripts:[{matches:['https://example.com/*'],js:['content.js']}],
    background:{scripts:['background.js']}
  };
  fs.writeFileSync(path.join(pkg,'manifest.json'),JSON.stringify(manifest));
  fs.writeFileSync(path.join(pkg,'content.js'),"browser.storage.local.get('x'); browser.runtime.sendMessage({hello:true});");
  fs.writeFileSync(path.join(pkg,'background.js'),"browser.runtime.onMessage.addListener(()=>({ok:true})); browser.tabs.query({active:true});");
  fs.writeFileSync(path.join(pkg,'popup.html'),'<!doctype html><script src="popup.js"></script>');
  fs.writeFileSync(path.join(pkg,'popup.js'),"browser.runtime.getBrowserInfo();");
  fs.writeFileSync(path.join(pkg,'options.html'),'<!doctype html><script src="options.js"></script>');
  fs.writeFileSync(path.join(pkg,'options.js'),"browser.storage.local.set({configured:true});");
  fs.writeFileSync(path.join(pkg,'icon.svg'),'<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32"><rect width="32" height="32"/></svg>');
  const xpi=path.join(root,'extension-'+version+'.xpi');
  execFileSync('/usr/bin/zip',['-qr',xpi,'.'],{cwd:pkg});
  return xpi;
}

test('real XPI package can be inspected staged installed updated and removed',async()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-xpi-lifecycle-'));
  try{
    const runtime=new AegisExtensionRuntime({rootDir:path.join(root,'runtime'),getTabs:()=>[],getActiveId:()=>null,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{},browserVersion:'test'});
    const first=makeXpi(root,'1.0.0');
    const staged=await runtime.stage(first);
    assert.equal(staged.summary.id,'aegis-test@example');
    assert.equal(staged.summary.manifestVersion,2);
    assert.equal(staged.summary.action.popup,'popup.html');
    assert.equal(staged.summary.optionsPage,'options.html');
    assert.ok(staged.summary.digest.length===64);
    assert.ok(staged.summary.detectedApis.includes('runtime'));
    assert.ok(staged.summary.detectedApis.includes('storage'));
    const installed=await runtime.installStaged(staged.token);
    assert.equal(installed.id,'aegis-test@example');
    assert.equal(installed.version,'1.0.0');
    assert.equal(installed.action.popup,'popup.html');
    assert.ok(installed.optionsPage.includes('aegis-extension://'));
    const internalBefore=runtime.items.get(installed.id);
    const resourceToken=internalBefore.resourceToken,installedAt=internalBefore.installedAt;

    const second=makeXpi(root,'1.1.0');
    const update=await runtime.stage(second);
    const updated=await runtime.installStaged(update.token);
    assert.equal(updated.version,'1.1.0');
    assert.equal(runtime.items.get(updated.id).resourceToken,resourceToken);
    assert.equal(runtime.items.get(updated.id).installedAt,installedAt);
    assert.equal(runtime.list().length,1);

    assert.equal(runtime.remove(updated.id),true);
    assert.equal(runtime.list().length,0);
    assert.equal(fs.existsSync(internalBefore.path),false);
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});
