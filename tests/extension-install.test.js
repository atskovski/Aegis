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


function chromeId(bytes){
  const alphabet='abcdefghijklmnop';
  return [...bytes.subarray(0,16)].map((value)=>alphabet[(value>>4)&15]+alphabet[value&15]).join('');
}
function wrapCrx2(zipFile,crxFile){
  const zip=fs.readFileSync(zipFile),publicKey=Buffer.from('aegis-chrome-test-public-key'),signature=Buffer.from('test-signature');
  const header=Buffer.alloc(16);header.write('Cr24',0,'ascii');header.writeUInt32LE(2,4);header.writeUInt32LE(publicKey.length,8);header.writeUInt32LE(signature.length,12);
  fs.writeFileSync(crxFile,Buffer.concat([header,publicKey,signature,zip]));
  return chromeId(require('node:crypto').createHash('sha256').update(publicKey).digest());
}
function varint(value){
  const out=[];let v=value;
  do{let b=v&0x7f;v=Math.floor(v/128);if(v)b|=0x80;out.push(b)}while(v);
  return Buffer.from(out);
}
function wrapCrx3(zipFile,crxFile,idBytes){
  const zip=fs.readFileSync(zipFile);
  const signedData=Buffer.concat([Buffer.from([0x0a,0x10]),idBytes]);
  const tag=varint(10000*8+2),headerBody=Buffer.concat([tag,varint(signedData.length),signedData]);
  const header=Buffer.alloc(12);header.write('Cr24',0,'ascii');header.writeUInt32LE(3,4);header.writeUInt32LE(headerBody.length,8);
  fs.writeFileSync(crxFile,Buffer.concat([header,headerBody,zip]));
  return chromeId(idBytes);
}
function makeChromeZip(root,version='1.0.0'){
  const pkg=path.join(root,'chrome-pkg-'+version);fs.mkdirSync(pkg,{recursive:true});
  const manifest={manifest_version:3,name:'Aegis Chrome Test',version,description:'Chrome package integration test',permissions:['storage','tabs'],host_permissions:['https://example.com/*'],action:{default_title:'Chrome Test'}};
  fs.writeFileSync(path.join(pkg,'manifest.json'),JSON.stringify(manifest));
  fs.writeFileSync(path.join(pkg,'content.js'),'chrome.storage.local.get(null);');
  const zip=path.join(root,'chrome-extension-'+version+'.zip');
  execFileSync('/usr/bin/zip',['-qr',zip,'.'],{cwd:pkg});
  return {zip,pkg};
}

test('CRX2 package preserves Chrome extension identity through install',async()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-crx2-'));
  try{
    const runtime=new AegisExtensionRuntime({rootDir:path.join(root,'runtime'),getTabs:()=>[],getActiveId:()=>null,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    const built=makeChromeZip(root),crx=path.join(root,'extension.crx'),expected=wrapCrx2(built.zip,crx);
    const staged=await runtime.stage(crx);
    assert.equal(staged.summary.id,expected);
    assert.equal(staged.summary.packageFormat,'crx2');
    const installed=await runtime.installStaged(staged.token);
    assert.equal(installed.id,expected);
    assert.equal(installed.source,'crx2');
    assert.equal(installed.manifestVersion,3);
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});

test('CRX3 package reads embedded Chrome extension id',async()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-crx3-'));
  try{
    const runtime=new AegisExtensionRuntime({rootDir:path.join(root,'runtime'),getTabs:()=>[],getActiveId:()=>null,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    const built=makeChromeZip(root),crx=path.join(root,'extension-v3.crx'),idBytes=Buffer.from('00112233445566778899aabbccddeeff','hex'),expected=wrapCrx3(built.zip,crx,idBytes);
    const staged=await runtime.stage(crx);
    assert.equal(staged.summary.id,expected);
    assert.equal(staged.summary.packageFormat,'crx3');
    assert.equal(staged.summary.signature.format,'crx3');
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});

test('unpacked Chrome extension can be staged and installed with stable local identity',async()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-unpacked-'));
  try{
    const runtime=new AegisExtensionRuntime({rootDir:path.join(root,'runtime'),getTabs:()=>[],getActiveId:()=>null,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    const built=makeChromeZip(root);
    const first=runtime.stageDirectory(built.pkg),second=runtime.stageDirectory(built.pkg);
    assert.equal(first.summary.id,second.summary.id);
    assert.equal(first.summary.packageFormat,'unpacked');
    const installed=await runtime.installStaged(first.token);
    assert.equal(installed.source,'unpacked');
    assert.equal(installed.id,first.summary.id);
    assert.ok(fs.existsSync(path.join(runtime.items.get(installed.id).path,'manifest.json')));
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});
