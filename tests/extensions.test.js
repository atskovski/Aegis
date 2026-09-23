'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { safeRel, normalizeManifest, compatibility, contentScriptPhase, matchPattern, matchingContentScripts, rewriteCssUrls, installRisk, extensionWorldId, bootstrap, AegisExtensionRuntime, hostPermissions, networkAllowedByManifest, extensionVisibleTab, scanUsedApiRoots } = require('../src/core/extensions');

test('XPI runtime rejects unsafe relative paths', () => {
  assert.equal(safeRel('../secret'), '');
  assert.equal(safeRel('/absolute'), '');
  assert.equal(safeRel('content/main.js'), 'content/main.js');
});

test('WebExtension manifest validation accepts v2/v3 and requires identity fields', () => {
  assert.equal(normalizeManifest({manifest_version:2,name:'Test',version:'1.0'}).name, 'Test');
  assert.equal(normalizeManifest({manifest_version:3,name:'Test',version:'1.0'}).manifest_version, 3);
  assert.throws(() => normalizeManifest({manifest_version:1,name:'Old',version:'1'}));
});

test('Firefox match patterns are applied conservatively', () => {
  assert.equal(matchPattern('https://news.example.com/a?b=1','*://*.example.com/*'), true);
  assert.equal(matchPattern('https://example.net/a','*://*.example.com/*'), false);
  assert.equal(matchPattern('https://example.com/a','<all_urls>'), true);
});

test('matching content scripts honor include and exclude patterns', () => {
  const manifest={manifest_version:2,name:'T',version:'1',content_scripts:[{matches:['*://*.example.com/*'],exclude_matches:['*://private.example.com/*'],js:['x.js']}]};
  assert.equal(matchingContentScripts(manifest,'https://www.example.com/page').length,1);
  assert.equal(matchingContentScripts(manifest,'https://private.example.com/page').length,0);
});

test('compatibility report never claims unsupported privileged APIs work', () => {
  const manifest={manifest_version:2,name:'T',version:'1',permissions:['storage','tabs','webRequest','proxy'],background:{scripts:['bg.js']}};
  const report=compatibility(manifest);
  assert.ok(report.supported.includes('storage'));
  assert.ok(report.unsupported.some((x)=>x.api==='webRequest'));
  assert.ok(report.unsupported.some((x)=>x.api==='proxy'));
  assert.equal(report.background,'sandboxed-emulation');
  assert.ok(report.warnings.some((x)=>x.api==='background'));
  assert.ok(report.score < 100);
});

test('high-power extension permissions are marked high risk', () => {
  const manifest={manifest_version:2,name:'T',version:'1',permissions:['<all_urls>','storage']};
  const risk=installRisk(manifest);
  assert.equal(risk.find((x)=>x.permission==='<all_urls>').level,'high');
});


test('each extension receives a stable isolated world id', () => {
  const a=extensionWorldId('one@example');
  const b=extensionWorldId('two@example');
  assert.ok(a >= 1000);
  assert.ok(b >= 1000);
  assert.equal(a, extensionWorldId('one@example'));
  assert.notEqual(a, b);
});


test('Firefox background pages are explicitly hosted in the sandboxed compatibility runtime', () => {
  const report=compatibility({manifest_version:2,name:'T',version:'1',background:{page:'background.html'}});
  assert.equal(report.background,'sandboxed-page');
  assert.ok(report.warnings.some((x)=>x.api==='background.page'));
});


test('generated content-script WebExtension bootstrap is valid JavaScript', () => {
  const ext={
    id:'compile-test@example',
    resourceToken:'0123456789abcdef0123456789abcdef',
    manifest:{manifest_version:2,name:'Compile Test',version:'1.0',permissions:['storage']}
  };
  assert.doesNotThrow(() => new Function(bootstrap(ext)));
});

test('generated background WebExtension bootstrap is valid JavaScript', () => {
  const root=require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(),'aegis-ext-compile-'));
  try {
    const runtime=new AegisExtensionRuntime({rootDir:root,getTabs:()=>[],createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    const ext={
      id:'background-test@example',
      resourceToken:'abcdef0123456789abcdef0123456789',
      manifest:{manifest_version:2,name:'Background Test',version:'1.0',permissions:['storage'],background:{scripts:['background.js']}}
    };
    assert.doesNotThrow(() => new Function(runtime.backgroundBootstrap(ext)));
  } finally {
    require('node:fs').rmSync(root,{recursive:true,force:true});
  }
});


test('content script run_at phases are explicit and document_start is a documented fallback', () => {
  assert.equal(contentScriptPhase({run_at:'document_idle'}),'idle');
  assert.equal(contentScriptPhase({run_at:'document_end'}),'end');
  assert.equal(contentScriptPhase({run_at:'document_start'}),'start');
  const report=compatibility({manifest_version:2,name:'T',version:'1',content_scripts:[{matches:['<all_urls>'],run_at:'document_start',js:['start.js']}]});
  assert.ok(report.warnings.some((x)=>x.api==='content_scripts.run_at'));
});

test('extension CSS relative assets are rewritten to private extension-resource URLs', () => {
  const ext={resourceToken:'abc123'};
  const css=rewriteCssUrls('.x{background:url("../img/icon.png")} .y{mask:url(data:image/png;base64,abc)}',ext,'styles/main.css');
  assert.match(css,/aegis-extension:\/\/abc123\/img\/icon\.png/);
  assert.match(css,/data:image\/png;base64,abc/);
});


test('extension background networking is limited to declared host permissions', () => {
  const m={manifest_version:2,name:'T',version:'1',permissions:['storage','https://api.example.com/*']};
  assert.deepEqual(hostPermissions(m),['https://api.example.com/*']);
  assert.equal(networkAllowedByManifest(m,'https://api.example.com/v1'),true);
  assert.equal(networkAllowedByManifest(m,'https://other.example.com/v1'),false);
});

test('anonymous and hardened tabs do not receive extension content scripts', async () => {
  const root=require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(),'aegis-ext-isolation-'));
  try {
    const runtime=new AegisExtensionRuntime({rootDir:root,getTabs:()=>[],createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    assert.deepEqual(await runtime.inject({securityDomain:'anonymous',disableExtensions:true}),[]);
    assert.deepEqual(await runtime.inject({securityDomain:'hardened',disableExtensions:true}),[]);
  } finally {
    require('node:fs').rmSync(root,{recursive:true,force:true});
  }
});


test('extensions cannot enumerate or control hardened/anonymous tabs', () => {
  assert.equal(extensionVisibleTab({securityDomain:'private',disableExtensions:false}),true);
  assert.equal(extensionVisibleTab({securityDomain:'hardened',disableExtensions:true}),false);
  assert.equal(extensionVisibleTab({securityDomain:'anonymous',disableExtensions:true}),false);
  assert.equal(extensionVisibleTab({securityDomain:'private',disableExtensions:true}),false);
});


test('toolbar actions scripting alarms commands and navigation are recognized capabilities', () => {
  const report=compatibility({
    manifest_version:3,name:'T',version:'1',
    permissions:['storage','tabs','scripting','alarms','webNavigation'],
    action:{default_title:'Run',default_popup:'popup.html'},
    commands:{run:{description:'Run'}}
  });
  for (const api of ['storage','tabs','scripting','alarms','webNavigation','action','commands']) {
    assert.ok(report.supported.includes(api), api + ' should be supported');
  }
  assert.equal(report.features.popup,true);
  assert.equal(report.features.commands,1);
});


test('<all_urls> is treated as host access rather than an unsupported API namespace', () => {
  const report=compatibility({manifest_version:2,name:'T',version:'1',permissions:['<all_urls>','storage']});
  assert.equal(report.unsupported.some((x)=>x.api==='<all_urls>'),false);
  assert.ok(report.supported.includes('storage'));
});

test('package source API scanning distinguishes supported and unsupported browser namespaces', () => {
  const fs=require('node:fs'), path=require('node:path'), os=require('node:os');
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-ext-scan-'));
  try {
    fs.writeFileSync(path.join(root,'background.js'),"browser.runtime.onMessage.addListener(()=>{}); chrome.proxy.settings.get(()=>{}); browser.cookies.getAll({});");
    const roots=scanUsedApiRoots(root);
    assert.ok(roots.includes('runtime'));
    assert.ok(roots.includes('proxy'));
    assert.ok(roots.includes('cookies'));
    const report=compatibility({manifest_version:2,name:'T',version:'1',background:{scripts:['background.js']}},roots);
    assert.ok(report.unsupported.some((x)=>x.api==='proxy'));
    assert.ok(report.supported.includes('cookies'));
    assert.equal(report.unsupported.some((x)=>x.api==='cookies'),false);
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});


test('background bootstrap preserves runtime.sendMessage response handling and unique origins', () => {
  const { webExtensionBootstrap }=require('../src/core/extension-shim');
  const ext={id:'msg@example',resourceToken:'token123',path:__dirname,manifest:{manifest_version:2,name:'Msg',version:'1',background:{scripts:['bg.js']}}};
  const source=webExtensionBootstrap(ext,'__aegisBackgroundBridge');
  assert.ok(source.includes("'aegis-extension://'+TOKEN+'/'"));
  assert.ok(source.includes('B.respond?.(p.messageId,response)'));
});


test('notifications and context menus are supported with explicit reduced-surface warnings', () => {
  const report=compatibility({manifest_version:2,name:'T',version:'1',permissions:['notifications','menus']});
  assert.ok(report.supported.includes('notifications'));
  assert.ok(report.supported.includes('menus'));
  assert.ok(report.warnings.some((x)=>x.api==='notifications'));
  assert.ok(report.warnings.some((x)=>x.api==='menus'));
});


test('Runtime 3 compatibility recognizes windows cookies and durable sync storage', () => {
  const report=compatibility({
    manifest_version:2,name:'Runtime 3',version:'1',
    permissions:['storage','tabs','windows','cookies','https://example.com/*']
  },['storage','tabs','windows','cookies']);
  for (const api of ['storage','tabs','windows','cookies']) assert.ok(report.supported.includes(api), api + ' should be supported');
  assert.equal(report.unsupported.some((x)=>['windows','cookies'].includes(x.api)),false);
});

test('generated WebExtension bootstrap exposes Runtime 3 APIs', () => {
  const source=bootstrap({
    id:'runtime3@example',
    resourceToken:'runtime3token',
    path:__dirname,
    manifest:{manifest_version:2,name:'Runtime 3',version:'1',permissions:['storage','tabs','windows','cookies']}
  });
  assert.match(source,/sync:area\('sync'\)/);
  assert.match(source,/managed:area\('managed'\)/);
  assert.match(source,/getBytesInUse/);
  assert.match(source,/getKeys/);
  assert.match(source,/runtimeConnect/);
  assert.match(source,/onConnect:event\('runtime\.onConnect'\)/);
  assert.match(source,/tabs\.connect|connect:\(id,info/);
  assert.match(source,/const windows=/);
  assert.match(source,/const cookies=/);
  assert.match(source,/captureVisibleTab/);
  assert.match(source,/getContexts/);
  assert.match(source,/setIcon/);
  assert.doesNotThrow(()=>new Function(source));
});

test('generated Chrome bridge supports callbacks, Promises, runtime.lastError and synchronous menu ids', async () => {
  const vm=require('node:vm');
  const source=bootstrap({
    id:'chrome-callback@example',
    resourceToken:'callbacktoken',
    path:__dirname,
    manifest:{manifest_version:3,name:'Chrome Callback',version:'1',permissions:['tabs','storage','contextMenus']}
  });
  const context={
    __aegisExtensionBridge:{
      call:(method)=>method==='tabs.get'?Promise.reject(new Error('tab missing')):Promise.resolve(method==='tabs.query'?[{id:1}]:true),
      onMessage:()=>{},
      onEvent:()=>{}
    }
  };
  vm.runInNewContext(source,context);
  const promised=await context.browser.tabs.query({});
  assert.equal(promised[0].id,1);
  await new Promise((resolve,reject)=>{
    const returned=context.chrome.tabs.query({},(tabs)=>{
      try{assert.equal(tabs[0].id,1);assert.equal(context.chrome.runtime.lastError,null);resolve()}catch(err){reject(err)}
    });
    assert.equal(returned,undefined);
  });
  await new Promise((resolve,reject)=>{
    context.chrome.tabs.get(99,()=>{
      try{assert.match(context.chrome.runtime.lastError.message,/tab missing/);resolve()}catch(err){reject(err)}
    });
  });
  assert.equal(context.chrome.runtime.lastError,null);
  const menuId=context.chrome.contextMenus.create({title:'Test'});
  assert.match(menuId,/^aegis-menu-/);
});

test('extension popup preload exposes the same Runtime 3 API families', () => {
  const fs=require('node:fs'),path=require('node:path');
  const source=fs.readFileSync(path.join(__dirname,'..','src','extension-page-preload.js'),'utf8');
  assert.match(source,/sync:area\('sync'\)/);
  assert.match(source,/managed:area\('managed'\)/);
  assert.match(source,/getBytesInUse/);
  assert.match(source,/getKeys/);
  assert.match(source,/runtimeConnect/);
  assert.match(source,/onConnect:/);
  assert.match(source,/connect: \(id,info=/);
  assert.match(source,/windows:/);
  assert.match(source,/cookies:/);
  assert.match(source,/captureVisibleTab/);
  assert.match(source,/getContexts/);
  assert.match(source,/setIcon/);
  assert.match(source,/runtimeLastError/);
  assert.match(source,/get lastError/);
});

test('installed extension diagnostics verify package resources and bootstrap health', async () => {
  const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-ext-health-'));
  try {
    const extRoot=path.join(root,'extensions','health@example');
    fs.mkdirSync(extRoot,{recursive:true});
    const manifest={manifest_version:2,name:'Health',version:'1',browser_specific_settings:{gecko:{id:'health@example'}},background:{scripts:['background.js']},content_scripts:[{matches:['<all_urls>'],js:['content.js']}]};
    fs.writeFileSync(path.join(extRoot,'manifest.json'),JSON.stringify(manifest));
    fs.writeFileSync(path.join(extRoot,'background.js'),'void 0;');
    fs.writeFileSync(path.join(extRoot,'content.js'),'void 0;');
    const runtime=new AegisExtensionRuntime({rootDir:root,getTabs:()=>[],createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    const e={id:'health@example',path:extRoot,resourceToken:'healthtoken',worldId:extensionWorldId('health@example'),enabled:true,manifest,detectedApis:[],compatibility:compatibility(manifest)};
    runtime.items.set(e.id,e);
    const result=await runtime.diagnose(e.id,{repair:false});
    assert.ok(['pass','fail'].includes(result.status));
    assert.ok(result.checks.some((x)=>x.id==='manifest'&&x.status==='pass'));
    assert.ok(result.checks.some((x)=>x.id==='resources'&&x.status==='pass'));
    assert.ok(result.checks.some((x)=>x.id==='bootstrap'&&x.status==='pass'));
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});


test('runtime.connect Port messages route between a content context and background host', async () => {
  const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-port-runtime-'));
  try {
    const sourceEvents=[],backgroundEvents=[];
    const source={send:(channel,payload)=>sourceEvents.push({channel,payload})};
    const background={send:(channel,payload)=>backgroundEvents.push({channel,payload})};
    const host={isDestroyed:()=>false,webContents:background};
    const tab={id:7,url:'https://example.com/',title:'Example',loading:false,securityDomain:'private',disableExtensions:false,view:{webContents:source}};
    const runtime=new AegisExtensionRuntime({rootDir:root,getTabs:()=>[tab],getActiveId:()=>7,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    const manifest={manifest_version:2,name:'Ports',version:'1',permissions:['tabs','https://example.com/*']};
    runtime.items.set('ports@example',{id:'ports@example',path:root,resourceToken:'porttoken',worldId:extensionWorldId('ports@example'),enabled:true,manifest,detectedApis:['runtime','tabs'],compatibility:compatibility(manifest,['runtime','tabs'])});
    runtime.backgroundHosts.set('ports@example',host);

    await runtime.call(source,{extensionId:'ports@example',method:'runtime.portOpen',args:[{portId:'aegis-port-test123',name:'channel'}]});
    assert.equal(backgroundEvents.at(-1).payload.type,'runtime.onConnect');
    await runtime.call(source,{extensionId:'ports@example',method:'runtime.portPost',args:['aegis-port-test123',{hello:true}]});
    assert.equal(backgroundEvents.at(-1).payload.type,'runtime.portMessage');
    assert.deepEqual(backgroundEvents.at(-1).payload.args[1],{hello:true});
    await runtime.call(background,{extensionId:'ports@example',method:'runtime.portPost',args:['aegis-port-test123',{reply:true}]});
    assert.equal(sourceEvents.at(-1).payload.type,'runtime.portMessage');
    assert.deepEqual(sourceEvents.at(-1).payload.args[1],{reply:true});
    await runtime.call(source,{extensionId:'ports@example',method:'runtime.portDisconnect',args:['aegis-port-test123']});
    assert.equal(sourceEvents.length >= 1,true);
    assert.equal(runtime.ports.size,0);
  } finally { fs.rmSync(root,{recursive:true,force:true}); }
});
