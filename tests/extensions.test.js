'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { safeRel, normalizeManifest, localizeManifest, packageEcosystem, extensionId, compatibility, contentScriptPhase, matchPattern, matchingContentScripts, rewriteCssUrls, installRisk, extensionWorldId, bootstrap, AegisExtensionRuntime, hostPermissions, networkAllowedByManifest, extensionVisibleTab, scanUsedApiRoots } = require('../src/core/extensions');

test('Chrome extension runtime rejects unsafe relative paths', () => {
  assert.equal(safeRel('../secret'), '');
  assert.equal(safeRel('/absolute'), '');
  assert.equal(safeRel('content/main.js'), 'content/main.js');
});

test('Chrome extension manifest validation accepts v2/v3 and requires identity fields', () => {
  assert.equal(normalizeManifest({manifest_version:2,name:'Test',version:'1.0'}).name, 'Test');
  assert.equal(normalizeManifest({manifest_version:3,name:'Test',version:'1.0'}).manifest_version, 3);
  assert.throws(() => normalizeManifest({manifest_version:1,name:'Old',version:'1'}));
});

test('Chrome match patterns are applied conservatively', () => {
  assert.equal(matchPattern('https://news.example.com/a?b=1','*://*.example.com/*'), true);
  assert.equal(matchPattern('https://example.net/a','*://*.example.com/*'), false);
  assert.equal(matchPattern('https://example.com/a','<all_urls>'), true);
  assert.equal(matchPattern('wss://socket.example.com/live','<all_urls>'), true);
  assert.equal(matchPattern('ws://socket.example.com/live','ws://*.example.com/*'), true);
  assert.equal(matchPattern('wss://socket.example.com/live','wss://*.example.com/*'), true);
  assert.equal(matchPattern('wss://socket.example.com/live','*://*.example.com/*'), false);
});

test('matching content scripts honor include and exclude patterns', () => {
  const manifest={manifest_version:2,name:'T',version:'1',content_scripts:[{matches:['*://*.example.com/*'],exclude_matches:['*://private.example.com/*'],js:['x.js']}]};
  assert.equal(matchingContentScripts(manifest,'https://www.example.com/page').length,1);
  assert.equal(matchingContentScripts(manifest,'https://private.example.com/page').length,0);
});

test('compatibility report distinguishes hosted APIs from protected browser takeover APIs', () => {
  const manifest={manifest_version:2,name:'T',version:'1',permissions:['storage','tabs','webRequest','proxy'],background:{scripts:['bg.js']}};
  const report=compatibility(manifest);
  assert.ok(report.supported.includes('storage'));
  assert.ok(report.supported.includes('webRequest'));
  assert.equal(report.unsupported.some((x)=>x.api==='webRequest'),false);
  assert.ok(report.warnings.some((x)=>x.api==='webRequest'));
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


test('Manifest V2 background pages are explicitly hosted in the sandboxed compatibility runtime', () => {
  const report=compatibility({manifest_version:2,name:'T',version:'1',background:{page:'background.html'}});
  assert.equal(report.background,'sandboxed-page');
  assert.ok(report.warnings.some((x)=>x.api==='background.page'));
});


test('generated content-script Chrome extension bootstrap is valid JavaScript', () => {
  const ext={
    id:'compile-test@example',
    resourceToken:'0123456789abcdef0123456789abcdef',
    manifest:{manifest_version:2,name:'Compile Test',version:'1.0',permissions:['storage']}
  };
  assert.doesNotThrow(() => new Function(bootstrap(ext)));
});

test('generated background Chrome extension bootstrap is valid JavaScript', () => {
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


test('WebExtension bootstrap is idempotent across multiple content-script groups', () => {
  const vm=require('node:vm');
  const ext={id:'repeat@example',resourceToken:'repeat-token',path:__dirname,manifest:{manifest_version:3,name:'Repeat',version:'1'}};
  let eventSubscriptions=0,messageSubscriptions=0;
  const context={
    setTimeout,
    __aegisExtensionBridge:{
      call:()=>Promise.resolve(),
      onMessage:()=>{messageSubscriptions++},
      onEvent:()=>{eventSubscriptions++}
    }
  };
  const source=bootstrap(ext);
  vm.runInNewContext(source,context);
  vm.runInNewContext(source,context);
  assert.equal(context.chrome.runtime.id,'repeat@example');
  assert.equal(context.browser.runtime.id,'repeat@example');
  assert.equal(messageSubscriptions,1);
  assert.equal(eventSubscriptions,1);
});

test('callback-style runtime messaging preserves asynchronous sendResponse', async () => {
  const vm=require('node:vm');
  const { webExtensionBootstrap }=require('../src/core/extension-shim');
  const ext={id:'response@example',resourceToken:'responsetoken',path:__dirname,manifest:{manifest_version:3,name:'Response',version:'1',background:{service_worker:'bg.js'}}};
  let inbound=null,response=null;
  const context={
    setTimeout,
    __aegisBackgroundBridge:{
      call:()=>Promise.resolve(),
      onMessage:(fn)=>{inbound=fn},
      onEvent:()=>{},
      respond:(messageId,value)=>{response={messageId,value}}
    }
  };
  vm.runInNewContext(webExtensionBootstrap(ext,'__aegisBackgroundBridge'),context);
  context.chrome.runtime.onMessage.addListener((message,sender,sendResponse)=>{
    setTimeout(()=>sendResponse({ok:true,value:message.value,origin:sender.origin}),5);
    return true;
  });
  await inbound({messageId:'m1',message:{value:42},sender:{origin:'https://example.com'}});
  assert.deepEqual(JSON.parse(JSON.stringify(response)),{messageId:'m1',value:{ok:true,value:42,origin:'https://example.com'}});
});

test('registered content scripts support MV3 dynamic scripting metadata', () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-registered-scripts-'));
  try{
    const extRoot=path.join(root,'extension');fs.mkdirSync(extRoot,{recursive:true});
    fs.writeFileSync(path.join(extRoot,'dnt.js'),'globalThis.__dnt=true;');
    const manifest={manifest_version:3,name:'Dynamic',version:'1',permissions:['scripting'],host_permissions:['<all_urls>']};
    const runtime=new AegisExtensionRuntime({rootDir:path.join(root,'runtime'),getTabs:()=>[],createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    const e={id:'dynamic-test',path:extRoot,enabled:true,manifest,detectedApis:['scripting'],compatibility:compatibility(manifest,['scripting'])};
    runtime.items.set(e.id,e);
    const dnt={id:'dnt_signal',js:['dnt.js'],matches:['<all_urls>'],runAt:'document_start',allFrames:true,world:'MAIN',persistAcrossSessions:false};
    runtime.registerContentScripts(e,[dnt]);
    runtime.registerContentScripts(e,[dnt]);
    const rows=runtime.getRegisteredContentScripts(e,{});
    assert.equal(rows.length,1);
    assert.equal(rows[0].id,'dnt_signal');
    assert.equal(rows[0].world,'MAIN');
    assert.equal(rows[0].runAt,'document_start');
    assert.equal(rows[0].allFrames,true);
    assert.equal(contentScriptPhase(runtime.contentScriptsFor(e).at(-1)),'start');
    runtime.unregisterContentScripts(e,{ids:['dnt_signal']});
    assert.equal(runtime.getRegisteredContentScripts(e,{}).length,0);
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});

test('all_frames content scripts use the sandboxed subframe bridge', async () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-all-frames-'));
  try{
    const extRoot=path.join(root,'extension');fs.mkdirSync(extRoot,{recursive:true});
    fs.writeFileSync(path.join(extRoot,'content.js'),'globalThis.__frameWorked=true;');
    const mainFrame={framesInSubtree:[]};
    const frame={processId:77,routingId:88,url:'https://sub.example.com/frame',parent:{url:'https://example.com/'},isDestroyed:()=>false};
    mainFrame.framesInSubtree=[mainFrame,frame];
    let runtime;
    let payloadSeen=null;
    const contents={
      mainFrame,
      isDestroyed:()=>false,
      sendToFrame:(_frameId,channel,payload)=>{
        assert.equal(channel,'extension:frame-inject');
        payloadSeen=payload;
        setImmediate(()=>runtime.handleFrameInjectionResult(contents,frame,{
          requestId:payload.requestId,extensionId:payload.extensionId,ok:true,scriptCount:2,cssCount:0,failures:[]
        }));
      }
    };
    const tab={id:1,url:'https://example.com/',securityDomain:'private',disableExtensions:false,view:{webContents:contents},extensionInjectionKeys:new Set()};
    const manifest={manifest_version:3,name:'All Frames',version:'1',host_permissions:['<all_urls>'],content_scripts:[{matches:['<all_urls>'],all_frames:true,js:['content.js']}]};
    runtime=new AegisExtensionRuntime({rootDir:path.join(root,'runtime'),getTabs:()=>[tab],getActiveId:()=>1,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    const e={id:'all-frames',path:extRoot,resourceToken:'frametoken',enabled:true,manifest,detectedApis:['runtime'],compatibility:compatibility(manifest,['runtime'])};
    runtime.items.set(e.id,e);
    assert.equal(runtime.requiresSubFramePreload(tab),true);
    const ids=await runtime.injectFrame(tab,frame,'idle');
    assert.deepEqual(ids,['all-frames']);
    assert.equal(payloadSeen.world,'ISOLATED');
    assert.equal(payloadSeen.scripts.length,2);
    assert.match(payloadSeen.scripts[1].code,/__frameWorked/);
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});

test('content-script messaging preserves subframe id and inherited origin', async () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-frame-sender-'));
  try{
    const mainFrame={routingId:1,url:'https://example.com/',parent:null};
    const frame={routingId:9,processId:3,url:'about:blank',parent:{url:'https://embed.example/path',parent:null},isDestroyed:()=>false};
    let runtime,captured;
    const contents={mainFrame,isDestroyed:()=>false};
    const tab={id:5,url:'https://example.com/',title:'Example',securityDomain:'private',disableExtensions:false,view:{webContents:contents}};
    const background={
      send:(_channel,payload)=>{
        captured=payload;
        setImmediate(()=>runtime.handleBackgroundResponse(background,{extensionId:payload.extensionId,messageId:payload.messageId,response:{ok:true}}));
      }
    };
    const manifest={manifest_version:3,name:'Sender',version:'1',host_permissions:['<all_urls>']};
    runtime=new AegisExtensionRuntime({rootDir:path.join(root,'runtime'),getTabs:()=>[tab],getActiveId:()=>5,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    const e={id:'sender-test',path:root,resourceToken:'sendertoken',enabled:true,manifest,detectedApis:['runtime'],compatibility:compatibility(manifest,['runtime'])};
    runtime.items.set(e.id,e);runtime.backgroundHosts.set(e.id,{isDestroyed:()=>false,webContents:background});
    const response=await runtime.call(contents,{extensionId:e.id,method:'runtime.sendMessage',args:[{hello:true}]},frame);
    assert.deepEqual(response,{ok:true});
    assert.equal(captured.sender.frameId,9);
    assert.equal(captured.sender.url,'about:blank');
    assert.equal(captured.sender.origin,'https://embed.example');
    assert.equal(captured.sender.tab.id,5);
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});

test('tabs.sendMessage can target an injected subframe by frameId', async () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-frame-message-'));
  try{
    const extRoot=path.join(root,'extension');fs.mkdirSync(extRoot,{recursive:true});
    fs.writeFileSync(path.join(extRoot,'content.js'),'chrome.runtime.onMessage.addListener(()=>true);');
    const mainFrame={framesInSubtree:[]};
    const frame={processId:12,routingId:34,url:'https://sub.example.com/',parent:{url:'https://example.com/'},isDestroyed:()=>false};
    mainFrame.framesInSubtree=[mainFrame,frame];
    let runtime;
    const contents={
      mainFrame,
      isDestroyed:()=>false,
      sendToFrame:(_frameId,channel,payload)=>{
        assert.equal(channel,'extension:frame-message');
        setImmediate(()=>runtime.handleFrameMessageResult(contents,frame,{
          requestId:payload.requestId,extensionId:payload.extensionId,ok:true,response:{frame:'ok'}
        }));
      },
      executeJavaScriptInIsolatedWorld:async()=>({top:'ok'})
    };
    const tab={id:2,url:'https://example.com/',securityDomain:'private',disableExtensions:false,view:{webContents:contents}};
    const manifest={manifest_version:3,name:'Frame Message',version:'1',permissions:['tabs'],host_permissions:['<all_urls>'],content_scripts:[{matches:['<all_urls>'],all_frames:true,js:['content.js']}]};
    runtime=new AegisExtensionRuntime({rootDir:path.join(root,'runtime'),getTabs:()=>[tab],getActiveId:()=>2,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    const e={id:'frame-message',path:extRoot,resourceToken:'messagetoken',enabled:true,manifest,detectedApis:['tabs'],compatibility:compatibility(manifest,['tabs'])};
    runtime.items.set(e.id,e);
    const result=await runtime.sendTabMessage(e,tab,{hello:'frame'},{frameId:34});
    assert.deepEqual(result,{frame:'ok'});
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});

test('scripting.executeScript targets a specific subframe in MAIN world', async () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-frame-scripting-'));
  try{
    const extRoot=path.join(root,'extension');fs.mkdirSync(extRoot,{recursive:true});
    fs.writeFileSync(path.join(extRoot,'clobber.js'),'globalThis.__clobberWorked=true;');
    const mainFrame={framesInSubtree:[]};
    const frame={processId:41,routingId:42,url:'https://tracker.example/frame',parent:{url:'https://example.com/'},isDestroyed:()=>false};
    mainFrame.framesInSubtree=[mainFrame,frame];
    let runtime,payloadSeen;
    const contents={
      mainFrame,
      isDestroyed:()=>false,
      sendToFrame:(_frameId,channel,payload)=>{
        assert.equal(channel,'extension:frame-inject');
        payloadSeen=payload;
        setImmediate(()=>runtime.handleFrameInjectionResult(contents,frame,{
          requestId:payload.requestId,extensionId:payload.extensionId,ok:true,scriptCount:1,cssCount:0,failures:[],result:'ran'
        }));
      }
    };
    const tab={id:7,url:'https://example.com/',securityDomain:'private',disableExtensions:false,view:{webContents:contents}};
    const manifest={manifest_version:3,name:'Frame Scripting',version:'1',permissions:['scripting'],host_permissions:['<all_urls>']};
    runtime=new AegisExtensionRuntime({rootDir:path.join(root,'runtime'),getTabs:()=>[tab],getActiveId:()=>7,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    const e={id:'frame-scripting',path:extRoot,resourceToken:'scripttoken',enabled:true,manifest,detectedApis:['scripting'],compatibility:compatibility(manifest,['scripting'])};
    runtime.items.set(e.id,e);
    assert.equal(runtime.requiresSubFramePreload(tab),true);
    const result=await runtime.executeExtensionScript(e,tab,{target:{tabId:7,frameIds:[42]},world:'MAIN',files:['clobber.js']});
    assert.deepEqual(result,[{frameId:42,result:'ran'}]);
    assert.equal(payloadSeen.world,'MAIN');
    assert.equal(payloadSeen.scripts.length,1);
    assert.match(payloadSeen.scripts[0].code,/__clobberWorked/);
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});

test('MAIN-world scripting executes packaged files without the isolated API bootstrap', async () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-main-world-'));
  try{
    const extRoot=path.join(root,'extension');fs.mkdirSync(extRoot,{recursive:true});
    fs.writeFileSync(path.join(extRoot,'main.js'),'globalThis.__mainWorldWorked=true;');
    const calls=[];
    const contents={
      isDestroyed:()=>false,
      executeJavaScript:async(code)=>{calls.push(code);return 'ok'},
      executeJavaScriptInIsolatedWorld:async()=>{throw new Error('isolated world should not run')}
    };
    const tab={id:1,url:'https://example.com/',securityDomain:'private',disableExtensions:false,view:{webContents:contents}};
    const manifest={manifest_version:3,name:'Main World',version:'1',permissions:['scripting'],host_permissions:['<all_urls>']};
    const runtime=new AegisExtensionRuntime({rootDir:path.join(root,'runtime'),getTabs:()=>[tab],getActiveId:()=>1,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    const e={id:'main-world',path:extRoot,enabled:true,manifest,detectedApis:['scripting'],compatibility:compatibility(manifest,['scripting'])};
    runtime.items.set(e.id,e);
    const result=await runtime.executeExtensionScript(e,tab,{target:{tabId:1,frameIds:[0]},world:'MAIN',files:['main.js']});
    assert.equal(result[0].frameId,0);
    assert.equal(calls.length,1);
    assert.match(calls[0],/__mainWorldWorked/);
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});

test('runtime repair clears stale extension errors and reloads eligible tabs for clean reinjection', async () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-extension-repair-'));
  try{
    const extRoot=path.join(root,'extension');fs.mkdirSync(extRoot,{recursive:true});
    fs.writeFileSync(path.join(extRoot,'content.js'),'globalThis.__repairTest=true;');
    let reloads=0;
    const tab={
      id:1,url:'https://example.com/',securityDomain:'private',disableExtensions:false,
      extensionInjectionKeys:new Set(['repair-test:0:idle','other:0:idle']),
      view:{webContents:{isDestroyed:()=>false,reload:()=>{reloads++}}}
    };
    const manifest={manifest_version:3,name:'Repair',version:'1',host_permissions:['<all_urls>'],content_scripts:[{matches:['<all_urls>'],js:['content.js']}]};
    const runtime=new AegisExtensionRuntime({rootDir:path.join(root,'runtime'),getTabs:()=>[tab],getActiveId:()=>1,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    const e={id:'repair-test',path:extRoot,resourceToken:'repairtoken',enabled:true,manifest,detectedApis:['runtime'],compatibility:compatibility(manifest,['runtime'])};
    runtime.items.set(e.id,e);
    runtime.noteRuntimeError(e.id,'content-script:content.js',new Error('old failure'));
    const diagnostic=await runtime.diagnose(e.id,{repair:true});
    assert.equal(reloads,1);
    assert.equal(runtime.healthFor(e.id).errors.length,0);
    assert.equal(tab.extensionInjectionKeys.has('repair-test:0:idle'),false);
    assert.equal(tab.extensionInjectionKeys.has('other:0:idle'),true);
    assert.ok(diagnostic.checks.some((check)=>check.id==='repair'&&check.status==='pass'));
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});

test('extension-owned tabs retain their extension context and support URL queries', async () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-extension-tabs-'));
  try{
    const created=[],tabs=[];
    const background={send:()=>{}};
    const host={isDestroyed:()=>false,webContents:background};
    const runtime=new AegisExtensionRuntime({
      rootDir:root,
      getTabs:()=>tabs,
      getActiveId:()=>tabs[0]?.id||null,
      createTab:async(url,active,_wait,options)=>{
        created.push({url,active,options});
        const tab={id:9,url,title:'Extension page',securityDomain:'private',disableExtensions:false,view:{webContents:{}}};
        tabs.push(tab);return tab;
      },
      updateTab:async()=>{},removeTab:()=>{}
    });
    const manifest={manifest_version:3,name:'Owned tab',version:'1',permissions:['tabs']};
    const e={id:'owned-tab',path:root,resourceToken:'ownedtoken',enabled:true,manifest,detectedApis:['tabs'],compatibility:compatibility(manifest,['tabs'])};
    runtime.items.set(e.id,e);runtime.backgroundHosts.set(e.id,host);
    const url='aegis-extension://ownedtoken/skin/firstRun.html';
    const createdTab=await runtime.call(background,{extensionId:e.id,method:'tabs.create',args:[{url,active:true}]});
    assert.equal(created[0].options.extensionPageExtensionId,e.id);
    assert.equal(createdTab.url,url);
    const found=await runtime.call(background,{extensionId:e.id,method:'tabs.query',args:[{url}]});
    assert.equal(found.length,1);
    assert.equal(found[0].id,9);
    const missing=await runtime.call(background,{extensionId:e.id,method:'tabs.query',args:[{url:'aegis-extension://ownedtoken/other.html'}]});
    assert.equal(missing.length,0);
  }finally{fs.rmSync(root,{recursive:true,force:true})}
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


test('signed Chrome CRX identity is authoritative even when cross-browser metadata exists', () => {
  const manifest={
    manifest_version:2,name:'Cross-browser',version:'1.0',
    browser_specific_settings:{gecko:{id:'jid1-MnnxcxisBPnSXQ@jetpack'}}
  };
  assert.equal(extensionId(manifest,'a'.repeat(64),{format:'crx3',id:'pkehgijcmpdhfbdbbnkijodmdjhbjlgp',verified:true}),'pkehgijcmpdhfbdbbnkijodmdjhbjlgp');
});

test('generic Chrome ZIP identity ignores Gecko-only ids and uses Chrome identity rules', () => {
  const manifest={
    manifest_version:2,name:'Cross-browser package',version:'1.0',
    browser_specific_settings:{gecko:{id:'jid1-MnnxcxisBPnSXQ@jetpack'}}
  };
  assert.equal(extensionId(manifest,'b'.repeat(64),{format:'zip',id:''}),'chromeext-'+('b'.repeat(32)));
});


test('localized extension metadata resolves __MSG_ placeholders', () => {
  const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-ext-locale-'));
  try{
    fs.mkdirSync(path.join(root,'_locales','en'),{recursive:true});
    fs.writeFileSync(path.join(root,'_locales','en','messages.json'),JSON.stringify({name:{message:'Privacy Badger'},description:{message:'Blocks invisible trackers'}}));
    const manifest=localizeManifest(root,{manifest_version:3,default_locale:'en',name:'__MSG_name__',description:'__MSG_description__',version:'1.0'});
    assert.equal(manifest.name,'Privacy Badger');
    assert.equal(manifest.description,'Blocks invisible trackers');
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});

test('API scanner does not mistake URL host suffixes for chrome APIs', () => {
  const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-ext-scan-url-'));
  try{
    fs.writeFileSync(path.join(root,'background.js'),"const u='https://chrome.com/path'; chrome.runtime.getManifest();");
    const roots=scanUsedApiRoots(root);
    assert.ok(roots.includes('runtime'));
    assert.equal(roots.includes('com'),false);
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});

test('Runtime 6 reports one Chrome extension ecosystem', () => {
  const manifest={manifest_version:2,name:'Cross-browser metadata',version:'1',browser_specific_settings:{gecko:{id:'f@example'}}};
  assert.equal(packageEcosystem(manifest,{format:'zip'}),'chrome');
  assert.equal(packageEcosystem(manifest,{format:'crx3',id:'pkehgijcmpdhfbdbbnkijodmdjhbjlgp'}),'chrome');
});


test('DNR privacy and webRequest roots are compatibility-hosted instead of rejected', () => {
  const report=compatibility({manifest_version:3,name:'PB',version:'1',permissions:['declarativeNetRequest','privacy','webRequest'],host_permissions:['<all_urls>']});
  for(const api of ['declarativeNetRequest','privacy','webRequest']) assert.equal(report.unsupported.some((x)=>x.api===api),false,api+' should not be unsupported');
  assert.ok(report.warnings.some((x)=>x.api==='declarativeNetRequest'));
});

test('DNR modifyHeaders only permits privacy-strengthening removals', () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-dnr-headers-')),extRoot=path.join(root,'extensions','dnr-headers');
  try{
    fs.mkdirSync(extRoot,{recursive:true});
    const manifest={manifest_version:3,name:'DNR Headers',version:'1',permissions:['declarativeNetRequest'],host_permissions:['<all_urls>'],declarative_net_request:{rule_resources:[{id:'base',enabled:true,path:'rules.json'}]}};
    fs.writeFileSync(path.join(extRoot,'manifest.json'),JSON.stringify(manifest));
    fs.writeFileSync(path.join(extRoot,'rules.json'),JSON.stringify([{
      id:7,priority:2,
      action:{
        type:'modifyHeaders',
        requestHeaders:[
          {header:'Cookie',operation:'remove'},
          {header:'User-Agent',operation:'remove'},
          {header:'Referer',operation:'set',value:'https://bad.example/'}
        ],
        responseHeaders:[
          {header:'Set-Cookie',operation:'remove'},
          {header:'Content-Security-Policy',operation:'remove'}
        ]
      },
      condition:{urlFilter:'||tracker.example^',resourceTypes:['script']}
    }]));
    const tab={id:1,url:'https://site.example/',topUrl:'https://site.example/',securityDomain:'private',disableExtensions:false};
    const runtime=new AegisExtensionRuntime({rootDir:root,getTabs:()=>[tab],getActiveId:()=>1,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{},getSettings:()=>({})});
    runtime.items.set('dnr-headers',{id:'dnr-headers',path:extRoot,enabled:true,manifest,detectedApis:[],compatibility:compatibility(manifest)});
    const details={url:'https://tracker.example/ad.js',resourceType:'script',method:'GET'};
    assert.equal(runtime.networkDecision(tab,details),null);
    assert.deepEqual(runtime.headerModifications(tab,details,'request').map((x)=>x.header),['cookie']);
    assert.deepEqual(runtime.headerModifications(tab,details,'response').map((x)=>x.header),['set-cookie']);
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});

test('DNR block rules are enforced through the Aegis network decision bridge', () => {
  const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-dnr-')),extRoot=path.join(root,'extensions','dnr-test');
  try{
    fs.mkdirSync(extRoot,{recursive:true});
    const manifest={manifest_version:3,name:'DNR',version:'1',permissions:['declarativeNetRequest'],host_permissions:['<all_urls>'],declarative_net_request:{rule_resources:[{id:'base',enabled:true,path:'rules.json'}]}};
    fs.writeFileSync(path.join(extRoot,'manifest.json'),JSON.stringify(manifest));
    fs.writeFileSync(path.join(extRoot,'rules.json'),JSON.stringify([{id:1,priority:1,action:{type:'block'},condition:{urlFilter:'||tracker.example^',resourceTypes:['script']}}]));
    const tab={id:1,url:'https://site.example/',topUrl:'https://site.example/',securityDomain:'private',disableExtensions:false};
    const runtime=new AegisExtensionRuntime({rootDir:root,getTabs:()=>[tab],getActiveId:()=>1,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{},getSettings:()=>({})});
    runtime.items.set('dnr-test',{id:'dnr-test',path:extRoot,enabled:true,manifest,detectedApis:[],compatibility:compatibility(manifest)});
    const decision=runtime.networkDecision(tab,{url:'https://tracker.example/ad.js',resourceType:'script'});
    assert.equal(decision?.action,'block');
    assert.equal(decision?.ruleId,1);
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});


test('MV2 webRequestBlocking is bounded and compatibility-hosted', () => {
  const report=compatibility({manifest_version:2,name:'PB',version:'1',permissions:['webRequest','webRequestBlocking','<all_urls>'],background:{page:'background.html'}});
  assert.equal(report.unsupported.some((x)=>x.api==='webRequestBlocking'),false);
  assert.ok(report.supported.includes('webRequestBlocking'));
  assert.ok(report.warnings.some((x)=>x.api==='webRequestBlocking'));
});


test('Privacy Badger 2026.9.15 MV2 profile boots with its required Chrome APIs hosted', async () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-pb-mv2-')),extRoot=path.join(root,'extensions','privacy-badger');
  try{
    fs.mkdirSync(extRoot,{recursive:true});
    const manifest={
      manifest_version:2,name:'Privacy Badger',version:'2026.9.15',
      permissions:['<all_urls>','alarms','cookies','privacy','scripting','storage','tabs','webNavigation','webRequest','webRequestBlocking'],
      background:{page:'background.html'},
      browser_action:{default_popup:'skin/popup.html'},
      options_ui:{page:'/skin/options.html',open_in_tab:true},
      content_scripts:[{matches:['<all_urls>'],all_frames:true,run_at:'document_start',js:['js/contentscripts/utils.js']}]
    };
    fs.writeFileSync(path.join(extRoot,'manifest.json'),JSON.stringify(manifest));
    fs.writeFileSync(path.join(extRoot,'background.html'),'<!doctype html><script type="module" src="js/background.js"></script>');
    fs.mkdirSync(path.join(extRoot,'js','contentscripts'),{recursive:true});
    fs.writeFileSync(path.join(extRoot,'js','background.js'),'');
    fs.writeFileSync(path.join(extRoot,'js','contentscripts','utils.js'),'');
    fs.mkdirSync(path.join(extRoot,'skin'),{recursive:true});
    fs.writeFileSync(path.join(extRoot,'skin','popup.html'),'<!doctype html>');
    fs.writeFileSync(path.join(extRoot,'skin','options.html'),'<!doctype html>');
    const roots=['runtime','storage','tabs','cookies','privacy','scripting','webNavigation','webRequest','webRequestBlocking','browserAction','alarms'];
    const report=compatibility(manifest,roots);
    for(const api of roots)assert.equal(report.unsupported.some((x)=>x.api===api),false,api+' should remain hosted');
    assert.equal(report.background,'sandboxed-page');
    assert.ok(report.warnings.some((x)=>x.api==='content_scripts.all_frames'));

    const sender={};
    const runtime=new AegisExtensionRuntime({rootDir:root,getTabs:()=>[],getActiveId:()=>null,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{},getSettings:()=>({})});
    const e={id:'pkehgijcmpdhfbdbbnkijodmdjhbjlgp',path:extRoot,resourceToken:'pb-token',enabled:true,manifest,detectedApis:roots,compatibility:report};
    runtime.items.set(e.id,e);
    runtime.backgroundHosts.set(e.id,{isDestroyed:()=>false,webContents:sender});
    const bootstrapData=runtime.pageBootstrapData(sender,e.id,'background');
    assert.equal(bootstrapData.manifest.background.page,'background.html');
    assert.equal(bootstrapData.manifest.version,'2026.9.15');
    assert.match(runtime.publicRecord(e).optionsPage,/\/skin\/options\.html$/);

    const cookies=await runtime.call(sender,{extensionId:e.id,method:'cookies.getAll',args:[{firstPartyDomain:null}]});
    assert.deepEqual(cookies,[]);
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});


test('large extension manifests bootstrap over authenticated IPC instead of command-line arguments', () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-large-manifest-'));
  try{
    const runtime=new AegisExtensionRuntime({rootDir:root,getTabs:()=>[],getActiveId:()=>null,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{},getSettings:()=>({})});
    const extensionId='large-extension',sender={};
    const manifest={
      manifest_version:3,name:'Large Extension',version:'1',
      background:{service_worker:'background.js'},
      host_permissions:['<all_urls>'],
      content_scripts:[{matches:Array.from({length:3000},(_,i)=>'https://host'+i+'.example/*'),js:['content.js']}]
    };
    const e={id:extensionId,path:root,resourceToken:'large-token',enabled:true,manifest,detectedApis:[],compatibility:compatibility(manifest)};
    runtime.items.set(extensionId,e);
    runtime.backgroundHosts.set(extensionId,{isDestroyed:()=>false,webContents:sender});
    const args=runtime.pageArguments(e,'background');
    assert.ok(args.some((x)=>x.startsWith('--aegis-extension-id=')));
    assert.ok(args.some((x)=>x.startsWith('--aegis-extension-context=')));
    assert.equal(args.some((x)=>x.startsWith('--aegis-extension-manifest=')),false);
    assert.equal(args.some((x)=>x.startsWith('--aegis-extension-messages=')),false);
    assert.equal(args.some((x)=>x.startsWith('--aegis-extension-token=')),false);
    assert.ok(args.join(' ').length<512);
    const bootstrapData=runtime.pageBootstrapData(sender,extensionId,'background');
    assert.equal(bootstrapData.manifest.background.service_worker,'background.js');
    assert.equal(bootstrapData.manifest.content_scripts[0].matches.length,3000);
    assert.equal(bootstrapData.resourceToken,'large-token');
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});


test('renderer error diagnostics retain stack context for authenticated extension pages', () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-ext-errors-'));
  try{
    const sender={},runtime=new AegisExtensionRuntime({rootDir:root,getTabs:()=>[],getActiveId:()=>null,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    const manifest={manifest_version:2,name:'Runtime Errors',version:'1',background:{page:'background.html'}};
    const e={id:'runtime-errors',path:root,resourceToken:'token',enabled:true,manifest,detectedApis:[],compatibility:compatibility(manifest)};
    runtime.items.set(e.id,e);
    runtime.backgroundHosts.set(e.id,{isDestroyed:()=>false,webContents:sender});
    assert.equal(runtime.recordRendererError(sender,{extensionId:e.id,context:'background',message:'boom',stack:'TypeError: boom\n at js/utils.js:26:10'}),true);
    const health=runtime.healthFor(e.id);
    assert.match(health.errors[0].message,/js\/utils\.js:26/);
    assert.equal(health.errors[0].scope,'background-runtime');
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});


test('Privacy Badger 2026.9.15 MV3 profile preserves complete startup manifest', () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-pb-mv3-')),extRoot=path.join(root,'extensions','privacy-badger-mv3');
  try{
    fs.mkdirSync(extRoot,{recursive:true});
    const manifest={
      manifest_version:3,name:'Privacy Badger',version:'2026.9.15',
      permissions:['alarms','declarativeNetRequest','privacy','scripting','storage','tabs','webNavigation','webRequest'],
      host_permissions:['<all_urls>'],
      background:{service_worker:'js/background.js',type:'module'},
      action:{default_popup:'skin/popup.html'},
      content_scripts:[{matches:['<all_urls>'],all_frames:true,run_at:'document_start',js:['js/contentscripts/utils.js']}]
    };
    fs.mkdirSync(path.join(extRoot,'js','contentscripts'),{recursive:true});
    fs.mkdirSync(path.join(extRoot,'skin'),{recursive:true});
    fs.writeFileSync(path.join(extRoot,'manifest.json'),JSON.stringify(manifest));
    fs.writeFileSync(path.join(extRoot,'js','background.js'),'');
    fs.writeFileSync(path.join(extRoot,'js','contentscripts','utils.js'),'');
    fs.writeFileSync(path.join(extRoot,'skin','popup.html'),'<!doctype html>');
    const roots=['runtime','storage','tabs','privacy','scripting','webNavigation','webRequest','declarativeNetRequest','alarms','action'];
    const report=compatibility(manifest,roots);
    for(const api of roots)assert.equal(report.unsupported.some((x)=>x.api===api),false,api+' should remain hosted');
    const sender={},runtime=new AegisExtensionRuntime({rootDir:root,getTabs:()=>[],getActiveId:()=>null,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{},getSettings:()=>({})});
    const e={id:'pkehgijcmpdhfbdbbnkijodmdjhbjlgp',path:extRoot,resourceToken:'pb-mv3-token',enabled:true,manifest,detectedApis:roots,compatibility:report};
    runtime.items.set(e.id,e);
    runtime.backgroundHosts.set(e.id,{isDestroyed:()=>false,webContents:sender});
    const data=runtime.pageBootstrapData(sender,e.id,'background');
    assert.equal(data.manifest.manifest_version,3);
    assert.equal(data.manifest.background.service_worker,'js/background.js');
    assert.doesNotThrow(()=>Object.prototype.hasOwnProperty.call(data.manifest.background,'persistent'));
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});


test('Privacy Badger dynamic DNT script preserves matchOriginAsFallback and MAIN world', () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-pb-dynamic-script-')),extRoot=path.join(root,'extensions','privacy-badger');
  try{
    fs.mkdirSync(path.join(extRoot,'js','contentscripts'),{recursive:true});
    const manifest={manifest_version:2,name:'Privacy Badger',version:'2026.9.15',permissions:['scripting'],background:{page:'background.html'}};
    fs.writeFileSync(path.join(extRoot,'manifest.json'),JSON.stringify(manifest));
    fs.writeFileSync(path.join(extRoot,'background.html'),'<!doctype html>');
    fs.writeFileSync(path.join(extRoot,'js','contentscripts','dnt.js'),'globalThis.__pbDnt=true;');
    const runtime=new AegisExtensionRuntime({rootDir:root,getTabs:()=>[],getActiveId:()=>null,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    const e={id:'pkehgijcmpdhfbdbbnkijodmdjhbjlgp',path:extRoot,resourceToken:'pb-dynamic',enabled:true,manifest,detectedApis:['scripting'],compatibility:compatibility(manifest,['scripting'])};
    runtime.items.set(e.id,e);
    runtime.registerContentScripts(e,[{
      id:'dnt_signal',js:['js/contentscripts/dnt.js'],matches:['<all_urls>'],allFrames:true,
      matchOriginAsFallback:true,runAt:'document_start',world:'MAIN',persistAcrossSessions:false
    }]);
    const scripts=runtime.getRegisteredContentScripts(e,{ids:['dnt_signal']});
    assert.equal(scripts.length,1);
    assert.equal(scripts[0].allFrames,true);
    assert.equal(scripts[0].matchOriginAsFallback,true);
    assert.equal(scripts[0].world,'MAIN');
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});


test('Chrome MV2 toolbar API presence matches Privacy Badger feature detection', () => {
  const vm=require('node:vm');
  const ext={
    id:'pkehgijcmpdhfbdbbnkijodmdjhbjlgp',resourceToken:'pb-toolbar',path:__dirname,
    manifest:{manifest_version:2,name:'Privacy Badger',version:'2026.9.15',browser_action:{default_popup:'skin/popup.html'}}
  };
  const context={
    setTimeout,clearTimeout,
    __aegisExtensionBridge:{call:()=>Promise.resolve(),onMessage:()=>{},onEvent:()=>{}}
  };
  vm.runInNewContext(bootstrap(ext),context);
  assert.ok(context.chrome.browserAction);
  assert.equal(context.chrome.browserAction.getUserSettings,undefined);
  assert.equal(context.chrome.action,undefined);
});

test('Chrome MV3 toolbar API presence exposes action without legacy browserAction', () => {
  const vm=require('node:vm');
  const ext={
    id:'mv3-action-test',resourceToken:'mv3-toolbar',path:__dirname,
    manifest:{manifest_version:3,name:'MV3 Action',version:'1.0',action:{default_title:'Run'}}
  };
  const context={
    setTimeout,clearTimeout,
    __aegisExtensionBridge:{call:()=>Promise.resolve(),onMessage:()=>{},onEvent:()=>{}}
  };
  vm.runInNewContext(bootstrap(ext),context);
  assert.ok(context.chrome.action);
  assert.equal(typeof context.chrome.action.getUserSettings,'function');
  assert.equal(context.chrome.browserAction,undefined);
});


test('Privacy Badger browserAction badge state is isolated per tab', async () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'aegis-pb-badge-'));
  try{
    let active=1;
    const sender={},tabs=[
      {id:1,url:'https://one.example/',title:'One',loading:false,securityDomain:'private',disableExtensions:false,view:{webContents:{}}},
      {id:2,url:'https://two.example/',title:'Two',loading:false,securityDomain:'private',disableExtensions:false,view:{webContents:{}}}
    ];
    const runtime=new AegisExtensionRuntime({rootDir:root,getTabs:()=>tabs,getActiveId:()=>active,createTab:async()=>{},updateTab:async()=>{},removeTab:()=>{}});
    const manifest={manifest_version:2,name:'Privacy Badger',version:'2026.9.15',permissions:['tabs','<all_urls>'],browser_action:{default_title:'Privacy Badger'}};
    const e={id:'pkehgijcmpdhfbdbbnkijodmdjhbjlgp',path:root,resourceToken:'pb-badge',enabled:true,manifest,detectedApis:['browserAction'],compatibility:compatibility(manifest,['browserAction'])};
    runtime.items.set(e.id,e);
    runtime.backgroundHosts.set(e.id,{isDestroyed:()=>false,webContents:sender});

    await runtime.call(sender,{extensionId:e.id,method:'browserAction.setBadgeText',args:[{tabId:1,text:'3'}]});
    await runtime.call(sender,{extensionId:e.id,method:'browserAction.setBadgeText',args:[{tabId:2,text:'8'}]});
    assert.equal(await runtime.call(sender,{extensionId:e.id,method:'browserAction.getBadgeText',args:[{tabId:1}]}),'3');
    assert.equal(await runtime.call(sender,{extensionId:e.id,method:'browserAction.getBadgeText',args:[{tabId:2}]}),'8');
    assert.equal(runtime.publicRecord(e).action.badgeText,'3');
    active=2;
    assert.equal(runtime.publicRecord(e).action.badgeText,'8');
    runtime.notifyTabRemoved(1,true);
    assert.equal(await runtime.call(sender,{extensionId:e.id,method:'browserAction.getBadgeText',args:[{tabId:1}]}),'');
  }finally{fs.rmSync(root,{recursive:true,force:true})}
});


test('Privacy Badger all_urls host access includes WebSocket requests', () => {
  const manifest={manifest_version:2,name:'Privacy Badger',version:'2026.9.15',permissions:['<all_urls>','webRequest','webRequestBlocking']};
  assert.equal(networkAllowedByManifest(manifest,'ws://socket.example.test/live'),true);
  assert.equal(networkAllowedByManifest(manifest,'wss://socket.example.test/live'),true);
});
