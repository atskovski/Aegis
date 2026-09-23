'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { safeRel, normalizeManifest, compatibility, contentScriptPhase, matchPattern, matchingContentScripts, rewriteCssUrls, installRisk, extensionWorldId, bootstrap, AegisExtensionRuntime, hostPermissions, networkAllowedByManifest, extensionVisibleTab } = require('../src/core/extensions');

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
  assert.equal(contentScriptPhase({run_at:'document_start'}),'end');
  const report=compatibility({manifest_version:2,name:'T',version:'1',content_scripts:[{matches:['<all_urls>'],run_at:'document_start',js:['start.js']}]});
  assert.ok(report.warnings.some((x)=>x.api==='content_scripts.run_at'));
});

test('extension CSS relative assets are rewritten to private extension-resource URLs', () => {
  const ext={resourceToken:'abc123'};
  const css=rewriteCssUrls('.x{background:url("../img/icon.png")} .y{mask:url(data:image/png;base64,abc)}',ext,'styles/main.css');
  assert.match(css,/aegis-extension:\/\/ext\/abc123\/img\/icon\.png/);
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
