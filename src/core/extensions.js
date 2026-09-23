'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { webExtensionBootstrap, localeMessages, commandList } = require('./extension-shim');

const execFileAsync = promisify(execFile);
const SUPPORTED_ROOTS = new Set([
  'runtime','storage','tabs','permissions','i18n','activeTab',
  'action','browserAction','pageAction','alarms','commands','scripting','webNavigation'
]);
const DENIED_ROOTS = Object.freeze({
  webRequest:'Aegis owns the network firewall; blocking webRequest is not exposed.',
  webRequestBlocking:'Aegis owns the network firewall; blocking webRequest is not exposed.',
  declarativeNetRequest:'DNR import is not implemented yet.',
  proxy:'Extensions cannot replace Aegis network routing.',
  nativeMessaging:'Native messaging is disabled.',
  cookies:'Cookie API is withheld until per-tab cookie-store scoping is complete.',
  history:'Aegis deliberately does not keep a browsing-history database.',
  management:'Extensions cannot manage other extensions.',
  debugger:'The Chrome debugger API is not exposed to add-ons.',
  devtools:'DevTools extension pages are not supported by the Aegis shell.',
  experiments:'Firefox experiment APIs are not supported.',
  telemetry:'Browser telemetry APIs are not exposed.'
});

function readJson(file){ return JSON.parse(fs.readFileSync(file,'utf8')); }
function safeRel(v){
  v=String(v||'').replace(/\\/g,'/').replace(/^\.\//,'');
  if(!v||v.startsWith('/')||v.includes('\0')||v.split('/').some((x)=>!x||x==='.'||x==='..')) return '';
  return v;
}
function normalizeManifest(m){
  if(!m||typeof m!=='object') throw new Error('Invalid manifest.json.');
  if(![2,3].includes(Number(m.manifest_version))) throw new Error('Only WebExtensions manifest v2/v3 is supported.');
  if(!String(m.name||'').trim()||!String(m.version||'').trim()) throw new Error('Extension name/version is required.');
  return m;
}
function permissions(m){ return [...new Set([...(Array.isArray(m.permissions)?m.permissions:[]),...(Array.isArray(m.host_permissions)?m.host_permissions:[])])]; }
function hostPermissions(m){
  return permissions(m).filter((p)=>p === '<all_urls>' || /^(?:\*|https?):\/\//.test(String(p||'')));
}
function networkAllowedByManifest(m,url){
  const patterns=hostPermissions(m);
  return patterns.some((p)=>matchPattern(url,p));
}
function extensionVisibleTab(tab){
  return Boolean(tab && !tab.disableExtensions && tab.securityDomain!=='anonymous' && tab.securityDomain!=='hardened');
}
function extensionWorldId(id){
  const h=crypto.createHash('sha256').update(String(id)).digest();
  return 1100 + (h.readUInt32BE(0) % 50000);
}
function extensionId(m,digest){
  const id=m?.browser_specific_settings?.gecko?.id||m?.applications?.gecko?.id||('xpi-'+digest.slice(0,32));
  return String(id).toLowerCase().replace(/[^a-z0-9@._-]/g,'-').slice(0,120);
}
function apiRoots(m){
  const roots=new Set();
  for(const p of permissions(m)) if(p!=='<all_urls>'&&!/^(?:\*|https?|file):\/\//.test(p)) roots.add(p);
  if(m.background||m.content_scripts) roots.add('runtime');
  if(m.action) roots.add('action');
  if(m.browser_action) roots.add('browserAction');
  if(m.page_action) roots.add('pageAction');
  if(m.commands) roots.add('commands');
  return [...roots];
}
function extensionAction(m){
  const value=m?.action||m?.browser_action||m?.page_action||null;
  if(!value||typeof value!=='object')return null;
  return {
    kind:m?.action?'action':(m?.browser_action?'browserAction':'pageAction'),
    title:String(value.default_title||m.name||'Extension').slice(0,160),
    popup:safeRel(value.default_popup||''),
    icon:value.default_icon||m.icons||null
  };
}
function optionsPage(m){
  const raw=m?.options_ui?.page||m?.options_page||'';
  return safeRel(raw);
}
function iconPath(m){
  const source=extensionAction(m)?.icon||m?.icons||null;
  if(typeof source==='string')return safeRel(source);
  if(!source||typeof source!=='object')return '';
  const ranked=Object.entries(source).map(([size,value])=>({size:Number(size)||0,value:safeRel(value)})).filter((x)=>x.value).sort((a,b)=>b.size-a.size);
  return ranked[0]?.value||'';
}
function manifestFeatures(m){
  const action=extensionAction(m);
  const bg=m?.background||{};
  return {
    manifestVersion:Number(m?.manifest_version||0),
    contentScripts:Array.isArray(m?.content_scripts)?m.content_scripts.length:0,
    action:Boolean(action),
    actionKind:action?.kind||'',
    popup:Boolean(action?.popup),
    options:Boolean(optionsPage(m)),
    commands:Object.keys(m?.commands||{}).length,
    backgroundPage:Boolean(bg.page),
    backgroundScripts:Array.isArray(bg.scripts)?bg.scripts.length:0,
    serviceWorker:Boolean(bg.service_worker),
    webAccessibleResources:Array.isArray(m?.web_accessible_resources)?m.web_accessible_resources.length:0
  };
}
function compatibility(m,detectedRoots=[]){
  const unsupported=[],supported=[],warnings=[];
  const roots=[...new Set([...apiRoots(m),...(Array.isArray(detectedRoots)?detectedRoots:[])])];
  for(const root of roots){
    if(SUPPORTED_ROOTS.has(root)) supported.push(root);
    else unsupported.push({api:root,reason:DENIED_ROOTS[root]||'API not implemented by Aegis Extension Runtime.'});
  }
  const features=manifestFeatures(m);
  const contentEntries=Array.isArray(m.content_scripts)?m.content_scripts:[];
  if(contentEntries.some((e)=>e?.run_at==='document_start')) warnings.push({api:'content_scripts.run_at',reason:'document_start uses the earliest Electron DOM-ready compatible phase; exact Firefox pre-page-script timing is not guaranteed.'});
  if(contentEntries.some((e)=>e?.all_frames)) warnings.push({api:'content_scripts.all_frames',reason:'Aegis currently injects into the top-level document only.'});
  if(Array.isArray(m.optional_permissions)&&m.optional_permissions.length) warnings.push({api:'optional_permissions',reason:'Optional permissions require explicit user approval in Aegis and are not auto-granted.'});
  if(Array.isArray(m.optional_host_permissions)&&m.optional_host_permissions.length) warnings.push({api:'optional_host_permissions',reason:'Optional host access requires explicit user approval in Aegis and is not auto-granted.'});
  const bg=m.background||{};
  let background='none', backgroundCredit=0;
  if(bg.page){
    background='sandboxed-page'; backgroundCredit=1;
    warnings.push({api:'background.page',reason:'Background pages run in a sandboxed Aegis extension window with Aegis WebExtension APIs; Firefox browser internals remain unavailable.'});
  } else if((Array.isArray(bg.scripts)&&bg.scripts.length)||bg.service_worker){
    background='sandboxed-emulation'; backgroundCredit=1;
    warnings.push({api:'background',reason:bg.service_worker?'MV3 service-worker code runs in a sandboxed persistent Aegis background host; service-worker suspension semantics differ from Chromium.':'Background scripts run in a sandboxed Aegis background host.'});
  }
  if(m.sidebar_action) unsupported.push({api:'sidebarAction',reason:'Firefox sidebar_action is not implemented in the Aegis shell yet.'});
  if(m.omnibox) unsupported.push({api:'omnibox',reason:'Extension omnibox keyword providers are not implemented yet.'});
  if(m.devtools_page) unsupported.push({api:'devtools_page',reason:'DevTools extension pages are disabled because remote DevTools is not exposed.'});
  const capabilityCount=roots.length+(features.contentScripts?1:0)+(background!=='none'?1:0)+(features.action?1:0)+(features.options?1:0);
  const supportedCount=supported.length+(features.contentScripts?1:0)+backgroundCredit+(features.action?1:0)+(features.options?1:0);
  const penalty=Math.min(unsupported.length,Math.max(1,capabilityCount));
  const score=Math.max(0,Math.min(100,Math.round(100*(supportedCount/Math.max(1,capabilityCount+penalty*0.6)))));
  const status=unsupported.length===0?(warnings.length?'good':'excellent'):(score>=70?'partial':'limited');
  return {score,status,supported,unsupported,warnings,contentScripts:features.contentScripts,background,features,detectedApis:[...new Set(detectedRoots)].sort()};
}
function matchPattern(url,p){
  if(p==='<all_urls>') return /^https?:/.test(url);
  let u; try{u=new URL(url);}catch{return false;}
  const m=String(p||'').match(/^(\*|https?):\/\/([^/]+)(\/.*)$/); if(!m)return false;
  if(m[1]!=='*'&&u.protocol!==m[1]+':')return false;
  const h=m[2].toLowerCase(), host=u.hostname.toLowerCase();
  if(h!=='*' && !(h.startsWith('*.')?(host===h.slice(2)||host.endsWith('.'+h.slice(2))):host===h)) return false;
  const escaped=m[3].split('*').map((x)=>x.replace(/[.+?^$()|[\]\\]/g,'\\$&')).join('.*');
  return new RegExp('^'+escaped+'$').test(u.pathname+u.search);
}
function contentScriptPhase(entry){
  const runAt=String(entry?.run_at||'document_idle');
  if(runAt==='document_idle')return 'idle';
  // Electron cannot inject this compatibility runtime before the page's own
  // document-start scripts. document_start is therefore a documented,
  // conservative DOM-ready fallback rather than a false compatibility claim.
  return 'end';
}
function matchingContentScripts(m,url,phase=null){
  return (Array.isArray(m.content_scripts)?m.content_scripts:[]).filter((e)=>{
    const inc=Array.isArray(e.matches)?e.matches:[], exc=Array.isArray(e.exclude_matches)?e.exclude_matches:[];
    const matched=inc.some((p)=>matchPattern(url,p))&&!exc.some((p)=>matchPattern(url,p));
    return matched && (!phase || contentScriptPhase(e)===phase);
  });
}
function extensionResourceUrl(ext, rel){
  const safe=safeRel(rel); if(!safe)return '';
  return 'aegis-extension://'+ext.resourceToken+'/'+safe.split('/').map(encodeURIComponent).join('/');
}
function rewriteCssUrls(css, ext, cssRel=''){
  const base=path.posix.dirname(String(cssRel||'').replace(/\\/g,'/'));
  return String(css||'').replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi,(whole,_quote,raw)=>{
    const value=String(raw||'').trim();
    if(!value||/^(?:data:|https?:|blob:|aegis-extension:|#|\/)/i.test(value))return whole;
    const combined=path.posix.normalize(path.posix.join(base==='.'?'':base,value));
    const resolved=extensionResourceUrl(ext,combined);
    return resolved?'url("'+resolved.replace(/"/g,'%22')+'")':whole;
  });
}
function installRisk(m){
  return permissions(m).map((p)=>({permission:p,level:(p==='<all_urls>'||p==='*://*/*'||DENIED_ROOTS[p])?'high':(/:\/\//.test(p)||['tabs','activeTab','storage'].includes(p)?'medium':'low')}));
}
async function zipEntries(file){
  const st=fs.statSync(file); if(!st.isFile()||st.size>64*1024*1024) throw new Error('XPI must be smaller than 64 MB.');
  const r=await execFileAsync('/usr/bin/unzip',['-Z1',file],{maxBuffer:4*1024*1024});
  const entries=r.stdout.split(/\r?\n/).map((x)=>x.trim()).filter(Boolean); if(!entries.length||entries.length>5000)throw new Error('Invalid XPI file count.');
  for(const e of entries) if(!safeRel(e.replace(/\/$/,'')))throw new Error('Unsafe XPI path: '+e);
  return entries;
}
function scanUsedApiRoots(root){
  const roots=new Set(),extensions=new Set(['.js','.mjs','.cjs','.html','.htm']),maxFile=2*1024*1024,maxTotal=12*1024*1024;
  let total=0,files=0;
  const walk=(dir)=>{
    for(const name of fs.readdirSync(dir)){
      if(files>500||total>maxTotal)return;
      const full=path.join(dir,name),stat=fs.lstatSync(full);
      if(stat.isDirectory()){if(!/^_locales$/i.test(name))walk(full);continue;}
      if(!stat.isFile()||!extensions.has(path.extname(name).toLowerCase())||stat.size>maxFile)continue;
      files+=1;total+=stat.size;
      let source='';try{source=fs.readFileSync(full,'utf8')}catch{continue}
      for(const match of source.matchAll(/\b(?:browser|chrome)\.([A-Za-z_$][\w$]*)/g))roots.add(match[1]);
    }
  };
  walk(root);return [...roots].sort();
}
function validateExtractedTree(root){
  let total=0, count=0;
  const walk=(dir)=>{
    for(const name of fs.readdirSync(dir)){
      const full=path.join(dir,name); const stat=fs.lstatSync(full);
      if(stat.isSymbolicLink()) throw new Error('XPI symlinks are not allowed: '+name);
      if(stat.isDirectory()) { walk(full); continue; }
      if(!stat.isFile()) throw new Error('Unsupported XPI filesystem entry: '+name);
      count += 1; total += stat.size;
      if(stat.size > 16*1024*1024) throw new Error('XPI contains a file larger than 16 MB: '+name);
      if(total > 128*1024*1024) throw new Error('Expanded XPI exceeds the 128 MB safety limit.');
      if(count > 5000) throw new Error('Expanded XPI exceeds the file-count limit.');
    }
  };
  walk(root); return {files:count,bytes:total};
}
async function inspectXpi(file,tmpRoot){
  const entries=await zipEntries(file); const tmp=path.join(tmpRoot,'inspect-'+crypto.randomUUID()); fs.mkdirSync(tmp,{recursive:true,mode:0o700});
  try{
    await execFileAsync('/usr/bin/unzip',['-qq','-o',file,'-d',tmp],{maxBuffer:4*1024*1024});
    validateExtractedTree(tmp);
    let root=tmp; if(!fs.existsSync(path.join(root,'manifest.json'))){const dirs=fs.readdirSync(tmp,{withFileTypes:true}).filter((x)=>x.isDirectory()); if(dirs.length===1)root=path.join(tmp,dirs[0].name);}
    const manifest=normalizeManifest(readJson(path.join(root,'manifest.json')));
    const detectedApis=scanUsedApiRoots(root);
    const signatureMetadata=entries.some((e)=>/^META-INF\/(?:mozilla\.rsa|mozilla\.sf|manifest\.mf)$/i.test(e));
    return {root,tmp,manifest,detectedApis,compatibility:compatibility(manifest,detectedApis),risk:installRisk(manifest),signature:{metadataPresent:signatureMetadata,verified:false}};
  }catch(err){try{fs.rmSync(tmp,{recursive:true,force:true});}catch{} throw err;}
}
function bootstrap(ext){ return webExtensionBootstrap(ext,'__aegisExtensionBridge'); }
function readStore(file){try{return readJson(file)}catch{return {}}}
function writeStore(file,v){fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});fs.writeFileSync(file,JSON.stringify(v,null,2),{mode:0o600})}
function getKeys(store,keys){
  if(keys==null)return {...store}; if(typeof keys==='string')return {[keys]:store[keys]};
  if(Array.isArray(keys))return Object.fromEntries(keys.filter((k)=>Object.prototype.hasOwnProperty.call(store,k)).map((k)=>[k,store[k]]));
  if(typeof keys==='object')return Object.fromEntries(Object.entries(keys).map(([k,d])=>[k,Object.prototype.hasOwnProperty.call(store,k)?store[k]:d])); return {};
}
class AegisExtensionRuntime{
  constructor({rootDir,getTabs,getActiveId,createTab,updateTab,removeTab,BrowserWindow,electronSession,registerProtocols,browserVersion}){
    this.rootDir=rootDir;this.installDir=path.join(rootDir,'extensions');this.indexFile=path.join(this.installDir,'index.json');this.dataDir=path.join(rootDir,'extension-data');
    this.getTabs=getTabs;this.getActiveId=getActiveId||(()=>null);this.createTab=createTab;this.updateTab=updateTab;this.removeTab=removeTab;this.BrowserWindow=BrowserWindow;this.electronSession=electronSession;this.registerProtocols=registerProtocols;
    this.items=new Map();this.sessionStores=new Map();this.backgroundHosts=new Map();this.pendingMessages=new Map();this.pendingInstalls=new Map();this.suspensionReasons=new Set();this.actionState=new Map();this.alarmTimers=new Map();this.pageWindows=new Set();this.pageSessions=new Map();this.activeGrants=new Map();this.cssKeys=new Map();this.runtimeHealth=new Map();this.browserVersion=String(browserVersion||'1.1');
    fs.mkdirSync(this.installDir,{recursive:true,mode:0o700}); this.load(); this.save();
  }
  load(){let rows=[];try{rows=readJson(this.indexFile)}catch{} for(const row of Array.isArray(rows)?rows:[]){try{const manifest=normalizeManifest(readJson(path.join(row.path,'manifest.json')));this.items.set(row.id,{...row,worldId:row.worldId||extensionWorldId(row.id),resourceToken:row.resourceToken||crypto.randomBytes(18).toString('hex'),manifest,compatibility:compatibility(manifest,row.detectedApis||[])})}catch{}}}
  save(){writeStore(this.indexFile,[...this.items.values()].map(({manifest,compatibility,...r})=>r))}
  healthFor(id){
    if(!this.runtimeHealth.has(id))this.runtimeHealth.set(id,{errors:[],lastStartedAt:'',lastInjectionAt:''});
    return this.runtimeHealth.get(id);
  }
  noteRuntimeError(id,scope,error){
    const health=this.healthFor(id),message=String(error?.message||error||'Unknown extension runtime error').slice(0,500);
    health.errors.unshift({scope:String(scope||'runtime'),message,at:new Date().toISOString()});health.errors=health.errors.slice(0,8);
  }
  clearRuntimeErrors(id,scope=''){
    const health=this.healthFor(id);health.errors=scope?health.errors.filter((x)=>x.scope!==scope):[];
  }
  publicRecord(e){
    const action=extensionAction(e.manifest);
    const icon=iconPath(e.manifest);
    const options=optionsPage(e.manifest);
    const state=this.actionState.get(e.id)||{},health=this.healthFor(e.id),backgroundExpected=Boolean(e.manifest?.background&&(e.manifest.background.page||e.manifest.background.service_worker||(Array.isArray(e.manifest.background.scripts)&&e.manifest.background.scripts.length)));
    return {
      id:e.id,name:e.manifest.name,version:e.manifest.version,description:String(e.manifest.description||''),
      manifestVersion:Number(e.manifest.manifest_version||0),enabled:e.enabled!==false,worldId:e.worldId||extensionWorldId(e.id),
      compatibility:e.compatibility,risk:installRisk(e.manifest),installedAt:e.installedAt||'',updatedAt:e.updatedAt||'',
      source:e.source||'xpi',digest:e.digest||'',permissions:permissions(e.manifest),hostPermissions:hostPermissions(e.manifest),
      optionalPermissions:[...(Array.isArray(e.manifest.optional_permissions)?e.manifest.optional_permissions:[]),...(Array.isArray(e.manifest.optional_host_permissions)?e.manifest.optional_host_permissions:[])],
      detectedApis:Array.isArray(e.detectedApis)?e.detectedApis:[],
      runtime:{backgroundExpected,backgroundRunning:backgroundExpected?Boolean(this.backgroundHosts.get(e.id)&&!this.backgroundHosts.get(e.id).isDestroyed()):false,status:e.enabled===false?'disabled':(health.errors.length?'degraded':(backgroundExpected?(this.backgroundHosts.has(e.id)?'running':'stopped'):'ready')),errors:[...health.errors],lastStartedAt:health.lastStartedAt,lastInjectionAt:health.lastInjectionAt},
      action:action?{...action,title:String(state.title||action.title),badgeText:String(state.badgeText||''),iconUrl:icon?extensionResourceUrl(e,icon):''}:null,
      optionsPage:options?extensionResourceUrl(e,options):'',
      features:manifestFeatures(e.manifest)
    };
  }
  list(){return [...this.items.values()].map((e)=>this.publicRecord(e))}
  bridgeArguments(){return this.enabled().map((e)=>'--aegis-extension-world='+encodeURIComponent(e.id)+':'+String(e.worldId||extensionWorldId(e.id)))}
  async inspect(file){
    const digest=crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    const x=await inspectXpi(file,path.join(this.rootDir,'extension-staging'));
    try{
      const id=extensionId(x.manifest,digest);
      return {
        id,name:x.manifest.name,version:x.manifest.version,description:String(x.manifest.description||''),
        manifestVersion:Number(x.manifest.manifest_version||0),compatibility:x.compatibility,risk:x.risk,signature:x.signature,
        digest,permissions:permissions(x.manifest),hostPermissions:hostPermissions(x.manifest),detectedApis:x.detectedApis||[],
        optionalPermissions:[...(Array.isArray(x.manifest.optional_permissions)?x.manifest.optional_permissions:[]),...(Array.isArray(x.manifest.optional_host_permissions)?x.manifest.optional_host_permissions:[])],
        action:extensionAction(x.manifest),optionsPage:optionsPage(x.manifest),features:manifestFeatures(x.manifest)
      };
    }finally{try{fs.rmSync(x.tmp,{recursive:true,force:true})}catch{}}
  }
  async stage(file){
    const summary=await this.inspect(file);
    const token=crypto.randomUUID();
    const expiresAt=Date.now()+5*60*1000;
    this.pendingInstalls.set(token,{file:String(file),summary,expiresAt});
    for(const [key,value] of this.pendingInstalls) if(value.expiresAt<Date.now())this.pendingInstalls.delete(key);
    return {token,summary,expiresAt:new Date(expiresAt).toISOString()};
  }
  cancelStage(token){return this.pendingInstalls.delete(String(token||''))}
  reviewStage(token){const staged=this.pendingInstalls.get(String(token||''));return staged&&staged.expiresAt>=Date.now()?staged.summary:null}
  async installStaged(token){
    const staged=this.pendingInstalls.get(String(token||''));
    if(!staged||staged.expiresAt<Date.now()){this.pendingInstalls.delete(String(token||''));throw new Error('Extension review expired. Select the package again.');}
    this.pendingInstalls.delete(String(token||''));
    return this.install(staged.file);
  }
  async install(file){
    const digest=crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'), x=await inspectXpi(file,path.join(this.rootDir,'extension-staging')), id=extensionId(x.manifest,digest), dest=path.join(this.installDir,id);
    const previous=this.items.get(id);
    this.stopBackground(id);
    fs.rmSync(dest,{recursive:true,force:true}); fs.renameSync(x.root,dest); if(x.tmp!==x.root)try{fs.rmSync(x.tmp,{recursive:true,force:true})}catch{}
    const now=new Date().toISOString();
    const e={id,path:dest,worldId:extensionWorldId(id),resourceToken:previous?.resourceToken||crypto.randomBytes(18).toString('hex'),enabled:previous?.enabled!==false,source:'xpi',digest,installedAt:previous?.installedAt||now,updatedAt:now,manifest:x.manifest,detectedApis:x.detectedApis||[],compatibility:x.compatibility};
    this.items.set(id,e);this.save();if(e.enabled)await this.startBackground(e);this.emitEvent(e,'runtime.onInstalled',[{reason:previous?'update':'install',previousVersion:previous?.manifest?.version||undefined}]);return this.publicRecord(e);
  }
  async setEnabled(id,v){const e=this.items.get(id);if(!e)throw new Error('Extension not found');e.enabled=Boolean(v);this.save();if(e.enabled){await this.startBackground(e);this.emitEvent(e,'runtime.onStartup',[]);}else this.stopBackground(id);return this.publicRecord(e)}
  remove(id){const e=this.items.get(id);if(!e)return false;this.stopBackground(id);this.clearAllAlarms(id);this.items.delete(id);this.sessionStores.delete(id);this.actionState.delete(id);this.runtimeHealth.delete(id);this.activeGrants.delete(id);this.save();try{fs.rmSync(e.path,{recursive:true,force:true})}catch{}try{fs.rmSync(path.join(this.dataDir,id),{recursive:true,force:true})}catch{}return true}
  enabled(){return [...this.items.values()].filter((e)=>e.enabled!==false)}
  extensionFor(id){const e=this.items.get(String(id||''));if(!e||e.enabled===false)throw new Error('Extension disabled or missing');return e}
  tabById(id){return this.getTabs().find((t)=>t.id===Number(id))}
  canAccessTab(e,tab,{inject=false}={}){
    if(!extensionVisibleTab(tab))return false;
    if(!inject)return permissions(e.manifest).includes('tabs')||networkAllowedByManifest(e.manifest,tab.url||'')||this.activeGrants.get(e.id)?.has(tab.id);
    return networkAllowedByManifest(e.manifest,tab.url||'')||this.activeGrants.get(e.id)?.has(tab.id);
  }
  publicTab(e,tab){
    if(!tab||!extensionVisibleTab(tab))return null;
    const mayRead=this.canAccessTab(e,tab);
    return {id:tab.id,index:Math.max(0,this.getTabs().filter(extensionVisibleTab).findIndex((x)=>x.id===tab.id)),windowId:1,url:mayRead?(tab.url||''):'',title:mayRead?(tab.title||''):'',active:tab.id===this.getActiveId(),highlighted:tab.id===this.getActiveId(),incognito:true,status:tab.loading?'loading':'complete',pinned:false,audible:false,mutedInfo:{muted:false}};
  }
  emitEvent(e,type,args=[]){
    if(!e||e.enabled===false)return;
    const payload={extensionId:e.id,type:String(type||''),args:Array.isArray(args)?args:[]};
    const host=this.backgroundHosts.get(e.id);
    if(host&&!host.isDestroyed())try{host.webContents.send('extension:event',payload)}catch{}
    for(const tab of this.getTabs()){
      if(!extensionVisibleTab(tab)||!tab?.view?.webContents||tab.view.webContents.isDestroyed())continue;
      try{tab.view.webContents.send('extension:event',payload)}catch{}
    }
    for(const win of this.pageWindows){
      if(win.__aegisExtensionId===e.id&&!win.isDestroyed())try{win.webContents.send('extension:event',payload)}catch{}
    }
  }
  emitEventAll(type,argsForExtension){
    for(const e of this.enabled()){
      const args=typeof argsForExtension==='function'?argsForExtension(e):argsForExtension;
      if(args!==null&&args!==undefined)this.emitEvent(e,type,args);
    }
  }
  clearActiveGrantForTab(tabId){for(const grants of this.activeGrants.values())grants.delete(Number(tabId))}
  notifyTabCreated(tab){this.emitEventAll('tabs.onCreated',(e)=>{const value=this.publicTab(e,tab);return value?[value]:null})}
  notifyTabActivated(tab){this.emitEventAll('tabs.onActivated',(e)=>this.publicTab(e,tab)?[{tabId:tab.id,windowId:1}]:null)}
  notifyTabUpdated(tab,changeInfo={}){
    this.emitEventAll('tabs.onUpdated',(e)=>{const value=this.publicTab(e,tab);return value?[tab.id,{...changeInfo},value]:null});
  }
  notifyTabRemoved(tabId,wasVisible=true){if(!wasVisible)return;this.emitEventAll('tabs.onRemoved',[Number(tabId),{windowId:1,isWindowClosing:false}])}
  notifyNavigation(type,tab,url,error=''){
    const eventName=String(type||'');
    this.emitEventAll(eventName,(e)=>{
      if(!permissions(e.manifest).includes('webNavigation')||!this.publicTab(e,tab))return null;
      return [{tabId:tab.id,url:String(url||''),frameId:0,parentFrameId:-1,timeStamp:Date.now(),error:String(error||'')}];
    });
  }
  commandMatchesInput(shortcut,input={}){
    const parts=String(shortcut||'').split('+').map((x)=>x.trim()).filter(Boolean);if(!parts.length)return false;
    const key=String(parts.pop()||'').toLowerCase(),actual=String(input.key||'').toLowerCase();
    const aliases={comma:',',period:'.',space:' ',pageup:'pageup',pagedown:'pagedown',home:'home',end:'end',insert:'insert',delete:'delete'};
    const expected=aliases[key]||key;
    if(actual!==expected&&String(input.code||'').toLowerCase()!==expected)return false;
    const wantShift=parts.some((x)=>/^shift$/i.test(x));
    const wantAlt=parts.some((x)=>/^(?:alt|option)$/i.test(x));
    const wantCtrl=parts.some((x)=>/^(?:ctrl|control|macctrl)$/i.test(x));
    const wantMeta=parts.some((x)=>/^(?:command|cmd|meta|commandorcontrol)$/i.test(x));
    const commandOrControl=parts.some((x)=>/^commandorcontrol$/i.test(x));
    if(Boolean(input.shift)!==wantShift||Boolean(input.alt)!==wantAlt)return false;
    if(commandOrControl){if(!(input.meta||input.control))return false;}
    else if(Boolean(input.control)!==wantCtrl||Boolean(input.meta)!==wantMeta)return false;
    return true;
  }
  dispatchCommandInput(input={}){
    if(String(input.type||'').toLowerCase()!=='keydown')return false;
    let handled=false;
    for(const e of this.enabled()){
      for(const command of commandList(e.manifest)){
        if(command.shortcut&&this.commandMatchesInput(command.shortcut,input)){
          this.emitEvent(e,'commands.onCommand',[command.name]);
          handled=true;
        }
      }
    }
    return handled;
  }
  alarmKey(id,name){return String(id)+':'+String(name||'')}
  alarmList(id){const prefix=String(id)+':';return [...this.alarmTimers.entries()].filter(([key])=>key.startsWith(prefix)).map(([,value])=>value.alarm)}
  clearAlarm(id,name){const key=this.alarmKey(id,name),entry=this.alarmTimers.get(key);if(!entry)return false;clearTimeout(entry.timer);this.alarmTimers.delete(key);return true}
  clearAllAlarms(id){let changed=false;for(const key of [...this.alarmTimers.keys()])if(key.startsWith(String(id)+':')){const entry=this.alarmTimers.get(key);clearTimeout(entry?.timer);this.alarmTimers.delete(key);changed=true}return changed}
  createAlarm(e,name,info={}){
    name=String(name||'');this.clearAlarm(e.id,name);
    const delayMs=Number.isFinite(Number(info.when))?Math.max(0,Number(info.when)-Date.now()):Math.max(0,Number(info.delayInMinutes||0)*60000);
    const periodMs=Number(info.periodInMinutes)>0?Math.max(60000,Number(info.periodInMinutes)*60000):0;
    const alarm={name,scheduledTime:Date.now()+delayMs,periodInMinutes:periodMs?periodMs/60000:undefined};
    const fire=()=>{if(!this.items.has(e.id)||e.enabled===false)return;alarm.scheduledTime=Date.now();this.emitEvent(e,'alarms.onAlarm',[{...alarm}]);if(periodMs){alarm.scheduledTime=Date.now()+periodMs;const timer=setTimeout(fire,periodMs);this.alarmTimers.set(this.alarmKey(e.id,name),{timer,alarm})}else this.alarmTimers.delete(this.alarmKey(e.id,name))};
    const timer=setTimeout(fire,delayMs);this.alarmTimers.set(this.alarmKey(e.id,name),{timer,alarm});return undefined;
  }
  pageArguments(e,context='page'){
    const enc=(value)=>Buffer.from(JSON.stringify(value),'utf8').toString('base64url');
    return [
      '--aegis-extension-id='+encodeURIComponent(e.id),
      '--aegis-extension-token='+encodeURIComponent(e.resourceToken),
      '--aegis-extension-context='+encodeURIComponent(context),
      '--aegis-extension-manifest='+enc(e.manifest),
      '--aegis-extension-messages='+enc(localeMessages(e))
    ];
  }
  extensionSession(e){
    if(this.pageSessions.has(e.id))return this.pageSessions.get(e.id);
    const ses=this.electronSession.fromPartition('aegis-extension-page-'+crypto.createHash('sha256').update(e.id).digest('hex').slice(0,24),{cache:false});
    try{ses.webRequest.onBeforeRequest({urls:['http://*/*','https://*/*']},(details,callback)=>callback({cancel:!networkAllowedByManifest(e.manifest,details.url)}))}catch{}
    if(typeof this.registerProtocols==='function')this.registerProtocols(ses.protocol,'extension page '+e.id);
    this.pageSessions.set(e.id,ses);return ses;
  }
  async openExtensionPage(id,rel,{parent=null,title='',width=620,height=720,context='page'}={}){
    const e=this.extensionFor(id),safe=safeRel(rel);if(!safe)throw new Error('Extension page is not configured.');
    const target=path.resolve(e.path,safe),root=path.resolve(e.path)+path.sep;
    if(!target.startsWith(root)||!fs.existsSync(target)||!fs.statSync(target).isFile())throw new Error('Extension page does not exist: '+safe);
    const win=new this.BrowserWindow({
      parent:parent&&!parent.isDestroyed?.()?parent:undefined,show:false,width:Math.max(360,Math.min(900,width)),height:Math.max(300,Math.min(900,height)),
      minWidth:320,minHeight:240,title:title||e.manifest.name,backgroundColor:'#10141d',autoHideMenuBar:true,
      webPreferences:{sandbox:true,contextIsolation:true,nodeIntegration:false,webSecurity:true,devTools:false,session:this.extensionSession(e),preload:path.join(__dirname,'..','extension-page-preload.js'),additionalArguments:this.pageArguments(e,context)}
    });
    win.__aegisExtensionId=e.id;this.pageWindows.add(win);win.on('closed',()=>this.pageWindows.delete(win));
    await win.loadURL(extensionResourceUrl(e,safe));win.show();return true;
  }
  async openOptions(id,parent=null){const e=this.extensionFor(id),page=optionsPage(e.manifest);if(!page)throw new Error('This extension does not provide an options page.');return this.openExtensionPage(e.id,page,{parent,title:e.manifest.name+' — Options',width:760,height:760,context:'options'})}
  async openAction(id,parent=null){
    const e=this.extensionFor(id),action=extensionAction(e.manifest);if(!action)throw new Error('This extension does not expose a toolbar action.');
    const active=this.tabById(this.getActiveId());if(active&&extensionVisibleTab(active)){if(!this.activeGrants.has(e.id))this.activeGrants.set(e.id,new Set());this.activeGrants.get(e.id).add(active.id)}
    const state=this.actionState.get(e.id)||{},popup=safeRel(state.popup||action.popup||'');
    if(popup)return this.openExtensionPage(e.id,popup,{parent,title:state.title||action.title,width:440,height:600,context:'popup'});
    const tab=this.publicTab(e,active);if(tab){this.emitEvent(e,action.kind+'.onClicked',[tab]);if(action.kind!=='action')this.emitEvent(e,'action.onClicked',[tab])}return true;
  }
  resolveResource(token, rel){
    const ext=[...this.items.values()].find((e)=>e.enabled!==false && e.resourceToken===String(token||''));
    const safe=safeRel(rel); if(!ext||!safe)return null;
    const target=path.resolve(ext.path,safe), root=path.resolve(ext.path)+path.sep;
    if(!target.startsWith(root)||!fs.existsSync(target)||!fs.statSync(target).isFile())return null;
    return {extensionId:ext.id,path:target,relative:safe};
  }
  async inject(tab,phase='idle'){
    if(tab?.disableExtensions || tab?.securityDomain === 'anonymous' || tab?.securityDomain === 'hardened') return [];
    if(!tab?.view?.webContents||tab.view.webContents.isDestroyed())return [];
    const url=tab.view.webContents.getURL(); if(!/^https?:\/\//.test(url))return [];
    if(!tab.extensionInjectionKeys)tab.extensionInjectionKeys=new Set();
    const done=[];
    for(const e of this.enabled()){
      const all=Array.isArray(e.manifest.content_scripts)?e.manifest.content_scripts:[];
      for(let index=0;index<all.length;index++){
        const entry=all[index];
        if(contentScriptPhase(entry)!==phase||!matchingContentScripts({content_scripts:[entry]},url,phase).length)continue;
        const key=e.id+':'+index+':'+phase;
        if(tab.extensionInjectionKeys.has(key))continue;
        const scripts=[{code:bootstrap(e)}];
        for(const rel of Array.isArray(entry.js)?entry.js:[]){
          const s=safeRel(rel),f=path.resolve(e.path,s);
          if(s&&f.startsWith(path.resolve(e.path)+path.sep)&&fs.existsSync(f))scripts.push({code:fs.readFileSync(f,'utf8')});
        }
        let scriptOk=scripts.length===1;
        if(scripts.length>1){
          try{await tab.view.webContents.executeJavaScriptInIsolatedWorld(e.worldId||extensionWorldId(e.id),scripts,false);scriptOk=true;done.push(e.id);const health=this.healthFor(e.id);health.lastInjectionAt=new Date().toISOString();this.clearRuntimeErrors(e.id,'content-script')}catch(err){this.noteRuntimeError(e.id,'content-script',err)}
        }
        const cssParts=[];
        for(const rel of Array.isArray(entry.css)?entry.css:[]){
          const s=safeRel(rel),f=path.resolve(e.path,s);
          if(s&&f.startsWith(path.resolve(e.path)+path.sep)&&fs.existsSync(f))cssParts.push(rewriteCssUrls(fs.readFileSync(f,'utf8'),e,s));
        }
        if(cssParts.length)try{await tab.view.webContents.insertCSS(cssParts.join('\n'),{cssOrigin:'author'});done.push(e.id)}catch(err){this.noteRuntimeError(e.id,'content-css',err)}
        if(scriptOk||cssParts.length)tab.extensionInjectionKeys.add(key);
      }
    }
    return [...new Set(done)];
  }
  extensionFile(e,rel){
    const safe=safeRel(rel),file=safe?path.resolve(e.path,safe):'',root=path.resolve(e.path)+path.sep;
    if(!safe||!file.startsWith(root)||!fs.existsSync(file)||!fs.statSync(file).isFile())throw new Error('Extension file not found: '+String(rel||''));
    return file;
  }
  async executeExtensionScript(e,tab,details={}){
    if(!this.canAccessTab(e,tab,{inject:true}))throw new Error('Extension lacks host or activeTab access to this tab.');
    if(details.allFrames||details.target?.allFrames)throw new Error('allFrames script injection is not supported yet.');
    const files=[...(Array.isArray(details.files)?details.files:[]),...(details.file?[details.file]:[])];
    const scripts=[{code:bootstrap(e)}];
    for(const rel of files)scripts.push({code:fs.readFileSync(this.extensionFile(e,rel),'utf8')});
    if(details.code) scripts.push({code:String(details.code)});
    if(scripts.length===1)throw new Error('Function-object injection is not transferable through Aegis IPC; use files or code.');
    const result=await tab.view.webContents.executeJavaScriptInIsolatedWorld(e.worldId||extensionWorldId(e.id),scripts,false);
    return [{frameId:0,result}];
  }
  async insertExtensionCss(e,tab,details={}){
    if(!this.canAccessTab(e,tab,{inject:true}))throw new Error('Extension lacks host or activeTab access to this tab.');
    const files=[...(Array.isArray(details.files)?details.files:[]),...(details.file?[details.file]:[])];
    const chunks=[];for(const rel of files)chunks.push(rewriteCssUrls(fs.readFileSync(this.extensionFile(e,rel),'utf8'),e,rel));
    if(details.css||details.code)chunks.push(String(details.css||details.code));
    if(!chunks.length)throw new Error('No CSS supplied.');
    const css=chunks.join('\n'),key=await tab.view.webContents.insertCSS(css,{cssOrigin:details.origin==='USER'?'user':'author'});
    const lookup=e.id+':'+tab.id+':'+crypto.createHash('sha256').update(css).digest('hex');this.cssKeys.set(lookup,key);return undefined;
  }
  async removeExtensionCss(e,tab,details={}){
    if(!this.canAccessTab(e,tab,{inject:true}))throw new Error('Extension lacks host or activeTab access to this tab.');
    const files=[...(Array.isArray(details.files)?details.files:[]),...(details.file?[details.file]:[])];
    const chunks=[];for(const rel of files)chunks.push(rewriteCssUrls(fs.readFileSync(this.extensionFile(e,rel),'utf8'),e,rel));
    if(details.css||details.code)chunks.push(String(details.css||details.code));
    if(!chunks.length)return false;
    const css=chunks.join('\n'),lookup=e.id+':'+tab.id+':'+crypto.createHash('sha256').update(css).digest('hex'),key=this.cssKeys.get(lookup);
    if(!key)return false;try{await tab.view.webContents.removeInsertedCSS(key)}catch{return false}this.cssKeys.delete(lookup);return true;
  }
  async call(sender,p={}){
    const e=this.extensionFor(p.extensionId),m=String(p.method||''),a=Array.isArray(p.args)?p.args:[],tabs=this.getTabs(),source=tabs.find((t)=>t.view?.webContents===sender);
    const declared=new Set(permissions(e.manifest)),hasTabs=declared.has('tabs')||declared.has('activeTab'),requireTabs=()=>{if(!hasTabs)throw new Error('Extension lacks tabs/activeTab permission.')};
    const tabArg=(value,allowSource=true)=>{const id=Number(value);return Number.isFinite(id)?this.tabById(id):(allowSource?source:null)};
    if(m==='runtime.getManifest')return e.manifest;
    if(m==='runtime.getURL')return extensionResourceUrl(e,String(a[0]||''));
    if(m==='runtime.getPlatformInfo')return {os:process.platform==='darwin'?'mac':(process.platform==='win32'?'win':'linux'),arch:process.arch==='arm64'?'arm':'x86-64'};
    if(m==='runtime.getBrowserInfo')return {name:'Aegis Privacy Browser',vendor:'Aegis',version:this.browserVersion,buildID:''};
    if(m==='runtime.openOptionsPage')return this.openOptions(e.id);
    if(m==='runtime.reload'){this.stopBackground(e.id);await this.startBackground(e);return true}
    if(m==='runtime.sendMessage'){
      if(typeof a[0]==='string'&&a.length>1){
        if(a[0]!==e.id)throw new Error('Cross-extension messaging is not supported.');
        return this.sendRuntimeMessage(e,source,a[1]);
      }
      return this.sendRuntimeMessage(e,source,a[0]);
    }

    if(m==='permissions.contains'){const set=new Set(permissions(e.manifest));return [...(a[0]?.permissions||[]),...(a[0]?.origins||[])].every((x)=>set.has(x))}
    if(m==='permissions.getAll')return {permissions:permissions(e.manifest).filter((x)=>!/:\/\//.test(x)&&x!=='<all_urls>'),origins:hostPermissions(e.manifest)};
    if(m==='permissions.request')return false;
    if(m==='permissions.remove')return false;

    if(m.startsWith('storage.')){
      const [,area,op]=m.split('.'),file=path.join(this.dataDir,e.id,'storage.json'),store=area==='local'?readStore(file):(this.sessionStores.get(e.id)||{}),before={...store};this.sessionStores.set(e.id,store);
      if(op==='get')return getKeys(store,a[0]);
      if(op==='set')Object.assign(store,a[0]||{});
      if(op==='remove')for(const k of Array.isArray(a[0])?a[0]:[a[0]])delete store[k];
      if(op==='clear')for(const k of Object.keys(store))delete store[k];
      if(area==='local')writeStore(file,store);
      const changes={};for(const key of new Set([...Object.keys(before),...Object.keys(store)])){if(JSON.stringify(before[key])!==JSON.stringify(store[key]))changes[key]={oldValue:before[key],newValue:store[key]}}
      if(Object.keys(changes).length)this.emitEvent(e,'storage.onChanged',[changes,area]);return undefined;
    }

    if(m==='tabs.query'){
      const q=a[0]||{};return tabs.filter(extensionVisibleTab).filter((t)=>!q.active||t.id===this.getActiveId()).map((t)=>this.publicTab(e,t));
    }
    if(m==='tabs.get'){const t=this.tabById(a[0]);if(!extensionVisibleTab(t))throw new Error('Tab unavailable to extensions');return this.publicTab(e,t)}
    if(m==='tabs.getCurrent')return source?this.publicTab(e,source):null;
    if(m==='tabs.create'){requireTabs();return this.publicTab(e,await this.createTab(String(a[0]?.url||'aegis://app/start.html'),a[0]?.active!==false))}
    if(m==='tabs.update'){
      requireTabs();const id=typeof a[0]==='number'?a[0]:source?.id,target=this.tabById(id);if(!extensionVisibleTab(target))throw new Error('Extensions cannot access hardened or anonymous compartments.');
      await this.updateTab(id,typeof a[0]==='number'?(a[1]||{}):(a[0]||{}));
      return this.publicTab(e,this.tabById(id));
    }
    if(m==='tabs.reload'){requireTabs();const target=tabArg(typeof a[0]==='number'?a[0]:undefined);if(!extensionVisibleTab(target))throw new Error('Tab unavailable to extensions');target.view.webContents.reload();return undefined}
    if(m==='tabs.remove'){requireTabs();for(const id of (Array.isArray(a[0])?a[0]:[a[0]])){const target=this.tabById(id);if(!extensionVisibleTab(target))throw new Error('Extensions cannot access hardened or anonymous compartments.');this.removeTab(Number(id))}return undefined}
    if(m==='tabs.sendMessage'){const t=this.tabById(a[0]);if(!t||!extensionVisibleTab(t)||!this.canAccessTab(e,t,{inject:true}))throw new Error('Tab unavailable to this extension');return t.view.webContents.executeJavaScriptInIsolatedWorld(e.worldId||extensionWorldId(e.id),[{code:'globalThis.__aegisReceiveMessage?globalThis.__aegisReceiveMessage('+JSON.stringify(a[1])+','+JSON.stringify({id:e.id})+'):undefined'}],false)}
    if(m==='tabs.executeScript'){const target=tabArg(typeof a[0]==='number'?a[0]:undefined),details=typeof a[0]==='number'?(a[1]||{}):(a[0]||{});return this.executeExtensionScript(e,target,details)}
    if(m==='tabs.insertCSS'){const target=tabArg(typeof a[0]==='number'?a[0]:undefined),details=typeof a[0]==='number'?(a[1]||{}):(a[0]||{});return this.insertExtensionCss(e,target,details)}
    if(m==='tabs.removeCSS'){const target=tabArg(typeof a[0]==='number'?a[0]:undefined),details=typeof a[0]==='number'?(a[1]||{}):(a[0]||{});return this.removeExtensionCss(e,target,details)}

    if(m==='scripting.executeScript'){if(!declared.has('scripting'))throw new Error('Extension lacks scripting permission.');const target=this.tabById(a[0]?.target?.tabId);return this.executeExtensionScript(e,target,a[0]||{})}
    if(m==='scripting.insertCSS'){if(!declared.has('scripting'))throw new Error('Extension lacks scripting permission.');const target=this.tabById(a[0]?.target?.tabId);return this.insertExtensionCss(e,target,a[0]||{})}
    if(m==='scripting.removeCSS'){if(!declared.has('scripting'))throw new Error('Extension lacks scripting permission.');const target=this.tabById(a[0]?.target?.tabId);return this.removeExtensionCss(e,target,a[0]||{})}

    if(m==='alarms.create'){if(!declared.has('alarms'))throw new Error('Extension lacks alarms permission.');return this.createAlarm(e,typeof a[0]==='string'?a[0]:'',typeof a[0]==='string'?(a[1]||{}):(a[0]||{}))}
    if(m==='alarms.get'){return this.alarmTimers.get(this.alarmKey(e.id,a[0]))?.alarm||null}
    if(m==='alarms.getAll')return this.alarmList(e.id);
    if(m==='alarms.clear')return this.clearAlarm(e.id,a[0]);
    if(m==='alarms.clearAll')return this.clearAllAlarms(e.id);
    if(m==='commands.getAll')return commandList(e.manifest);

    if(/^(?:action|browserAction|pageAction)\./.test(m)){
      const [,op]=m.split('.'),action=extensionAction(e.manifest);if(!action)throw new Error('Extension has no browser action.');
      const state={...(this.actionState.get(e.id)||{})},details=a[0]||{};
      if(op==='setTitle'){state.title=String(details.title||'').slice(0,160);this.actionState.set(e.id,state);return}
      if(op==='getTitle')return String(state.title||action.title||e.manifest.name);
      if(op==='setBadgeText'){state.badgeText=String(details.text||'').slice(0,12);this.actionState.set(e.id,state);return}
      if(op==='getBadgeText')return String(state.badgeText||'');
      if(op==='setBadgeBackgroundColor'){state.badgeColor=details.color||null;this.actionState.set(e.id,state);return}
      if(op==='setPopup'){state.popup=safeRel(details.popup||'');this.actionState.set(e.id,state);return}
      if(op==='getPopup')return String(state.popup!==undefined?state.popup:(action.popup||''));
      if(op==='openPopup')return this.openAction(e.id);
    }

    throw new Error('Unsupported extension API: '+m);
  }
  backgroundScripts(ext){
    const bg=ext?.manifest?.background||{};
    if(bg.page)return [];
    const list=[];
    if(Array.isArray(bg.scripts))list.push(...bg.scripts);
    if(bg.service_worker)list.push(bg.service_worker);
    return list.map(safeRel).filter(Boolean);
  }
  backgroundBootstrap(ext){ return webExtensionBootstrap(ext,'__aegisBackgroundBridge'); }
  async startBackground(ext){
    this.stopBackground(ext.id);
    if(this.suspensionReasons.size||ext.enabled===false||!this.BrowserWindow||!this.electronSession)return false;
    const bg=ext?.manifest?.background||{},scripts=this.backgroundScripts(ext);
    const ses=this.electronSession.fromPartition('aegis-extension-bg-'+crypto.createHash('sha256').update(ext.id).digest('hex').slice(0,24),{cache:false});
    try{ses.webRequest.onBeforeRequest({urls:['http://*/*','https://*/*']},(details,callback)=>callback({cancel:!networkAllowedByManifest(ext.manifest,details.url)}))}catch{}
    if(typeof this.registerProtocols==='function')this.registerProtocols(ses.protocol,'extension '+ext.id);

    if(bg.page){
      const page=safeRel(bg.page);if(!page)return false;
      const target=path.resolve(ext.path,page),root=path.resolve(ext.path)+path.sep;
      if(!target.startsWith(root)||!fs.existsSync(target)||!fs.statSync(target).isFile())return false;
      const host=new this.BrowserWindow({show:false,webPreferences:{sandbox:true,contextIsolation:true,nodeIntegration:false,webSecurity:true,devTools:false,session:ses,preload:path.join(__dirname,'..','extension-page-preload.js'),additionalArguments:this.pageArguments(ext,'background')}});
      host.__aegisExtensionId=ext.id;this.backgroundHosts.set(ext.id,host);host.on('closed',()=>{if(this.backgroundHosts.get(ext.id)===host)this.backgroundHosts.delete(ext.id)});
      try{await host.loadURL(extensionResourceUrl(ext,page));const health=this.healthFor(ext.id);health.lastStartedAt=new Date().toISOString();this.clearRuntimeErrors(ext.id,'background');return true}catch(err){this.noteRuntimeError(ext.id,'background',err);try{host.destroy()}catch{}this.backgroundHosts.delete(ext.id);return false}
    }

    if(!scripts.length)return false;
    const valid=scripts.filter((rel)=>{try{this.extensionFile(ext,rel);return true}catch{return false}});
    if(!valid.length)return false;
    const wrapper=path.join(ext.path,'__aegis_background.html'),bootstrapFile=path.join(ext.path,'__aegis_background_bootstrap.js');
    fs.writeFileSync(bootstrapFile,this.backgroundBootstrap(ext),{mode:0o600});
    const tags=['<script src="__aegis_background_bootstrap.js"></script>',...valid.map((rel)=>'<script src="'+rel.replace(/&/g,'&amp;').replace(/"/g,'&quot;')+'"></script>')].join('');
    const html='<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'; connect-src https: http: aegis-extension:; img-src \'self\' data: aegis-extension:; style-src \'self\' \'unsafe-inline\'; object-src \'none\'">'+tags;
    fs.writeFileSync(wrapper,html,{mode:0o600});
    const host=new this.BrowserWindow({show:false,webPreferences:{sandbox:true,contextIsolation:true,nodeIntegration:false,webSecurity:true,devTools:false,session:ses,preload:path.join(__dirname,'..','extension-host-preload.js'),additionalArguments:['--aegis-extension-id='+encodeURIComponent(ext.id)]}});
    host.__aegisExtensionId=ext.id;this.backgroundHosts.set(ext.id,host);host.on('closed',()=>{if(this.backgroundHosts.get(ext.id)===host)this.backgroundHosts.delete(ext.id)});
    try{await host.loadFile(wrapper);const health=this.healthFor(ext.id);health.lastStartedAt=new Date().toISOString();this.clearRuntimeErrors(ext.id,'background');return true}catch(err){this.noteRuntimeError(ext.id,'background',err);try{host.destroy()}catch{}this.backgroundHosts.delete(ext.id);return false}
  }
  async startAll(){if(this.suspensionReasons.size)return;for(const ext of this.enabled()){await this.startBackground(ext);this.emitEvent(ext,'runtime.onStartup',[])}}
  suspendAll(reason='privacy-compartment'){
    this.suspensionReasons.add(String(reason));
    for(const id of [...this.backgroundHosts.keys()])this.stopBackground(id);
  }
  async resumeAll(reason='privacy-compartment'){
    this.suspensionReasons.delete(String(reason));
    if(!this.suspensionReasons.size)await this.startAll();
  }
  stopBackground(id){const host=this.backgroundHosts.get(id);if(host&&!host.isDestroyed())try{host.destroy()}catch{}this.backgroundHosts.delete(id)}
  sendRuntimeMessage(ext, sourceTab, message){
    const host=this.backgroundHosts.get(ext.id);
    if(!host||host.isDestroyed())return Promise.resolve(undefined);
    const messageId=crypto.randomUUID();
    return new Promise((resolve)=>{
      const timer=setTimeout(()=>{this.pendingMessages.delete(messageId);resolve(undefined)},2500);
      this.pendingMessages.set(messageId,{extensionId:ext.id,resolve:(value)=>{clearTimeout(timer);resolve(value)}});
      host.webContents.send('extension:runtime-message',{extensionId:ext.id,messageId,message,sender:sourceTab&&!sourceTab.disableExtensions&&sourceTab.securityDomain!=='anonymous'&&sourceTab.securityDomain!=='hardened'?{tab:{id:sourceTab.id,url:sourceTab.url||'',title:sourceTab.title||'',incognito:true}}:{id:ext.id}});
    });
  }
  handleBackgroundResponse(sender,payload={}){
    const id=String(payload.extensionId||''),pending=this.pendingMessages.get(String(payload.messageId||'')),host=this.backgroundHosts.get(id);
    if(!pending||pending.extensionId!==id||!host||host.webContents!==sender)return false;
    this.pendingMessages.delete(String(payload.messageId));pending.resolve(payload.response);return true;
  }
  stopAll(){for(const id of [...this.backgroundHosts.keys()])this.stopBackground(id);for(const win of [...this.pageWindows])try{if(!win.isDestroyed())win.destroy()}catch{}this.pageWindows.clear();for(const id of this.items.keys())this.clearAllAlarms(id);for(const pending of this.pendingMessages.values())pending.resolve(undefined);this.pendingMessages.clear()}
}
module.exports={hostPermissions,networkAllowedByManifest,extensionVisibleTab,extensionWorldId,safeRel,normalizeManifest,extensionId,permissions,compatibility,contentScriptPhase,matchPattern,matchingContentScripts,extensionResourceUrl,rewriteCssUrls,installRisk,scanUsedApiRoots,validateExtractedTree,bootstrap,AegisExtensionRuntime};
