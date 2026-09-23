'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

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
  for(const p of permissions(m)) if(!/^(?:\*|https?|file):\/\//.test(p)) roots.add(p);
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
function compatibility(m){
  const unsupported=[],supported=[],warnings=[];
  for(const root of apiRoots(m)){
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
  const capabilityCount=apiRoots(m).length+(features.contentScripts?1:0)+(background!=='none'?1:0)+(features.action?1:0)+(features.options?1:0);
  const supportedCount=supported.length+(features.contentScripts?1:0)+backgroundCredit+(features.action?1:0)+(features.options?1:0);
  const penalty=Math.min(unsupported.length,Math.max(1,capabilityCount));
  const score=Math.max(0,Math.min(100,Math.round(100*(supportedCount/Math.max(1,capabilityCount+penalty*0.6)))));
  const status=unsupported.length===0?(warnings.length?'good':'excellent'):(score>=70?'partial':'limited');
  return {score,status,supported,unsupported,warnings,contentScripts:features.contentScripts,background,features};
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
  return 'aegis-extension://ext/'+ext.resourceToken+'/'+safe.split('/').map(encodeURIComponent).join('/');
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
  return permissions(m).map((p)=>({permission:p,level:(p==='<all_urls>'||p==='*://*/*'||DENIED_ROOTS[p])?'high':(/:\/\//.test(p)||['tabs','activeTab','storage','scripting'].includes(p)?'medium':'low')}));
}
function localeMessages(ext){
  const locale=safeRel(ext?.manifest?.default_locale||'');
  if(!locale)return {};
  const file=path.join(ext.path,'_locales',locale,'messages.json');
  try{
    const raw=readJson(file),out={};
    for(const [key,value] of Object.entries(raw||{})) if(value&&typeof value.message==='string')out[key]=value.message;
    return out;
  }catch{return {};}
}
function formatLocaleMessage(messages,key,substitutions){
  let text=String(messages?.[String(key||'')]||'');
  const values=Array.isArray(substitutions)?substitutions:[substitutions];
  values.filter((x)=>x!==undefined).forEach((value,index)=>{text=text.replace(new RegExp('\\\\
async function zipEntries(file){
  const st=fs.statSync(file); if(!st.isFile()||st.size>64*1024*1024) throw new Error('XPI must be smaller than 64 MB.');
  const r=await execFileAsync('/usr/bin/unzip',['-Z1',file],{maxBuffer:4*1024*1024});
  const entries=r.stdout.split(/\r?\n/).map((x)=>x.trim()).filter(Boolean); if(!entries.length||entries.length>5000)throw new Error('Invalid XPI file count.');
  for(const e of entries) if(!safeRel(e.replace(/\/$/,'')))throw new Error('Unsafe XPI path: '+e);
  return entries;
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
    const signatureMetadata=entries.some((e)=>/^META-INF\/(?:mozilla\.rsa|mozilla\.sf|manifest\.mf)$/i.test(e));
    return {root,tmp,manifest,compatibility:compatibility(manifest),risk:installRisk(manifest),signature:{metadataPresent:signatureMetadata,verified:false}};
  }catch(err){try{fs.rmSync(tmp,{recursive:true,force:true});}catch{} throw err;}
}
function bootstrap(ext){
  const id=JSON.stringify(ext.id), token=JSON.stringify(ext.resourceToken), manifest=JSON.stringify(ext.manifest);
  return "(()=>{'use strict';const ID="+id+",TOKEN="+token+",M=Object.freeze("+manifest+"),B=globalThis.__aegisExtensionBridge;if(!B)return;const L=[],call=(m,...a)=>B.call(m,a);globalThis.__aegisReceiveMessage=async(msg)=>{for(const f of [...L]){try{const r=await f(msg,{tab:{url:location.href}},()=>{});if(r!==undefined)return r}catch{}}};B.onMessage((p)=>globalThis.__aegisReceiveMessage(p.message));const area=(n)=>({get:(k)=>call('storage.'+n+'.get',k),set:(v)=>call('storage.'+n+'.set',v),remove:(k)=>call('storage.'+n+'.remove',k),clear:()=>call('storage.'+n+'.clear')});const runtime={id:ID,getManifest:()=>M,getURL:(p='')=>'aegis-extension://ext/'+TOKEN+'/'+String(p).replace(/^\\/+/,''),getPlatformInfo:()=>call('runtime.getPlatformInfo'),sendMessage:(...a)=>call('runtime.sendMessage',...a),onMessage:{addListener:(f)=>{if(typeof f==='function'&&!L.includes(f))L.push(f)},removeListener:(f)=>{const i=L.indexOf(f);if(i>=0)L.splice(i,1)},hasListener:(f)=>L.includes(f)}};const api={runtime,extension:{getURL:runtime.getURL},storage:{local:area('local'),session:area('session')},tabs:{query:(q)=>call('tabs.query',q||{}),create:(p)=>call('tabs.create',p||{}),update:(...a)=>call('tabs.update',...a),remove:(ids)=>call('tabs.remove',ids),sendMessage:(id,msg)=>call('tabs.sendMessage',id,msg)},permissions:{contains:(p)=>call('permissions.contains',p||{})},i18n:{getUILanguage:()=> 'en-US'}};Object.defineProperty(globalThis,'browser',{value:api});if(!globalThis.chrome)Object.defineProperty(globalThis,'chrome',{value:api});})();";
}
function readStore(file){try{return readJson(file)}catch{return {}}}
function writeStore(file,v){fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});fs.writeFileSync(file,JSON.stringify(v,null,2),{mode:0o600})}
function getKeys(store,keys){
  if(keys==null)return {...store}; if(typeof keys==='string')return {[keys]:store[keys]};
  if(Array.isArray(keys))return Object.fromEntries(keys.filter((k)=>Object.prototype.hasOwnProperty.call(store,k)).map((k)=>[k,store[k]]));
  if(typeof keys==='object')return Object.fromEntries(Object.entries(keys).map(([k,d])=>[k,Object.prototype.hasOwnProperty.call(store,k)?store[k]:d])); return {};
}
class AegisExtensionRuntime{
  constructor({rootDir,getTabs,getActiveId,createTab,updateTab,removeTab,BrowserWindow,electronSession,registerProtocols}){
    this.rootDir=rootDir;this.installDir=path.join(rootDir,'extensions');this.indexFile=path.join(this.installDir,'index.json');this.dataDir=path.join(rootDir,'extension-data');
    this.getTabs=getTabs;this.getActiveId=getActiveId||(()=>null);this.createTab=createTab;this.updateTab=updateTab;this.removeTab=removeTab;this.BrowserWindow=BrowserWindow;this.electronSession=electronSession;this.registerProtocols=registerProtocols;
    this.items=new Map();this.sessionStores=new Map();this.backgroundHosts=new Map();this.pendingMessages=new Map();this.pendingInstalls=new Map();this.suspensionReasons=new Set();this.actionState=new Map();this.alarmTimers=new Map();this.pageWindows=new Set();this.pageSessions=new Map();
    fs.mkdirSync(this.installDir,{recursive:true,mode:0o700}); this.load(); this.save();
  }
  load(){let rows=[];try{rows=readJson(this.indexFile)}catch{} for(const row of Array.isArray(rows)?rows:[]){try{const manifest=normalizeManifest(readJson(path.join(row.path,'manifest.json')));this.items.set(row.id,{...row,worldId:row.worldId||extensionWorldId(row.id),resourceToken:row.resourceToken||crypto.randomBytes(18).toString('hex'),manifest,compatibility:compatibility(manifest)})}catch{}}}
  save(){writeStore(this.indexFile,[...this.items.values()].map(({manifest,compatibility,...r})=>r))}
  publicRecord(e){
    const action=extensionAction(e.manifest);
    const icon=iconPath(e.manifest);
    const options=optionsPage(e.manifest);
    const state=this.actionState.get(e.id)||{};
    return {
      id:e.id,name:e.manifest.name,version:e.manifest.version,description:String(e.manifest.description||''),
      manifestVersion:Number(e.manifest.manifest_version||0),enabled:e.enabled!==false,worldId:e.worldId||extensionWorldId(e.id),
      compatibility:e.compatibility,risk:installRisk(e.manifest),installedAt:e.installedAt||'',updatedAt:e.updatedAt||'',
      source:e.source||'xpi',digest:e.digest||'',permissions:permissions(e.manifest),hostPermissions:hostPermissions(e.manifest),
      optionalPermissions:[...(Array.isArray(e.manifest.optional_permissions)?e.manifest.optional_permissions:[]),...(Array.isArray(e.manifest.optional_host_permissions)?e.manifest.optional_host_permissions:[])],
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
        digest,permissions:permissions(x.manifest),hostPermissions:hostPermissions(x.manifest),
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
    const e={id,path:dest,worldId:extensionWorldId(id),resourceToken:previous?.resourceToken||crypto.randomBytes(18).toString('hex'),enabled:previous?.enabled!==false,source:'xpi',digest,installedAt:previous?.installedAt||now,updatedAt:now,manifest:x.manifest,compatibility:x.compatibility};
    this.items.set(id,e);this.save();if(e.enabled)await this.startBackground(e);this.emitEvent(e,'runtime.onInstalled',[{reason:previous?'update':'install',previousVersion:previous?.manifest?.version||undefined}]);return this.publicRecord(e);
  }
  async setEnabled(id,v){const e=this.items.get(id);if(!e)throw new Error('Extension not found');e.enabled=Boolean(v);this.save();if(e.enabled){await this.startBackground(e);this.emitEvent(e,'runtime.onStartup',[]);}else this.stopBackground(id);return this.publicRecord(e)}
  remove(id){const e=this.items.get(id);if(!e)return false;this.stopBackground(id);this.clearAllAlarms(id);this.items.delete(id);this.sessionStores.delete(id);this.actionState.delete(id);this.save();try{fs.rmSync(e.path,{recursive:true,force:true})}catch{}try{fs.rmSync(path.join(this.dataDir,id),{recursive:true,force:true})}catch{}return true}
  enabled(){return [...this.items.values()].filter((e)=>e.enabled!==false)}
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
          try{await tab.view.webContents.executeJavaScriptInIsolatedWorld(e.worldId||extensionWorldId(e.id),scripts,false);scriptOk=true;done.push(e.id)}catch{}
        }
        const cssParts=[];
        for(const rel of Array.isArray(entry.css)?entry.css:[]){
          const s=safeRel(rel),f=path.resolve(e.path,s);
          if(s&&f.startsWith(path.resolve(e.path)+path.sep)&&fs.existsSync(f))cssParts.push(rewriteCssUrls(fs.readFileSync(f,'utf8'),e,s));
        }
        if(cssParts.length)try{await tab.view.webContents.insertCSS(cssParts.join('\n'),{cssOrigin:'author'});done.push(e.id)}catch{}
        if(scriptOk||cssParts.length)tab.extensionInjectionKeys.add(key);
      }
    }
    return [...new Set(done)];
  }
  async call(sender,p={}){
    const e=this.items.get(String(p.extensionId||'')); if(!e||e.enabled===false)throw new Error('Extension disabled or missing'); const m=String(p.method||''),a=Array.isArray(p.args)?p.args:[],tabs=this.getTabs(),source=tabs.find((t)=>t.view?.webContents===sender);
    if(m==='runtime.getManifest')return e.manifest;
    if(m==='runtime.getURL')return 'aegis-extension://ext/'+e.resourceToken+'/'+String(a[0]||'').replace(/^\/+/, '');
    if(m==='runtime.getPlatformInfo')return {os:process.platform==='darwin'?'mac':'unknown',arch:process.arch==='arm64'?'arm':'x86-64'};
    if(m==='permissions.contains'){const set=new Set(permissions(e.manifest));return [...(a[0]?.permissions||[]),...(a[0]?.origins||[])].every((x)=>set.has(x))}
    if(m.startsWith('storage.')){const [,area,op]=m.split('.'),file=path.join(this.dataDir,e.id,'storage.json'),store=area==='local'?readStore(file):(this.sessionStores.get(e.id)||{});this.sessionStores.set(e.id,store);if(op==='get')return getKeys(store,a[0]);if(op==='set')Object.assign(store,a[0]||{});if(op==='remove')for(const k of Array.isArray(a[0])?a[0]:[a[0]])delete store[k];if(op==='clear')for(const k of Object.keys(store))delete store[k];if(area==='local'&&op!=='get')writeStore(file,store);return;}
    const extensionVisible=extensionVisibleTab;
    const declared=new Set(permissions(e.manifest));
    const hasTabs=declared.has('tabs')||declared.has('activeTab');
    const mayRead=(t)=>Boolean(t&&extensionVisible(t)&&(declared.has('tabs')||networkAllowedByManifest(e.manifest,t.url||'')));
    const requireTabs=()=>{if(!hasTabs)throw new Error('Extension lacks tabs/activeTab permission.');};
    const pub=(t)=>({id:t.id,url:mayRead(t)?(t.url||''):'',title:mayRead(t)?(t.title||''):'',active:t.id===this.getActiveId(),incognito:true,status:t.loading?'loading':'complete'});
    if(m==='tabs.query')return tabs.filter(extensionVisible).filter((t)=>!a[0]?.active||t.id===this.getActiveId()).map(pub);
    if(m==='tabs.create'){requireTabs();return pub(await this.createTab(String(a[0]?.url||'aegis://app/start.html'),a[0]?.active!==false));}
    if(m==='tabs.update'){
      requireTabs();
      const id=typeof a[0]==='number'?a[0]:source?.id, target=tabs.find((t)=>t.id===Number(id));
      if(!extensionVisible(target))throw new Error('Extensions cannot access hardened or anonymous compartments.');
      return this.updateTab(id,typeof a[0]==='number'?(a[1]||{}):(a[0]||{}));
    }
    if(m==='tabs.remove'){
      requireTabs();
      for(const id of (Array.isArray(a[0])?a[0]:[a[0]])){
        const target=tabs.find((t)=>t.id===Number(id));
        if(!extensionVisible(target))throw new Error('Extensions cannot access hardened or anonymous compartments.');
        this.removeTab(Number(id));
      }
      return;
    }
    if(m==='tabs.sendMessage'){requireTabs();const t=tabs.find((x)=>x.id===Number(a[0]));if(!t||!extensionVisible(t))throw new Error('Tab unavailable to extensions');const targetExt=this.items.get(e.id); return t.view.webContents.executeJavaScriptInIsolatedWorld(targetExt.worldId||extensionWorldId(e.id),[{code:'globalThis.__aegisReceiveMessage?globalThis.__aegisReceiveMessage('+JSON.stringify(a[1])+'):undefined'}])}
    if(m==='runtime.sendMessage')return this.sendRuntimeMessage(e, source, a[0]);
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
  backgroundBootstrap(ext){
    const id=JSON.stringify(ext.id), token=JSON.stringify(ext.resourceToken), manifest=JSON.stringify(ext.manifest);
    return "(()=>{'use strict';const ID="+id+",TOKEN="+token+",M=Object.freeze("+manifest+"),B=globalThis.__aegisBackgroundBridge;if(!B)return;const L=[],call=(m,...a)=>B.call(m,a),area=(n)=>({get:(k)=>call('storage.'+n+'.get',k),set:(v)=>call('storage.'+n+'.set',v),remove:(k)=>call('storage.'+n+'.remove',k),clear:()=>call('storage.'+n+'.clear')});const runtime={id:ID,getManifest:()=>M,getURL:(p='')=>'aegis-extension://ext/'+TOKEN+'/'+String(p).replace(/^\\/+/,''),getPlatformInfo:()=>call('runtime.getPlatformInfo'),sendMessage:(...a)=>call('runtime.sendMessage',...a),onMessage:{addListener:(f)=>{if(typeof f==='function'&&!L.includes(f))L.push(f)},removeListener:(f)=>{const i=L.indexOf(f);if(i>=0)L.splice(i,1)},hasListener:(f)=>L.includes(f)}};const api={runtime,extension:{getURL:runtime.getURL},storage:{local:area('local'),session:area('session')},tabs:{query:(q)=>call('tabs.query',q||{}),create:(p)=>call('tabs.create',p||{}),update:(...a)=>call('tabs.update',...a),remove:(ids)=>call('tabs.remove',ids),sendMessage:(id,msg)=>call('tabs.sendMessage',id,msg)},permissions:{contains:(p)=>call('permissions.contains',p||{})},i18n:{getUILanguage:()=> 'en-US'}};Object.defineProperty(globalThis,'browser',{value:api});if(!globalThis.chrome)Object.defineProperty(globalThis,'chrome',{value:api});B.onMessage(async(p)=>{let response;for(const fn of [...L]){try{const r=await fn(p.message,p.sender||{},()=>{});if(r!==undefined){response=r;break}}catch{}}B.respond(p.messageId,response)});})();";
  }
  async startBackground(ext){
    this.stopBackground(ext.id);
    if(this.suspensionReasons.size)return false;
    const scripts=this.backgroundScripts(ext);
    if(!ext.enabled||!scripts.length||!this.BrowserWindow||!this.electronSession)return false;
    const valid=scripts.filter((rel)=>{const file=path.resolve(ext.path,rel);return file.startsWith(path.resolve(ext.path)+path.sep)&&fs.existsSync(file)&&fs.statSync(file).isFile()});
    if(!valid.length)return false;
    const wrapper=path.join(ext.path,'__aegis_background.html');
    const bootstrapFile=path.join(ext.path,'__aegis_background_bootstrap.js');
    fs.writeFileSync(bootstrapFile,this.backgroundBootstrap(ext),{mode:0o600});
    const tags=['<script src="__aegis_background_bootstrap.js"></script>',...valid.map((rel)=>'<script src="'+rel.replace(/&/g,'&amp;').replace(/"/g,'&quot;')+'"></script>')].join('');
    const html='<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'; connect-src https: http: aegis-extension:; img-src \'self\' data: aegis-extension:; style-src \'self\' \'unsafe-inline\'; object-src \'none\'">'+tags;
    fs.writeFileSync(wrapper,html,{mode:0o600});
    const ses=this.electronSession.fromPartition('aegis-extension-bg-'+crypto.createHash('sha256').update(ext.id).digest('hex').slice(0,24),{cache:false});
    // Extension background networking is least-privilege: only manifest-declared
    // host permissions may leave the sandboxed background session.
    try {
      ses.webRequest.onBeforeRequest({urls:['http://*/*','https://*/*']},(details,callback)=>{
        callback({cancel:!networkAllowedByManifest(ext.manifest,details.url)});
      });
    } catch {}
    if(typeof this.registerProtocols==='function')this.registerProtocols(ses.protocol,'extension '+ext.id);
    const host=new this.BrowserWindow({show:false,webPreferences:{sandbox:true,contextIsolation:true,nodeIntegration:false,webSecurity:true,devTools:false,session:ses,preload:path.join(__dirname,'..','extension-host-preload.js'),additionalArguments:['--aegis-extension-id='+encodeURIComponent(ext.id)]}});
    this.backgroundHosts.set(ext.id,host);
    host.on('closed',()=>{if(this.backgroundHosts.get(ext.id)===host)this.backgroundHosts.delete(ext.id)});
    try{await host.loadFile(wrapper);return true}catch(err){try{host.destroy()}catch{}this.backgroundHosts.delete(ext.id);return false}
  }
  async startAll(){if(this.suspensionReasons.size)return;for(const ext of this.enabled())await this.startBackground(ext)}
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
  stopAll(){for(const id of [...this.backgroundHosts.keys()])this.stopBackground(id);for(const pending of this.pendingMessages.values())pending.resolve(undefined);this.pendingMessages.clear()}
}
module.exports={hostPermissions,networkAllowedByManifest,extensionVisibleTab,extensionWorldId,safeRel,normalizeManifest,extensionId,permissions,compatibility,contentScriptPhase,matchPattern,matchingContentScripts,extensionResourceUrl,rewriteCssUrls,installRisk,validateExtractedTree,bootstrap,AegisExtensionRuntime};
+(index+1),'g'),String(value));});
  return text;
}
function commandList(m){
  return Object.entries(m?.commands||{}).map(([name,value])=>({
    name,
    description:String(value?.description||''),
    shortcut:String(value?.suggested_key?.mac||value?.suggested_key?.default||'')
  }));
}
async function zipEntries(file){
  const st=fs.statSync(file); if(!st.isFile()||st.size>64*1024*1024) throw new Error('XPI must be smaller than 64 MB.');
  const r=await execFileAsync('/usr/bin/unzip',['-Z1',file],{maxBuffer:4*1024*1024});
  const entries=r.stdout.split(/\r?\n/).map((x)=>x.trim()).filter(Boolean); if(!entries.length||entries.length>5000)throw new Error('Invalid XPI file count.');
  for(const e of entries) if(!safeRel(e.replace(/\/$/,'')))throw new Error('Unsafe XPI path: '+e);
  return entries;
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
    const signatureMetadata=entries.some((e)=>/^META-INF\/(?:mozilla\.rsa|mozilla\.sf|manifest\.mf)$/i.test(e));
    return {root,tmp,manifest,compatibility:compatibility(manifest),risk:installRisk(manifest),signature:{metadataPresent:signatureMetadata,verified:false}};
  }catch(err){try{fs.rmSync(tmp,{recursive:true,force:true});}catch{} throw err;}
}
function bootstrap(ext){
  const id=JSON.stringify(ext.id), token=JSON.stringify(ext.resourceToken), manifest=JSON.stringify(ext.manifest);
  return "(()=>{'use strict';const ID="+id+",TOKEN="+token+",M=Object.freeze("+manifest+"),B=globalThis.__aegisExtensionBridge;if(!B)return;const L=[],call=(m,...a)=>B.call(m,a);globalThis.__aegisReceiveMessage=async(msg)=>{for(const f of [...L]){try{const r=await f(msg,{tab:{url:location.href}},()=>{});if(r!==undefined)return r}catch{}}};B.onMessage((p)=>globalThis.__aegisReceiveMessage(p.message));const area=(n)=>({get:(k)=>call('storage.'+n+'.get',k),set:(v)=>call('storage.'+n+'.set',v),remove:(k)=>call('storage.'+n+'.remove',k),clear:()=>call('storage.'+n+'.clear')});const runtime={id:ID,getManifest:()=>M,getURL:(p='')=>'aegis-extension://ext/'+TOKEN+'/'+String(p).replace(/^\\/+/,''),getPlatformInfo:()=>call('runtime.getPlatformInfo'),sendMessage:(...a)=>call('runtime.sendMessage',...a),onMessage:{addListener:(f)=>{if(typeof f==='function'&&!L.includes(f))L.push(f)},removeListener:(f)=>{const i=L.indexOf(f);if(i>=0)L.splice(i,1)},hasListener:(f)=>L.includes(f)}};const api={runtime,extension:{getURL:runtime.getURL},storage:{local:area('local'),session:area('session')},tabs:{query:(q)=>call('tabs.query',q||{}),create:(p)=>call('tabs.create',p||{}),update:(...a)=>call('tabs.update',...a),remove:(ids)=>call('tabs.remove',ids),sendMessage:(id,msg)=>call('tabs.sendMessage',id,msg)},permissions:{contains:(p)=>call('permissions.contains',p||{})},i18n:{getUILanguage:()=> 'en-US'}};Object.defineProperty(globalThis,'browser',{value:api});if(!globalThis.chrome)Object.defineProperty(globalThis,'chrome',{value:api});})();";
}
function readStore(file){try{return readJson(file)}catch{return {}}}
function writeStore(file,v){fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});fs.writeFileSync(file,JSON.stringify(v,null,2),{mode:0o600})}
function getKeys(store,keys){
  if(keys==null)return {...store}; if(typeof keys==='string')return {[keys]:store[keys]};
  if(Array.isArray(keys))return Object.fromEntries(keys.filter((k)=>Object.prototype.hasOwnProperty.call(store,k)).map((k)=>[k,store[k]]));
  if(typeof keys==='object')return Object.fromEntries(Object.entries(keys).map(([k,d])=>[k,Object.prototype.hasOwnProperty.call(store,k)?store[k]:d])); return {};
}
class AegisExtensionRuntime{
  constructor({rootDir,getTabs,getActiveId,createTab,updateTab,removeTab,BrowserWindow,electronSession,registerProtocols}){
    this.rootDir=rootDir;this.installDir=path.join(rootDir,'extensions');this.indexFile=path.join(this.installDir,'index.json');this.dataDir=path.join(rootDir,'extension-data');
    this.getTabs=getTabs;this.getActiveId=getActiveId||(()=>null);this.createTab=createTab;this.updateTab=updateTab;this.removeTab=removeTab;this.BrowserWindow=BrowserWindow;this.electronSession=electronSession;this.registerProtocols=registerProtocols;
    this.items=new Map();this.sessionStores=new Map();this.backgroundHosts=new Map();this.pendingMessages=new Map();this.pendingInstalls=new Map();this.suspensionReasons=new Set();this.actionState=new Map();this.alarmTimers=new Map();this.pageWindows=new Set();this.pageSessions=new Map();
    fs.mkdirSync(this.installDir,{recursive:true,mode:0o700}); this.load(); this.save();
  }
  load(){let rows=[];try{rows=readJson(this.indexFile)}catch{} for(const row of Array.isArray(rows)?rows:[]){try{const manifest=normalizeManifest(readJson(path.join(row.path,'manifest.json')));this.items.set(row.id,{...row,worldId:row.worldId||extensionWorldId(row.id),resourceToken:row.resourceToken||crypto.randomBytes(18).toString('hex'),manifest,compatibility:compatibility(manifest)})}catch{}}}
  save(){writeStore(this.indexFile,[...this.items.values()].map(({manifest,compatibility,...r})=>r))}
  publicRecord(e){
    const action=extensionAction(e.manifest);
    const icon=iconPath(e.manifest);
    const options=optionsPage(e.manifest);
    const state=this.actionState.get(e.id)||{};
    return {
      id:e.id,name:e.manifest.name,version:e.manifest.version,description:String(e.manifest.description||''),
      manifestVersion:Number(e.manifest.manifest_version||0),enabled:e.enabled!==false,worldId:e.worldId||extensionWorldId(e.id),
      compatibility:e.compatibility,risk:installRisk(e.manifest),installedAt:e.installedAt||'',updatedAt:e.updatedAt||'',
      source:e.source||'xpi',digest:e.digest||'',permissions:permissions(e.manifest),hostPermissions:hostPermissions(e.manifest),
      optionalPermissions:[...(Array.isArray(e.manifest.optional_permissions)?e.manifest.optional_permissions:[]),...(Array.isArray(e.manifest.optional_host_permissions)?e.manifest.optional_host_permissions:[])],
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
        digest,permissions:permissions(x.manifest),hostPermissions:hostPermissions(x.manifest),
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
    const e={id,path:dest,worldId:extensionWorldId(id),resourceToken:previous?.resourceToken||crypto.randomBytes(18).toString('hex'),enabled:previous?.enabled!==false,source:'xpi',digest,installedAt:previous?.installedAt||now,updatedAt:now,manifest:x.manifest,compatibility:x.compatibility};
    this.items.set(id,e);this.save();if(e.enabled)await this.startBackground(e);this.emitEvent(e,'runtime.onInstalled',[{reason:previous?'update':'install',previousVersion:previous?.manifest?.version||undefined}]);return this.publicRecord(e);
  }
  async setEnabled(id,v){const e=this.items.get(id);if(!e)throw new Error('Extension not found');e.enabled=Boolean(v);this.save();if(e.enabled){await this.startBackground(e);this.emitEvent(e,'runtime.onStartup',[]);}else this.stopBackground(id);return this.publicRecord(e)}
  remove(id){const e=this.items.get(id);if(!e)return false;this.stopBackground(id);this.clearAllAlarms(id);this.items.delete(id);this.sessionStores.delete(id);this.actionState.delete(id);this.save();try{fs.rmSync(e.path,{recursive:true,force:true})}catch{}try{fs.rmSync(path.join(this.dataDir,id),{recursive:true,force:true})}catch{}return true}
  enabled(){return [...this.items.values()].filter((e)=>e.enabled!==false)}
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
          try{await tab.view.webContents.executeJavaScriptInIsolatedWorld(e.worldId||extensionWorldId(e.id),scripts,false);scriptOk=true;done.push(e.id)}catch{}
        }
        const cssParts=[];
        for(const rel of Array.isArray(entry.css)?entry.css:[]){
          const s=safeRel(rel),f=path.resolve(e.path,s);
          if(s&&f.startsWith(path.resolve(e.path)+path.sep)&&fs.existsSync(f))cssParts.push(rewriteCssUrls(fs.readFileSync(f,'utf8'),e,s));
        }
        if(cssParts.length)try{await tab.view.webContents.insertCSS(cssParts.join('\n'),{cssOrigin:'author'});done.push(e.id)}catch{}
        if(scriptOk||cssParts.length)tab.extensionInjectionKeys.add(key);
      }
    }
    return [...new Set(done)];
  }
  async call(sender,p={}){
    const e=this.items.get(String(p.extensionId||'')); if(!e||e.enabled===false)throw new Error('Extension disabled or missing'); const m=String(p.method||''),a=Array.isArray(p.args)?p.args:[],tabs=this.getTabs(),source=tabs.find((t)=>t.view?.webContents===sender);
    if(m==='runtime.getManifest')return e.manifest;
    if(m==='runtime.getURL')return 'aegis-extension://ext/'+e.resourceToken+'/'+String(a[0]||'').replace(/^\/+/, '');
    if(m==='runtime.getPlatformInfo')return {os:process.platform==='darwin'?'mac':'unknown',arch:process.arch==='arm64'?'arm':'x86-64'};
    if(m==='permissions.contains'){const set=new Set(permissions(e.manifest));return [...(a[0]?.permissions||[]),...(a[0]?.origins||[])].every((x)=>set.has(x))}
    if(m.startsWith('storage.')){const [,area,op]=m.split('.'),file=path.join(this.dataDir,e.id,'storage.json'),store=area==='local'?readStore(file):(this.sessionStores.get(e.id)||{});this.sessionStores.set(e.id,store);if(op==='get')return getKeys(store,a[0]);if(op==='set')Object.assign(store,a[0]||{});if(op==='remove')for(const k of Array.isArray(a[0])?a[0]:[a[0]])delete store[k];if(op==='clear')for(const k of Object.keys(store))delete store[k];if(area==='local'&&op!=='get')writeStore(file,store);return;}
    const extensionVisible=extensionVisibleTab;
    const declared=new Set(permissions(e.manifest));
    const hasTabs=declared.has('tabs')||declared.has('activeTab');
    const mayRead=(t)=>Boolean(t&&extensionVisible(t)&&(declared.has('tabs')||networkAllowedByManifest(e.manifest,t.url||'')));
    const requireTabs=()=>{if(!hasTabs)throw new Error('Extension lacks tabs/activeTab permission.');};
    const pub=(t)=>({id:t.id,url:mayRead(t)?(t.url||''):'',title:mayRead(t)?(t.title||''):'',active:t.id===this.getActiveId(),incognito:true,status:t.loading?'loading':'complete'});
    if(m==='tabs.query')return tabs.filter(extensionVisible).filter((t)=>!a[0]?.active||t.id===this.getActiveId()).map(pub);
    if(m==='tabs.create'){requireTabs();return pub(await this.createTab(String(a[0]?.url||'aegis://app/start.html'),a[0]?.active!==false));}
    if(m==='tabs.update'){
      requireTabs();
      const id=typeof a[0]==='number'?a[0]:source?.id, target=tabs.find((t)=>t.id===Number(id));
      if(!extensionVisible(target))throw new Error('Extensions cannot access hardened or anonymous compartments.');
      return this.updateTab(id,typeof a[0]==='number'?(a[1]||{}):(a[0]||{}));
    }
    if(m==='tabs.remove'){
      requireTabs();
      for(const id of (Array.isArray(a[0])?a[0]:[a[0]])){
        const target=tabs.find((t)=>t.id===Number(id));
        if(!extensionVisible(target))throw new Error('Extensions cannot access hardened or anonymous compartments.');
        this.removeTab(Number(id));
      }
      return;
    }
    if(m==='tabs.sendMessage'){requireTabs();const t=tabs.find((x)=>x.id===Number(a[0]));if(!t||!extensionVisible(t))throw new Error('Tab unavailable to extensions');const targetExt=this.items.get(e.id); return t.view.webContents.executeJavaScriptInIsolatedWorld(targetExt.worldId||extensionWorldId(e.id),[{code:'globalThis.__aegisReceiveMessage?globalThis.__aegisReceiveMessage('+JSON.stringify(a[1])+'):undefined'}])}
    if(m==='runtime.sendMessage')return this.sendRuntimeMessage(e, source, a[0]);
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
  backgroundBootstrap(ext){
    const id=JSON.stringify(ext.id), token=JSON.stringify(ext.resourceToken), manifest=JSON.stringify(ext.manifest);
    return "(()=>{'use strict';const ID="+id+",TOKEN="+token+",M=Object.freeze("+manifest+"),B=globalThis.__aegisBackgroundBridge;if(!B)return;const L=[],call=(m,...a)=>B.call(m,a),area=(n)=>({get:(k)=>call('storage.'+n+'.get',k),set:(v)=>call('storage.'+n+'.set',v),remove:(k)=>call('storage.'+n+'.remove',k),clear:()=>call('storage.'+n+'.clear')});const runtime={id:ID,getManifest:()=>M,getURL:(p='')=>'aegis-extension://ext/'+TOKEN+'/'+String(p).replace(/^\\/+/,''),getPlatformInfo:()=>call('runtime.getPlatformInfo'),sendMessage:(...a)=>call('runtime.sendMessage',...a),onMessage:{addListener:(f)=>{if(typeof f==='function'&&!L.includes(f))L.push(f)},removeListener:(f)=>{const i=L.indexOf(f);if(i>=0)L.splice(i,1)},hasListener:(f)=>L.includes(f)}};const api={runtime,extension:{getURL:runtime.getURL},storage:{local:area('local'),session:area('session')},tabs:{query:(q)=>call('tabs.query',q||{}),create:(p)=>call('tabs.create',p||{}),update:(...a)=>call('tabs.update',...a),remove:(ids)=>call('tabs.remove',ids),sendMessage:(id,msg)=>call('tabs.sendMessage',id,msg)},permissions:{contains:(p)=>call('permissions.contains',p||{})},i18n:{getUILanguage:()=> 'en-US'}};Object.defineProperty(globalThis,'browser',{value:api});if(!globalThis.chrome)Object.defineProperty(globalThis,'chrome',{value:api});B.onMessage(async(p)=>{let response;for(const fn of [...L]){try{const r=await fn(p.message,p.sender||{},()=>{});if(r!==undefined){response=r;break}}catch{}}B.respond(p.messageId,response)});})();";
  }
  async startBackground(ext){
    this.stopBackground(ext.id);
    if(this.suspensionReasons.size)return false;
    const scripts=this.backgroundScripts(ext);
    if(!ext.enabled||!scripts.length||!this.BrowserWindow||!this.electronSession)return false;
    const valid=scripts.filter((rel)=>{const file=path.resolve(ext.path,rel);return file.startsWith(path.resolve(ext.path)+path.sep)&&fs.existsSync(file)&&fs.statSync(file).isFile()});
    if(!valid.length)return false;
    const wrapper=path.join(ext.path,'__aegis_background.html');
    const bootstrapFile=path.join(ext.path,'__aegis_background_bootstrap.js');
    fs.writeFileSync(bootstrapFile,this.backgroundBootstrap(ext),{mode:0o600});
    const tags=['<script src="__aegis_background_bootstrap.js"></script>',...valid.map((rel)=>'<script src="'+rel.replace(/&/g,'&amp;').replace(/"/g,'&quot;')+'"></script>')].join('');
    const html='<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'; connect-src https: http: aegis-extension:; img-src \'self\' data: aegis-extension:; style-src \'self\' \'unsafe-inline\'; object-src \'none\'">'+tags;
    fs.writeFileSync(wrapper,html,{mode:0o600});
    const ses=this.electronSession.fromPartition('aegis-extension-bg-'+crypto.createHash('sha256').update(ext.id).digest('hex').slice(0,24),{cache:false});
    // Extension background networking is least-privilege: only manifest-declared
    // host permissions may leave the sandboxed background session.
    try {
      ses.webRequest.onBeforeRequest({urls:['http://*/*','https://*/*']},(details,callback)=>{
        callback({cancel:!networkAllowedByManifest(ext.manifest,details.url)});
      });
    } catch {}
    if(typeof this.registerProtocols==='function')this.registerProtocols(ses.protocol,'extension '+ext.id);
    const host=new this.BrowserWindow({show:false,webPreferences:{sandbox:true,contextIsolation:true,nodeIntegration:false,webSecurity:true,devTools:false,session:ses,preload:path.join(__dirname,'..','extension-host-preload.js'),additionalArguments:['--aegis-extension-id='+encodeURIComponent(ext.id)]}});
    this.backgroundHosts.set(ext.id,host);
    host.on('closed',()=>{if(this.backgroundHosts.get(ext.id)===host)this.backgroundHosts.delete(ext.id)});
    try{await host.loadFile(wrapper);return true}catch(err){try{host.destroy()}catch{}this.backgroundHosts.delete(ext.id);return false}
  }
  async startAll(){if(this.suspensionReasons.size)return;for(const ext of this.enabled())await this.startBackground(ext)}
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
  stopAll(){for(const id of [...this.backgroundHosts.keys()])this.stopBackground(id);for(const pending of this.pendingMessages.values())pending.resolve(undefined);this.pendingMessages.clear()}
}
module.exports={hostPermissions,networkAllowedByManifest,extensionVisibleTab,extensionWorldId,safeRel,normalizeManifest,extensionId,permissions,compatibility,contentScriptPhase,matchPattern,matchingContentScripts,extensionResourceUrl,rewriteCssUrls,installRisk,validateExtractedTree,bootstrap,AegisExtensionRuntime};
