'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { webExtensionBootstrap, localeMessages, commandList } = require('./extension-shim');

const execFileAsync = promisify(execFile);
const SUPPORTED_ROOTS = new Set([
  'runtime','storage','tabs','windows','cookies','permissions','i18n','activeTab',
  'action','browserAction','pageAction','alarms','commands','scripting','webNavigation','notifications','menus','contextMenus',
  'privacy','declarativeNetRequest','declarativeNetRequestWithHostAccess','webRequest','webRequestBlocking'
]);
const DENIED_ROOTS = Object.freeze({
  proxy:'Extensions cannot replace Aegis network routing.',
  nativeMessaging:'Native messaging is disabled.',
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
function localeTable(root,manifest){
  const locale=safeRel(manifest?.default_locale||'');
  if(!locale)return {};
  try{
    const raw=readJson(path.join(root,'_locales',locale,'messages.json')),out={};
    for(const [key,value] of Object.entries(raw||{}))if(value&&typeof value.message==='string')out[String(key).toLowerCase()]=value.message;
    return out;
  }catch{return {}}
}
function localizeManifest(root,manifest){
  const messages=localeTable(root,manifest);
  if(!Object.keys(messages).length)return manifest;
  const resolve=(value)=>typeof value==='string'?value.replace(/__MSG_([A-Za-z0-9_@.-]+)__/g,(whole,key)=>messages[String(key).toLowerCase()]??whole):value;
  const clone=JSON.parse(JSON.stringify(manifest));
  for(const key of ['name','short_name','description'])if(typeof clone[key]==='string')clone[key]=resolve(clone[key]);
  for(const key of ['action','browser_action','page_action'])if(clone[key]&&typeof clone[key].default_title==='string')clone[key].default_title=resolve(clone[key].default_title);
  return clone;
}
function packageEcosystem(manifest,packageInfo={}){
  const format=String(packageInfo?.format||'').toLowerCase();
  if(format==='crx2'||format==='crx3')return 'chrome';
  if(format==='xpi'||manifest?.browser_specific_settings?.gecko||manifest?.applications?.gecko)return 'firefox';
  return 'webextension';
}
function permissions(m){ return [...new Set([...(Array.isArray(m.permissions)?m.permissions:[]),...(Array.isArray(m.host_permissions)?m.host_permissions:[])])]; }
function hostPermissions(m){
  return permissions(m).filter((p)=>p === '<all_urls>' || /^(?:\*|https?):\/\//.test(String(p||'')));
}
function networkAllowedByManifest(m,url){
  const patterns=hostPermissions(m);
  return patterns.some((p)=>matchPattern(url,p));
}
const DNR_RESOURCE_TYPES=Object.freeze({mainFrame:'main_frame',subFrame:'sub_frame',stylesheet:'stylesheet',script:'script',image:'image',font:'font',object:'object',xhr:'xmlhttprequest',xmlhttprequest:'xmlhttprequest',ping:'ping',media:'media',webSocket:'websocket',websocket:'websocket',other:'other'});
function domainMatchesAny(host,list=[]){host=String(host||'').toLowerCase();return (Array.isArray(list)?list:[]).some((d)=>{d=String(d||'').toLowerCase().replace(/^\*\./,'');return host===d||host.endsWith('.'+d)});}
function dnrUrlFilterMatches(raw,filter,matchCase=false){
  const text=String(raw||''),value=String(filter||'');if(!value)return true;
  let url;try{url=new URL(text)}catch{return false}
  if(value.startsWith('||')){const rest=value.slice(2),cut=rest.search(/[\/^]/),host=(cut<0?rest:rest.slice(0,cut)).replace(/\^.*$/,''),tail=cut<0?'':rest.slice(cut);if(host&&!domainMatchesAny(url.hostname,[host]))return false;if(!tail||tail==='^')return true;filter=tail;}
  const escape=(v)=>String(v).replace(/[|\\{}()[\]^$+*?.-]/g,'\\$&');
  let body=String(filter),startAnchor=false,endAnchor=false;if(body.startsWith('|')){startAnchor=true;body=body.slice(1)}if(body.endsWith('|')){endAnchor=true;body=body.slice(0,-1)}
  let pattern=escape(body).replace(/\\\*/g,'.*').replace(/\\\^/g,'(?:[^a-zA-Z0-9_.%-]|$)');if(startAnchor)pattern='^'+pattern;if(endAnchor)pattern+='$';
  try{return new RegExp(pattern,matchCase?'':'i').test(text)}catch{return false}
}
function dnrRuleMatches(rule,rawUrl,topUrl,resourceType,details={}){
  const cond=rule?.condition||{};let u,top;try{u=new URL(rawUrl)}catch{return false}try{top=new URL(topUrl||rawUrl)}catch{top=u}
  const rt=DNR_RESOURCE_TYPES[resourceType]||String(resourceType||'other').toLowerCase(),method=String(details.method||'GET').toLowerCase(),tabId=Number(details.tabId);
  if(Array.isArray(cond.resourceTypes)&&cond.resourceTypes.length&&!cond.resourceTypes.includes(rt))return false;
  if(Array.isArray(cond.excludedResourceTypes)&&cond.excludedResourceTypes.includes(rt))return false;
  if(Array.isArray(cond.requestMethods)&&cond.requestMethods.length&&!cond.requestMethods.map((x)=>String(x).toLowerCase()).includes(method))return false;
  if(Array.isArray(cond.excludedRequestMethods)&&cond.excludedRequestMethods.map((x)=>String(x).toLowerCase()).includes(method))return false;
  if(Array.isArray(cond.tabIds)&&cond.tabIds.length&&(!Number.isFinite(tabId)||!cond.tabIds.map(Number).includes(tabId)))return false;
  if(Array.isArray(cond.excludedTabIds)&&Number.isFinite(tabId)&&cond.excludedTabIds.map(Number).includes(tabId))return false;
  const requestDomains=cond.requestDomains||cond.domains,excludedRequestDomains=cond.excludedRequestDomains||cond.excludedDomains;
  if(Array.isArray(requestDomains)&&requestDomains.length&&!domainMatchesAny(u.hostname,requestDomains))return false;
  if(domainMatchesAny(u.hostname,excludedRequestDomains))return false;
  if(Array.isArray(cond.initiatorDomains)&&cond.initiatorDomains.length&&!domainMatchesAny(top.hostname,cond.initiatorDomains))return false;
  if(domainMatchesAny(top.hostname,cond.excludedInitiatorDomains))return false;
  const third=!(u.hostname===top.hostname||u.hostname.endsWith('.'+top.hostname)||top.hostname.endsWith('.'+u.hostname));
  if(cond.domainType==='thirdParty'&&!third)return false;if(cond.domainType==='firstParty'&&third)return false;
  if(cond.regexFilter){try{if(!new RegExp(cond.regexFilter,cond.isUrlFilterCaseSensitive?'':'i').test(rawUrl))return false}catch{return false}}
  else if(cond.urlFilter&&!dnrUrlFilterMatches(rawUrl,cond.urlFilter,Boolean(cond.isUrlFilterCaseSensitive)))return false;
  return true;
}
function sanitizeDnrRules(value){return (Array.isArray(value)?value:[]).filter((r)=>r&&Number.isInteger(Number(r.id))&&r.action&&r.condition).map((r)=>({...r,id:Number(r.id),priority:Math.max(1,Number(r.priority)||1)})).slice(0,30000)}
function extensionVisibleTab(tab){
  return Boolean(tab && !tab.disableExtensions && tab.securityDomain!=='anonymous' && tab.securityDomain!=='hardened');
}
function extensionWorldId(id){
  const h=crypto.createHash('sha256').update(String(id)).digest();
  return 1100 + (h.readUInt32BE(0) % 50000);
}
function chromeIdFromBytes(bytes){
  const alphabet='abcdefghijklmnop',b=Buffer.from(bytes||[]);
  if(b.length<16)return '';
  return [...b.subarray(0,16)].map((value)=>alphabet[(value>>4)&15]+alphabet[value&15]).join('');
}
function chromeIdFromManifestKey(m){
  const raw=String(m?.key||'').trim();if(!raw)return '';
  try{return chromeIdFromBytes(crypto.createHash('sha256').update(Buffer.from(raw,'base64')).digest().subarray(0,16))}catch{return ''}
}
function readProtoVarint(buf,state){
  let value=0,shift=0;
  while(state.i<buf.length&&shift<56){const byte=buf[state.i++];value+=(byte&0x7f)*2**shift;if(!(byte&0x80))return value;shift+=7}
  throw new Error('Invalid CRX protobuf varint.');
}
function protoLengthFields(buf,field){
  const values=[],state={i:0};
  while(state.i<buf.length){
    const tag=readProtoVarint(buf,state),number=Math.floor(tag/8),wire=tag&7;
    if(wire===0){readProtoVarint(buf,state);continue}
    if(wire===1){state.i+=8;continue}
    if(wire===5){state.i+=4;continue}
    if(wire!==2)throw new Error('Unsupported CRX protobuf wire type.');
    const len=readProtoVarint(buf,state);if(len<0||state.i+len>buf.length)throw new Error('Invalid CRX protobuf field length.');
    const value=buf.subarray(state.i,state.i+len);state.i+=len;
    if(number===field)values.push(value);
  }
  return values;
}
function protoLengthField(buf,field){return protoLengthFields(buf,field)[0]||null}
function verifyCrxProof(publicKey,signature,payload,algorithm){
  if(!publicKey?.length||!signature?.length)return false;
  try{
    const key={key:Buffer.from(publicKey),format:'der',type:'spki'};
    if(algorithm==='rsa')key.padding=crypto.constants.RSA_PKCS1_PADDING;
    return crypto.verify('sha256',payload,key,Buffer.from(signature));
  }catch{return false}
}
function parseCrxBuffer(buffer){
  const buf=Buffer.from(buffer||[]);
  if(buf.length<12||buf.subarray(0,4).toString('ascii')!=='Cr24')return null;
  const version=buf.readUInt32LE(4);
  if(version===2){
    if(buf.length<16)throw new Error('Invalid CRX2 header.');
    const publicKeyLength=buf.readUInt32LE(8),signatureLength=buf.readUInt32LE(12),zipOffset=16+publicKeyLength+signatureLength;
    if(publicKeyLength>65536||signatureLength>65536||zipOffset>=buf.length)throw new Error('Invalid CRX2 header lengths.');
    const publicKey=buf.subarray(16,16+publicKeyLength),signature=buf.subarray(16+publicKeyLength,zipOffset),archive=buf.subarray(zipOffset);
    const id=chromeIdFromBytes(crypto.createHash('sha256').update(publicKey).digest().subarray(0,16));
    let verified=false;try{verified=crypto.verify('sha1',archive,{key:publicKey,format:'der',type:'spki',padding:crypto.constants.RSA_PKCS1_PADDING},signature)}catch{}
    return {format:'crx2',version,zipOffset,id,signatureMetadata:true,verified};
  }
  if(version===3){
    const headerLength=buf.readUInt32LE(8),zipOffset=12+headerLength;
    if(headerLength>262144||zipOffset>=buf.length)throw new Error('Invalid CRX3 header length.');
    const header=buf.subarray(12,zipOffset);
    for(const token of [Buffer.from([0x50,0x4b,0x05,0x06]),Buffer.from([0x50,0x4b,0x06,0x06]),Buffer.from([0x50,0x4b,0x06,0x07])])if(header.indexOf(token)>=0)throw new Error('Unsafe ZIP end marker found inside CRX3 header.');
    const signedData=protoLengthField(header,10000),crxId=signedData?protoLengthField(signedData,1):null;
    const id=crxId&&crxId.length===16?chromeIdFromBytes(crxId):'';
    if(!signedData||!id)throw new Error('CRX3 signed extension identity is missing.');
    const size=Buffer.alloc(4);size.writeUInt32LE(signedData.length,0);
    const payload=Buffer.concat([Buffer.from('CRX3 SignedData','utf8'),Buffer.from([0]),size,signedData,buf.subarray(zipOffset)]);
    let verified=false,developerProof=false;
    for(const [field,algorithm] of [[2,'rsa'],[3,'ecdsa']]){
      for(const proof of protoLengthFields(header,field)){
        const publicKey=protoLengthField(proof,1),signature=protoLengthField(proof,2);if(!publicKey||!signature)continue;
        const proofId=chromeIdFromBytes(crypto.createHash('sha256').update(publicKey).digest().subarray(0,16));
        if(proofId!==id)continue;
        developerProof=true;
        if(verifyCrxProof(publicKey,signature,payload,algorithm)){verified=true;break}
      }
      if(verified)break;
    }
    return {format:'crx3',version,zipOffset,id,signatureMetadata:true,verified,developerProof};
  }
  throw new Error('Unsupported CRX package version: '+version);
}
function extensionId(m,digest,packageInfo={}){
  const format=String(packageInfo?.format||'').toLowerCase();
  const signedChromeId=/^crx[23]$/.test(format)?String(packageInfo?.id||'').trim():'';
  const geckoId=String(m?.browser_specific_settings?.gecko?.id||m?.applications?.gecko?.id||'').trim();
  const id=signedChromeId||geckoId||packageInfo?.id||chromeIdFromManifestKey(m)||('webext-'+digest.slice(0,32));
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
  if(permissions(m).includes('menus')) roots.add('menus');
  if(permissions(m).includes('contextMenus')) roots.add('contextMenus');
  if(permissions(m).includes('notifications')) roots.add('notifications');
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
  if(contentEntries.some((e)=>e?.run_at==='document_start')) warnings.push({api:'content_scripts.run_at',reason:'document_start uses Aegis early-navigation isolated-world injection; exact Firefox pre-page-script ordering is not guaranteed on every Chromium navigation.'});
  if(contentEntries.some((e)=>e?.all_frames)) warnings.push({api:'content_scripts.all_frames',reason:'Aegis injects declared all_frames scripts into loaded subframes through the sandboxed frame bridge. Exact document_start ordering in newly created subframes can still differ from upstream Chrome/Firefox.'});
  if(Array.isArray(m.optional_permissions)&&m.optional_permissions.length) warnings.push({api:'optional_permissions',reason:'Optional permissions require explicit user approval in Aegis and are not auto-granted.'});
  if(Array.isArray(m.optional_host_permissions)&&m.optional_host_permissions.length) warnings.push({api:'optional_host_permissions',reason:'Optional host access requires explicit user approval in Aegis and is not auto-granted.'});
  if(permissions(m).includes('notifications')) warnings.push({api:'notifications',reason:'Notifications are rendered as prominent Aegis browser-chrome notices; OS notification buttons and native notification-center persistence are not emulated.'});
  if(permissions(m).includes('webRequestBlocking')) warnings.push({api:'webRequestBlocking',reason:'Aegis supports bounded MV2 blocking listeners for cancel, redirect and privacy-strengthening header changes. Extension decisions can only make Aegis stricter; they cannot override Aegis firewall blocks or weaken protected headers.'});
  else if(permissions(m).includes('webRequest')) warnings.push({api:'webRequest',reason:'Aegis forwards request-observation events to extensions. Blocking behavior requires the declared webRequestBlocking permission.'});
  if(permissions(m).some((p)=>p==='declarativeNetRequest'||p==='declarativeNetRequestWithHostAccess')) warnings.push({api:'declarativeNetRequest',reason:'Aegis imports static, dynamic and session DNR rules for block, allow, redirect and upgradeScheme actions. Privacy-strengthening modifyHeaders removals are supported for cookies, referrers and cache/tracking identifiers; security-weakening header changes remain blocked.'});
  if(permissions(m).includes('privacy')) warnings.push({api:'privacy',reason:'Privacy settings are exposed through an Aegis-controlled compatibility surface. Extensions can query them; attempts to weaken Aegis-enforced protections are ignored.'});
  if(permissions(m).includes('menus')||permissions(m).includes('contextMenus')) warnings.push({api:'menus',reason:'Aegis hosts standard extension context-menu items; advanced Firefox menu surfaces and icons are reduced.'});
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
  const runAt=String(entry?.run_at||entry?.runAt||'document_idle');
  if(runAt==='document_idle')return 'idle';
  if(runAt==='document_start')return 'start';
  return 'end';
}
function normalizeRegisteredScript(value){
  const input=value&&typeof value==='object'?value:{},id=String(input.id||'').trim();
  if(!id||id.length>128)throw new Error('Registered content script requires a valid id.');
  const matches=(Array.isArray(input.matches)?input.matches:[]).map(String).filter(Boolean);
  if(!matches.length)throw new Error('Registered content script requires at least one match pattern.');
  const js=(Array.isArray(input.js)?input.js:[]).map(safeRel).filter(Boolean),css=(Array.isArray(input.css)?input.css:[]).map(safeRel).filter(Boolean);
  const exclude=(Array.isArray(input.excludeMatches)?input.excludeMatches:(Array.isArray(input.exclude_matches)?input.exclude_matches:[])).map(String).filter(Boolean);
  return {
    id,matches,exclude_matches:exclude,js,css,
    run_at:String(input.runAt||input.run_at||'document_idle'),
    all_frames:Boolean(input.allFrames??input.all_frames),
    match_about_blank:Boolean(input.matchAboutBlank??input.match_about_blank),
    world:String(input.world||'ISOLATED').toUpperCase()==='MAIN'?'MAIN':'ISOLATED',
    persistAcrossSessions:input.persistAcrossSessions!==false,
    __registered:true
  };
}
function publicRegisteredScript(entry){
  return {
    id:entry.id,matches:[...(entry.matches||[])],excludeMatches:[...(entry.exclude_matches||[])],
    js:[...(entry.js||[])],css:[...(entry.css||[])],runAt:String(entry.run_at||'document_idle'),
    allFrames:Boolean(entry.all_frames),matchOriginAsFallback:Boolean(entry.match_about_blank),
    world:String(entry.world||'ISOLATED'),persistAcrossSessions:entry.persistAcrossSessions!==false
  };
}
function matchingContentScripts(m,url,phase=null){
  return (Array.isArray(m.content_scripts)?m.content_scripts:[]).filter((e)=>{
    const inc=Array.isArray(e.matches)?e.matches:[], exc=Array.isArray(e.exclude_matches)?e.exclude_matches:(Array.isArray(e.excludeMatches)?e.excludeMatches:[]);
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
  const st=fs.statSync(file); if(!st.isFile()||st.size>64*1024*1024) throw new Error('Extension package must be smaller than 64 MB.');
  const r=await execFileAsync('/usr/bin/unzip',['-Z1',file],{maxBuffer:4*1024*1024});
  const entries=r.stdout.split(/\r?\n/).map((x)=>x.trim()).filter(Boolean); if(!entries.length||entries.length>5000)throw new Error('Invalid extension package file count.');
  for(const e of entries) if(!safeRel(e.replace(/\/$/,'')))throw new Error('Unsafe extension package path: '+e);
  return entries;
}
function preparePackageArchive(file,tmpRoot){
  const input=fs.readFileSync(file);if(input.length>64*1024*1024)throw new Error('Extension package must be smaller than 64 MB.');
  const crx=parseCrxBuffer(input);
  if(!crx)return {archive:file,packageInfo:{format:path.extname(file).toLowerCase()==='.xpi'?'xpi':'zip',id:'',signatureMetadata:false,verified:false},ownedArchive:false};
  const archive=path.join(tmpRoot,'crx-payload-'+crypto.randomUUID()+'.zip');
  fs.mkdirSync(tmpRoot,{recursive:true,mode:0o700});fs.writeFileSync(archive,input.subarray(crx.zipOffset),{mode:0o600});
  return {archive,packageInfo:crx,ownedArchive:true};
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
      for(const match of source.matchAll(/\b(?:browser|chrome)\.([A-Za-z_$][\w$]*)/g)){
        const api=String(match[1]||''),before=source.slice(Math.max(0,(match.index||0)-48),match.index||0);
        if(/(?:https?|wss?):\/\/[^\s'\"`]*$/i.test(before))continue;
        if(['com','org','net','io','dev','app','google','mozilla'].includes(api))continue;
        roots.add(api);
      }
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
async function inspectPackage(file,tmpRoot){
  const prepared=preparePackageArchive(file,tmpRoot),entries=await zipEntries(prepared.archive),tmp=path.join(tmpRoot,'inspect-'+crypto.randomUUID());fs.mkdirSync(tmp,{recursive:true,mode:0o700});
  try{
    await execFileAsync('/usr/bin/unzip',['-qq','-o',prepared.archive,'-d',tmp],{maxBuffer:4*1024*1024});
    validateExtractedTree(tmp);
    let root=tmp;if(!fs.existsSync(path.join(root,'manifest.json'))){const dirs=fs.readdirSync(tmp,{withFileTypes:true}).filter((x)=>x.isDirectory());if(dirs.length===1)root=path.join(tmp,dirs[0].name);}
    const rawManifest=normalizeManifest(readJson(path.join(root,'manifest.json'))),manifest=localizeManifest(root,rawManifest),detectedApis=scanUsedApiRoots(root);
    const mozillaMetadata=entries.some((e)=>/^META-INF\/(?:mozilla\.rsa|mozilla\.sf|manifest\.mf)$/i.test(e));
    const packageInfo={...prepared.packageInfo,signatureMetadata:Boolean(prepared.packageInfo.signatureMetadata||mozillaMetadata)};
    return {root,tmp,manifest,detectedApis,packageInfo,compatibility:compatibility(manifest,detectedApis),risk:installRisk(manifest),signature:{metadataPresent:packageInfo.signatureMetadata,verified:Boolean(packageInfo.verified),format:packageInfo.format||'zip'}};
  }catch(err){try{fs.rmSync(tmp,{recursive:true,force:true});}catch{}throw err}
  finally{if(prepared.ownedArchive)try{fs.rmSync(prepared.archive,{force:true})}catch{}}
}
function inspectUnpackedDirectory(dir){
  const root=path.resolve(String(dir||''));const stat=fs.statSync(root);if(!stat.isDirectory())throw new Error('Unpacked extension path is not a directory.');
  validateExtractedTree(root);const rawManifest=normalizeManifest(readJson(path.join(root,'manifest.json'))),manifest=localizeManifest(root,rawManifest),detectedApis=scanUsedApiRoots(root);
  const stableId=chromeIdFromManifestKey(manifest)||chromeIdFromBytes(crypto.createHash('sha256').update(fs.realpathSync(root)).digest().subarray(0,16));
  return {root,manifest,detectedApis,packageInfo:{format:'unpacked',id:stableId,signatureMetadata:false,verified:false},compatibility:compatibility(manifest,detectedApis),risk:installRisk(manifest),signature:{metadataPresent:false,verified:false,format:'unpacked'}};
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
  constructor({rootDir,getTabs,getActiveId,createTab,updateTab,removeTab,BrowserWindow,electronSession,registerProtocols,browserVersion,notifyExtension,getSettings}){
    this.rootDir=rootDir;this.installDir=path.join(rootDir,'extensions');this.indexFile=path.join(this.installDir,'index.json');this.dataDir=path.join(rootDir,'extension-data');
    this.getTabs=getTabs;this.getActiveId=getActiveId||(()=>null);this.createTab=createTab;this.updateTab=updateTab;this.removeTab=removeTab;this.BrowserWindow=BrowserWindow;this.electronSession=electronSession;this.registerProtocols=registerProtocols;this.notifyExtension=typeof notifyExtension==='function'?notifyExtension:null;this.getSettings=typeof getSettings==='function'?getSettings:(()=>({}));
    this.items=new Map();this.sessionStores=new Map();this.backgroundHosts=new Map();this.pendingMessages=new Map();this.pendingBlockingRequests=new Map();this.pendingFrameInjections=new Map();this.pendingFrameMessages=new Map();this.ports=new Map();this.pendingInstalls=new Map();this.suspensionReasons=new Set();this.actionState=new Map();this.alarmTimers=new Map();this.pageWindows=new Set();this.pageSessions=new Map();this.activeGrants=new Map();this.cssKeys=new Map();this.runtimeHealth=new Map();this.menuItems=new Map();this.extensionNotifications=new Map();this.dnrSessionRules=new Map();this.registeredContentScripts=new Map();this.browserVersion=String(browserVersion||'1.1');
    fs.mkdirSync(this.installDir,{recursive:true,mode:0o700}); this.load(); this.save();
  }
  load(){let rows=[];try{rows=readJson(this.indexFile)}catch{} for(const row of Array.isArray(rows)?rows:[]){try{const rawManifest=normalizeManifest(readJson(path.join(row.path,'manifest.json'))),manifest=localizeManifest(row.path,rawManifest);this.items.set(row.id,{...row,worldId:row.worldId||extensionWorldId(row.id),resourceToken:row.resourceToken||crypto.randomBytes(18).toString('hex'),manifest,compatibility:compatibility(manifest,row.detectedApis||[])})}catch{}}}
  save(){writeStore(this.indexFile,[...this.items.values()].map(({manifest,compatibility,...r})=>r))}
  healthFor(id){
    if(!this.runtimeHealth.has(id))this.runtimeHealth.set(id,{errors:[],lastStartedAt:'',lastInjectionAt:'',lastDiagnostic:null});
    return this.runtimeHealth.get(id);
  }
  noteRuntimeError(id,scope,error){
    const health=this.healthFor(id),message=String(error?.message||error||'Unknown extension runtime error').slice(0,500);
    health.errors.unshift({scope:String(scope||'runtime'),message,at:new Date().toISOString()});health.errors=health.errors.slice(0,8);
  }
  clearRuntimeErrors(id,scope=''){
    const health=this.healthFor(id);health.errors=scope?health.errors.filter((x)=>x.scope!==scope&&!x.scope.startsWith(scope+':')):[];
  }
  publicRecord(e){
    const action=extensionAction(e.manifest);
    const icon=iconPath(e.manifest);
    const options=optionsPage(e.manifest);
    const state=this.actionState.get(e.id)||{},health=this.healthFor(e.id),backgroundExpected=Boolean(e.manifest?.background&&(e.manifest.background.page||e.manifest.background.service_worker||(Array.isArray(e.manifest.background.scripts)&&e.manifest.background.scripts.length)));
    return {
      id:e.id,name:e.manifest.name,version:e.manifest.version,description:String(e.manifest.description||''),
      manifestVersion:Number(e.manifest.manifest_version||0),ecosystem:packageEcosystem(e.manifest,{format:e.source}),installability:{status:'installed',packageCoverage:100},enabled:e.enabled!==false,worldId:e.worldId||extensionWorldId(e.id),
      compatibility:e.compatibility,risk:installRisk(e.manifest),installedAt:e.installedAt||'',updatedAt:e.updatedAt||'',
      source:e.source||'webextension',sourceUrl:e.sourceUrl||'',digest:e.digest||'',permissions:permissions(e.manifest),hostPermissions:hostPermissions(e.manifest),
      optionalPermissions:[...(Array.isArray(e.manifest.optional_permissions)?e.manifest.optional_permissions:[]),...(Array.isArray(e.manifest.optional_host_permissions)?e.manifest.optional_host_permissions:[])],
      detectedApis:Array.isArray(e.detectedApis)?e.detectedApis:[],
      runtime:{backgroundExpected,backgroundRunning:backgroundExpected?Boolean(this.backgroundHosts.get(e.id)&&!this.backgroundHosts.get(e.id).isDestroyed()):false,status:e.enabled===false?'disabled':(health.errors.length?'degraded':(backgroundExpected?(this.backgroundHosts.has(e.id)?'running':'stopped'):'ready')),errors:[...health.errors],lastStartedAt:health.lastStartedAt,lastInjectionAt:health.lastInjectionAt,lastDiagnostic:health.lastDiagnostic},
      action:action?{...action,title:String(state.title||action.title),badgeText:String(state.badgeText||''),enabled:state.enabled!==false,iconUrl:String(state.iconUrl||(icon?extensionResourceUrl(e,icon):''))}:null,
      optionsPage:options?extensionResourceUrl(e,options):'',
      features:manifestFeatures(e.manifest)
    };
  }
  list(){return [...this.items.values()].map((e)=>this.publicRecord(e))}
  registeredScriptFile(e){const dir=path.join(this.dataDir,e.id);fs.mkdirSync(dir,{recursive:true,mode:0o700});return path.join(dir,'registered-content-scripts.json')}
  registeredScriptsFor(e){
    if(this.registeredContentScripts.has(e.id))return this.registeredContentScripts.get(e.id);
    const map=new Map();let rows=[];try{rows=readJson(this.registeredScriptFile(e))}catch{}
    for(const row of Array.isArray(rows)?rows:[]){try{const normalized=normalizeRegisteredScript(row);if(normalized.persistAcrossSessions)map.set(normalized.id,normalized)}catch{}}
    this.registeredContentScripts.set(e.id,map);return map;
  }
  saveRegisteredScripts(e){writeStore(this.registeredScriptFile(e),[...this.registeredScriptsFor(e).values()].filter((x)=>x.persistAcrossSessions).map(publicRegisteredScript))}
  registerContentScripts(e,rows=[]){
    const map=this.registeredScriptsFor(e),incoming=(Array.isArray(rows)?rows:[]).map(normalizeRegisteredScript);
    for(const row of incoming){
      const existing=map.get(row.id);
      if(existing&&JSON.stringify(publicRegisteredScript(existing))!==JSON.stringify(publicRegisteredScript(row)))throw new Error('Content script id already registered: '+row.id);
    }
    for(const row of incoming){for(const rel of [...row.js,...row.css])this.extensionFile(e,rel);map.set(row.id,row)}
    this.saveRegisteredScripts(e);return undefined;
  }
  updateRegisteredContentScripts(e,rows=[]){
    const map=this.registeredScriptsFor(e);
    for(const input of Array.isArray(rows)?rows:[]){
      const id=String(input?.id||'');if(!map.has(id))throw new Error('Registered content script not found: '+id);
      const current=publicRegisteredScript(map.get(id)),next=normalizeRegisteredScript({...current,...input,id});
      for(const rel of [...next.js,...next.css])this.extensionFile(e,rel);map.set(id,next);
    }
    this.saveRegisteredScripts(e);return undefined;
  }
  unregisterContentScripts(e,filter={}){
    const map=this.registeredScriptsFor(e),ids=Array.isArray(filter?.ids)?filter.ids.map(String):null;
    if(ids)for(const id of ids)map.delete(id);else map.clear();
    this.saveRegisteredScripts(e);return undefined;
  }
  getRegisteredContentScripts(e,filter={}){
    const ids=Array.isArray(filter?.ids)?new Set(filter.ids.map(String)):null;
    return [...this.registeredScriptsFor(e).values()].filter((row)=>!ids||ids.has(row.id)).map(publicRegisteredScript);
  }
  contentScriptsFor(e){return [...(Array.isArray(e.manifest?.content_scripts)?e.manifest.content_scripts:[]),...this.registeredScriptsFor(e).values()]}
  requiresSubFramePreload(tab=null){
    if(tab&&!extensionVisibleTab(tab))return false;
    return this.enabled().some((e)=>this.contentScriptsFor(e).some((entry)=>Boolean(entry?.all_frames??entry?.allFrames))||permissions(e.manifest).includes('scripting'));
  }
  frameMatchUrl(tab,frame,entry){
    const raw=String(frame?.url||'');
    if(/^https?:\/\//i.test(raw))return raw;
    const fallback=Boolean(entry?.match_about_blank??entry?.matchAboutBlank??entry?.matchOriginAsFallback);
    if(!fallback)return raw;
    let current=frame?.parent||null;
    while(current){
      const candidate=String(current.url||'');
      if(/^https?:\/\//i.test(candidate))return candidate;
      current=current.parent||null;
    }
    return String(tab?.url||'');
  }
  frameInjectionKey(e,entry,phase,frame){
    const entryId=entry.__registered?('registered:'+entry.id):String(this.contentScriptsFor(e).indexOf(entry));
    return e.id+':'+entryId+':'+phase+':frame:'+String(frame?.processId??'p')+':'+String(frame?.routingId??'r');
  }
  sendFrameInjection(contents,frame,payload){
    if(!contents||contents.isDestroyed?.()||!frame||frame.isDestroyed?.())return Promise.resolve({ok:false,error:'Frame is unavailable.'});
    const requestId=crypto.randomUUID(),processId=Number(frame.processId),routingId=Number(frame.routingId);
    return new Promise((resolve)=>{
      const timer=setTimeout(()=>{this.pendingFrameInjections.delete(requestId);resolve({ok:false,error:'Timed out waiting for the subframe extension bridge.'})},2500);
      this.pendingFrameInjections.set(requestId,{resolve:(value)=>{clearTimeout(timer);resolve(value)},contents,processId,routingId,extensionId:String(payload.extensionId||'')});
      try{
        contents.sendToFrame([processId,routingId],'extension:frame-inject',{...payload,requestId,frameProcessId:processId,frameRoutingId:routingId});
      }catch(err){
        clearTimeout(timer);this.pendingFrameInjections.delete(requestId);resolve({ok:false,error:String(err?.message||err)});
      }
    });
  }
  handleFrameInjectionResult(sender,senderFrame,payload={}){
    const requestId=String(payload.requestId||''),pending=this.pendingFrameInjections.get(requestId);
    if(!pending||pending.contents!==sender||pending.extensionId!==String(payload.extensionId||''))return false;
    const processId=Number(senderFrame?.processId),routingId=Number(senderFrame?.routingId);
    if(processId!==pending.processId||routingId!==pending.routingId)return false;
    this.pendingFrameInjections.delete(requestId);pending.resolve(payload);return true;
  }
  sendFrameMessage(contents,frame,payload){
    if(!contents||contents.isDestroyed?.()||!frame||frame.isDestroyed?.())return Promise.resolve({ok:false,error:'Frame is unavailable.'});
    const requestId=crypto.randomUUID(),processId=Number(frame.processId),routingId=Number(frame.routingId);
    return new Promise((resolve)=>{
      const timer=setTimeout(()=>{this.pendingFrameMessages.delete(requestId);resolve({ok:false,error:'Timed out waiting for the subframe message bridge.'})},1500);
      this.pendingFrameMessages.set(requestId,{resolve:(value)=>{clearTimeout(timer);resolve(value)},contents,processId,routingId,extensionId:String(payload.extensionId||'')});
      try{contents.sendToFrame([processId,routingId],'extension:frame-message',{...payload,requestId,frameProcessId:processId,frameRoutingId:routingId})}
      catch(err){clearTimeout(timer);this.pendingFrameMessages.delete(requestId);resolve({ok:false,error:String(err?.message||err)})}
    });
  }
  handleFrameMessageResult(sender,senderFrame,payload={}){
    const requestId=String(payload.requestId||''),pending=this.pendingFrameMessages.get(requestId);
    if(!pending||pending.contents!==sender||pending.extensionId!==String(payload.extensionId||''))return false;
    const processId=Number(senderFrame?.processId),routingId=Number(senderFrame?.routingId);
    if(processId!==pending.processId||routingId!==pending.routingId)return false;
    this.pendingFrameMessages.delete(requestId);pending.resolve(payload);return true;
  }
  async sendTabMessage(e,tab,message,options={}){
    if(!tab||!extensionVisibleTab(tab)||!this.canAccessTab(e,tab,{inject:true}))throw new Error('Tab unavailable to this extension');
    const contents=tab.view?.webContents;if(!contents||contents.isDestroyed())throw new Error('Tab renderer is unavailable');
    const sender={id:e.id};
    const source='globalThis.__aegisReceiveMessage?globalThis.__aegisReceiveMessage('+JSON.stringify(message)+','+JSON.stringify(sender)+'):undefined';
    const requested=options&&Number.isFinite(Number(options.frameId))?Number(options.frameId):null;
    const topResult=async()=>contents.executeJavaScriptInIsolatedWorld(e.worldId||extensionWorldId(e.id),[{code:source}],false);
    if(requested===0)return topResult();
    const main=contents.mainFrame||{__aegisTopFrame:true},frames=Array.isArray(main?.framesInSubtree)?main.framesInSubtree:[main];
    if(requested!==null){
      const frame=frames.find((x)=>x!==main&&Number(x?.routingId)===requested&&!x?.isDestroyed?.());
      if(!frame)throw new Error('Requested extension frame is unavailable.');
      const result=await this.sendFrameMessage(contents,frame,{extensionId:e.id,worldId:e.worldId||extensionWorldId(e.id),message,sender});
      if(!result?.ok)throw new Error(String(result?.error||'Frame message failed.'));
      return result.response;
    }
    let first;
    try{first=await topResult()}catch{}
    if(this.contentScriptsFor(e).some((entry)=>Boolean(entry?.all_frames??entry?.allFrames))){
      for(const frame of frames){
        if(frame===main||frame?.isDestroyed?.())continue;
        try{
          const result=await this.sendFrameMessage(contents,frame,{extensionId:e.id,worldId:e.worldId||extensionWorldId(e.id),message,sender});
          if(first===undefined&&result?.ok&&result.response!==undefined)first=result.response;
        }catch{}
      }
    }
    return first;
  }
  async injectFrame(tab,frame,phase='idle'){
    if(!extensionVisibleTab(tab)||!frame||frame.isDestroyed?.())return [];
    const contents=tab?.view?.webContents;if(!contents||contents.isDestroyed())return [];
    if(contents.mainFrame===frame)return this.inject(tab,phase,String(frame.url||tab.url||''));
    if(!tab.extensionInjectionKeys)tab.extensionInjectionKeys=new Set();
    const done=[];
    for(const e of this.enabled()){
      const all=this.contentScriptsFor(e);
      for(let index=0;index<all.length;index++){
        const entry=all[index];
        if(!Boolean(entry?.all_frames??entry?.allFrames)||contentScriptPhase(entry)!==phase)continue;
        const matchUrl=this.frameMatchUrl(tab,frame,entry);
        if(!matchingContentScripts({content_scripts:[entry]},matchUrl,phase).length)continue;
        const entryId=entry.__registered?('registered:'+entry.id):String(index),key=e.id+':'+entryId+':'+phase+':frame:'+String(frame.processId)+':'+String(frame.routingId);
        if(tab.extensionInjectionKeys.has(key))continue;
        const js=(Array.isArray(entry.js)?entry.js:[]).map(safeRel).filter(Boolean),css=[];
        for(const rel of Array.isArray(entry.css)?entry.css:[]){
          const s=safeRel(rel);if(!s)continue;
          try{css.push({label:s,code:rewriteCssUrls(fs.readFileSync(this.extensionFile(e,s),'utf8'),e,s)})}
          catch(err){this.noteRuntimeError(e.id,'content-css:'+s,err)}
        }
        const scripts=[];
        if(String(entry.world||'ISOLATED').toUpperCase()!=='MAIN')scripts.push({label:'__aegis_content_bootstrap.js',code:bootstrap(e),url:extensionResourceUrl(e,'__aegis_content_bootstrap.js')});
        for(const rel of js){
          try{scripts.push({label:rel,code:fs.readFileSync(this.extensionFile(e,rel),'utf8')+'\n//# sourceURL='+extensionResourceUrl(e,rel),url:extensionResourceUrl(e,rel)})}
          catch(err){this.noteRuntimeError(e.id,'content-script:'+rel,err)}
        }
        const result=await this.sendFrameInjection(contents,frame,{extensionId:e.id,worldId:e.worldId||extensionWorldId(e.id),world:String(entry.world||'ISOLATED').toUpperCase(),scripts,css});
        if(!result?.ok){
          this.noteRuntimeError(e.id,'content-script:frame',new Error(String(result?.error||'Subframe content script injection failed.')));
          continue;
        }
        for(const failure of Array.isArray(result.failures)?result.failures:[]){
          const label=String(failure?.label||'frame');
          this.noteRuntimeError(e.id,(failure?.kind==='css'?'content-css:':'content-script:')+label,new Error(String(failure?.message||'Execution failed.')));
        }
        if((result.scriptCount||result.cssCount)>0){
          done.push(e.id);const health=this.healthFor(e.id);health.lastInjectionAt=new Date().toISOString();
          tab.extensionInjectionKeys.add(key);
        }
        if(!(result.failures||[]).length){this.clearRuntimeErrors(e.id,'content-script');this.clearRuntimeErrors(e.id,'content-css')}
      }
    }
    return [...new Set(done)];
  }
  async injectAllSubframes(tab,phase='idle'){
    if(!extensionVisibleTab(tab)||!this.requiresSubFramePreload(tab))return [];
    const main=tab?.view?.webContents?.mainFrame,frames=Array.isArray(main?.framesInSubtree)?main.framesInSubtree:[];
    const done=[];
    for(const frame of frames){
      if(frame===main||frame?.isDestroyed?.())continue;
      try{done.push(...await this.injectFrame(tab,frame,phase))}catch{}
    }
    return [...new Set(done)];
  }
  dnrFile(e,name){const dir=path.join(this.dataDir,e.id);fs.mkdirSync(dir,{recursive:true,mode:0o700});return path.join(dir,name)}
  dnrEnabledRulesets(e){
    const resources=Array.isArray(e.manifest?.declarative_net_request?.rule_resources)?e.manifest.declarative_net_request.rule_resources:[];
    const defaults=resources.filter((x)=>x?.enabled!==false&&x?.id).map((x)=>String(x.id));
    try{const saved=readJson(this.dnrFile(e,'dnr-enabled.json'));return Array.isArray(saved)?saved.map(String):defaults}catch{return defaults}
  }
  dnrDynamicRules(e){try{return sanitizeDnrRules(readJson(this.dnrFile(e,'dnr-dynamic.json')))}catch{return []}}
  dnrRules(e){
    const out=[],enabled=new Set(this.dnrEnabledRulesets(e)),resources=Array.isArray(e.manifest?.declarative_net_request?.rule_resources)?e.manifest.declarative_net_request.rule_resources:[];
    for(const resource of resources){
      if(!resource?.id||!enabled.has(String(resource.id)))continue;const rel=safeRel(resource.path||'');if(!rel)continue;
      try{out.push(...sanitizeDnrRules(readJson(this.extensionFile(e,rel))))}catch(err){this.noteRuntimeError(e.id,'dnr',err)}
    }
    out.push(...this.dnrDynamicRules(e),...sanitizeDnrRules(this.dnrSessionRules.get(e.id)||[]));
    return out.slice(0,60000);
  }
  updateDnrRules(e,kind,details={}){
    const session=kind==='session',current=session?sanitizeDnrRules(this.dnrSessionRules.get(e.id)||[]):this.dnrDynamicRules(e),remove=new Set((details.removeRuleIds||[]).map(Number));
    const next=current.filter((x)=>!remove.has(Number(x.id))),byId=new Map(next.map((x)=>[Number(x.id),x]));for(const rule of sanitizeDnrRules(details.addRules||[]))byId.set(Number(rule.id),rule);
    const value=[...byId.values()].slice(0,30000);if(session)this.dnrSessionRules.set(e.id,value);else writeStore(this.dnrFile(e,'dnr-dynamic.json'),value);return undefined;
  }
  updateDnrRulesets(e,details={}){
    const set=new Set(this.dnrEnabledRulesets(e));for(const id of details.disableRulesetIds||[])set.delete(String(id));for(const id of details.enableRulesetIds||[])set.add(String(id));
    const valid=new Set((e.manifest?.declarative_net_request?.rule_resources||[]).map((x)=>String(x.id)));const value=[...set].filter((x)=>valid.has(x));writeStore(this.dnrFile(e,'dnr-enabled.json'),value);return undefined;
  }
  networkDecision(tab,details={}){
    if(!extensionVisibleTab(tab))return null;const rawUrl=String(details.url||''),topUrl=String(tab.topUrl||tab.url||rawUrl),rt=details.resourceType||'other';let best=null;
    for(const e of this.enabled()){
      const declared=new Set(permissions(e.manifest));if(!declared.has('declarativeNetRequest')&&!declared.has('declarativeNetRequestWithHostAccess'))continue;if(!networkAllowedByManifest(e.manifest,rawUrl))continue;
      for(const rule of this.dnrRules(e)){if(!dnrRuleMatches(rule,rawUrl,topUrl,rt,{...details,tabId:tab.id}))continue;const type=String(rule.action?.type||''),rank={allow:5,allowAllRequests:5,block:4,upgradeScheme:3,redirect:2,modifyHeaders:1}[type]||0,candidate={e,rule,type,priority:Number(rule.priority)||1,rank};if(!best||candidate.priority>best.priority||(candidate.priority===best.priority&&candidate.rank>best.rank))best=candidate}
    }
    if(!best)return null;const {e,rule,type}=best;if(type==='block')return {action:'block',extensionId:e.id,ruleId:rule.id};if(type==='upgradeScheme'&&/^http:/i.test(rawUrl))return {action:'redirect',redirectURL:rawUrl.replace(/^http:/i,'https:'),extensionId:e.id,ruleId:rule.id};
    if(type==='redirect'){const redir=rule.action?.redirect||{};let target='';if(typeof redir.url==='string'&&/^https?:\/\//i.test(redir.url))target=redir.url;else if(redir.extensionPath)target=extensionResourceUrl(e,redir.extensionPath);else if(redir.regexSubstitution&&rule.condition?.regexFilter){try{target=rawUrl.replace(new RegExp(rule.condition.regexFilter),String(redir.regexSubstitution))}catch{}}if(target)return {action:'redirect',redirectURL:target,extensionId:e.id,ruleId:rule.id}}
    return type==='modifyHeaders'?null:{action:'allow',extensionId:e.id,ruleId:rule.id};
  }
  headerModifications(tab,details={},phase='request'){
    if(!extensionVisibleTab(tab))return [];
    const rawUrl=String(details.url||''),topUrl=String(tab.topUrl||tab.url||rawUrl),rt=details.resourceType||'other';
    const allowedRequestRemovals=new Set(['cookie','referer','if-none-match','if-modified-since','x-client-data']);
    const allowedResponseRemovals=new Set(['set-cookie','etag','last-modified','report-to','nel']);
    const allowed=phase==='response'?allowedResponseRemovals:allowedRequestRemovals,rows=[];
    for(const e of this.enabled()){
      const declared=new Set(permissions(e.manifest));
      if(!declared.has('declarativeNetRequest')&&!declared.has('declarativeNetRequestWithHostAccess'))continue;
      if(!networkAllowedByManifest(e.manifest,rawUrl))continue;
      for(const rule of this.dnrRules(e)){
        if(String(rule.action?.type||'')!=='modifyHeaders'||!dnrRuleMatches(rule,rawUrl,topUrl,rt,{...details,tabId:tab.id}))continue;
        const entries=phase==='response'?rule.action?.responseHeaders:rule.action?.requestHeaders;
        for(const item of Array.isArray(entries)?entries:[]){
          const header=String(item?.header||'').trim().toLowerCase(),operation=String(item?.operation||'').toLowerCase();
          if(operation!=='remove'||!allowed.has(header))continue;
          rows.push({header,operation:'remove',priority:Number(rule.priority)||1,ruleId:Number(rule.id),extensionId:e.id});
        }
      }
    }
    rows.sort((a,b)=>a.priority-b.priority||String(a.extensionId).localeCompare(String(b.extensionId))||a.ruleId-b.ruleId);
    return rows;
  }
  notifyWebRequest(type,tab,details={}){
    if(!extensionVisibleTab(tab))return;
    const url=String(details.url||''),toHeaders=(value)=>{
      if(Array.isArray(value))return value.map((h)=>({name:String(h?.name||''),value:String(h?.value??'')})).filter((h)=>h.name);
      const out=[];for(const [name,raw] of Object.entries(value||{})){for(const item of (Array.isArray(raw)?raw:[raw]))out.push({name:String(name),value:String(item??'')})}return out;
    };
    for(const e of this.enabled()){
      const declared=new Set(permissions(e.manifest));if(!declared.has('webRequest')||!networkAllowedByManifest(e.manifest,url))continue;
      const payload={
        requestId:String(details.id||details.requestId||''),url,method:String(details.method||'GET'),tabId:tab.id,
        type:DNR_RESOURCE_TYPES[details.resourceType]||String(details.resourceType||'other').replace(/[A-Z]/g,(m)=>'_'+m.toLowerCase()),
        frameId:Number(details.frameId??details.frame?.routingId??0),parentFrameId:Number(details.parentFrameId??details.frame?.parent?.routingId??-1),
        initiator:String(details.initiatorOrigin||details.initiator||tab.topUrl||tab.url||''),documentUrl:String(details.documentUrl||details.frame?.url||tab.topUrl||tab.url||''),
        timeStamp:Number(details.timestamp||details.timeStamp||Date.now())
      };
      if(details.requestHeaders)payload.requestHeaders=toHeaders(details.requestHeaders);
      if(details.responseHeaders)payload.responseHeaders=toHeaders(details.responseHeaders);
      if(details.statusCode!=null)payload.statusCode=Number(details.statusCode);
      if(details.statusLine!=null)payload.statusLine=String(details.statusLine);
      if(details.fromCache!=null)payload.fromCache=Boolean(details.fromCache);
      if(details.ip!=null)payload.ip=String(details.ip);
      if(details.error!=null)payload.error=String(details.error);
      this.emitEvent(e,String(type),[payload]);
    }
  }
  blockingWebRequestDetails(tab,details={}){
    const toHeaders=(value)=>{if(Array.isArray(value))return value.map((h)=>({name:String(h?.name||''),value:String(h?.value??'')})).filter((h)=>h.name);const out=[];for(const [name,raw] of Object.entries(value||{})){for(const item of (Array.isArray(raw)?raw:[raw]))out.push({name:String(name),value:String(item??'')})}return out;};
    const payload={requestId:String(details.id||details.requestId||''),url:String(details.url||''),method:String(details.method||'GET'),tabId:tab.id,type:DNR_RESOURCE_TYPES[details.resourceType]||String(details.resourceType||'other').replace(/[A-Z]/g,(m)=>'_'+m.toLowerCase()),frameId:Number(details.frameId??details.frame?.routingId??0),parentFrameId:Number(details.parentFrameId??details.frame?.parent?.routingId??-1),initiator:String(details.initiatorOrigin||details.initiator||tab.topUrl||tab.url||''),documentUrl:String(details.documentUrl||details.frame?.url||tab.topUrl||tab.url||''),timeStamp:Number(details.timestamp||details.timeStamp||Date.now())};
    if(details.requestHeaders)payload.requestHeaders=toHeaders(details.requestHeaders);if(details.responseHeaders)payload.responseHeaders=toHeaders(details.responseHeaders);if(details.statusCode!=null)payload.statusCode=Number(details.statusCode);if(details.statusLine!=null)payload.statusLine=String(details.statusLine);if(details.fromCache!=null)payload.fromCache=Boolean(details.fromCache);if(details.ip!=null)payload.ip=String(details.ip);if(details.error!=null)payload.error=String(details.error);return payload;
  }
  async blockingWebRequestDecision(tab,type,details={},timeoutMs=350){
    if(!extensionVisibleTab(tab))return null;const url=String(details.url||''),jobs=[];
    for(const e of this.enabled()){const declared=new Set(permissions(e.manifest));if(!declared.has('webRequest')||!declared.has('webRequestBlocking')||!networkAllowedByManifest(e.manifest,url))continue;const host=this.backgroundHosts.get(e.id);if(!host||host.isDestroyed())continue;const requestId=crypto.randomUUID(),payload={extensionId:e.id,requestId,type:String(type||''),details:this.blockingWebRequestDetails(tab,details)};jobs.push(new Promise((resolve)=>{const timer=setTimeout(()=>{this.pendingBlockingRequests.delete(requestId);resolve(null)},Math.max(50,Math.min(1000,Number(timeoutMs)||350)));this.pendingBlockingRequests.set(requestId,{extensionId:e.id,host:host.webContents,resolve:(value)=>{clearTimeout(timer);resolve(value)}});try{host.webContents.send('extension:blocking-webrequest',payload)}catch{clearTimeout(timer);this.pendingBlockingRequests.delete(requestId);resolve(null)}}));}
    if(!jobs.length)return null;const results=await Promise.all(jobs),merged={};for(const value of results){if(!value||typeof value!=='object')continue;if(value.cancel===true)merged.cancel=true;const redirect=String(value.redirectUrl||value.redirectURL||'');if(!merged.redirectURL&&/^https?:\/\//i.test(redirect))merged.redirectURL=redirect;if(Array.isArray(value.requestHeaders))merged.requestHeaders=value.requestHeaders;if(Array.isArray(value.responseHeaders))merged.responseHeaders=value.responseHeaders;}return Object.keys(merged).length?merged:null;
  }
  handleBlockingWebRequestResponse(sender,payload={}){
    const requestId=String(payload.requestId||''),pending=this.pendingBlockingRequests.get(requestId);if(!pending||pending.host!==sender||pending.extensionId!==String(payload.extensionId||''))return false;this.pendingBlockingRequests.delete(requestId);const raw=payload.response&&typeof payload.response==='object'?payload.response:null;if(!raw){pending.resolve(null);return true}const safe={cancel:raw.cancel===true};const redirect=String(raw.redirectUrl||raw.redirectURL||'');if(/^https?:\/\//i.test(redirect))safe.redirectURL=redirect;if(Array.isArray(raw.requestHeaders))safe.requestHeaders=raw.requestHeaders.slice(0,256);if(Array.isArray(raw.responseHeaders))safe.responseHeaders=raw.responseHeaders.slice(0,256);pending.resolve(safe);return true;
  }
  privacyValue(key){
    const s=this.getSettings()||{};switch(String(key||'')){case 'network.webRTCIPHandlingPolicy':return 'disable_non_proxied_udp';case 'network.networkPredictionEnabled':return false;case 'services.passwordSavingEnabled':case 'services.autofillAddressEnabled':case 'services.autofillCreditCardEnabled':return false;case 'websites.thirdPartyCookiesAllowed':return s.blockThirdPartyCookies===false;case 'websites.hyperlinkAuditingEnabled':return s.blockTrackingBeacons===false;case 'websites.referrersEnabled':return s.stripCrossSiteReferrers===false;case 'websites.protectedContentEnabled':return false;default:return undefined}}
  privacySetting(key){const value=this.privacyValue(key);return {value,levelOfControl:'not_controllable'}}
  bridgeArguments(){return this.enabled().map((e)=>'--aegis-extension-world='+encodeURIComponent(e.id)+':'+String(e.worldId||extensionWorldId(e.id)))}
  inspectionSummary(x,digest){
    const id=extensionId(x.manifest,digest,x.packageInfo||{});
    return {
      id,name:x.manifest.name,version:x.manifest.version,description:String(x.manifest.description||''),
      manifestVersion:Number(x.manifest.manifest_version||0),compatibility:x.compatibility,risk:x.risk,signature:x.signature,
      packageFormat:x.packageInfo?.format||'zip',ecosystem:packageEcosystem(x.manifest,x.packageInfo||{}),installability:{status:'installable',packageCoverage:100,note:'The package can be installed completely; API/runtime compatibility is reported separately.'},digest,permissions:permissions(x.manifest),hostPermissions:hostPermissions(x.manifest),detectedApis:x.detectedApis||[],
      optionalPermissions:[...(Array.isArray(x.manifest.optional_permissions)?x.manifest.optional_permissions:[]),...(Array.isArray(x.manifest.optional_host_permissions)?x.manifest.optional_host_permissions:[])],
      action:extensionAction(x.manifest),optionsPage:optionsPage(x.manifest),features:manifestFeatures(x.manifest)
    };
  }
  async inspect(file){
    const digest=crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'),x=await inspectPackage(file,path.join(this.rootDir,'extension-staging'));
    try{return this.inspectionSummary(x,digest)}
    finally{try{fs.rmSync(x.tmp,{recursive:true,force:true})}catch{}}
  }
  inspectDirectory(dir){
    const x=inspectUnpackedDirectory(dir),manifestBytes=fs.readFileSync(path.join(x.root,'manifest.json'));
    const digest=crypto.createHash('sha256').update(fs.realpathSync(x.root)).update(manifestBytes).digest('hex');
    return this.inspectionSummary(x,digest);
  }
  async stage(file,{owned=false,sourceUrl=''}={}){
    const summary=await this.inspect(file),token=crypto.randomUUID(),expiresAt=Date.now()+5*60*1000;
    this.pendingInstalls.set(token,{file:String(file),summary,expiresAt,owned:Boolean(owned),sourceUrl:String(sourceUrl||'')});
    for(const [key,value] of this.pendingInstalls)if(value.expiresAt<Date.now()){this.pendingInstalls.delete(key);if(value.owned&&value.file)try{fs.rmSync(value.file,{force:true})}catch{}}
    return {token,summary,expiresAt:new Date(expiresAt).toISOString()};
  }
  stageDirectory(dir){
    const summary=this.inspectDirectory(dir),token=crypto.randomUUID(),expiresAt=Date.now()+5*60*1000;
    this.pendingInstalls.set(token,{directory:path.resolve(String(dir)),summary,expiresAt,owned:false});
    return {token,summary,expiresAt:new Date(expiresAt).toISOString()};
  }
  cancelStage(token){const key=String(token||''),staged=this.pendingInstalls.get(key);if(!staged)return false;this.pendingInstalls.delete(key);if(staged.owned&&staged.file)try{fs.rmSync(staged.file,{force:true})}catch{}return true}
  reviewStage(token){const staged=this.pendingInstalls.get(String(token||''));return staged&&staged.expiresAt>=Date.now()?staged.summary:null}
  async installStaged(token){
    const key=String(token||''),staged=this.pendingInstalls.get(key);
    if(!staged||staged.expiresAt<Date.now()){this.pendingInstalls.delete(key);if(staged?.owned&&staged.file)try{fs.rmSync(staged.file,{force:true})}catch{}throw new Error('Extension review expired. Select the package again.');}
    this.pendingInstalls.delete(key);
    try{return staged.directory?await this.installDirectory(staged.directory):await this.install(staged.file,{sourceUrl:staged.sourceUrl})}
    finally{if(staged.owned&&staged.file)try{fs.rmSync(staged.file,{force:true})}catch{}}
  }
  async install(file,{sourceUrl=''}={}){
    const digest=crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'),x=await inspectPackage(file,path.join(this.rootDir,'extension-staging')),id=extensionId(x.manifest,digest,x.packageInfo||{}),dest=path.join(this.installDir,id);
    const previous=this.items.get(id);this.stopBackground(id);
    fs.rmSync(dest,{recursive:true,force:true});fs.renameSync(x.root,dest);if(x.tmp!==x.root)try{fs.rmSync(x.tmp,{recursive:true,force:true})}catch{}
    const now=new Date().toISOString(),source=x.packageInfo?.format||path.extname(file).slice(1)||'zip';
    const e={id,path:dest,worldId:extensionWorldId(id),resourceToken:previous?.resourceToken||crypto.randomBytes(18).toString('hex'),enabled:previous?.enabled!==false,source,sourceUrl:String(sourceUrl||previous?.sourceUrl||''),digest,installedAt:previous?.installedAt||now,updatedAt:now,manifest:x.manifest,detectedApis:x.detectedApis||[],compatibility:x.compatibility};
    this.items.set(id,e);this.save();if(e.enabled)await this.startBackground(e);this.emitEvent(e,'runtime.onInstalled',[{reason:previous?'update':'install',previousVersion:previous?.manifest?.version||undefined}]);await this.diagnose(id,{repair:false});return this.publicRecord(e);
  }
  async installDirectory(dir){
    const x=inspectUnpackedDirectory(dir),manifestBytes=fs.readFileSync(path.join(x.root,'manifest.json')),digest=crypto.createHash('sha256').update(fs.realpathSync(x.root)).update(manifestBytes).digest('hex'),id=extensionId(x.manifest,digest,x.packageInfo||{}),dest=path.join(this.installDir,id);
    const previous=this.items.get(id);this.stopBackground(id);fs.rmSync(dest,{recursive:true,force:true});fs.cpSync(x.root,dest,{recursive:true,errorOnExist:false,force:true});
    const now=new Date().toISOString(),e={id,path:dest,worldId:extensionWorldId(id),resourceToken:previous?.resourceToken||crypto.randomBytes(18).toString('hex'),enabled:previous?.enabled!==false,source:'unpacked',sourceUrl:fs.realpathSync(x.root),digest,installedAt:previous?.installedAt||now,updatedAt:now,manifest:x.manifest,detectedApis:x.detectedApis||[],compatibility:x.compatibility};
    this.items.set(id,e);this.save();if(e.enabled)await this.startBackground(e);this.emitEvent(e,'runtime.onInstalled',[{reason:previous?'update':'install',previousVersion:previous?.manifest?.version||undefined}]);await this.diagnose(id,{repair:false});return this.publicRecord(e);
  }
  async diagnose(id,{repair=false}={}){
    const e=this.items.get(String(id||''));if(!e)throw new Error('Extension not found');
    const checks=[];
    const add=(id,label,status,evidence)=>checks.push({id,label,status,evidence});
    try{normalizeManifest(e.manifest);add('manifest','Manifest','pass','Manifest V'+e.manifest.manifest_version+' parsed successfully.')}catch(err){add('manifest','Manifest','fail',err.message)}
    try{new Function(this.backgroundBootstrap(e));add('bootstrap','Compatibility bootstrap','pass','Aegis WebExtension compatibility bootstrap compiles.')}catch(err){add('bootstrap','Compatibility bootstrap','fail',err.message)}
    const refs=new Set();
    const addRef=(value)=>{const rel=safeRel(value);if(rel)refs.add(rel)};
    const bg=e.manifest?.background||{};addRef(bg.page);addRef(bg.service_worker);for(const x of Array.isArray(bg.scripts)?bg.scripts:[])addRef(x);
    addRef(extensionAction(e.manifest)?.popup);addRef(optionsPage(e.manifest));
    for(const entry of Array.isArray(e.manifest?.content_scripts)?e.manifest.content_scripts:[]){
      for(const x of Array.isArray(entry.js)?entry.js:[])addRef(x);
      for(const x of Array.isArray(entry.css)?entry.css:[])addRef(x);
    }
    let missing=0;
    for(const rel of refs){try{this.extensionFile(e,rel)}catch{missing++;add('resource:'+rel,'Package resource','fail','Missing or unsafe referenced file: '+rel)}}
    if(!missing)add('resources','Package resources','pass',refs.size+' referenced resource'+(refs.size===1?'':'s')+' verified.');
    const unsupported=e.compatibility?.unsupported||[];
    add('compatibility','API compatibility',unsupported.length?(e.compatibility?.score>=70?'warning':'fail'):'pass',unsupported.length?unsupported.map((x)=>x.api).join(', ')+' unsupported or restricted.':'No unsupported API namespaces detected by static inspection.');
    const expected=Boolean(bg.page||bg.service_worker||(Array.isArray(bg.scripts)&&bg.scripts.length));
    let running=Boolean(this.backgroundHosts.get(e.id)&&!this.backgroundHosts.get(e.id).isDestroyed()),reloadedTabs=0;
    if(repair&&e.enabled!==false){
      this.clearRuntimeErrors(e.id);
      if(expected){
        this.stopBackground(e.id);
        await this.startBackground(e);
        running=Boolean(this.backgroundHosts.get(e.id)&&!this.backgroundHosts.get(e.id).isDestroyed());
      }
      for(const tab of this.getTabs()){
        if(!extensionVisibleTab(tab)||!tab?.view?.webContents||tab.view.webContents.isDestroyed())continue;
        if(tab.extensionInjectionKeys instanceof Set){
          for(const key of [...tab.extensionInjectionKeys])if(String(key).startsWith(e.id+':'))tab.extensionInjectionKeys.delete(key);
        }
        try{tab.view.webContents.reload();reloadedTabs+=1}catch(err){this.noteRuntimeError(e.id,'repair-reload',err)}
      }
    }
    add('background','Background runtime',!expected?'pass':(running?'pass':'fail'),!expected?'No background runtime required.':(running?'Background runtime is running.':'Background runtime is expected but is not running.'));
    if(repair)add('repair','Runtime repair',reloadedTabs||!this.getTabs().some(extensionVisibleTab)?'pass':'warning',reloadedTabs?(reloadedTabs+' private tab'+(reloadedTabs===1?'':'s')+' reloaded so content scripts can start from a clean extension world.'):'No eligible private tabs were reloaded.');
    const health=this.healthFor(e.id);
    add('runtime-errors','Runtime errors',health.errors.length?'warning':'pass',health.errors.length?(health.errors[0].scope+': '+health.errors[0].message):'No recorded extension runtime errors after this check.');
    const counts=checks.reduce((acc,x)=>{acc[x.status]=(acc[x.status]||0)+1;return acc},{pass:0,warning:0,fail:0});
    const status=counts.fail?'fail':(counts.warning?'warning':'pass');
    const diagnostic={testedAt:new Date().toISOString(),status,counts,checks};
    health.lastDiagnostic=diagnostic;return diagnostic;
  }
  async setEnabled(id,v){const e=this.items.get(id);if(!e)throw new Error('Extension not found');e.enabled=Boolean(v);this.save();if(e.enabled){await this.startBackground(e);this.emitEvent(e,'runtime.onStartup',[]);await this.diagnose(id,{repair:false});}else this.stopBackground(id);return this.publicRecord(e)}
  remove(id){const e=this.items.get(id);if(!e)return false;this.stopBackground(id);this.clearAllAlarms(id);this.items.delete(id);this.sessionStores.delete(id);this.dnrSessionRules.delete(id);this.registeredContentScripts.delete(id);this.actionState.delete(id);this.runtimeHealth.delete(id);this.activeGrants.delete(id);this.menuItems.delete(id);this.extensionNotifications.delete(id);this.save();try{fs.rmSync(e.path,{recursive:true,force:true})}catch{}try{fs.rmSync(path.join(this.dataDir,id),{recursive:true,force:true})}catch{}return true}
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
  menuMap(id){if(!this.menuItems.has(id))this.menuItems.set(id,new Map());return this.menuItems.get(id)}
  menuMatches(item,tab,params={}){
    if(item.visible===false||item.enabled===false)return false;
    const contexts=Array.isArray(item.contexts)&&item.contexts.length?item.contexts:['page'];
    const activeContexts=new Set(['all']);
    if(params.linkURL)activeContexts.add('link');
    if(params.selectionText)activeContexts.add('selection');
    if(params.isEditable)activeContexts.add('editable');
    if(['image','video','audio'].includes(params.mediaType))activeContexts.add(params.mediaType);
    if(activeContexts.size===1)activeContexts.add('page');
    if(!contexts.some((ctx)=>activeContexts.has(ctx)||ctx==='all'))return false;
    const documentPatterns=Array.isArray(item.documentUrlPatterns)?item.documentUrlPatterns:[];
    if(documentPatterns.length&&!documentPatterns.some((p)=>matchPattern(tab?.url||'',p)))return false;
    const target=String(params.linkURL||params.srcURL||'');
    const targetPatterns=Array.isArray(item.targetUrlPatterns)?item.targetUrlPatterns:[];
    if(targetPatterns.length&&(!target||!targetPatterns.some((p)=>matchPattern(target,p))))return false;
    return true;
  }
  contextMenuTemplate(tab,params={}){
    if(!extensionVisibleTab(tab))return [];
    const groups=[];
    for(const e of this.enabled()){
      const declared=new Set(permissions(e.manifest));
      if(!declared.has('menus')&&!declared.has('contextMenus'))continue;
      const items=[...this.menuMap(e.id).values()].filter((item)=>this.menuMatches(item,tab,params));
      if(!items.length)continue;
      const byParent=new Map();
      for(const item of items){const parent=String(item.parentId??'__root__');if(!byParent.has(parent))byParent.set(parent,[]);byParent.get(parent).push(item)}
      const build=(parent='__root__',depth=0)=> (byParent.get(String(parent))||[]).slice(0,40).map((item)=>{
        if(item.type==='separator')return {type:'separator'};
        const submenu=depth<3?build(item.id,depth+1):[];
        return {
          label:String(item.title||e.manifest.name).replace(/%s/g,String(params.selectionText||'').slice(0,120)).slice(0,160),
          type:item.type==='checkbox'||item.type==='radio'?item.type:'normal',
          checked:Boolean(item.checked),
          enabled:item.enabled!==false,
          submenu:submenu.length?submenu:undefined,
          click:()=>{
            const info={menuItemId:item.originalId??item.id,parentMenuItemId:item.parentId,mediaType:params.mediaType||'',linkUrl:params.linkURL||'',srcUrl:params.srcURL||'',selectionText:String(params.selectionText||''),editable:Boolean(params.isEditable),pageUrl:this.canAccessTab(e,tab)?(tab.url||''):''};
            const publicTab=this.publicTab(e,tab);this.emitEvent(e,'menus.onClicked',[info,publicTab]);this.emitEvent(e,'contextMenus.onClicked',[info,publicTab]);
          }
        };
      });
      const submenu=build();if(submenu.length)groups.push({label:String(e.manifest.name||'Extension').slice(0,100),submenu});
    }
    return groups;
  }
  clearActiveGrantForTab(tabId){for(const grants of this.activeGrants.values())grants.delete(Number(tabId))}
  notifyTabCreated(tab){this.emitEventAll('tabs.onCreated',(e)=>{const value=this.publicTab(e,tab);return value?[value]:null})}
  notifyTabActivated(tab){this.emitEventAll('tabs.onActivated',(e)=>this.publicTab(e,tab)?[{tabId:tab.id,windowId:1}]:null)}
  notifyTabUpdated(tab,changeInfo={}){
    this.emitEventAll('tabs.onUpdated',(e)=>{const value=this.publicTab(e,tab);return value?[tab.id,{...changeInfo},value]:null});
  }
  notifyTabRemoved(tabId,wasVisible=true){if(!wasVisible)return;this.emitEventAll('tabs.onRemoved',[Number(tabId),{windowId:1,isWindowClosing:false}])}
  notifyNavigation(type,tab,url,error='',frame=null){
    const eventName=String(type||''),main=tab?.view?.webContents?.mainFrame;
    const frameId=frame&&frame!==main?Number(frame.routingId||0):0,parentFrameId=frameId?Number(frame?.parent?.routingId??0):-1;
    this.emitEventAll(eventName,(e)=>{
      if(!permissions(e.manifest).includes('webNavigation')||!this.publicTab(e,tab))return null;
      return [{tabId:tab.id,url:String(url||''),frameId,parentFrameId,timeStamp:Date.now(),error:String(error||'')}];
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
    return [
      '--aegis-extension-id='+encodeURIComponent(e.id),
      '--aegis-extension-context='+encodeURIComponent(context)
    ];
  }
  pageBootstrapData(sender,id,context='page'){
    const e=this.extensionFor(String(id||'')),background=this.backgroundHosts.get(e.id);
    const source=this.getTabs().find((tab)=>tab?.view?.webContents===sender&&tab?.extensionPageExtensionId===e.id);
    const pageAuthorized=[...this.pageWindows].some((win)=>win.__aegisExtensionId===e.id&&!win.isDestroyed()&&win.webContents===sender);
    const backgroundAuthorized=Boolean(background&&!background.isDestroyed()&&background.webContents===sender);
    if(!source&&!pageAuthorized&&!backgroundAuthorized)throw new Error('Extension bootstrap sender is not authorized for '+e.id);
    return {
      extensionId:e.id,
      context:String(context||'page').slice(0,32),
      resourceToken:e.resourceToken,
      manifest:e.manifest,
      messages:localeMessages(e)
    };
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
  async inject(tab,phase='idle',urlOverride=''){
    if(tab?.disableExtensions || tab?.securityDomain === 'anonymous' || tab?.securityDomain === 'hardened') return [];
    if(!tab?.view?.webContents||tab.view.webContents.isDestroyed())return [];
    const contents=tab.view.webContents,url=String(urlOverride||contents.getURL()||''); if(!/^https?:\/\//.test(url))return [];
    if(!tab.extensionInjectionKeys)tab.extensionInjectionKeys=new Set();
    const done=[];
    for(const e of this.enabled()){
      const all=this.contentScriptsFor(e);
      for(let index=0;index<all.length;index++){
        const entry=all[index];
        if(contentScriptPhase(entry)!==phase||!matchingContentScripts({content_scripts:[entry]},url,phase).length)continue;
        const entryId=entry.__registered?('registered:'+entry.id):String(index),key=e.id+':'+entryId+':'+phase;
        if(tab.extensionInjectionKeys.has(key))continue;
        const js=(Array.isArray(entry.js)?entry.js:[]).map(safeRel).filter(Boolean),world=String(entry.world||'ISOLATED').toUpperCase();
        let scriptOk=!js.length,scriptRan=false;
        if(js.length){
          if(world==='MAIN'){
            let failures=0;
            for(const rel of js){
              try{
                const source=fs.readFileSync(this.extensionFile(e,rel),'utf8')+'\n//# sourceURL='+extensionResourceUrl(e,rel);
                await contents.executeJavaScript(source,false);
                scriptRan=true;
              }catch(err){
                failures+=1;
                this.noteRuntimeError(e.id,'content-script:'+rel,err);
              }
            }
            scriptOk=failures===0;
          }else{
            let bridgeReady=false,lastBridgeError=null;
            for(const delay of [0,20,60]){
              if(delay)await new Promise((resolve)=>setTimeout(resolve,delay));
              try{
                await contents.executeJavaScriptInIsolatedWorld(e.worldId||extensionWorldId(e.id),[{code:bootstrap(e),url:extensionResourceUrl(e,'__aegis_content_bootstrap.js')}],false);
                bridgeReady=Boolean(await contents.executeJavaScriptInIsolatedWorld(
                  e.worldId||extensionWorldId(e.id),
                  [{code:"Boolean(globalThis.chrome&&globalThis.chrome.runtime&&typeof globalThis.chrome.runtime.sendMessage==='function')",url:extensionResourceUrl(e,'__aegis_bridge_probe.js')}],
                  false
                ));
                if(bridgeReady)break;
              }catch(err){lastBridgeError=err}
            }
            if(!bridgeReady){
              this.noteRuntimeError(e.id,'content-script',new Error('Aegis isolated-world bridge was not ready for this document'+(lastBridgeError?': '+String(lastBridgeError?.message||lastBridgeError):'.')));
            }else{
              let failures=0;
              for(const rel of js){
                try{
                  const source=fs.readFileSync(this.extensionFile(e,rel),'utf8')+'\n//# sourceURL='+extensionResourceUrl(e,rel);
                  await contents.executeJavaScriptInIsolatedWorld(e.worldId||extensionWorldId(e.id),[{code:source,url:extensionResourceUrl(e,rel)}],false);
                  scriptRan=true;
                }catch(err){
                  failures+=1;
                  this.noteRuntimeError(e.id,'content-script:'+rel,err);
                }
              }
              scriptOk=failures===0;
            }
          }
          if(scriptRan){done.push(e.id);const health=this.healthFor(e.id);health.lastInjectionAt=new Date().toISOString();}
          if(scriptOk)this.clearRuntimeErrors(e.id,'content-script');
        }
        const cssParts=[];
        for(const rel of Array.isArray(entry.css)?entry.css:[]){
          const s=safeRel(rel);if(!s)continue;
          try{cssParts.push(rewriteCssUrls(fs.readFileSync(this.extensionFile(e,s),'utf8'),e,s))}
          catch(err){this.noteRuntimeError(e.id,'content-css:'+s,err)}
        }
        if(cssParts.length)try{await contents.insertCSS(cssParts.join('\n'),{cssOrigin:'author'});done.push(e.id);this.clearRuntimeErrors(e.id,'content-css')}catch(err){this.noteRuntimeError(e.id,'content-css',err)}
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
    const target=details.target||{},frameIds=Array.isArray(target.frameIds)?target.frameIds.map(Number):(Number.isFinite(Number(details.frameId))?[Number(details.frameId)]:[]);
    const allFrames=Boolean(target.allFrames??details.allFrames),files=[...(Array.isArray(details.files)?details.files:[]),...(details.file?[details.file]:[])],world=String(details.world||'ISOLATED').toUpperCase(),contents=tab.view.webContents;
    if(!files.length&&!details.code)throw new Error('Function-object injection is not transferable through Aegis IPC; use files or code.');
    const main=contents.mainFrame||{__aegisTopFrame:true},frames=Array.isArray(main?.framesInSubtree)?main.framesInSubtree:[main];
    let selected=[];
    if(allFrames)selected=frames.length?frames:[main];
    else if(frameIds.length){
      for(const id of frameIds){
        if(id===0){if(main)selected.push(main);continue}
        const frame=frames.find((x)=>x!==main&&Number(x?.routingId)===id&&!x?.isDestroyed?.());
        if(!frame)throw new Error('Requested extension frame is unavailable: '+id);
        selected.push(frame);
      }
    }else selected=main?[main]:[];
    if(!selected.length)throw new Error('No target frame is available for script injection.');

    const packaged=[];
    if(world!=='MAIN')packaged.push({label:'__aegis_scripting_bootstrap.js',code:bootstrap(e),url:extensionResourceUrl(e,'__aegis_scripting_bootstrap.js')});
    for(const rel of files){
      const safe=safeRel(rel);if(!safe)throw new Error('Unsafe extension script path: '+String(rel||''));
      packaged.push({label:safe,code:fs.readFileSync(this.extensionFile(e,safe),'utf8')+'\n//# sourceURL='+extensionResourceUrl(e,safe),url:extensionResourceUrl(e,safe)});
    }
    if(details.code)packaged.push({label:'__aegis_inline_script.js',code:String(details.code),url:extensionResourceUrl(e,'__aegis_inline_script.js')});

    const results=[];
    for(const frame of selected){
      if(frame===main){
        let result;
        if(world==='MAIN'){
          for(const item of packaged)result=await contents.executeJavaScript(item.code,false);
        }else{
          for(const item of packaged)result=await contents.executeJavaScriptInIsolatedWorld(e.worldId||extensionWorldId(e.id),[{code:item.code,url:item.url}],false);
        }
        results.push({frameId:0,result});
        continue;
      }
      const response=await this.sendFrameInjection(contents,frame,{extensionId:e.id,worldId:e.worldId||extensionWorldId(e.id),world,scripts:packaged,css:[]});
      if(!response?.ok)throw new Error('Frame '+String(frame.routingId)+' script injection failed: '+String(response?.error||'unknown error'));
      if(Array.isArray(response.failures)&&response.failures.length){
        const failure=response.failures[0];throw new Error(String(failure?.label||'frame script')+': '+String(failure?.message||'execution failed'));
      }
      results.push({frameId:Number(frame.routingId),result:response.result});
    }
    return results;
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
  async call(sender,p={},senderFrame=null){
    const e=this.extensionFor(p.extensionId),m=String(p.method||''),a=Array.isArray(p.args)?p.args:[],tabs=this.getTabs(),source=tabs.find((t)=>t.view?.webContents===sender),sourceFrame=source&&senderFrame&&!senderFrame.isDestroyed?.()?senderFrame:null;
    const background=this.backgroundHosts.get(e.id),pageAuthorized=[...this.pageWindows].some((win)=>win.__aegisExtensionId===e.id&&!win.isDestroyed()&&win.webContents===sender);
    const senderAuthorized=Boolean((source&&extensionVisibleTab(source))||(background&&!background.isDestroyed()&&background.webContents===sender)||pageAuthorized);
    if(!senderAuthorized)throw new Error('Extension IPC sender is not authorized for '+e.id);
    const declared=new Set(permissions(e.manifest)),hasTabs=declared.has('tabs')||declared.has('activeTab'),requireTabs=()=>{if(!hasTabs)throw new Error('Extension lacks tabs/activeTab permission.')};
    const tabArg=(value,allowSource=true)=>{const id=Number(value);return Number.isFinite(id)?this.tabById(id):(allowSource?source:null)};
    if(m==='runtime.getManifest')return e.manifest;
    if(m==='runtime.getURL')return extensionResourceUrl(e,String(a[0]||''));
    if(m==='runtime.getPlatformInfo')return {os:process.platform==='darwin'?'mac':(process.platform==='win32'?'win':'linux'),arch:process.arch==='arm64'?'arm':'x86-64'};
    if(m==='runtime.getBrowserInfo')return {name:'Aegis Privacy Browser',vendor:'Aegis',version:this.browserVersion,buildID:''};
    if(m==='runtime.openOptionsPage')return this.openOptions(e.id);
    if(m==='runtime.getContexts'){
      const contexts=[];const host=this.backgroundHosts.get(e.id);
      if(host&&!host.isDestroyed())contexts.push({contextId:'background:'+e.id,contextType:'BACKGROUND',documentUrl:host.webContents.getURL()||'',incognito:true});
      for(const win of this.pageWindows)if(win.__aegisExtensionId===e.id&&!win.isDestroyed())contexts.push({contextId:'page:'+String(win.id),contextType:'POPUP',documentUrl:win.webContents.getURL()||'',incognito:true});
      return contexts;
    }
    if(m==='runtime.reload'){this.stopBackground(e.id);await this.startBackground(e);return true}
    if(m==='runtime.sendMessage'){
      if(typeof a[0]==='string'&&a.length>1){
        if(a[0]!==e.id)throw new Error('Cross-extension messaging is not supported.');
        return this.sendRuntimeMessage(e,source,a[1],sourceFrame);
      }
      return this.sendRuntimeMessage(e,source,a[0],sourceFrame);
    }

    if(m==='runtime.portOpen'){
      const details=a[0]||{},portId=String(details.portId||''),name=String(details.name||'').slice(0,120);
      if(!/^[a-zA-Z0-9._:-]{8,160}$/.test(portId))throw new Error('Invalid extension Port id.');
      let target=this.backgroundHosts.get(e.id);
      if((!target||target.isDestroyed())&&e.enabled!==false){await this.startBackground(e);target=this.backgroundHosts.get(e.id)}
      if(!target||target.isDestroyed())throw new Error('Extension background context is unavailable for runtime.connect().');
      this.ports.set(portId,{extensionId:e.id,name,a:sender,b:target.webContents});
      target.webContents.send('extension:event',{extensionId:e.id,type:'runtime.onConnect',args:[{__aegisPort:true,portId,name,sender:source?{tab:this.publicTab(e,source),id:e.id}:{id:e.id}}]});
      return {portId,name};
    }
    if(m==='tabs.connect'){
      requireTabs();
      const target=this.tabById(a[0]);if(!target||!this.canAccessTab(e,target,{inject:true}))throw new Error('Tab unavailable to this extension.');
      const details=a[1]||{},portId=String(details.portId||''),name=String(details.name||'').slice(0,120);
      if(!/^[a-zA-Z0-9._:-]{8,160}$/.test(portId))throw new Error('Invalid extension Port id.');
      this.ports.set(portId,{extensionId:e.id,name,a:sender,b:target.view.webContents});
      target.view.webContents.send('extension:event',{extensionId:e.id,type:'runtime.onConnect',args:[{__aegisPort:true,portId,name,sender:{id:e.id}}]});
      return {portId,name};
    }
    if(m==='runtime.portPost'){
      const portId=String(a[0]||''),entry=this.ports.get(portId);if(!entry||entry.extensionId!==e.id)throw new Error('Extension Port is closed.');
      const target=entry.a===sender?entry.b:(entry.b===sender?entry.a:null);if(!target)throw new Error('Extension Port sender mismatch.');
      try{target.send('extension:event',{extensionId:e.id,type:'runtime.portMessage',args:[portId,a[1]]})}catch{this.ports.delete(portId);throw new Error('Extension Port destination is unavailable.')}
      return true;
    }
    if(m==='runtime.portDisconnect'){
      const portId=String(a[0]||''),entry=this.ports.get(portId);if(!entry||entry.extensionId!==e.id)return false;
      const other=entry.a===sender?entry.b:(entry.b===sender?entry.a:null);this.ports.delete(portId);
      if(other)try{other.send('extension:event',{extensionId:e.id,type:'runtime.portDisconnect',args:[portId]})}catch{}
      return true;
    }

    if(m==='permissions.contains'){const set=new Set(permissions(e.manifest));return [...(a[0]?.permissions||[]),...(a[0]?.origins||[])].every((x)=>set.has(x))}
    if(m==='permissions.getAll')return {permissions:permissions(e.manifest).filter((x)=>!/:\/\//.test(x)&&x!=='<all_urls>'),origins:hostPermissions(e.manifest)};
    if(m==='permissions.request')return false;
    if(m==='permissions.remove')return false;

    if(m.startsWith('privacy.')){
      if(!declared.has('privacy'))throw new Error('Extension lacks privacy permission.');const match=m.match(/^privacy\.(network|services|websites)\.([A-Za-z0-9_]+)\.(get|set|clear)$/);if(!match)throw new Error('Unsupported privacy API: '+m);const key=match[1]+'.'+match[2],op=match[3];
      if(op==='get')return this.privacySetting(key);if(op==='clear')return undefined;const requested=a[0]?.value,current=this.privacyValue(key);if(requested===current)return undefined;throw new Error('Aegis security policy owns '+key+' and will not let an extension weaken it.');
    }

    if(m==='webRequest.handlerBehaviorChanged')return undefined;

    if(m.startsWith('declarativeNetRequest.')){
      if(!declared.has('declarativeNetRequest')&&!declared.has('declarativeNetRequestWithHostAccess'))throw new Error('Extension lacks declarativeNetRequest permission.');
      if(m==='declarativeNetRequest.getDynamicRules')return this.dnrDynamicRules(e);if(m==='declarativeNetRequest.getSessionRules')return sanitizeDnrRules(this.dnrSessionRules.get(e.id)||[]);if(m==='declarativeNetRequest.getEnabledRulesets')return this.dnrEnabledRulesets(e);
      if(m==='declarativeNetRequest.updateDynamicRules')return this.updateDnrRules(e,'dynamic',a[0]||{});if(m==='declarativeNetRequest.updateSessionRules')return this.updateDnrRules(e,'session',a[0]||{});if(m==='declarativeNetRequest.updateEnabledRulesets')return this.updateDnrRulesets(e,a[0]||{});
      if(m==='declarativeNetRequest.isRegexSupported'){try{new RegExp(String(a[0]?.regex||''));return {isSupported:true}}catch(err){return {isSupported:false,reason:String(err.message||err)}}}
      if(m==='declarativeNetRequest.getMatchedRules')return {rulesMatchedInfo:[]};if(m==='declarativeNetRequest.setExtensionActionOptions')return undefined;
    }

    if(m.startsWith('storage.')){
      const [,area,op]=m.split('.');
      const persistent=area==='local'||area==='sync';
      const file=path.join(this.dataDir,e.id,area==='sync'?'storage-sync.json':'storage.json');
      const store=area==='managed'?{}:(persistent?readStore(file):(this.sessionStores.get(e.id)||{}));
      const before={...store};if(!persistent&&area!=='managed')this.sessionStores.set(e.id,store);
      if(op==='get')return getKeys(store,a[0]);
      if(op==='getKeys')return Object.keys(store);
      if(op==='getBytesInUse'){
        const selected=getKeys(store,a[0]);
        return Buffer.byteLength(JSON.stringify(selected),'utf8');
      }
      if(area==='managed'&&['set','remove','clear'].includes(op))throw new Error('storage.managed is read-only.');
      if(op==='set')Object.assign(store,a[0]||{});
      if(op==='remove')for(const k of Array.isArray(a[0])?a[0]:[a[0]])delete store[k];
      if(op==='clear')for(const k of Object.keys(store))delete store[k];
      if(persistent)writeStore(file,store);
      const changes={};for(const key of new Set([...Object.keys(before),...Object.keys(store)])){if(JSON.stringify(before[key])!==JSON.stringify(store[key]))changes[key]={oldValue:before[key],newValue:store[key]}}
      if(Object.keys(changes).length)this.emitEvent(e,'storage.onChanged',[changes,area]);return undefined;
    }

    if(m==='tabs.query'){
      const q=a[0]||{},patterns=q.url==null?null:(Array.isArray(q.url)?q.url:[q.url]).map(String);
      const urlMatches=(raw)=>{
        if(!patterns)return true;
        const value=String(raw||'');
        return patterns.some((pattern)=>{
          if(pattern==='<all_urls>')return /^https?:\/\//i.test(value);
          if(!pattern.includes('*'))return value===pattern;
          const escaped=pattern.split('*').map((part)=>part.replace(/[-/\\^$+?.()|[\]{}]/g,'\\$&')).join('.*');
          try{return new RegExp('^'+escaped+'$').test(value)}catch{return false}
        });
      };
      return tabs.filter(extensionVisibleTab)
        .filter((t)=>!q.active||t.id===this.getActiveId())
        .filter((t)=>urlMatches(t.url))
        .map((t)=>this.publicTab(e,t));
    }
    if(m==='tabs.get'){const t=this.tabById(a[0]);if(!extensionVisibleTab(t))throw new Error('Tab unavailable to extensions');return this.publicTab(e,t)}
    if(m==='tabs.getCurrent')return source?this.publicTab(e,source):null;
    if(m==='tabs.create'){requireTabs();
      const raw=String(a[0]?.url||'aegis://app/start.html');let options={};
      try{const u=new URL(raw);if(u.protocol==='aegis-extension:'&&u.hostname===e.resourceToken)options={extensionPageExtensionId:e.id}}catch{}
      return this.publicTab(e,await this.createTab(raw,a[0]?.active!==false,false,options))
    }
    if(m==='tabs.update'){
      requireTabs();const id=typeof a[0]==='number'?a[0]:source?.id,target=this.tabById(id);if(!extensionVisibleTab(target))throw new Error('Extensions cannot access hardened or anonymous compartments.');
      await this.updateTab(id,typeof a[0]==='number'?(a[1]||{}):(a[0]||{}));
      return this.publicTab(e,this.tabById(id));
    }
    if(m==='tabs.reload'){requireTabs();const target=tabArg(typeof a[0]==='number'?a[0]:undefined);if(!extensionVisibleTab(target))throw new Error('Tab unavailable to extensions');target.view.webContents.reload();return undefined}
    if(m==='tabs.remove'){requireTabs();for(const id of (Array.isArray(a[0])?a[0]:[a[0]])){const target=this.tabById(id);if(!extensionVisibleTab(target))throw new Error('Extensions cannot access hardened or anonymous compartments.');this.removeTab(Number(id))}return undefined}
    if(m==='tabs.sendMessage'){const t=this.tabById(a[0]);return this.sendTabMessage(e,t,a[1],a[2]||{})}
    if(m==='tabs.executeScript'){const target=tabArg(typeof a[0]==='number'?a[0]:undefined),details=typeof a[0]==='number'?(a[1]||{}):(a[0]||{});return this.executeExtensionScript(e,target,details)}
    if(m==='tabs.insertCSS'){const target=tabArg(typeof a[0]==='number'?a[0]:undefined),details=typeof a[0]==='number'?(a[1]||{}):(a[0]||{});return this.insertExtensionCss(e,target,details)}
    if(m==='tabs.removeCSS'){const target=tabArg(typeof a[0]==='number'?a[0]:undefined),details=typeof a[0]==='number'?(a[1]||{}):(a[0]||{});return this.removeExtensionCss(e,target,details)}
    if(m==='tabs.getZoom'){const target=tabArg(typeof a[0]==='number'?a[0]:undefined);if(!target||!extensionVisibleTab(target))throw new Error('Tab unavailable to extensions');return Number(target.view.webContents.getZoomFactor?.()||1)}
    if(m==='tabs.setZoom'){const target=tabArg(typeof a[0]==='number'?a[0]:undefined),factor=Number(typeof a[0]==='number'?a[1]:a[0]);if(!target||!extensionVisibleTab(target)||!Number.isFinite(factor)||factor<0.5||factor>3)throw new Error('Invalid tab zoom request');target.view.webContents.setZoomFactor?.(factor);return undefined}
    if(m==='tabs.captureVisibleTab'){requireTabs();const target=this.tabById(this.getActiveId());if(!target||!this.canAccessTab(e,target,{inject:true}))throw new Error('Extension lacks access to the active tab');const image=await target.view.webContents.capturePage();return image.toDataURL()}

    if(m.startsWith('windows.')){
      const visible=tabs.filter(extensionVisibleTab),active=this.tabById(this.getActiveId());
      const record=()=>({id:1,focused:true,incognito:true,type:'normal',state:'normal',alwaysOnTop:false,tabs:visible.map((t)=>this.publicTab(e,t)).filter(Boolean)});
      if(['windows.get','windows.getCurrent','windows.getLastFocused'].includes(m))return record();
      if(m==='windows.getAll')return [record()];
      if(m==='windows.update')return record();
    }

    if(m.startsWith('cookies.')){
      if(!declared.has('cookies'))throw new Error('Extension lacks cookies permission.');
      const details=a[0]||{},requested=String(details.url||'');
      const candidates=tabs.filter(extensionVisibleTab).filter((t)=>this.canAccessTab(e,t));
      let target=requested?candidates.find((t)=>{try{return new URL(t.url||'').origin===new URL(requested).origin}catch{return false}}):this.tabById(this.getActiveId());
      if(!target||!extensionVisibleTab(target)||!this.canAccessTab(e,target))throw new Error('Cookie access requires a declared host permission for an open private tab.');
      const ses=target.privateSession||target.view?.webContents?.session;if(!ses?.cookies)throw new Error('Cookie store unavailable.');
      if(m==='cookies.get'){const rows=await ses.cookies.get({url:requested||target.url,name:String(details.name||'')});return rows[0]||null}
      if(m==='cookies.getAll'){
        const query={};if(requested)query.url=requested;if(details.name)query.name=String(details.name);if(details.domain)query.domain=String(details.domain);if(details.path)query.path=String(details.path);
        return ses.cookies.get(query);
      }
      if(m==='cookies.set'){
        const url=requested||target.url;if(!networkAllowedByManifest(e.manifest,url)&&!this.activeGrants.get(e.id)?.has(target.id))throw new Error('Cookie write is outside declared host access.');
        const payload={...details,url};delete payload.storeId;await ses.cookies.set(payload);const rows=await ses.cookies.get({url,name:String(payload.name||'')});return rows[0]||null;
      }
      if(m==='cookies.remove'){const url=requested||target.url;const rows=await ses.cookies.get({url,name:String(details.name||'')});await ses.cookies.remove(url,String(details.name||''));return rows[0]?{url,name:String(details.name||''),storeId:'aegis-private-'+target.id}:null}
      if(m==='cookies.getAllCookieStores')return [{id:'aegis-private-'+target.id,tabIds:[target.id],incognito:true}];
    }

    if(m==='scripting.executeScript'){if(!declared.has('scripting'))throw new Error('Extension lacks scripting permission.');const target=this.tabById(a[0]?.target?.tabId);return this.executeExtensionScript(e,target,a[0]||{})}
    if(m==='scripting.insertCSS'){if(!declared.has('scripting'))throw new Error('Extension lacks scripting permission.');const target=this.tabById(a[0]?.target?.tabId);return this.insertExtensionCss(e,target,a[0]||{})}
    if(m==='scripting.removeCSS'){if(!declared.has('scripting'))throw new Error('Extension lacks scripting permission.');const target=this.tabById(a[0]?.target?.tabId);return this.removeExtensionCss(e,target,a[0]||{})}
    if(m==='scripting.registerContentScripts'){if(!declared.has('scripting'))throw new Error('Extension lacks scripting permission.');return this.registerContentScripts(e,a[0]||[])}
    if(m==='scripting.updateContentScripts'){if(!declared.has('scripting'))throw new Error('Extension lacks scripting permission.');return this.updateRegisteredContentScripts(e,a[0]||[])}
    if(m==='scripting.unregisterContentScripts'){if(!declared.has('scripting'))throw new Error('Extension lacks scripting permission.');return this.unregisterContentScripts(e,a[0]||{})}
    if(m==='scripting.getRegisteredContentScripts'){if(!declared.has('scripting'))throw new Error('Extension lacks scripting permission.');return this.getRegisteredContentScripts(e,a[0]||{})}

    if(m==='alarms.create'){if(!declared.has('alarms'))throw new Error('Extension lacks alarms permission.');return this.createAlarm(e,typeof a[0]==='string'?a[0]:'',typeof a[0]==='string'?(a[1]||{}):(a[0]||{}))}
    if(m==='alarms.get'){return this.alarmTimers.get(this.alarmKey(e.id,a[0]))?.alarm||null}
    if(m==='alarms.getAll')return this.alarmList(e.id);
    if(m==='alarms.clear')return this.clearAlarm(e.id,a[0]);
    if(m==='alarms.clearAll')return this.clearAllAlarms(e.id);
    if(m==='commands.getAll')return commandList(e.manifest);

    if(m==='notifications.create'){
      if(!declared.has('notifications'))throw new Error('Extension lacks notifications permission.');
      const id=typeof a[0]==='string'?a[0]:crypto.randomUUID(),details=(typeof a[0]==='string'?(a[1]||{}):(a[0]||{}));
      const record={id,title:String(details.title||e.manifest.name).slice(0,160),message:String(details.message||'').slice(0,1000),createdAt:new Date().toISOString()};
      if(!this.extensionNotifications.has(e.id))this.extensionNotifications.set(e.id,new Map());this.extensionNotifications.get(e.id).set(String(id),record);
      this.notifyExtension?.({extensionId:e.id,name:e.manifest.name,title:record.title,message:record.message,tone:'default'});
      return String(id);
    }
    if(m==='notifications.clear'){const map=this.extensionNotifications.get(e.id);return Boolean(map?.delete(String(a[0]||'')))}
    if(m==='notifications.getAll')return Object.fromEntries(this.extensionNotifications.get(e.id)||[]);

    if(/^(?:menus|contextMenus)\./.test(m)){
      if(!declared.has('menus')&&!declared.has('contextMenus'))throw new Error('Extension lacks menus/contextMenus permission.');
      const [,op]=m.split('.'),map=this.menuMap(e.id);
      if(op==='create'){
        const item={...(a[0]||{})},originalId=item.id,id=originalId!==undefined?String(originalId):String(crypto.randomUUID());
        item.id=id;map.set(id,item);return item.originalId??id;
      }
      if(op==='update'){const id=String(a[0]||''),item=map.get(id);if(!item)return false;Object.assign(item,a[1]||{});return true}
      if(op==='remove')return map.delete(String(a[0]||''));
      if(op==='removeAll'){map.clear();return true}
    }

    if(/^(?:action|browserAction|pageAction)\./.test(m)){
      const [,op]=m.split('.'),action=extensionAction(e.manifest);if(!action)throw new Error('Extension has no browser action.');
      const state={...(this.actionState.get(e.id)||{})},details=a[0]||{};
      if(op==='setTitle'){state.title=String(details.title||'').slice(0,160);this.actionState.set(e.id,state);return}
      if(op==='getTitle')return String(state.title||action.title||e.manifest.name);
      if(op==='setBadgeText'){state.badgeText=String(details.text||'').slice(0,12);this.actionState.set(e.id,state);return}
      if(op==='getBadgeText')return String(state.badgeText||'');
      if(op==='setBadgeBackgroundColor'){state.badgeColor=details.color||null;this.actionState.set(e.id,state);return}
      if(op==='setBadgeTextColor'){state.badgeTextColor=details.color||null;this.actionState.set(e.id,state);return}
      if(op==='getUserSettings')return {isOnToolbar:true};
      if(op==='setPopup'){state.popup=safeRel(details.popup||'');this.actionState.set(e.id,state);return}
      if(op==='getPopup')return String(state.popup!==undefined?state.popup:(action.popup||''));
      if(op==='setIcon'){
        let rel='';if(typeof details.path==='string')rel=safeRel(details.path);else if(details.path&&typeof details.path==='object'){rel=Object.values(details.path).map(safeRel).filter(Boolean).pop()||''}
        if(rel){this.extensionFile(e,rel);state.iconUrl=extensionResourceUrl(e,rel)}this.actionState.set(e.id,state);return;
      }
      if(op==='enable'){state.enabled=true;this.actionState.set(e.id,state);return}
      if(op==='disable'){state.enabled=false;this.actionState.set(e.id,state);return}
      if(op==='isEnabled')return state.enabled!==false;
      if(op==='openPopup'){if(state.enabled===false)return false;return this.openAction(e.id);}
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
  attachBackgroundDiagnostics(ext,host){
    if(!host?.webContents)return;
    try{host.webContents.on('console-message',(_event,...args)=>{
      let level=args[0],message=args[1],line=args[2],source=args[3];
      if(args.length===1&&args[0]&&typeof args[0]==='object'){const d=args[0];level=d.level;message=d.message;line=d.lineNumber;source=d.sourceId}
      const text=String(message||'');
      const severe=Number(level)>=3||/^(?:Uncaught\s+)?(?:SyntaxError|ReferenceError|TypeError|RangeError|Error)\b/i.test(text)||/Uncaught\s+(?:in promise\s+)?/i.test(text);
      if(severe)this.noteRuntimeError(ext.id,'background-console',text+(source?(' · '+source+(line?(':'+line):'')):''));
    })}catch{}
    try{host.webContents.on('render-process-gone',(_event,details)=>this.noteRuntimeError(ext.id,'background-process','Renderer exited: '+String(details?.reason||'unknown')))}catch{}
    try{host.on('unresponsive',()=>this.noteRuntimeError(ext.id,'background-process','Extension background became unresponsive.'))}catch{}
  }
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
      host.__aegisExtensionId=ext.id;this.backgroundHosts.set(ext.id,host);this.attachBackgroundDiagnostics(ext,host);host.on('closed',()=>{if(this.backgroundHosts.get(ext.id)===host)this.backgroundHosts.delete(ext.id)});
      try{await host.loadURL(extensionResourceUrl(ext,page));const health=this.healthFor(ext.id);health.lastStartedAt=new Date().toISOString();this.clearRuntimeErrors(ext.id,'background');return true}catch(err){this.noteRuntimeError(ext.id,'background',err);try{host.destroy()}catch{}this.backgroundHosts.delete(ext.id);return false}
    }

    if(!scripts.length)return false;
    const valid=scripts.filter((rel)=>{try{this.extensionFile(ext,rel);return true}catch{return false}});
    if(!valid.length)return false;
    const wrapper=path.join(ext.path,'__aegis_background.html'),bootstrapFile=path.join(ext.path,'__aegis_background_bootstrap.js');
    fs.writeFileSync(bootstrapFile,this.backgroundBootstrap(ext),{mode:0o600});
    const serviceWorker=safeRel(bg.service_worker||''),moduleWorker=Boolean(serviceWorker&&String(bg.type||'').toLowerCase()==='module');
    const tags=['<script src="__aegis_background_bootstrap.js"></script>',...valid.map((rel)=>'<script'+(moduleWorker&&rel===serviceWorker?' type="module"':'')+' src="'+rel.replace(/&/g,'&amp;').replace(/"/g,'&quot;')+'"></script>')].join('');
    const html='<!doctype html><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'self\'; script-src \'self\'; connect-src https: http: aegis-extension:; img-src \'self\' data: aegis-extension:; style-src \'self\' \'unsafe-inline\'; object-src \'none\'">'+tags;
    fs.writeFileSync(wrapper,html,{mode:0o600});
    const host=new this.BrowserWindow({show:false,webPreferences:{sandbox:true,contextIsolation:true,nodeIntegration:false,webSecurity:true,devTools:false,session:ses,preload:path.join(__dirname,'..','extension-host-preload.js'),additionalArguments:['--aegis-extension-id='+encodeURIComponent(ext.id)]}});
    host.__aegisExtensionId=ext.id;this.backgroundHosts.set(ext.id,host);this.attachBackgroundDiagnostics(ext,host);host.on('closed',()=>{if(this.backgroundHosts.get(ext.id)===host)this.backgroundHosts.delete(ext.id)});
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
  sendRuntimeMessage(ext, sourceTab, message, sourceFrame=null){
    const host=this.backgroundHosts.get(ext.id);
    if(!host||host.isDestroyed())return Promise.resolve(undefined);
    const messageId=crypto.randomUUID(),visible=sourceTab&&!sourceTab.disableExtensions&&sourceTab.securityDomain!=='anonymous'&&sourceTab.securityDomain!=='hardened';
    let sender;
    if(visible){
      const topRaw=String(sourceTab.url||''),frameRaw=String(sourceFrame?.url||topRaw);let origin='null';
      try{origin=new URL(frameRaw).origin}catch{}
      if(origin==='null'&&sourceFrame){
        let parent=sourceFrame.parent||null;
        while(parent&&origin==='null'){
          try{const candidate=new URL(String(parent.url||''));if(/^https?:$/.test(candidate.protocol))origin=candidate.origin}catch{}
          parent=parent?.parent||null;
        }
      }
      const frameId=sourceFrame&&sourceTab?.view?.webContents?.mainFrame!==sourceFrame?Number(sourceFrame.routingId||0):0;
      sender={id:ext.id,tab:this.publicTab(ext,sourceTab)||{id:sourceTab.id,url:topRaw,title:sourceTab.title||'',incognito:true},frameId,url:frameRaw,origin};
    }else{
      sender={id:ext.id,frameId:0,url:extensionResourceUrl(ext,''),origin:'aegis-extension://'+ext.resourceToken};
    }
    return new Promise((resolve)=>{
      const timer=setTimeout(()=>{this.pendingMessages.delete(messageId);resolve(undefined)},30000);
      this.pendingMessages.set(messageId,{extensionId:ext.id,resolve:(value)=>{clearTimeout(timer);resolve(value)}});
      host.webContents.send('extension:runtime-message',{extensionId:ext.id,messageId,message,sender});
    });
  }
  handleBackgroundResponse(sender,payload={}){
    const id=String(payload.extensionId||''),pending=this.pendingMessages.get(String(payload.messageId||'')),host=this.backgroundHosts.get(id);
    if(!pending||pending.extensionId!==id||!host||host.webContents!==sender)return false;
    this.pendingMessages.delete(String(payload.messageId));pending.resolve(payload.response);return true;
  }
  stopAll(){for(const id of [...this.backgroundHosts.keys()])this.stopBackground(id);for(const win of [...this.pageWindows])try{if(!win.isDestroyed())win.destroy()}catch{}this.pageWindows.clear();for(const id of this.items.keys())this.clearAllAlarms(id);for(const pending of this.pendingMessages.values())pending.resolve(undefined);this.pendingMessages.clear();for(const pending of this.pendingBlockingRequests.values())pending.resolve(null);this.pendingBlockingRequests.clear();for(const pending of this.pendingFrameInjections.values())pending.resolve({ok:false,error:'Extension runtime stopped.'});this.pendingFrameInjections.clear();for(const pending of this.pendingFrameMessages.values())pending.resolve({ok:false,error:'Extension runtime stopped.'});this.pendingFrameMessages.clear();this.ports.clear()}
}
module.exports={hostPermissions,networkAllowedByManifest,extensionVisibleTab,extensionWorldId,safeRel,normalizeManifest,localizeManifest,packageEcosystem,extensionId,permissions,compatibility,contentScriptPhase,matchPattern,matchingContentScripts,extensionResourceUrl,rewriteCssUrls,installRisk,scanUsedApiRoots,validateExtractedTree,bootstrap,AegisExtensionRuntime};
