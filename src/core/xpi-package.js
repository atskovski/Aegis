'use strict';

const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const zlib=require('node:zlib');
const { analyzeManifest }=require('./extension-runtime');

const MAX_ARCHIVE=64*1024*1024;
const MAX_FILES=2500;
const MAX_UNCOMPRESSED=256*1024*1024;

function safeEntryName(name){
  if(typeof name!=='string'||!name||name.length>1000||name.includes('\\0')) return '';
  const normalized=path.posix.normalize(name.replace(/\\\\/g,'/'));
  if(normalized==='..'||normalized.startsWith('../')||normalized.startsWith('/')||/^[A-Za-z]:/.test(normalized)) return '';
  return normalized;
}
function findEocd(buf){
  for(let i=Math.max(0,buf.length-65557);i<=buf.length-22;i++){
    if(buf.readUInt32LE(i)===0x06054b50) return i;
  }
  return -1;
}
function readZipEntries(buffer){
  const buf=Buffer.isBuffer(buffer)?buffer:Buffer.from(buffer||[]);
  if(buf.length<22||buf.length>MAX_ARCHIVE) throw new Error('XPI size is invalid or exceeds 64 MB.');
  const eocd=findEocd(buf); if(eocd<0) throw new Error('XPI is not a valid ZIP archive.');
  const count=buf.readUInt16LE(eocd+10), centralSize=buf.readUInt32LE(eocd+12), centralOffset=buf.readUInt32LE(eocd+16);
  if(count>MAX_FILES||centralOffset+centralSize>buf.length) throw new Error('XPI central directory is invalid or too large.');
  let off=centralOffset,total=0; const entries=[];
  for(let n=0;n<count;n++){
    if(off+46>buf.length||buf.readUInt32LE(off)!==0x02014b50) throw new Error('XPI central directory entry is invalid.');
    const method=buf.readUInt16LE(off+10), compressed=buf.readUInt32LE(off+20), uncompressed=buf.readUInt32LE(off+24);
    const nameLen=buf.readUInt16LE(off+28), extraLen=buf.readUInt16LE(off+30), commentLen=buf.readUInt16LE(off+32), localOffset=buf.readUInt32LE(off+42);
    const name=safeEntryName(buf.subarray(off+46,off+46+nameLen).toString('utf8'));
    if(!name) throw new Error('XPI contains an unsafe file path.');
    total+=uncompressed; if(total>MAX_UNCOMPRESSED) throw new Error('XPI expands beyond the 256 MB safety limit.');
    entries.push({name,method,compressed,uncompressed,localOffset,directory:name.endsWith('/')});
    off+=46+nameLen+extraLen+commentLen;
  }
  return entries.map((entry)=>{
    if(entry.directory) return {...entry,data:Buffer.alloc(0)};
    const lo=entry.localOffset;
    if(lo+30>buf.length||buf.readUInt32LE(lo)!==0x04034b50) throw new Error('XPI local file header is invalid.');
    const nameLen=buf.readUInt16LE(lo+26), extraLen=buf.readUInt16LE(lo+28), start=lo+30+nameLen+extraLen, end=start+entry.compressed;
    if(end>buf.length) throw new Error('XPI file data is truncated.');
    const raw=buf.subarray(start,end);
    let data;
    if(entry.method===0) data=Buffer.from(raw);
    else if(entry.method===8) data=zlib.inflateRawSync(raw,{maxOutputLength:Math.max(1,entry.uncompressed)});
    else throw new Error('Unsupported XPI compression method '+entry.method+'.');
    if(data.length!==entry.uncompressed) throw new Error('XPI uncompressed size mismatch.');
    return {...entry,data};
  });
}
function manifestFromEntries(entries){
  const file=entries.find((e)=>e.name==='manifest.json'&&!e.directory);
  if(!file) throw new Error('XPI does not contain manifest.json at its root.');
  let manifest; try{manifest=JSON.parse(file.data.toString('utf8'));}catch{throw new Error('manifest.json is not valid JSON.');}
  return manifest;
}
function referencedScripts(manifest){
  const refs=[];
  for(const cs of (manifest.content_scripts||[])) for(const file of (cs.js||[])) refs.push(file);
  return [...new Set(refs)];
}
function scanRuntimeApiUsage(entries, manifest){
  const used=[];
  for(const file of referencedScripts(manifest)){
    const normalized=safeEntryName(file); const entry=entries.find((e)=>e.name===normalized&&!e.directory); if(!entry) continue;
    const src=entry.data.toString('utf8');
    if(/\b(?:browser|chrome)\s*\./.test(src)) used.push(file);
  }
  return used;
}
function packageReport(buffer){
  const buf=Buffer.isBuffer(buffer)?buffer:Buffer.from(buffer||[]);
  const entries=readZipEntries(buf), manifest=manifestFromEntries(entries), report=analyzeManifest(manifest);
  const apiScripts=scanRuntimeApiUsage(entries,manifest);
  if(apiScripts.length){
    report.unsupported=[...new Set([...(report.unsupported||[]),'content-script-extension-api'])];
    report.fullyCompatible=false;
    report.warnings=[...(report.warnings||[]),'Content scripts call browser/chrome extension APIs: '+apiScripts.slice(0,8).join(', ')];
  }
  return {hash:crypto.createHash('sha256').update(buf).digest('hex'),entries,manifest,report,apiScripts};
}
function stableDirName(report,hash){
  const raw=report.id||report.name||'extension';
  const clean=String(raw).toLowerCase().replace(/[^a-z0-9._@-]+/g,'-').replace(/^-+|-+$/g,'').slice(0,80)||'extension';
  return clean+'-'+hash.slice(0,12);
}
function installXpiBuffer(buffer,rootDir){
  const pkg=packageReport(buffer);
  if(!pkg.report.valid) return {installed:false,mode:'reject',report:pkg.report,hash:pkg.hash};
  if(!pkg.report.fullyCompatible) return {installed:false,mode:'requires-gecko',report:pkg.report,hash:pkg.hash};
  const dest=path.join(rootDir,stableDirName(pkg.report,pkg.hash));
  fs.mkdirSync(dest,{recursive:true,mode:0o700});
  for(const entry of pkg.entries){
    const target=path.join(dest,...entry.name.split('/'));
    const rel=path.relative(dest,target);
    if(rel.startsWith('..')||path.isAbsolute(rel)) throw new Error('Unsafe extension path after extraction.');
    if(entry.directory){fs.mkdirSync(target,{recursive:true,mode:0o700});continue;}
    fs.mkdirSync(path.dirname(target),{recursive:true,mode:0o700});
    fs.writeFileSync(target,entry.data,{mode:0o600});
  }
  const metadata={id:pkg.report.id||'',name:pkg.report.name,version:pkg.report.version,hash:pkg.hash,installedAt:new Date().toISOString(),mode:'compat-runtime'};
  fs.writeFileSync(path.join(dest,'.aegis-extension.json'),JSON.stringify(metadata,null,2),{mode:0o600});
  return {installed:true,mode:'compat-runtime',report:pkg.report,hash:pkg.hash,path:dest,metadata};
}
function loadInstalledExtensions(rootDir){
  try{
    return fs.readdirSync(rootDir,{withFileTypes:true}).filter((d)=>d.isDirectory()).map((d)=>{
      const dir=path.join(rootDir,d.name), manifestPath=path.join(dir,'manifest.json'), metaPath=path.join(dir,'.aegis-extension.json');
      if(!fs.existsSync(manifestPath)||!fs.existsSync(metaPath)) return null;
      const manifest=JSON.parse(fs.readFileSync(manifestPath,'utf8')), metadata=JSON.parse(fs.readFileSync(metaPath,'utf8'));
      return {dir,manifest,metadata,report:analyzeManifest(manifest)};
    }).filter(Boolean);
  }catch{return [];}
}
function patternMatches(rawUrl,pattern){
  if(pattern==='<all_urls>') return /^(https?|file):/.test(String(rawUrl||''));
  let u; try{u=new URL(rawUrl);}catch{return false;}
  const m=String(pattern||'').match(/^(\*|http|https|file):\/\/([^/]*)(\/.*)$/); if(!m) return false;
  if(m[1]!=='*'&&u.protocol!==m[1]+':') return false;
  const host=m[2];
  if(host!=='*'){
    if(host.startsWith('*.')){const base=host.slice(2); if(u.hostname!==base&&!u.hostname.endsWith('.'+base)) return false;}
    else if(u.hostname!==host) return false;
  }
  const escaped=m[3].split('*').map((x)=>x.replace(/[.*+?^$()|[\]\\]/g,'\\$&')).join('.*');
  return new RegExp('^'+escaped+'$').test(u.pathname+u.search);
}
function contentPlans(extensions,rawUrl,runAt='document_idle'){
  const plans=[];
  for(const ext of extensions||[]) for(const cs of ext.manifest.content_scripts||[]){
    if((cs.run_at||'document_idle')!==runAt) continue;
    if(!(cs.matches||[]).some((p)=>patternMatches(rawUrl,p))) continue;
    if((cs.exclude_matches||[]).some((p)=>patternMatches(rawUrl,p))) continue;
    const read=(rel)=>{const safe=safeEntryName(rel);if(!safe)return'';const full=path.join(ext.dir,...safe.split('/'));const r=path.relative(ext.dir,full);if(r.startsWith('..')||path.isAbsolute(r)||!fs.existsSync(full))return'';return fs.readFileSync(full,'utf8');};
    plans.push({id:ext.metadata.id||ext.metadata.hash.slice(0,12),name:ext.metadata.name,css:(cs.css||[]).map(read).filter(Boolean),js:(cs.js||[]).map(read).filter(Boolean)});
  }
  return plans;
}
module.exports={safeEntryName,readZipEntries,manifestFromEntries,scanRuntimeApiUsage,packageReport,installXpiBuffer,loadInstalledExtensions,patternMatches,contentPlans};
