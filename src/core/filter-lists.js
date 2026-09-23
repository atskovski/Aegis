'use strict';
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const CATALOG=Object.freeze([
 {id:'ublock',name:'uBlock filters',url:'https://ublockorigin.github.io/uAssets/filters/filters.min.txt',format:'abp'},
 {id:'ublock-privacy',name:'uBlock privacy',url:'https://ublockorigin.github.io/uAssets/filters/privacy.min.txt',format:'abp'},
 {id:'ublock-unbreak',name:'uBlock unbreak',url:'https://ublockorigin.github.io/uAssets/filters/unbreak.min.txt',format:'abp'},
 {id:'easylist',name:'EasyList',url:'https://ublockorigin.github.io/uAssets/thirdparties/easylist.txt',format:'abp'},
 {id:'easyprivacy',name:'EasyPrivacy',url:'https://ublockorigin.github.io/uAssets/thirdparties/easyprivacy.txt',format:'abp'},
 {id:'pgl',name:'Peter Lowe',url:'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=1&mimetype=plaintext',format:'hosts'}
]);
function safeId(id){return String(id||'').replace(/[^a-z0-9_-]/gi,'').slice(0,60)}
function cacheFile(dir,id){return path.join(dir,safeId(id)+'.txt')}function metaFile(dir,id){return path.join(dir,safeId(id)+'.json')}
function hostsToRules(text){return String(text).split(/\r?\n/).map(l=>l.replace(/#.*/,'').trim()).filter(Boolean).map(l=>{const p=l.split(/\s+/);return p.length>1&&/^(?:0\.0\.0\.0|127\.0\.0\.1|::1)$/.test(p[0])?p.slice(1).map(h=>'||'+h+'^').join('\n'):''}).filter(Boolean).join('\n')}
function normalize(text,format){return format==='hosts'?hostsToRules(text):String(text)}
function readEnabled(dir,enabled=[]){const chunks=[];for(const id of enabled){try{const item=CATALOG.find(x=>x.id===id),s=fs.readFileSync(cacheFile(dir,id),'utf8');if(s.length<=12*1024*1024)chunks.push(normalize(s,item?.format))}catch{}}return chunks.join('\n')}
function readMeta(file){try{return JSON.parse(fs.readFileSync(file,'utf8'))}catch{return {}}}
async function readBounded(res,maxBytes){const len=Number(res.headers?.get?.('content-length')||0);if(len>maxBytes)throw new Error('list exceeds size limit');const reader=res.body?.getReader?.();if(!reader){const b=Buffer.from(await res.arrayBuffer());if(b.length>maxBytes)throw new Error('list exceeds size limit');return b}const chunks=[];let total=0;for(;;){const {done,value}=await reader.read();if(done)break;total+=value.byteLength;if(total>maxBytes){try{await reader.cancel()}catch{}throw new Error('list exceeds size limit')}chunks.push(Buffer.from(value))}return Buffer.concat(chunks,total)}
async function refresh({dir,enabled=[],fetchImpl,maxBytes=12*1024*1024,ttlMs=24*60*60*1000,force=false}){
 fs.mkdirSync(dir,{recursive:true,mode:0o700});const results=[];
 for(const item of CATALOG.filter(x=>enabled.includes(x.id))){try{
  const mf=metaFile(dir,item.id),old=readMeta(mf),cached=cacheFile(dir,item.id);
  if(!force&&fs.existsSync(cached)&&old.updatedAt&&Date.now()-Date.parse(old.updatedAt)<ttlMs){results.push({id:item.id,ok:true,cached:true,...old});continue}
  const headers={};if(old.etag)headers['If-None-Match']=old.etag;if(old.lastModified)headers['If-Modified-Since']=old.lastModified;
  const res=await fetchImpl(item.url,{redirect:'follow',headers,credentials:'omit',referrerPolicy:'no-referrer'});
  if(res.status===304&&fs.existsSync(cached)){const meta={...old,updatedAt:new Date().toISOString()};fs.writeFileSync(mf,JSON.stringify(meta),{mode:0o600});results.push({id:item.id,ok:true,cached:true,...meta});continue}
  if(!res.ok)throw new Error('HTTP '+res.status);const buf=await readBounded(res,maxBytes),text=buf.toString('utf8');if(!text.includes('\n'))throw new Error('invalid filter list');
  const normalized=normalize(text,item.format);if(normalized.split('\n').filter(Boolean).length<10)throw new Error('filter list failed parse-health threshold');
  const tmp=cached+'.tmp';fs.writeFileSync(tmp,text,{mode:0o600});fs.renameSync(tmp,cached);
  const meta={bytes:buf.length,sha256:crypto.createHash('sha256').update(buf).digest('hex'),updatedAt:new Date().toISOString(),etag:res.headers?.get?.('etag')||'',lastModified:res.headers?.get?.('last-modified')||'',format:item.format};fs.writeFileSync(mf,JSON.stringify(meta),{mode:0o600});results.push({id:item.id,ok:true,...meta});
 }catch(err){results.push({id:item.id,ok:false,lastKnownGood:fs.existsSync(cacheFile(dir,item.id)),error:String(err.message||err).slice(0,180)})}}
 return results;
}
module.exports={CATALOG,readEnabled,refresh,cacheFile,metaFile,hostsToRules,normalize,readBounded};
