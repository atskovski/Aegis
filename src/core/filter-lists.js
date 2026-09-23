'use strict';
const fs=require('node:fs');const path=require('node:path');const crypto=require('node:crypto');
const CATALOG=Object.freeze([
 {id:'ublock',name:'uBlock filters',url:'https://ublockorigin.github.io/uAssets/filters/filters.min.txt'},
 {id:'ublock-privacy',name:'uBlock privacy',url:'https://ublockorigin.github.io/uAssets/filters/privacy.min.txt'},
 {id:'ublock-unbreak',name:'uBlock unbreak',url:'https://ublockorigin.github.io/uAssets/filters/unbreak.min.txt'},
 {id:'easylist',name:'EasyList',url:'https://ublockorigin.github.io/uAssets/thirdparties/easylist.txt'},
 {id:'easyprivacy',name:'EasyPrivacy',url:'https://ublockorigin.github.io/uAssets/thirdparties/easyprivacy.txt'},
 {id:'pgl',name:'Peter Lowe',url:'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=1&mimetype=plaintext'}
]);
function safeId(id){return String(id||'').replace(/[^a-z0-9_-]/gi,'').slice(0,60);}
function cacheFile(dir,id){return path.join(dir,safeId(id)+'.txt');}
function readEnabled(dir,enabled=[]){const chunks=[];for(const id of enabled){try{const s=fs.readFileSync(cacheFile(dir,id),'utf8');if(s.length<=12*1024*1024)chunks.push(s);}catch{}}return chunks.join('\n');}
async function refresh({dir,enabled=[],fetchImpl,maxBytes=12*1024*1024}){
 fs.mkdirSync(dir,{recursive:true,mode:0o700});const results=[];
 for(const item of CATALOG.filter(x=>enabled.includes(x.id))){try{
   const res=await fetchImpl(item.url,{redirect:'follow'});if(!res.ok)throw new Error('HTTP '+res.status);
   const buf=Buffer.from(await res.arrayBuffer());if(buf.length>maxBytes)throw new Error('list exceeds size limit');
   const text=buf.toString('utf8');if(!text.includes('\n'))throw new Error('invalid filter list');
   const tmp=cacheFile(dir,item.id)+'.tmp';fs.writeFileSync(tmp,text,{mode:0o600});fs.renameSync(tmp,cacheFile(dir,item.id));
   results.push({id:item.id,ok:true,bytes:buf.length,sha256:crypto.createHash('sha256').update(buf).digest('hex')});
 }catch(err){results.push({id:item.id,ok:false,error:String(err.message||err).slice(0,180)});}}
 return results;
}
module.exports={CATALOG,readEnabled,refresh,cacheFile};
