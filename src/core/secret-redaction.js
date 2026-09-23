'use strict';
const KEY_RE=/(token|secret|password|passwd|authorization|cookie|api[-_]?key|private[-_]?key|credential)/i;
function redactString(v){
 const s=String(v??'');
 return s
  .replace(/\b(Bearer\s+)[A-Za-z0-9._~+\/-]+=*/gi,'$1[REDACTED]')
  .replace(/\b(sk-[A-Za-z0-9_-]{8,})\b/g,'[REDACTED]')
  .replace(/([?&](?:token|key|secret|password|auth)=)[^&#\s]+/gi,'$1[REDACTED]');
}
function redact(value,depth=0){
 if(depth>8)return '[REDACTED:DEPTH]';
 if(Array.isArray(value))return value.map(v=>redact(v,depth+1));
 if(value&&typeof value==='object'){
  const out={}; for(const [k,v] of Object.entries(value))out[k]=KEY_RE.test(k)?'[REDACTED]':redact(v,depth+1); return out;
 }
 return typeof value==='string'?redactString(value):value;
}
function maskProxyServer(v){const s=String(v||'');return s.replace(/\/\/([^/@:]+):([^/@]+)@/,'//$1:[REDACTED]@');}
module.exports={redact,redactString,maskProxyServer};
