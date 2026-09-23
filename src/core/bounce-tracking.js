'use strict';

function hostOf(raw='') { try { return new URL(String(raw)).hostname.toLowerCase(); } catch { return ''; } }
function registrableApprox(host='') {
  const p=String(host).split('.').filter(Boolean);
  return p.length > 2 ? p.slice(-2).join('.') : p.join('.');
}
function sameSite(a,b){ const x=registrableApprox(hostOf(a)),y=registrableApprox(hostOf(b)); return Boolean(x&&y&&x===y); }

function makeBounceTracker() {
  return { chain: [], lastCommitted: '', lastAt: 0 };
}
function noteNavigation(state, fromUrl, toUrl, at=Date.now()) {
  if (!state) return null;
  const from=String(fromUrl||''), to=String(toUrl||'');
  if (!/^https?:/i.test(to)) return null;
  const item={from,to,fromHost:hostOf(from),toHost:hostOf(to),at:Number(at)||Date.now()};
  state.chain.push(item); state.chain=state.chain.slice(-12); state.lastCommitted=to; state.lastAt=item.at;
  return item;
}
function detectBounce(state, windowSec=12, now=Date.now()) {
  const chain=state?.chain||[]; if(chain.length<2) return null;
  const a=chain[chain.length-2], b=chain[chain.length-1];
  const elapsed=Math.max(0,(Number(now)||Date.now())-a.at);
  if(elapsed>Math.max(3,Number(windowSec)||12)*1000) return null;
  if(!a.fromHost||!a.toHost||!b.toHost) return null;
  // A -> B -> C where B is a short-lived cross-site intermediary.
  if(sameSite(a.from,a.to)||sameSite(a.to,b.to)||sameSite(a.from,b.to)) return null;
  return { intermediaryOrigin:(()=>{try{return new URL(a.to).origin}catch{return ''}})(), intermediaryHost:a.toHost, destinationHost:b.toHost, elapsedMs:elapsed };
}
module.exports={makeBounceTracker,noteNavigation,detectBounce,sameSite,hostOf};
