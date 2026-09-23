'use strict';

function timeout(promise, ms, label) {
  let timer;
  return Promise.race([
    Promise.resolve(promise),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms); })
  ]).finally(() => clearTimeout(timer));
}

function isPublicIp(value) {
  const input = String(value || '').trim();
  if (!input || input.length > 64) return false;
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(input) && input.split('.').every((x) => Number(x) >= 0 && Number(x) <= 255);
  const ipv6 = /^[0-9a-f:]+$/i.test(input) && input.includes(':');
  return ipv4 || ipv6;
}

async function readText(response) {
  const text = await timeout(response.text(), 2500, 'Public IP response');
  return String(text || '').trim();
}

async function fetchPublicIp(ses) {
  if (!ses) return { ok: false, status: 'not-tested', ip: '', provider: '', error: 'No disposable session available.' };
  const endpoints = [
    { url: 'https://api.ipify.org?format=json', provider: 'ipify', parse: (text) => { try { return JSON.parse(text).ip || ''; } catch { return ''; } } },
    { url: 'https://icanhazip.com/', provider: 'icanhazip', parse: (text) => text.split(/\s+/)[0] || '' }
  ];
  const errors = [];
  for (const endpoint of endpoints) {
    try {
      const response = await timeout(ses.fetch(endpoint.url, { method: 'GET', redirect: 'follow', cache: 'no-store' }), 6500, 'Public IP lookup');
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const value = endpoint.parse(await readText(response));
      if (!isPublicIp(value)) throw new Error('Provider returned an invalid IP value');
      return { ok: true, status: 'info', ip: value, provider: endpoint.provider, error: '' };
    } catch (err) { errors.push(`${endpoint.provider}: ${err.message}`); }
  }
  return { ok: false, status: 'fail', ip: '', provider: '', error: errors.join(' | ').slice(0, 500) || 'Public IP lookup failed.' };
}

async function testSessionIsolation(createSession) {
  if (typeof createSession !== 'function') return { ok: false, status: 'not-tested', evidence: 'Session factory unavailable.' };
  const token = `aegis-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const url = 'https://aegis-isolation.test/';
  const a = createSession('proof-a');
  const b = createSession('proof-b');
  try {
    await a.cookies.set({ url, name: 'aegis_proof', value: token, secure: true, sameSite: 'lax' });
    const [cookiesA, cookiesB] = await Promise.all([
      a.cookies.get({ url, name: 'aegis_proof' }),
      b.cookies.get({ url, name: 'aegis_proof' })
    ]);
    const presentA = cookiesA.some((c) => c.value === token);
    const leakedB = cookiesB.some((c) => c.value === token);
    const ok = presentA && !leakedB;
    return {
      ok,
      status: ok ? 'pass' : 'fail',
      evidence: ok ? 'Cookie written to proof session A was absent from isolated session B.' : `Isolation proof failed (presentA=${presentA}, leakedB=${leakedB}).`
    };
  } catch (err) {
    return { ok: false, status: 'fail', evidence: `Isolation test error: ${err.message}` };
  } finally {
    for (const ses of [a, b]) {
      try { await ses.clearData(); } catch {}
      try { await ses.clearCache(); } catch {}
      try { await ses.closeAllConnections(); } catch {}
    }
  }
}

function candidateAddresses(candidates = []) {
  const out = [];
  for (const value of Array.isArray(candidates) ? candidates : []) {
    const text = String(value || '');
    for (const match of text.matchAll(/(?:candidate:\S+\s+\d+\s+\S+\s+\d+\s+)([^\s]+)\s+\d+\s+typ\s+host/gi)) out.push(match[1]);
  }
  return [...new Set(out)];
}
function isNumericLocalLeak(value) {
  const v = String(value || '').trim().toLowerCase();
  if (!v || /\.local$/.test(v)) return false;
  if (['0.0.0.0','127.0.0.1','::1'].includes(v)) return false;
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(v) || /^[0-9a-f:]+$/i.test(v);
}
async function testWebRtcLeakSurface(executeJavaScript) {
  if (typeof executeJavaScript !== 'function') return { status:'not-tested', ok:false, addresses:[], evidence:'Renderer execution unavailable.' };
  const source = `(async()=>{if(typeof RTCPeerConnection!=='function')return {supported:false,candidates:[]};const pc=new RTCPeerConnection({iceServers:[]});const c=[];pc.createDataChannel('a');pc.onicecandidate=e=>{if(e.candidate&&e.candidate.candidate)c.push(e.candidate.candidate)};try{await pc.setLocalDescription(await pc.createOffer());await new Promise(r=>setTimeout(r,900));}catch{}finally{try{pc.close()}catch{}}return {supported:true,candidates:c}})()`;
  try {
    const result = await timeout(executeJavaScript(source), 2200, 'WebRTC leak test');
    if (!result?.supported) return { status:'info', ok:true, addresses:[], evidence:'RTCPeerConnection is not exposed in this renderer.' };
    const addresses = candidateAddresses(result.candidates);
    const leaked = addresses.filter(isNumericLocalLeak);
    return { status: leaked.length ? 'fail' : 'pass', ok: leaked.length === 0, addresses, evidence: leaked.length ? `Numeric host ICE candidate(s) exposed: ${leaked.join(', ')}` : 'No numeric local host IP was exposed in host ICE candidates.' };
  } catch (err) { return { status:'not-tested', ok:false, addresses:[], evidence:`WebRTC behavioral test unavailable: ${err.message}` }; }
}

async function inspectPrivacySurfaces(executeJavaScript) {
  if (typeof executeJavaScript !== 'function') return { status:'not-tested', values:{}, evidence:'Renderer execution unavailable.' };
  const source = `(()=>{const n=navigator,d=document;let debugExt='unknown',webglVendor='',webglRenderer='';try{const c=d.createElement('canvas');const gl=c.getContext('webgl')||c.getContext('webgl2');debugExt=gl?Boolean(gl.getExtension('WEBGL_debug_renderer_info')):false;if(gl){try{webglVendor=String(gl.getParameter(gl.VENDOR)||'')}catch{};try{webglRenderer=String(gl.getParameter(gl.RENDERER)||'')}catch{}}}catch{};const storage=(name)=>{try{const s=window[name];if(!s)return false;const k='__aegis_probe_'+Math.random();s.setItem(k,'1');s.removeItem(k);return true}catch{return false}};const canvasSignature=(()=>{try{const c=d.createElement('canvas');c.width=220;c.height=30;const x=c.getContext('2d');x.textBaseline='top';x.font='14px Arial';x.fillStyle='#f60';x.fillRect(10,4,62,20);x.fillStyle='#069';x.fillText('Aegis privacy probe',2,7);const value=c.toDataURL();let h=2166136261;for(let i=0;i<value.length;i++){h^=value.charCodeAt(i);h=Math.imul(h,16777619)}return (h>>>0).toString(16).padStart(8,'0')}catch{return 'unavailable'}})();return {gpc:n.globalPrivacyControl===true,dnt:String(n.doNotTrack||''),language:String(n.language||''),languages:Array.from(n.languages||[]).slice(0,8),platform:String(n.platform||''),webdriver:Boolean(n.webdriver),plugins:Number(n.plugins?.length||0),cookieEnabled:Boolean(n.cookieEnabled),bluetooth:typeof n.bluetooth!=='undefined',usb:typeof n.usb!=='undefined',serial:typeof n.serial!=='undefined',hid:typeof n.hid!=='undefined',localFonts:typeof window.queryLocalFonts==='function',joinAdInterestGroup:typeof n.joinAdInterestGroup==='function',runAdAuction:typeof n.runAdAuction==='function',privateToken:typeof d.hasPrivateToken==='function',storageAccess:typeof d.requestStorageAccess==='function',hardwareConcurrency:n.hardwareConcurrency,deviceMemory:n.deviceMemory,maxTouchPoints:n.maxTouchPoints,screen:[screen.width,screen.height,screen.colorDepth,devicePixelRatio],timezone:(()=>{try{return Intl.DateTimeFormat().resolvedOptions().timeZone||''}catch{return ''}})(),timezoneOffset:(()=>{try{return new Date().getTimezoneOffset()}catch{return null}})(),localStorage:storage('localStorage'),sessionStorage:storage('sessionStorage'),indexedDB:typeof indexedDB!=='undefined',debugRendererInfo:debugExt,webglVendor,webglRenderer,userAgent:String(n.userAgent||''),canvasSignature,fontMetricProtected:(()=>{try{const make=(font)=>{const e=d.createElement('span');e.textContent='mmmmmmmmmmlliWW00';e.style.cssText='position:absolute;left:-9999px;top:-9999px;visibility:hidden;font-size:72px;white-space:nowrap;font-family:'+font+', monospace';d.documentElement.appendChild(e);const out=[e.offsetWidth,e.offsetHeight];e.remove();return out};const a=make('Arial'),b=make('Definitely Missing Aegis Font');return a[0]===b[0]&&a[1]===b[1]}catch{return false}})()}})()`;
  try {
    const values = await timeout(executeJavaScript(source), 1800, 'Privacy surface inspection');
    return { status:'pass', values: values || {}, evidence:'Renderer privacy surfaces inspected in the active tab.' };
  } catch (err) { return { status:'not-tested', values:{}, evidence:`Privacy surface inspection unavailable: ${err.message}` }; }
}

function routePrivacyStatus(proxyMode, route = null) {
  const mode = String(proxyMode || 'system');
  if (['socks5','http','https'].includes(mode)) {
    if (route?.fallback) return { status:'fail', evidence:'Configured proxy fell back to another route.' };
    if (route?.ok === false) return { status:'fail', evidence:'Configured proxy route is not healthy.' };
    return { status:'pass', evidence:`A fixed ${mode.toUpperCase()} proxy route is configured and no fallback was reported.` };
  }
  return { status:'warning', evidence: mode === 'direct' ? 'Direct mode exposes the network public IP to destination sites.' : 'System routing is active. Aegis cannot prove that the system route hides the public IP; use a trusted VPN/proxy if IP masking is required.' };
}

function makeCheck(id, label, status, evidence, scope = 'runtime') {
  const allowed = ['pass','warning','info','fail','not-tested'];
  const normalized = allowed.includes(status) ? status : 'not-tested';
  return { id, label, status: normalized, ok: normalized === 'pass', evidence: String(evidence || '').slice(0, 800), scope };
}

function summarizeChecks(checks) {
  const list = Array.isArray(checks) ? checks : [];
  const counts = { pass: 0, warning: 0, info: 0, fail: 0, 'not-tested': 0 };
  for (const check of list) counts[check?.status] = (counts[check?.status] || 0) + 1;
  return { ...counts, total: list.length };
}

module.exports = {
  isPublicIp, fetchPublicIp, testSessionIsolation, candidateAddresses, isNumericLocalLeak,
  testWebRtcLeakSurface, inspectPrivacySurfaces, routePrivacyStatus, makeCheck, summarizeChecks
};
