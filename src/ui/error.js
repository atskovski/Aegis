'use strict';
const p = new URLSearchParams(location.search);
const raw = p.get('url') || '';
const code = p.get('code') || '';
const description = p.get('description') || 'Page could not be loaded.';
const offerHttp = p.get('offerHttp') === '1';
let target = null;
try { target = new URL(raw); } catch {}
document.getElementById('description').textContent = description;
document.getElementById('targetUrl').textContent = raw || 'Unknown address';
document.getElementById('errorCode').textContent = code ? `Error ${code}` : 'Network error';
if (target && ['https:', 'http:'].includes(target.protocol)) {
  document.getElementById('retry').href = target.toString();
  if (offerHttp && target.protocol === 'https:') {
    const http = new URL(target.toString()); http.protocol = 'http:';
    const a = document.getElementById('httpRetry'); a.href = `aegis://app/open-http?url=${encodeURIComponent(http.toString())}`; a.classList.remove('hidden');
  }
}
