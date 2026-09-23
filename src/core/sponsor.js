'use strict';
const crypto = require('node:crypto');

function youtubeVideoId(raw) {
  try {
    const u = new URL(raw);
    if (/(^|\.)youtube\.com$/.test(u.hostname)) {
      if (u.pathname === '/watch') return (u.searchParams.get('v') || '').slice(0, 32);
      const m = u.pathname.match(/^\/(?:shorts|embed)\/([^/?]+)/); if (m) return m[1].slice(0, 32);
    }
    if (u.hostname === 'youtu.be') return u.pathname.slice(1).split('/')[0].slice(0, 32);
  } catch {}
  return '';
}

async function fetchSponsorSegments(ses, videoId, categories = ['sponsor'], timeoutMs = 6500) {
  if (!ses || !videoId) return [];
  const hash = crypto.createHash('sha256').update(videoId, 'ascii').digest('hex');
  const prefix = hash.slice(0, 4);
  const params = new URLSearchParams({ categories: JSON.stringify(categories), actionTypes: JSON.stringify(['skip']) });
  const url = `https://sponsor.ajay.app/api/skipSegments/${prefix}?${params}`;
  let timer;
  const response = await Promise.race([
    ses.fetch(url, { method: 'GET', redirect: 'follow', credentials: 'omit', cache: 'no-store' }),
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Sponsor lookup timeout')), timeoutMs); })
  ]).finally(() => clearTimeout(timer));
  if (response.status === 404) return [];
  if (!response.ok) throw new Error(`Sponsor service HTTP ${response.status}`);
  const data = await response.json();
  const exact = Array.isArray(data) ? data.find((item) => item?.videoID === videoId && item?.hash === hash) : null;
  return Array.isArray(exact?.segments) ? exact.segments.filter((s) => Array.isArray(s.segment) && s.segment.length === 2).map((s) => ({ start: Number(s.segment[0]), end: Number(s.segment[1]), category: s.category || 'sponsor' })).filter((s) => Number.isFinite(s.start) && Number.isFinite(s.end) && s.end > s.start) : [];
}

function sponsorSkipScript(segments) {
  const safe = JSON.stringify((segments || []).slice(0, 100));
  return `(() => { const segments=${safe}; if (!segments.length) return; if (window.__aegisSponsorTimer) clearInterval(window.__aegisSponsorTimer); window.__aegisSponsorTimer=setInterval(()=>{ const v=document.querySelector('video'); if(!v) return; const t=v.currentTime; const hit=segments.find(s=>t>=s.start&&t<s.end); if(hit) v.currentTime=Math.min(hit.end+0.04, Number.isFinite(v.duration)?v.duration:hit.end+0.04); },500); })();`;
}

module.exports = { youtubeVideoId, fetchSponsorSegments, sponsorSkipScript };
