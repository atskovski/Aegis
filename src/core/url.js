'use strict';

const TRACKING_PARAMS = [
  /^utm_/i,/^fbclid$/i,/^gclid$/i,/^dclid$/i,/^msclkid$/i,/^mc_cid$/i,/^mc_eid$/i,/^_hsenc$/i,/^_hsmi$/i,
  /^mkt_tok$/i,/^vero_id$/i,/^oly_anon_id$/i,/^oly_enc_id$/i,/^wickedid$/i,/^yclid$/i,/^twclid$/i,/^igshid$/i,
  /^s_cid$/i,/^rb_clickid$/i,/^referrer$/i,/^ref_src$/i,/^gbraid$/i,/^wbraid$/i,/^ttclid$/i,/^li_fat_id$/i,/^epik$/i,
  /^irclickid$/i,/^srsltid$/i,/^scid$/i,/^vero_conv$/i,/^vero_id$/i,/^pk_campaign$/i,/^pk_kwd$/i,/^mtm_/i,
  /^campaign_id$/i,/^ad_id$/i,/^adgroupid$/i,/^gad_source$/i,/^gad_campaignid$/i,/^zanpid$/i,/^spm$/i,/^si$/i,
  /^feature$/i,/^cvid$/i,/^ocid$/i,/^ef_id$/i,/^sscid$/i,/^trk$/i,/^trkEmail$/i,/^mid$/i,/^mibextid$/i
];

function isLocalHostname(hostname) {
  const h = (hostname || '').toLowerCase();
  return h === 'localhost' || h === '::1' || h === '[::1]' || h.endsWith('.localhost') || /^127(?:\.\d{1,3}){3}$/.test(h) || /^10(?:\.\d{1,3}){3}$/.test(h) || /^192\.168(?:\.\d{1,3}){2}$/.test(h) || /^172\.(1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}$/.test(h);
}
function registrableLike(hostname) {
  const h = (hostname || '').toLowerCase().replace(/^www\./, '');
  if (!h || isLocalHostname(h)) return h;
  const parts = h.split('.').filter(Boolean); if (parts.length <= 2) return h;
  const commonSecondLevel = new Set(['co.uk','org.uk','gov.uk','com.au','net.au','co.nz','co.jp','com.br']);
  const tail2 = parts.slice(-2).join('.');
  if (commonSecondLevel.has(tail2) && parts.length >= 3) return parts.slice(-3).join('.');
  return tail2;
}
function isThirdParty(requestUrl, topUrl) {
  try { const r = new URL(requestUrl); const t = new URL(topUrl); if (!/^https?:$/.test(r.protocol) || !/^https?:$/.test(t.protocol)) return false; return registrableLike(r.hostname) !== registrableLike(t.hostname); } catch { return false; }
}
function stripTrackingParams(raw) {
  try {
    const u = new URL(raw); if (!/^https?:$/.test(u.protocol)) return raw;
    let changed = false;
    for (const key of [...u.searchParams.keys()]) if (TRACKING_PARAMS.some((rx) => rx.test(key))) { u.searchParams.delete(key); changed = true; }
    return changed ? u.toString() : raw;
  } catch { return raw; }
}
function unwrapTrackingRedirect(raw) {
  try {
    const u = new URL(raw); const h = u.hostname.toLowerCase(); let candidate = '';
    if ((h === 'www.google.com' || h === 'google.com') && u.pathname === '/url') candidate = u.searchParams.get('q') || u.searchParams.get('url') || '';
    else if ((h === 'www.facebook.com' || h === 'l.facebook.com') && u.pathname.endsWith('/l.php')) candidate = u.searchParams.get('u') || '';
    else if ((h === 'www.youtube.com' || h === 'youtube.com') && u.pathname === '/redirect') candidate = u.searchParams.get('q') || '';
    else if (h.endsWith('safelinks.protection.outlook.com')) candidate = u.searchParams.get('url') || '';
    if (!candidate) return raw;
    const decoded = decodeURIComponent(candidate);
    const target = new URL(decoded);
    return ['https:','http:'].includes(target.protocol) ? target.toString() : raw;
  } catch { return raw; }
}
function cleanNavigationUrl(raw, options = {}) {
  let out = String(raw || '');
  if (options.unwrap !== false) out = unwrapTrackingRedirect(out);
  if (options.strip !== false) out = stripTrackingParams(out);
  return out;
}
function normalizeInput(input, searchTemplate = 'https://duckduckgo.com/?q=%s') {
  const text = String(input || '').trim();
  if (!text) return 'https://duckduckgo.com/';
  if (/^aegis:\/\//i.test(text)) return text;
  if (/^[a-zA-Z][a-zA-Z\d+.-]*:\/\//.test(text)) return text;
  const looksLikeHost = /^(localhost|\d{1,3}(?:\.\d{1,3}){3}|\[[a-fA-F0-9:]+\]|[^\s]+\.[^\s]+)(:\d+)?(?:\/.*)?$/.test(text);
  if (looksLikeHost) return `https://${text}`;
  return searchTemplate.replace('%s', encodeURIComponent(text));
}
function isAllowedNavigation(raw) { try { return ['https:','http:','aegis:','about:','data:','blob:'].includes(new URL(raw).protocol); } catch { return false; } }
function shouldUpgradeHttp(raw, allowHttp = false) { try { const u = new URL(raw); return u.protocol === 'http:' && !allowHttp && !isLocalHostname(u.hostname) && !u.hostname.endsWith('.onion'); } catch { return false; } }
function upgradeToHttps(raw) { const u = new URL(raw); u.protocol = 'https:'; return u.toString(); }

module.exports = { TRACKING_PARAMS, isLocalHostname, registrableLike, isThirdParty, stripTrackingParams, unwrapTrackingRedirect, cleanNavigationUrl, normalizeInput, isAllowedNavigation, shouldUpgradeHttp, upgradeToHttps };
