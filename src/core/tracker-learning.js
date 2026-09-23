'use strict';

function hostOf(raw) { try { return new URL(raw).hostname.toLowerCase(); } catch { return ''; } }
function siteKey(host) {
  const parts = String(host || '').split('.').filter(Boolean);
  return parts.length > 1 ? parts.slice(-2).join('.') : host;
}

class TrackerLearner {
  constructor() { this.map = new Map(); }
  observe(requestUrl, topUrl, evidence = {}) {
    const trackerHost = hostOf(requestUrl);
    const topHost = hostOf(topUrl);
    if (!trackerHost || !topHost || siteKey(trackerHost) === siteKey(topHost)) return false;
    const rec = this.map.get(trackerHost) || { sites: new Set(), cookieEvidence: 0, observations: 0 };
    rec.sites.add(siteKey(topHost));
    rec.observations += 1;
    if (evidence.cookie) rec.cookieEvidence += 1;
    this.map.set(trackerHost, rec);
    return this.isLikelyTracker(trackerHost);
  }
  isLikelyTracker(host) {
    const rec = this.map.get(String(host || '').toLowerCase());
    if (!rec) return false;
    return rec.sites.size >= 4 || (rec.sites.size >= 3 && rec.cookieEvidence >= 2);
  }
  score(host) {
    const rec = this.map.get(String(host || '').toLowerCase());
    if (!rec) return 0;
    return Math.min(100, rec.sites.size * 18 + rec.cookieEvidence * 12 + Math.min(20, rec.observations));
  }
  reset() { this.map.clear(); }
}

module.exports = { TrackerLearner, hostOf, siteKey };
