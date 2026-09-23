'use strict';

function normalizeHost(value) {
  const s = String(value || '').trim().toLowerCase().replace(/^\|\|/, '').replace(/\^.*$/, '').replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^\.+|\.+$/g, '');
  return /^[a-z0-9.-]+$/.test(s) && s.includes('.') ? s : '';
}

function hostMatches(host, ruleHost) {
  return host === ruleHost || host.endsWith(`.${ruleHost}`);
}

function parseFilterRules(text) {
  const block = [];
  const allow = [];
  for (const lineRaw of String(text || '').split(/\r?\n/).slice(0, 5000)) {
    const line = lineRaw.trim();
    if (!line || line.startsWith('!') || line.startsWith('#')) continue;
    const isAllow = line.startsWith('@@');
    const body = isAllow ? line.slice(2) : line;
    const host = normalizeHost(body);
    if (!host) continue;
    (isAllow ? allow : block).push(host);
  }
  return { block: [...new Set(block)].slice(0, 2500), allow: [...new Set(allow)].slice(0, 2500) };
}

function matchFilterRules(rawUrl, rules) {
  let host;
  try { host = new URL(rawUrl).hostname.toLowerCase(); } catch { return null; }
  if (rules?.allow?.some((r) => hostMatches(host, r))) return 'allow';
  if (rules?.block?.some((r) => hostMatches(host, r))) return 'block';
  return null;
}

module.exports = { parseFilterRules, matchFilterRules, normalizeHost, hostMatches };
